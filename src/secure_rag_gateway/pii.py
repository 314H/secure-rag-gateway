"""Detecção e pseudonimização de dados pessoais com Microsoft Presidio.

O LLM nunca recebe o dado real: cada valor vira um token (<CPF_1>, <PESSOA_1>...) guardado num cofre que
vive só durante a requisição. Na resposta, o token volta ao valor original apenas para as entidades que o
grupo do usuário pode ver (policy.pii.reidentify); as demais saem mascaradas.
"""

import re
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import CreditCardRecognizer, EmailRecognizer, SpacyRecognizer

from .br_recognizers import BrPhoneRecognizer, CnpjRecognizer, CpfRecognizer, PixEvpRecognizer

TOKEN_LABELS = {
    "BR_CPF": "CPF",
    "BR_CNPJ": "CNPJ",
    "CREDIT_CARD": "CARTAO",
    "EMAIL_ADDRESS": "EMAIL",
    "BR_PHONE": "TELEFONE",
    "PIX_EVP": "CHAVE_PIX",
    "PERSON": "PESSOA",
}
TOKEN_RE = re.compile(r"<(" + "|".join(TOKEN_LABELS.values()) + r")_(\d+)>")

SPACY_MODELS = {"pt": "pt_core_news_md"}

# O NER do spaCy confunde siglas e termos do domínio bancário com nomes de pessoa
PERSON_STOPWORDS = {"cpf", "cnpj", "pix", "ted", "doc", "rg", "cep", "iof", "cdb", "lgpd", "sac", "banco exemplo"}


def _is_false_person(text: str) -> bool:
    return text.lower() in PERSON_STOPWORDS or (text.isupper() and len(text) <= 5)


@lru_cache(maxsize=4)
def build_analyzer(language: str = "pt") -> AnalyzerEngine:
    nlp_engine = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": language, "model_name": SPACY_MODELS[language]}],
            "ner_model_configuration": {
                "model_to_presidio_entity_mapping": {"PER": "PERSON", "LOC": "LOCATION", "ORG": "ORGANIZATION"},
                "labels_to_ignore": ["MISC"],
            },
        }
    ).create_engine()
    registry = RecognizerRegistry(supported_languages=[language])
    for recognizer in (
        SpacyRecognizer(supported_language=language, supported_entities=["PERSON"]),
        EmailRecognizer(supported_language=language),
        CreditCardRecognizer(supported_language=language, context=["cartão", "cartao", "crédito", "credito", "débito"]),
        CpfRecognizer(language),
        CnpjRecognizer(language),
        BrPhoneRecognizer(language),
        PixEvpRecognizer(language),
    ):
        registry.add_recognizer(recognizer)
    return AnalyzerEngine(nlp_engine=nlp_engine, registry=registry, supported_languages=[language])


@dataclass
class PiiVault:
    """Cofre de pseudônimos de uma única requisição (nunca persistido nem enviado a logs)."""

    by_value: dict[tuple[str, str], str] = field(default_factory=dict)
    by_token: dict[str, tuple[str, str]] = field(default_factory=dict)
    counters: Counter = field(default_factory=Counter)

    def token_for(self, entity: str, value: str) -> str:
        key = (entity, value)
        if key not in self.by_value:
            self.counters[entity] += 1
            token = f"<{TOKEN_LABELS.get(entity, entity)}_{self.counters[entity]}>"
            self.by_value[key] = token
            self.by_token[token] = key
        return self.by_value[key]


def mask(entity: str, value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if entity == "BR_CPF":
        return f"***.***.***-{digits[-2:]}"
    if entity == "CREDIT_CARD":
        return f"**** **** **** {digits[-4:]}"
    if entity == "EMAIL_ADDRESS" and "@" in value:
        user, domain = value.split("@", 1)
        return f"{user[:1]}***@{domain}"
    return f"[{TOKEN_LABELS.get(entity, entity)}]"


def _non_overlapping(results: list[RecognizerResult]) -> list[RecognizerResult]:
    chosen: list[RecognizerResult] = []
    for r in sorted(results, key=lambda r: (-r.score, -(r.end - r.start))):
        if all(r.end <= c.start or r.start >= c.end for c in chosen):
            chosen.append(r)
    return sorted(chosen, key=lambda r: r.start)


class PiiEngine:
    def __init__(self, entities: list[str], language: str = "pt", min_score: float = 0.5):
        self.entities = entities
        self.language = language
        self.min_score = min_score
        self.analyzer = build_analyzer(language)

    def analyze(self, text: str, entities: list[str] | None = None) -> list[RecognizerResult]:
        results = self.analyzer.analyze(
            text=text, language=self.language, entities=entities or self.entities, score_threshold=self.min_score
        )
        # tokens já pseudonimizados (<PESSOA_1>) não podem ser reanalisados como novo dado pessoal
        protected = [(m.start(), m.end()) for m in TOKEN_RE.finditer(text)]
        results = [
            r
            for r in results
            if not any(r.start < e and r.end > s for s, e in protected)
            and not (r.entity_type == "PERSON" and _is_false_person(text[r.start : r.end]))
        ]
        return _non_overlapping(results)

    def pseudonymize(self, text: str, vault: PiiVault) -> tuple[str, Counter]:
        found: Counter = Counter()
        out = text
        for r in reversed(self.analyze(text)):
            token = vault.token_for(r.entity_type, text[r.start : r.end])
            out = out[: r.start] + token + out[r.end :]
            found[r.entity_type] += 1
        return out, found

    def redact(self, text: str, entities: list[str] | None = None) -> tuple[str, Counter]:
        """Remoção irreversível, usada na ingestão de documentos e como rede de segurança na saída."""
        found: Counter = Counter()
        out = text
        for r in reversed(self.analyze(text, entities)):
            out = out[: r.start] + mask(r.entity_type, text[r.start : r.end]) + out[r.end :]
            found[r.entity_type] += 1
        return out, found


def reidentify(text: str, vault: PiiVault, allowed_entities: set[str]) -> str:
    def swap(match: re.Match) -> str:
        entity, value = vault.by_token.get(match.group(0), (None, None))
        if entity is None:
            return f"[{match.group(1)}]"  # token inventado pelo modelo
        return value if entity in allowed_entities else mask(entity, value)

    return TOKEN_RE.sub(swap, text)
