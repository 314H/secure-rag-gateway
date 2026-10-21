"""Detector heurístico de prompt injection (PT e EN), executado antes de qualquer chamada a modelo.

É a primeira camada, barata e determinística. Não substitui classificadores (Llama Guard, Prompt Guard) nem
o desenho de menor privilégio: injeção indireta não tem mitigação completa por filtro de texto.
"""

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

# caracteres invisíveis e de controle bidirecional, montados por code point: o fonte fica só em ASCII
_INVISIBLE = [*range(0x200B, 0x2010), *range(0x202A, 0x202F), *range(0x2060, 0x2065), 0xFEFF]
_ZERO_WIDTH = re.compile("[" + "".join(re.escape(chr(c)) for c in _INVISIBLE) + "]")
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


@dataclass(frozen=True)
class Rule:
    id: str
    weight: int
    pattern: re.Pattern


def _rule(rule_id: str, weight: int, regex: str) -> Rule:
    return Rule(rule_id, weight, re.compile(regex, re.IGNORECASE | re.DOTALL))


RULES = [
    _rule(
        "override_instructions",
        3,
        r"\b(ignore|ignora\w*|disregard|forget|esquec\w*|desconsider\w*|override|bypass)\b.{0,60}"
        r"\b(previous|prior|above|earlier|all|any|anteriores?|acima|todas?|quaisquer|suas|as|seu)\b.{0,40}"
        r"\b(instructions?|rules?|prompts?|guidelines?|directions?|instruc\w*|regras?|orientac\w*|diretrizes?|politicas?)\b",
    ),
    # exige qualificador ("suas", "acima", "do sistema"): "mostre as regras do cartão" é pergunta legítima
    _rule(
        "prompt_leak",
        3,
        r"(system prompt|prompt (de|do) sistema|"
        r"\b(repeat|print|show|reveal|output|display|tell me)\b.{0,20}\byour\b.{0,15}"
        r"\b(prompt|instructions|rules|guidelines)\b|"
        r"\b(repeat|print|output|show)\b.{0,15}\b(the )?(text|words|everything)\b.{0,10}\b(above|before)\b|"
        r"\b(repita|mostre|revele|imprima|exiba|liste|diga)\b.{0,20}\b(seu|sua|suas|seus)\b.{0,15}"
        r"\b(prompt|instruc\w*|regras|diretrizes|configurac\w*)\b|"
        r"\b(repita|mostre|revele|imprima|exiba)\b.{0,20}\b(texto|prompt|instruc\w*|mensagem)\b.{0,15}"
        r"\b(acima|anterior\w*|inicia\w*|de sistema|do sistema|oculta\w*)\b)",
    ),
    _rule(
        "chat_template_tokens",
        3,
        r"(<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|start_header_id\|>|<\|eot_id\|>|\[/?inst\]|<<sys>>|"
        r"^\s*#{2,}\s*(system|instruction)s?\b)",
    ),
    _rule(
        "role_override",
        2,
        r"\b(you are now|from now on,? you|act as (an? )?(unrestricted|evil|dan)|pretend (to be|you are)|"
        r"voce (agora )?e (agora )?(um|uma) (ia|assistente) sem|a partir de agora,? voce|finja (ser|que)|aja como)\b",
    ),
    _rule(
        "jailbreak_persona",
        2,
        r"\b(dan|do anything now|developer mode|modo (de )?desenvolvedor|jailbreak\w*|sem (nenhuma )?restric\w*|"
        r"no (restrictions|filters|limits)|unfiltered|uncensored|sem censura|stan|aim mode)\b",
    ),
    _rule("markdown_exfiltration", 2, r"!\[[^\]]*\]\(\s*https?://"),
    _rule(
        "exfiltration_instruction",
        2,
        r"\b(send|post|forward|leak|envie|encaminhe|vaze|mande)\b.{0,60}(https?://|webhook|e-?mail|servidor externo)",
    ),
    _rule(
        "hidden_ai_instruction",
        2,
        r"\b(to (the )?(ai|assistant|llm|model)|para (a |o )?(ia|assistente|modelo|llm)s?|"
        r"ai assistants?|assistentes de ia)\b.{0,40}\b(ignore|ignor\w*|instruc\w*|must|deve\w*|responda|reply)\b",
    ),
]


def normalize(text: str) -> str:
    text = _ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", text))
    text = "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))
    return re.sub(r"[ \t]+", " ", text).lower()


def _decoded_payloads(text: str) -> list[str]:
    decoded = []
    for token in _B64_TOKEN.findall(text):
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if sum(c.isprintable() for c in raw) >= 0.9 * len(raw):
            decoded.append(raw)
    return decoded


@dataclass
class InjectionResult:
    score: int = 0
    rules: list[str] = field(default_factory=list)

    def blocked(self, threshold: int) -> bool:
        return self.score >= threshold


class InjectionDetector:
    def scan(self, text: str) -> InjectionResult:
        result = InjectionResult()
        variants = [normalize(text)]
        variants.append(variants[0].translate(_LEET))
        for payload in _decoded_payloads(text):
            variants.append(normalize(payload))
            result.rules.append("encoded_payload")
        for rule in RULES:
            if any(rule.pattern.search(v) for v in variants):
                result.score += rule.weight
                result.rules.append(rule.id)
        if "encoded_payload" in result.rules and result.score:
            result.score += 1  # instrução escondida em base64 é sinal forte de evasão
        return result
