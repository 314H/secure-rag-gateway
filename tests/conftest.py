"""Fixtures sem modelos de IA: embeddings por hashing de palavras, LLM e classificador falsos.

Presidio, Qdrant (em memória), ingestão e pipeline são os componentes reais.
"""

import asyncio
import hashlib
import math
import re
import unicodedata
from pathlib import Path

import pytest

from secure_rag_gateway.audit import AuditLog
from secure_rag_gateway.auth import PrincipalStore
from secure_rag_gateway.config import Policy, Settings
from secure_rag_gateway.ingest import ingest_documents
from secure_rag_gateway.llm import ChatResult
from secure_rag_gateway.pii import PiiEngine
from secure_rag_gateway.pipeline import Gateway
from secure_rag_gateway.retrieval import VectorStore
from secure_rag_gateway.safety import SafetyVerdict

ROOT = Path(__file__).resolve().parents[1]
DIM = 256
KEYS = {"atendimento": "demo-key-atendimento", "fraude": "demo-key-fraude", "ti": "demo-key-ti"}


def _words(text: str) -> list[str]:
    text = "".join(c for c in unicodedata.normalize("NFKD", text.lower()) if not unicodedata.combining(c))
    return [w for w in re.findall(r"[a-z0-9]{4,}", text)]


class FakeLLM:
    def __init__(self):
        self.chat_calls: list[list[dict]] = []
        self.answer = lambda messages: "Segundo a política, a fatura fecha 7 dias antes do vencimento."

    async def chat(self, messages, model, max_tokens, user=None):
        self.chat_calls.append(messages)
        return ChatResult(text=self.answer(messages), model=model, usage={"total_tokens": 42})

    async def embed(self, texts, model):
        vectors = []
        for text in texts:
            vec = [0.0] * DIM
            for word in _words(text):
                vec[int(hashlib.md5(word.encode(), usedforsecurity=False).hexdigest(), 16) % DIM] += 1.0
            norm = math.sqrt(sum(v * v for v in vec)) or 1.0
            vectors.append([v / norm for v in vec])
        return vectors


class FakeSafety:
    def __init__(self):
        self.output_verdict = SafetyVerdict(safe=True)

    async def check_input(self, text):
        return SafetyVerdict(safe=False, categories=["S2"]) if "clonar" in text.lower() else SafetyVerdict(safe=True)

    async def check_output(self, prompt, response):
        return self.output_verdict


@pytest.fixture(scope="session")
def pii_engine() -> PiiEngine:
    policy = Policy.load(ROOT / "config/policy.yaml")
    return PiiEngine(policy.pii.entities, policy.pii.language, policy.pii.min_score)


@pytest.fixture
def components(tmp_path, pii_engine):
    settings = Settings(
        environment="test",
        policy_file=ROOT / "config/policy.yaml",
        principals_file=ROOT / "config/principals.yaml",
        docs_dir=ROOT / "data/docs",
        vector_path=":memory:",
        audit_log=tmp_path / "audit.jsonl",
        embed_query_prefix="",
        embed_doc_prefix="",
        _env_file=None,
    )
    policy = Policy.load(settings.policy_file)
    policy.rag.min_score = 0.05  # escala de similaridade do embedding falso é outra
    llm, safety = FakeLLM(), FakeSafety()
    store, audit = VectorStore(":memory:"), AuditLog(settings.audit_log)
    report = asyncio.run(ingest_documents(settings, policy, llm, store, pii_engine, audit))
    gateway = Gateway(settings, policy, llm, safety, pii_engine, store, audit)
    return {
        "settings": settings,
        "gateway": gateway,
        "llm": llm,
        "safety": safety,
        "report": report,
        "principals": PrincipalStore.load(settings.principals_file),
    }
