"""Ingestão segura de documentos: segredo recusa o documento, instrução oculta põe o documento inteiro em
quarentena (a fonte está comprometida) e dado pessoal é removido antes de gerar embeddings, então a base
vetorial nunca guarda PII em claro.

Uso: python -m secure_rag_gateway.ingest
"""

import asyncio
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .audit import AuditLog
from .config import Policy, Settings
from .injection import InjectionDetector
from .llm import LiteLLMClient, LLMClient
from .pii import PiiEngine
from .retrieval import Chunk, VectorStore
from .secrets_scan import scan_secrets


@dataclass
class IngestReport:
    indexed: list[str] = field(default_factory=list)
    rejected: dict[str, list[str]] = field(default_factory=dict)
    quarantined: list[str] = field(default_factory=list)
    chunks: int = 0


def parse_document(path: Path) -> tuple[dict, str]:
    text = path.read_text(encoding="utf-8")
    if text.startswith("---"):
        _, front, body = text.split("---", 2)
        return yaml.safe_load(front) or {}, body.strip()
    return {}, text.strip()


def split_chunks(body: str, max_chars: int = 700) -> list[str]:
    chunks, current = [], ""
    for paragraph in (p.strip() for p in body.split("\n\n")):
        if not paragraph:
            continue
        if current and len(current) + len(paragraph) > max_chars:
            chunks.append(current)
            current = ""
        current = f"{current}\n\n{paragraph}".strip()
    if current:
        chunks.append(current)
    return chunks


async def ingest_documents(
    settings: Settings,
    policy: Policy,
    llm: LLMClient,
    store: VectorStore,
    pii: PiiEngine,
    audit: AuditLog,
    injection: InjectionDetector | None = None,
) -> IngestReport:
    injection = injection or InjectionDetector()
    report = IngestReport()
    chunks: list[Chunk] = []
    for path in sorted(settings.docs_dir.glob("*.md")):
        meta, body = parse_document(path)
        doc_id = meta.get("id", path.stem)
        secrets = scan_secrets(body)
        if secrets:
            report.rejected[doc_id] = sorted({s.rule for s in secrets})
            audit.write(
                "document_rejected_secret",
                "blocked",
                document={"id": doc_id},
                gateway={"rules": report.rejected[doc_id]},
            )
            continue
        texts = split_chunks(body)
        scans = [injection.scan(t) for t in texts]
        flagged = [s for s in scans if s.blocked(policy.injection.block_threshold)]
        if flagged:
            report.quarantined.append(doc_id)
            audit.write(
                "document_quarantined_injection",
                "blocked",
                document={"id": doc_id},
                gateway={"rules": sorted({r for s in flagged for r in s.rules}), "injection_score": flagged[0].score},
            )
        for text in texts:
            redacted, entities = pii.redact(text)
            chunks.append(
                Chunk(
                    doc_id=doc_id,
                    title=meta.get("title", doc_id),
                    text=redacted,
                    acl=list(meta.get("acl", [])),
                    classification=meta.get("classification", "interno"),
                    quarantined=bool(flagged),
                )
            )
            if entities:
                audit.write("chunk_pii_redacted", "success", document={"id": doc_id}, gateway={"pii": dict(entities)})
        report.indexed.append(doc_id)

    if chunks:
        vectors = await llm.embed([settings.embed_doc_prefix + c.text for c in chunks], model=settings.embed_model)
        store.reset(dim=len(vectors[0]))
        store.upsert(chunks, vectors)
    report.chunks = len(chunks)
    return report


async def _main() -> None:
    settings = Settings()
    policy = Policy.load(settings.policy_file)
    llm = LiteLLMClient(settings.llm_base_url, settings.llm_api_key, settings.request_timeout_s)
    try:
        report = await ingest_documents(
            settings,
            policy,
            llm,
            VectorStore(settings.vector_path),
            PiiEngine(policy.pii.entities, policy.pii.language, policy.pii.min_score),
            AuditLog(settings.audit_log),
        )
    finally:
        await llm.aclose()
    print(report)


if __name__ == "__main__":
    asyncio.run(_main())
