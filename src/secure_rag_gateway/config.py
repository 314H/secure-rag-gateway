"""Configuração do gateway: variáveis de ambiente (Settings) e política de segurança (policy.yaml)."""

from pathlib import Path

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "dev"
    llm_base_url: str = "http://localhost:4000"  # LiteLLM proxy (OpenAI-compatible)
    llm_api_key: str = "sk-local-dev"
    chat_model: str = "chat-default"
    guard_model: str = "guard"
    embed_model: str = "embed"
    # prefixos de tarefa recomendados pelo EmbeddingGemma (multilíngue); outro modelo, outros prefixos
    embed_query_prefix: str = "task: search result | query: "
    embed_doc_prefix: str = "title: none | text: "
    safety_classifier: str = "llamaguard"  # llamaguard | none
    request_timeout_s: float = 180.0

    policy_file: Path = Path("config/policy.yaml")
    principals_file: Path = Path("config/principals.yaml")
    docs_dir: Path = Path("data/docs")
    vector_path: str = "data/qdrant"
    ingest_on_startup: bool = True
    audit_log: Path = Path("logs/audit.jsonl")

    # Só para medir a linha de base dos testes de red teaming (ASR sem guardrails). Recusado fora de "test".
    unsafe_disable_guardrails: bool = False


class Limits(BaseModel):
    max_input_chars: int = 4000
    requests_per_minute: int = 30
    max_output_tokens: int = 400


class InjectionPolicy(BaseModel):
    block_threshold: int = 3
    scan_retrieved_chunks: bool = True


class SafetyPolicy(BaseModel):
    block_categories: list[str] = Field(default_factory=list)


class PiiPolicy(BaseModel):
    language: str = "pt"
    min_score: float = 0.5
    entities: list[str] = Field(default_factory=list)
    output_entities: list[str] = Field(default_factory=list)
    reidentify: dict[str, list[str]] = Field(default_factory=dict)


class OutputPolicy(BaseModel):
    allowed_link_domains: list[str] = Field(default_factory=list)


class RagPolicy(BaseModel):
    top_k: int = 4
    min_score: float = 0.40
    require_context: bool = True


class Policy(BaseModel):
    limits: Limits = Field(default_factory=Limits)
    injection: InjectionPolicy = Field(default_factory=InjectionPolicy)
    safety: SafetyPolicy = Field(default_factory=SafetyPolicy)
    pii: PiiPolicy = Field(default_factory=PiiPolicy)
    output: OutputPolicy = Field(default_factory=OutputPolicy)
    rag: RagPolicy = Field(default_factory=RagPolicy)

    @classmethod
    def load(cls, path: Path) -> "Policy":
        return cls.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
