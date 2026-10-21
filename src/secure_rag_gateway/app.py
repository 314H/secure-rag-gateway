"""API HTTP do gateway (FastAPI).

POST /v1/chat   {"message": "..."}  com  Authorization: Bearer <api key>
GET  /healthz
"""

import logging
from contextlib import asynccontextmanager
from dataclasses import asdict

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .audit import AuditLog
from .auth import PrincipalStore, RateLimiter
from .config import Policy, Settings
from .ingest import ingest_documents
from .llm import LiteLLMClient
from .pii import PiiEngine
from .pipeline import Gateway, UpstreamError
from .retrieval import VectorStore
from .safety import LlamaGuardClassifier, NoSafetyClassifier
from .tracing import Tracer

logger = logging.getLogger("secure_rag_gateway")


class ChatRequest(BaseModel):
    # teto de transporte; o limite da política (menor) é aplicado e auditado no pipeline
    message: str = Field(min_length=1, max_length=50_000)


class ChatResponse(BaseModel):
    request_id: str
    answer: str
    blocked: bool
    reason: str | None
    guardrails: list[str]
    citations: list[str]


async def build_gateway(settings: Settings) -> tuple[Gateway, PrincipalStore, LiteLLMClient]:
    if settings.unsafe_disable_guardrails:
        if settings.environment != "test":
            raise RuntimeError("UNSAFE_DISABLE_GUARDRAILS só é aceito com ENVIRONMENT=test")
        logger.warning("GUARDRAILS DESLIGADOS: modo de linha de base para red teaming, nunca usar em produção")
    policy = Policy.load(settings.policy_file)
    llm = LiteLLMClient(settings.llm_base_url, settings.llm_api_key, settings.request_timeout_s)
    safety = (
        LlamaGuardClassifier(llm, settings.guard_model)
        if settings.safety_classifier == "llamaguard"
        else NoSafetyClassifier()
    )
    pii = PiiEngine(policy.pii.entities, policy.pii.language, policy.pii.min_score)
    store = VectorStore(settings.vector_path)
    audit = AuditLog(settings.audit_log)
    if settings.ingest_on_startup and store.is_empty():
        report = await ingest_documents(settings, policy, llm, store, pii, audit)
        logger.info("ingestão: %s", report)
    gateway = Gateway(settings, policy, llm, safety, pii, store, audit, Tracer())
    return gateway, PrincipalStore.load(settings.principals_file), llm


def create_app(
    gateway: Gateway | None = None,
    principals: PrincipalStore | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    settings = settings or Settings()
    state: dict = {"gateway": gateway, "principals": principals}

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        llm = None
        if state["gateway"] is None:
            state["gateway"], state["principals"], llm = await build_gateway(settings)
        state["limiter"] = RateLimiter(state["gateway"].policy.limits.requests_per_minute)
        yield
        state["gateway"].tracer.flush()
        if llm:
            await llm.aclose()

    app = FastAPI(title="Secure RAG Gateway", version="0.1.0", lifespan=lifespan)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        return response

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok", "guardrails": state["gateway"].guardrails_on}

    @app.post("/v1/chat", response_model=ChatResponse)
    async def chat(body: ChatRequest, authorization: str | None = Header(default=None)):
        token = (authorization or "").removeprefix("Bearer ").strip()
        principal = state["principals"].authenticate(token) if token else None
        if principal is None:
            raise HTTPException(status_code=401, detail="credencial inválida")
        if not state["limiter"].allow(principal):
            return JSONResponse(status_code=429, content={"detail": "limite de requisições excedido"})
        try:
            result = await state["gateway"].handle(principal, body.message)
        except UpstreamError:
            logger.exception("falha no provedor de modelo")
            raise HTTPException(status_code=502, detail="provedor de modelo indisponível") from None
        return asdict(result)

    return app


app = create_app()
