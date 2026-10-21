"""Tracing opcional no Langfuse (self-hosted ou cloud), ligado quando LANGFUSE_PUBLIC_KEY/SECRET_KEY existem.

Cada requisição vira um trace com uma observação por etapa (guardrail, retriever, embedding, generation).
Só entram textos já pseudonimizados: o Langfuse também é um destino de dados e não pode receber PII.
"""

import logging
import os
from contextlib import contextmanager

logger = logging.getLogger("secure_rag_gateway.tracing")


class _NoopObservation:
    def update(self, **_: object) -> None:
        pass


class Tracer:
    def __init__(self) -> None:
        self._client = None
        if os.getenv("LANGFUSE_PUBLIC_KEY") and os.getenv("LANGFUSE_SECRET_KEY"):
            try:
                from langfuse import get_client

                self._client = get_client()
                logger.info("Langfuse tracing habilitado")
            except ImportError:
                logger.warning("LANGFUSE_* definido, mas o pacote langfuse não está instalado")

    @property
    def enabled(self) -> bool:
        return self._client is not None

    @contextmanager
    def request(self, request_id: str, user_id: str, input_text: str):
        if not self._client:
            yield _NoopObservation()
            return
        from langfuse import propagate_attributes

        with (
            self._client.start_as_current_observation(
                as_type="span", name="secure-rag-gateway.request", input=input_text, metadata={"request_id": request_id}
            ) as span,
            propagate_attributes(user_id=user_id, tags=["secure-rag-gateway"]),
        ):
            yield span

    @contextmanager
    def step(self, name: str, as_type: str = "span", **attrs):
        if not self._client:
            yield _NoopObservation()
            return
        with self._client.start_as_current_observation(as_type=as_type, name=name, **attrs) as observation:
            yield observation

    def flush(self) -> None:
        if self._client:
            self._client.flush()
