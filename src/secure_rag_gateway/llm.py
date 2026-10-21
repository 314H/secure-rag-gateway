"""Cliente do LiteLLM Proxy (API OpenAI-compatible).

O gateway não fala direto com nenhum provedor: todo modelo (chat, Llama Guard e embeddings) passa pelo
LiteLLM, que concentra chaves, roteamento, rate limit e custo. Trocar Ollama por Azure OpenAI ou Bedrock
é mudança de configuração do LiteLLM, não de código.
"""

from dataclasses import dataclass
from typing import Protocol

import httpx


@dataclass
class ChatResult:
    text: str
    model: str
    usage: dict


class LLMClient(Protocol):
    async def chat(self, messages: list[dict], model: str, max_tokens: int, user: str | None = None) -> ChatResult: ...

    async def embed(self, texts: list[str], model: str) -> list[list[float]]: ...


class LiteLLMClient:
    def __init__(self, base_url: str, api_key: str, timeout_s: float):
        self._http = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout_s,
        )

    async def chat(self, messages: list[dict], model: str, max_tokens: int, user: str | None = None) -> ChatResult:
        payload = {"model": model, "messages": messages, "max_tokens": max_tokens, "temperature": 0}
        if user:
            payload["user"] = user  # atribuição de custo por usuário no LiteLLM
        resp = await self._http.post("/v1/chat/completions", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return ChatResult(
            text=data["choices"][0]["message"]["content"] or "",
            model=data.get("model", model),
            usage=data.get("usage") or {},
        )

    async def embed(self, texts: list[str], model: str) -> list[list[float]]:
        resp = await self._http.post("/v1/embeddings", json={"model": model, "input": texts})
        resp.raise_for_status()
        return [item["embedding"] for item in sorted(resp.json()["data"], key=lambda d: d["index"])]

    async def aclose(self) -> None:
        await self._http.aclose()
