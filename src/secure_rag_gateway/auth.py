"""Autenticação por API key (guardada só como hash SHA-256) e rate limit por usuário.

Em produção a identidade viria de OIDC/JWT (Entra ID, Keycloak); o contrato com o resto do gateway é o
mesmo: um Principal com id e grupos, que alimentam o filtro de ACL do RAG e a política de reidentificação.
"""

import hashlib
import hmac
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Principal:
    id: str
    groups: tuple[str, ...]
    requests_per_minute: int | None = None  # cota própria (ex.: conta de serviço); None usa a da política


def hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


class PrincipalStore:
    def __init__(self, entries: list[dict]):
        self._entries = [
            (e["key_sha256"], Principal(e["id"], tuple(e["groups"]), e.get("requests_per_minute"))) for e in entries
        ]

    @classmethod
    def load(cls, path: Path) -> "PrincipalStore":
        return cls(yaml.safe_load(path.read_text(encoding="utf-8"))["principals"])

    def authenticate(self, api_key: str) -> Principal | None:
        digest = hash_key(api_key)
        found = None
        for key_hash, principal in self._entries:  # percorre todos: tempo não revela qual chave casou
            if hmac.compare_digest(digest, key_hash):
                found = principal
        return found


class RateLimiter:
    """Janela deslizante de 60 s por usuário (em memória; com várias réplicas usar Redis)."""

    def __init__(self, requests_per_minute: int):
        self.limit = requests_per_minute
        self._hits: dict[str, deque] = defaultdict(deque)

    def allow(self, principal: Principal) -> bool:
        now = time.monotonic()
        hits = self._hits[principal.id]
        while hits and now - hits[0] > 60:
            hits.popleft()
        if len(hits) >= (principal.requests_per_minute or self.limit):
            return False
        hits.append(now)
        return True
