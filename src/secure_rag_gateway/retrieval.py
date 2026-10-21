"""Base vetorial (Qdrant) com controle de acesso por documento.

O filtro de ACL é aplicado dentro da consulta vetorial, não depois: um trecho que o usuário não pode ler
nunca sai do banco, nem entra no prompt (OWASP LLM09 Vector and Embedding Weaknesses).
"""

import uuid
from dataclasses import dataclass

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, FieldCondition, Filter, MatchAny, MatchValue, PointStruct, VectorParams

COLLECTION = "documents"


@dataclass
class Chunk:
    doc_id: str
    title: str
    text: str
    acl: list[str]
    classification: str
    quarantined: bool = False


@dataclass
class Hit:
    chunk: Chunk
    score: float


class VectorStore:
    def __init__(self, path: str):
        self.client = QdrantClient(location=":memory:") if path == ":memory:" else QdrantClient(path=path)

    def is_empty(self) -> bool:
        if not self.client.collection_exists(COLLECTION):
            return True
        return self.client.count(COLLECTION).count == 0

    def reset(self, dim: int) -> None:
        if self.client.collection_exists(COLLECTION):
            self.client.delete_collection(COLLECTION)
        self.client.create_collection(COLLECTION, vectors_config=VectorParams(size=dim, distance=Distance.COSINE))

    def upsert(self, chunks: list[Chunk], vectors: list[list[float]]) -> None:
        points = [
            PointStruct(
                id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{c.doc_id}:{i}:{c.text[:40]}")),
                vector=v,
                payload=c.__dict__,
            )
            for i, (c, v) in enumerate(zip(chunks, vectors, strict=True))
        ]
        self.client.upsert(COLLECTION, points=points)

    def search(self, vector: list[float], groups: list[str], top_k: int, min_score: float) -> list[Hit]:
        acl_filter = Filter(
            must=[
                FieldCondition(key="acl", match=MatchAny(any=groups)),
                FieldCondition(key="quarantined", match=MatchValue(value=False)),
            ]
        )
        response = self.client.query_points(
            COLLECTION, query=vector, query_filter=acl_filter, limit=top_k, score_threshold=min_score
        )
        return [Hit(Chunk(**p.payload), p.score) for p in response.points]
