"""Trilha de auditoria em JSON Lines com campos no estilo Elastic Common Schema (ECS).

Um evento por requisição ou ingestão, pronto para Splunk, Elastic ou Sentinel. Nunca contém dado pessoal
nem segredo: só tipos e contagens de entidades, ids de documentos e regras disparadas.
"""

import json
import logging
import threading
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger("secure_rag_gateway.audit")


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, action: str, outcome: str, **fields) -> dict:
        record = {
            "@timestamp": datetime.now(UTC).isoformat(),
            "event": {
                "kind": "alert" if outcome == "blocked" else "event",
                "category": ["intrusion_detection"] if outcome == "blocked" else ["web"],
                "action": action,
                "outcome": outcome,
            },
            "service": {"name": "secure-rag-gateway"},
            **fields,
        }
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        logger.info(line)
        return record
