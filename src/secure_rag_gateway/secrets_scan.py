"""Detecção de segredos em documentos antes da indexação (mesma ideia de TruffleHog/Gitleaks).

Um documento com credencial é recusado inteiro: segredo indexado numa base vetorial vaza por qualquer
pergunta semanticamente próxima.
"""

import re
from dataclasses import dataclass

SECRET_RULES = {
    "aws_access_key_id": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "aws_secret_access_key": re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "openai_style_key": re.compile(r"\bsk-(proj-)?[A-Za-z0-9_-]{20,}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "slack_token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "private_key": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "credential_in_url": re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s/@]{4,}@[^\s/]+"),
    "generic_secret_assignment": re.compile(
        r"(?i)\b(password|passwd|senha|secret|segredo|api[_-]?key|token|client[_-]?secret)\b\s*[:=]\s*['\"]?[^\s'\"]{12,}"
    ),
}


@dataclass(frozen=True)
class SecretFinding:
    rule: str
    line: int
    preview: str  # só o começo do trecho: o segredo em si não vai para log


def scan_secrets(text: str) -> list[SecretFinding]:
    findings = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule, pattern in SECRET_RULES.items():
            match = pattern.search(line)
            if match:
                findings.append(SecretFinding(rule, lineno, match.group(0)[:6] + "…"))
    return findings
