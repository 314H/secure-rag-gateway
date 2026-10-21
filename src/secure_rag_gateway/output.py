"""Tratamento da saída do LLM (OWASP LLM10 Improper Output Handling e LLM08 Hidden Context Exposure).

- canário: um marcador aleatório no system prompt; se aparecer na resposta, o contexto oculto vazou.
- links e imagens markdown para domínios fora da allowlist são removidos: uma imagem com dados na URL
  exfiltra a conversa assim que o cliente a renderiza (exfiltração "zero clique").
- HTML ativo é neutralizado para não virar XSS no front-end.
"""

import re
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlparse

_MD_IMAGE = re.compile(r"!\[([^\]]*)\]\(([^)\s]+)[^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)[^)]*\)")
_RAW_URL = re.compile(r"\bhttps?://[^\s)\]>\"']+")
_ACTIVE_HTML = re.compile(r"<\s*/?\s*(script|iframe|img|object|embed|form|svg|a)\b[^>]*>", re.IGNORECASE)


def new_canary() -> str:
    return f"CANARIO-{secrets.token_hex(6).upper()}"


@dataclass
class OutputResult:
    text: str
    findings: list[str] = field(default_factory=list)
    canary_leaked: bool = False


class OutputSanitizer:
    def __init__(self, allowed_domains: list[str]):
        self.allowed = [d.lower() for d in allowed_domains]

    def _allowed(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        return any(host == d or host.endswith("." + d) for d in self.allowed)

    def sanitize(self, text: str, canary: str | None = None) -> OutputResult:
        result = OutputResult(text=text)
        if canary and canary.lower() in text.lower():
            result.canary_leaked = True
            result.findings.append("canary_leak")

        def image(m: re.Match) -> str:
            if self._allowed(m.group(2)):
                return m.group(0)
            result.findings.append("markdown_image_exfiltration")
            return "[imagem removida]"

        def link(m: re.Match) -> str:
            if self._allowed(m.group(2)):
                return m.group(0)
            result.findings.append("untrusted_link")
            return m.group(1)

        def raw_url(m: re.Match) -> str:
            if self._allowed(m.group(0)):
                return m.group(0)
            result.findings.append("untrusted_link")
            return "[link removido]"

        out = _MD_IMAGE.sub(image, text)
        out = _MD_LINK.sub(link, out)
        out = _RAW_URL.sub(raw_url, out)
        if _ACTIVE_HTML.search(out):
            result.findings.append("active_html")
            out = _ACTIVE_HTML.sub("", out)
        result.text = out
        return result
