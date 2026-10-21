"""Classificação de segurança de entrada e saída com Llama Guard 3 (Meta), servido via LiteLLM/Ollama.

O template do llama-guard3 no Ollama monta o prompt de classificação a partir das mensagens: só a mensagem
do usuário classifica a entrada; usuário + assistente classifica a resposta. A saída é "safe" ou
"unsafe" seguido das categorias (S1..S14).
"""

from dataclasses import dataclass, field
from typing import Protocol

from .llm import LLMClient

LLAMA_GUARD_CATEGORIES = {
    "S1": "Violent Crimes",
    "S2": "Non-Violent Crimes",
    "S3": "Sex-Related Crimes",
    "S4": "Child Sexual Exploitation",
    "S5": "Defamation",
    "S6": "Specialized Advice",
    "S7": "Privacy",
    "S8": "Intellectual Property",
    "S9": "Indiscriminate Weapons",
    "S10": "Hate",
    "S11": "Suicide & Self-Harm",
    "S12": "Sexual Content",
    "S13": "Elections",
    "S14": "Code Interpreter Abuse",
}


@dataclass
class SafetyVerdict:
    safe: bool
    categories: list[str] = field(default_factory=list)

    def blocks(self, block_categories: list[str]) -> bool:
        return not self.safe and any(c in block_categories for c in self.categories)


def parse_llama_guard(raw: str) -> SafetyVerdict:
    lines = [line.strip() for line in raw.strip().splitlines() if line.strip()]
    if not lines or lines[0].lower().startswith("safe"):
        return SafetyVerdict(safe=True)
    categories = [c.strip().upper() for c in lines[1].split(",")] if len(lines) > 1 else []
    return SafetyVerdict(safe=False, categories=[c for c in categories if c in LLAMA_GUARD_CATEGORIES])


class SafetyClassifier(Protocol):
    async def check_input(self, text: str) -> SafetyVerdict: ...

    async def check_output(self, prompt: str, response: str) -> SafetyVerdict: ...


class LlamaGuardClassifier:
    def __init__(self, llm: LLMClient, model: str):
        self.llm = llm
        self.model = model

    async def _classify(self, messages: list[dict]) -> SafetyVerdict:
        result = await self.llm.chat(messages, model=self.model, max_tokens=20)
        return parse_llama_guard(result.text)

    async def check_input(self, text: str) -> SafetyVerdict:
        return await self._classify([{"role": "user", "content": text}])

    async def check_output(self, prompt: str, response: str) -> SafetyVerdict:
        return await self._classify([{"role": "user", "content": prompt}, {"role": "assistant", "content": response}])


class NoSafetyClassifier:
    async def check_input(self, text: str) -> SafetyVerdict:
        return SafetyVerdict(safe=True)

    async def check_output(self, prompt: str, response: str) -> SafetyVerdict:
        return SafetyVerdict(safe=True)
