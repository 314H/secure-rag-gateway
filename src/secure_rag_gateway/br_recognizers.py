"""Reconhecedores Presidio para dados pessoais brasileiros.

CPF e CNPJ são confirmados pelo dígito verificador, o que elimina a maior parte dos falsos positivos de
regex. O CNPJ aceita o formato alfanumérico (IN RFB 2.229/2024, emitido a partir de julho/2026), em que o
DV é calculado com o valor ASCII de cada caractere menos 48.
"""

import re

from presidio_analyzer import Pattern, PatternRecognizer

_NON_ALNUM = re.compile(r"[^0-9A-Za-z]")


def cpf_is_valid(value: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", value)]
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    for n in (9, 10):
        total = sum(d * (n + 1 - i) for i, d in enumerate(digits[:n]))
        if (total * 10) % 11 % 10 != digits[n]:
            return False
    return True


def cnpj_is_valid(value: str) -> bool:
    chars = _NON_ALNUM.sub("", value).upper()
    if len(chars) != 14 or not chars[12:].isdigit() or len(set(chars)) == 1:
        return False
    values = [ord(c) - 48 for c in chars]
    weights = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    for pos, w in ((12, weights), (13, [6, *weights])):
        remainder = sum(v * p for v, p in zip(values[:pos], w, strict=True)) % 11
        if (0 if remainder < 2 else 11 - remainder) != values[pos]:
            return False
    return True


class CpfRecognizer(PatternRecognizer):
    def __init__(self, supported_language: str = "pt"):
        super().__init__(
            supported_entity="BR_CPF",
            name="CpfRecognizer",
            supported_language=supported_language,
            patterns=[
                Pattern("cpf_formatado", r"(?<!\d)\d{3}\.\d{3}\.\d{3}-\d{2}(?!\d)", 0.6),
                Pattern("cpf_numerico", r"(?<!\d)\d{11}(?!\d)", 0.3),
            ],
            context=["cpf", "contribuinte", "documento"],
        )

    def validate_result(self, pattern_text: str) -> bool:
        return cpf_is_valid(pattern_text)


class CnpjRecognizer(PatternRecognizer):
    def __init__(self, supported_language: str = "pt"):
        super().__init__(
            supported_entity="BR_CNPJ",
            name="CnpjRecognizer",
            supported_language=supported_language,
            patterns=[
                Pattern(
                    "cnpj_formatado", r"(?<![0-9A-Z])[0-9A-Z]{2}\.[0-9A-Z]{3}\.[0-9A-Z]{3}/[0-9A-Z]{4}-\d{2}(?!\d)", 0.6
                ),
                Pattern("cnpj_bruto", r"(?<![0-9A-Z])[0-9A-Z]{12}\d{2}(?![0-9A-Z])", 0.3),
            ],
            context=["cnpj", "empresa", "razão social", "fornecedor"],
        )

    def validate_result(self, pattern_text: str) -> bool:
        return cnpj_is_valid(pattern_text)


class BrPhoneRecognizer(PatternRecognizer):
    def __init__(self, supported_language: str = "pt"):
        super().__init__(
            supported_entity="BR_PHONE",
            name="BrPhoneRecognizer",
            supported_language=supported_language,
            patterns=[
                # exige separador: 11 dígitos colados são tratados como CPF candidato
                Pattern("telefone_br", r"(?<!\d)(?:\+55\s?)?\(?[1-9]{2}\)?\s?9?\d{4}[-\s]\d{4}(?!\d)", 0.5),
            ],
            context=["telefone", "celular", "whatsapp", "contato", "fone"],
        )


class PixEvpRecognizer(PatternRecognizer):
    """Chave Pix aleatória (EVP = UUID v4). Sem contexto de Pix fica abaixo do limiar: UUIDs são comuns em TI."""

    def __init__(self, supported_language: str = "pt"):
        super().__init__(
            supported_entity="PIX_EVP",
            name="PixEvpRecognizer",
            supported_language=supported_language,
            patterns=[
                Pattern(
                    "pix_evp",
                    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
                    0.3,
                )
            ],
            context=["pix", "chave"],
        )
