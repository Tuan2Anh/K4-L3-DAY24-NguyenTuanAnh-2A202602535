"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store."""
from __future__ import annotations

import re


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII trong văn bản (VN_CCCD, VN_PHONE, VN_BANK_ACCOUNT, EMAIL).
    
    Returns list[{"type": str, "start": int, "end": int}]
    """
    entities: list[dict] = []

    # 1. EMAIL
    for m in re.finditer(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})

    # 2. VN_BANK_ACCOUNT: 8-16 chữ số thường có tiền tố STK / số tài khoản
    for m in re.finditer(
        r'(?i)(?:STK|số tài khoản|so tai khoan|tài khoản|tai khoan|TK)\s*[:.]?\s*(\d{8,16})',
        text,
    ):
        start = m.start(1)
        end = m.end(1)
        entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})

    bank_ranges = [(e["start"], e["end"]) for e in entities if e["type"] == "VN_BANK_ACCOUNT"]

    # 3. VN_CCCD: 12 chữ số liên tiếp
    for m in re.finditer(r'\b\d{12}\b', text):
        start, end = m.start(), m.end()
        if not any(bs <= start and end <= be for bs, be in bank_ranges):
            entities.append({"type": "VN_CCCD", "start": start, "end": end})

    cccd_ranges = [(e["start"], e["end"]) for e in entities if e["type"] == "VN_CCCD"]

    # 4. VN_PHONE: 0 + 9 chữ số (10 chữ số)
    for m in re.finditer(r'\b0\d{9}\b', text):
        start, end = m.start(), m.end()
        if not any(cs <= start and end <= ce for cs, ce in cccd_ranges) and not any(
            bs <= start and end <= be for bs, be in bank_ranges
        ):
            entities.append({"type": "VN_PHONE", "start": start, "end": end})

    entities.sort(key=lambda x: x["start"])
    return entities


def redact(text: str) -> str:
    """Thay thế các thực thể PII bằng [REDACTED_<TYPE>]."""
    entities = detect(text)
    # Thay từ cuối văn bản về đầu để offset không bị lệch
    for ent in sorted(entities, key=lambda x: x["start"], reverse=True):
        text = text[:ent["start"]] + f"[REDACTED_{ent['type']}]" + text[ent["end"]:]
    return text
