"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

# Regex patterns
# EMAIL
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# VN_BANK_ACCOUNT: thường đi kèm STK hoặc số tài khoản, độ dài 8-16 số
_BANK_PREFIX_RE = re.compile(
    r"(?:STK|số\s+tài\s+khoản|so\s+tai\s+khoan|tài\s+khoan|tai\s+khoan|TK)\s*[:.]?\s*(\d{8,16})\b",
    re.IGNORECASE,
)

# VN_CCCD: 12 chữ số liên tiếp
_CCCD_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")

# VN_PHONE: 0 + 9 chữ số (tổng 10 chữ số)
_PHONE_RE = re.compile(r"(?<!\d)(0\d{9})(?!\d)")


def detect(text: str) -> list[dict]:
    entities: list[dict] = []
    occupied_spans: list[tuple[int, int]] = []

    def _is_overlapping(start: int, end: int) -> bool:
        return any(s < end and start < e for s, e in occupied_spans)

    def _add_entity(ent_type: str, start: int, end: int):
        if not _is_overlapping(start, end):
            entities.append({"type": ent_type, "start": start, "end": end})
            occupied_spans.append((start, end))

    # 1. Email
    for m in _EMAIL_RE.finditer(text):
        _add_entity("EMAIL", m.start(), m.end())

    # 2. Bank Account
    for m in _BANK_PREFIX_RE.finditer(text):
        start, end = m.start(1), m.end(1)
        _add_entity("VN_BANK_ACCOUNT", start, end)

    # 3. CCCD (12 chữ số)
    for m in _CCCD_RE.finditer(text):
        start, end = m.start(1), m.end(1)
        _add_entity("VN_CCCD", start, end)

    # 4. SĐT (10 chữ số bắt đầu bằng 0)
    for m in _PHONE_RE.finditer(text):
        start, end = m.start(1), m.end(1)
        _add_entity("VN_PHONE", start, end)

    entities.sort(key=lambda x: x["start"])
    return entities


def redact(text: str) -> str:
    ents = detect(text)
    ents_sorted_desc = sorted(ents, key=lambda x: x["start"], reverse=True)
    result = text
    for ent in ents_sorted_desc:
        start = ent["start"]
        end = ent["end"]
        label = f"[REDACTED_{ent['type']}]"
        result = result[:start] + label + result[end:]
    return result
