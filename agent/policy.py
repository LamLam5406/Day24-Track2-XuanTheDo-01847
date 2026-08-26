"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc Guide.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input đúng slide §3.3 (đã định nghĩa sẵn, đừng đổi field):

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool


def check(context: PolicyContext) -> tuple[bool, str]:
    # Rule tối thiểu bắt buộc: restricted data + egress_enabled -> DENY
    if context.data_classification == "restricted" and context.egress_enabled:
        return (
            False,
            f"Policy Deny: restricted data cannot be accessed/exfiltrated with egress_enabled=True "
            f"(agent_owner='{context.agent_owner}', purpose='{context.request_purpose}')",
        )

    # Giới hạn delegation depth để tránh cascade privilege escalation
    if context.delegation_depth > 3:
        return (
            False,
            f"Policy Deny: delegation depth {context.delegation_depth} exceeds maximum threshold of 3",
        )

    # Các trường hợp hợp lệ
    return (
        True,
        f"Policy Allow: agent '{context.agent_owner}' authorized for {context.data_classification} data "
        f"under purpose '{context.request_purpose}' (egress={context.egress_enabled}, depth={context.delegation_depth})",
    )
