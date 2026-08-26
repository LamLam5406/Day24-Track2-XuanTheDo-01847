"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng biến
thể 5, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from agent import ledger, policy, tools
from agent.policy import PolicyContext

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

_TICKET_ID_RE = re.compile(r"ticket-(\d+)", re.IGNORECASE)


def _hash_args(args: dict) -> str:
    payload = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    ledger_path = (log_dir or REPORTS_DIR) / "ledger.jsonl"

    # ── RUN A: Untrusted Content Layer ──
    # Phân loại: internal/untrusted, chỉ gọi search_docs, egress_enabled=False
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="search-tickets",
        agent_owner="run-a",
        delegation_depth=0,
        egress_enabled=False,
    )
    allow_search, reason_search = policy.check(ctx_search)
    ledger.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": "lab24-agent",
            "run_id": "run-a",
            "tool": "search_docs",
            "args_hash": _hash_args({"query": message}),
            "classification": "internal",
            "decision": "allow" if allow_search else "deny",
            "reason": reason_search,
        },
        ledger_path,
    )

    if not allow_search:
        return "Yêu cầu bị từ chối bởi chính sách bảo mật."

    docs = tools.search_docs(message)

    # Trích xuất typed ticket IDs từ tên file tài liệu (sanitized metadata)
    ticket_ids: list[int] = []
    for d in docs:
        m = _TICKET_ID_RE.search(d.get("id", ""))
        if m:
            try:
                ticket_ids.append(int(m.group(1)))
            except ValueError:
                continue

    # Kiểm tra chỉ thị injection trong untrusted text (chỉ để audit / log)
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)

    # ── RUN B: Private Data Layer ──
    # Map ticket_ids sang customer_id qua nguồn tin cậy: data/customers.json (related_tickets)
    # KHÔNG dùng customer_ids do attacker đưa vào trong free text
    customers_data = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    ticket_ids_set = set(ticket_ids)

    matched_customers = []
    for c in customers_data:
        related = set(c.get("related_tickets", []))
        if related.intersection(ticket_ids_set):
            matched_customers.append(c)

    # Đọc thông tin khách hàng hợp lệ (Policy check cho từng cuộc gọi)
    for c in matched_customers:
        cust_id = c["customer_id"]
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose="customer-verification",
            agent_owner="run-b",
            delegation_depth=1,
            egress_enabled=False,
        )
        allow_read, reason_read = policy.check(ctx_read)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-agent",
                "run_id": "run-b",
                "tool": "read_customer",
                "args_hash": _hash_args({"customer_id": cust_id}),
                "classification": "restricted",
                "decision": "allow" if allow_read else "deny",
                "reason": reason_read,
            },
            ledger_path,
        )

        if allow_read:
            try:
                tools.read_customer(cust_id)
            except tools.ToolError:
                pass

    # ── CONTAINMENT & EGRESS CONTROL ──
    # Nếu có chỉ thị injection cố gắng kích hoạt egress gửi dữ liệu ra ngoài
    if injected is not None:
        ctx_egress = PolicyContext(
            data_classification="restricted",
            request_purpose="data-exfiltration-attempt",
            agent_owner="run-b",
            delegation_depth=1,
            egress_enabled=True,
        )
        allow_egress, reason_egress = policy.check(ctx_egress)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-agent",
                "run_id": "run-b",
                "tool": "http_post",
                "args_hash": _hash_args({"target_url": injected.target_url}),
                "classification": "restricted",
                "decision": "allow" if allow_egress else "deny",
                "reason": reason_egress,
            },
            ledger_path,
        )
        # Vì allow_egress là False, tuyệt đối KHÔNG gọi tools.http_post

    return llm.summarize(docs)
