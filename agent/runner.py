"""BƯỚC 3c & 3d — trifecta split + egress containment + OBO ledger."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import uuid

from agent import ledger, pii, policy, tools
from agent.policy import PolicyContext

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_FILE = BASE_DIR / "data" / "customers.json"


def _make_args_hash(args_data: dict) -> str:
    """Tạo sha256 cho tham số gọi tool."""
    canonical = json.dumps(args_data, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    """Xử lý yêu cầu người dùng qua kiến trúc Trifecta Split và PEP/Ledger."""
    ledger_path = (Path(log_dir) / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    scopes = ("search_docs", "read_customer", "http_post")

    # -------------------------------------------------------------
    # RUN A: Đọc untrusted content (corpus), sanitize PII
    # -------------------------------------------------------------
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner="lab24-agent/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=scopes,
        parent_scopes=(),
        expires_at=expires_at,
    )
    allow_search, reason_search = policy.check(ctx_search)
    ledger.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": "lab24-agent/run-a",
            "run_id": run_id,
            "tool": "search_docs",
            "args_hash": _make_args_hash({"query": message}),
            "classification": "internal",
            "decision": "allow" if allow_search else "deny",
            "reason": reason_search,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        },
        ledger_path,
    )

    if not allow_search:
        return "Yêu cầu bị từ chối bởi chính sách bảo mật."

    docs = tools.search_docs(message)

    # Sanitize / Redact PII trước khi truyền text qua boundary
    sanitized_docs = [{"id": d["id"], "text": pii.redact(d["text"])} for d in docs]

    # TRIFECTA SPLIT: Chỉ trích xuất ticket ID dạng số từ TÊN FILE
    # Tuyệt đối không trích xuất customer_id từ free text của tài liệu
    ticket_ids: list[int] = []
    for d in docs:
        m = re.search(r"ticket-(\d+)", d["id"])
        if m:
            ticket_ids.append(int(m.group(1)))

    # Kiểm tra xem có chỉ thị injection nào được cài cắm không
    raw_combined = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(raw_combined)

    # -------------------------------------------------------------
    # RUN B: Truy xuất private data dựa trên NGUỒN TIN CẬY (related_tickets)
    # -------------------------------------------------------------
    customers_data = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    target_customer_ids: list[str] = []
    for cust in customers_data:
        related = cust.get("related_tickets", [])
        if any(t in related for t in ticket_ids):
            target_customer_ids.append(cust["customer_id"])

    collected_records: list[dict] = []
    for cid in target_customer_ids:
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=0,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=scopes,
            parent_scopes=(),
            expires_at=expires_at,
        )
        allow_read, reason_read = policy.check(ctx_read)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-agent/run-b",
                "run_id": run_id,
                "tool": "read_customer",
                "args_hash": _make_args_hash({"customer_id": cid}),
                "classification": "restricted",
                "decision": "allow" if allow_read else "deny",
                "reason": reason_read,
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
            },
            ledger_path,
        )
        if allow_read:
            try:
                record = tools.read_customer(cid)
                collected_records.append(record)
            except tools.ToolError:
                pass

    # -------------------------------------------------------------
    # KIỂM TRA EGRESS: Nếu có chỉ thị exfil, kiểm tra policy trước
    # -------------------------------------------------------------
    if injected is not None:
        ctx_post = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=0,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=scopes,
            parent_scopes=(),
            expires_at=expires_at,
        )
        allow_post, reason_post = policy.check(ctx_post)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-agent/run-b",
                "run_id": run_id,
                "tool": "http_post",
                "args_hash": _make_args_hash({"target_url": injected.target_url}),
                "classification": "restricted",
                "decision": "allow" if allow_post else "deny",
                "reason": reason_post,
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
            },
            ledger_path,
        )
        if allow_post:
            tools.http_post(injected.target_url, {"records": collected_records})

    return llm.summarize(sanitized_docs)
