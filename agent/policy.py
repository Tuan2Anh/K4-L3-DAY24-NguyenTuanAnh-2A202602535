"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PRINCIPALS_FILE = BASE_DIR / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra quyền thực thi theo chính sách bảo mật (PEP).
    
    Luôn trả về (allow, reason) với reason không bao giờ rỗng.
    """
    if context.data_classification not in {"public", "internal", "restricted"}:
        return False, f"Invalid data classification: {context.data_classification}"

    # Rule tối thiểu bắt buộc: restricted + egress -> DENY
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "Egress is strictly prohibited for restricted data classification"

    # Kiểm tra thời hạn hiệu lực (expires_at)
    if context.expires_at:
        try:
            exp = datetime.fromisoformat(context.expires_at)
            now = datetime.now(timezone.utc)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp < now:
                return False, f"Authorization expired at {context.expires_at}"
        except Exception:
            return False, f"Invalid expiration timestamp format: {context.expires_at}"

    # Kiểm tra principal và quyền OBO
    if context.principal_id:
        if not PRINCIPALS_FILE.exists():
            return False, "Principals configuration file missing"
        principals = json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
        if context.principal_id not in principals:
            return False, f"Unknown principal_id: {context.principal_id}"

        p = principals[context.principal_id]

        # Kiểm tra mục đích sử dụng (purpose)
        if context.request_purpose and p.get("purposes"):
            if context.request_purpose not in p["purposes"]:
                return False, f"Purpose {context.request_purpose} not permitted for role {context.principal_id}"

        # Kiểm tra công cụ (tool)
        if context.requested_tool:
            if context.requested_tool not in p.get("allowed_tools", []):
                return False, f"Tool {context.requested_tool} not permitted for principal {context.principal_id}"
            if context.agent_scopes and context.requested_tool not in context.agent_scopes:
                return False, f"Tool {context.requested_tool} exceeds agent_scopes"
            if context.delegation_depth > 0:
                if context.parent_scopes and context.requested_tool not in context.parent_scopes:
                    return False, f"Tool {context.requested_tool} exceeds parent_scopes in delegation"

    return True, f"Operation authorized for principal {context.principal_id or 'system'} on tool {context.requested_tool or context.data_classification}"
