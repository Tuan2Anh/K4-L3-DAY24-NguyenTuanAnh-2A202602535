"""BƯỚC 3e — audit ledger append-only, tamper-evident."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _compute_hash(data: dict) -> str:
    """Tính SHA-256 từ canonical JSON (sort_keys=True)."""
    canonical = json.dumps(data, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def append(entry: dict, path: Path) -> dict:
    """Thêm một bản ghi vào ledger với hash chain liên kết dòng trước."""
    path.parent.mkdir(parents=True, exist_ok=True)
    prev_hash = "0" * 64
    if path.exists() and path.stat().st_size > 0:
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            last = json.loads(lines[-1])
            prev_hash = last.get("hash", "0" * 64)

    record = dict(entry)
    record["prev_hash"] = prev_hash
    record["hash"] = _compute_hash(record)

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


def verify(path: Path) -> bool:
    """Kiểm tra tính toàn vẹn của chuỗi hash trong ledger."""
    if not path.exists():
        return False
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return False

    expected_prev = "0" * 64
    for line in lines:
        try:
            entry = json.loads(line)
        except Exception:
            return False

        # Mọi dòng phải có reason non-empty
        if not entry.get("reason"):
            return False

        # prev_hash phải khớp với hash của dòng trước
        if entry.get("prev_hash") != expected_prev:
            return False

        # hash phải khớp với nội dung dòng hiện tại
        stored_hash = entry.get("hash")
        calc_entry = {k: v for k, v in entry.items() if k != "hash"}
        if _compute_hash(calc_entry) != stored_hash:
            return False

        expected_prev = stored_hash

    return True
