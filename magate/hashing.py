"""ツール定義の正規化とハッシュ化（ラグプル検知の土台）。"""
from __future__ import annotations

import hashlib
import json
from typing import Any

# モデルの挙動に影響しうるフィールドだけをハッシュ対象にする
PINNED_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def tool_view(tool: dict) -> dict:
    return {k: tool[k] for k in PINNED_FIELDS if k in tool}


def tool_hash(tool: dict) -> str:
    return hashlib.sha256(canonical(tool_view(tool)).encode("utf-8")).hexdigest()


def manifest(tools: list[dict]) -> dict:
    per_tool = {t["name"]: tool_hash(t) for t in tools}
    overall = hashlib.sha256(canonical(per_tool).encode("utf-8")).hexdigest()
    return {"overall": overall, "tools": per_tool}
