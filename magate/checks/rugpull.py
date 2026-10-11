"""ラグプル検知：承認時に固定したツール定義ハッシュと、現在の定義を比較する。"""
from __future__ import annotations

import json
import os
import re

from ..hashing import manifest, tool_hash, tool_view
from ..model import FAIL, OK, UNKNOWN, WARN, Finding

ASI = ["ASI04"]
LLM = ["LLM03"]  # サプライチェーン


def pin_path(pins_dir: str, server_name: str) -> str:
    safe = re.sub(r"[^\w.-]", "_", server_name)
    return os.path.join(pins_dir, f"{safe}.pin.json")


def save_pin(pins_dir: str, snapshot: dict, approved_by: str = "", note: str = "") -> str:
    os.makedirs(pins_dir, exist_ok=True)
    path = pin_path(pins_dir, snapshot["server"]["name"])
    data = {
        "server": snapshot["server"],
        "approved_by": approved_by,
        "note": note,
        "manifest": manifest(snapshot["tools"]),
        "tools": [tool_view(t) for t in snapshot["tools"]],  # 差分表示用に定義本体も保存
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return path


def load_pin(pins_dir: str, server_name: str) -> dict | None:
    path = pin_path(pins_dir, server_name)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def diff(pin: dict, snapshot: dict) -> dict:
    old = {t["name"]: t for t in pin["tools"]}
    new = {t["name"]: tool_view(t) for t in snapshot["tools"]}
    changed = {}
    for name in old.keys() & new.keys():
        if tool_hash(old[name]) != tool_hash(new[name]):
            fields = sorted(k for k in set(old[name]) | set(new[name]) if old[name].get(k) != new[name].get(k))
            changed[name] = fields
    return {"added": sorted(new.keys() - old.keys()), "removed": sorted(old.keys() - new.keys()), "changed": changed,
            "unchanged": manifest(snapshot["tools"])["overall"] == pin["manifest"]["overall"]}


def check_rugpull(snapshot: dict, pins_dir: str | None) -> list[Finding]:
    if not pins_dir:
        return [Finding("rug_pull", UNKNOWN, "固定ハッシュの保存先が未指定のため、ラグプル監視は未設定です", ASI, LLM,
                        condition="承認時に `magate pin` で定義を固定し、定期監視を設定すること")]
    pin = load_pin(pins_dir, snapshot["server"]["name"])
    if pin is None:
        return [Finding("rug_pull", OK, "初回審査（固定済みの定義なし）。承認後に `pin` で固定してください", ASI, LLM)]
    d = diff(pin, snapshot)
    if d["unchanged"]:
        return [Finding("rug_pull", OK, "承認時のツール定義から変更はありません", ASI, LLM)]
    findings = []
    for name, fields in d["changed"].items():
        sev = FAIL if {"description", "inputSchema"} & set(fields) else WARN
        findings.append(Finding("rug_pull", sev, f"承認後にツール `{name}` の定義が変更されています（{', '.join(fields)}）", ASI, LLM,
                                evidence=_field_diff(pin, snapshot, name, fields),
                                condition="変更内容を再審査し、問題なければ再度 pin すること"))
    for name in d["added"]:
        findings.append(Finding("rug_pull", FAIL, f"承認後にツール `{name}` が追加されています", ASI, LLM,
                                condition="追加ツールを審査するまで無効化すること"))
    for name in d["removed"]:
        findings.append(Finding("rug_pull", WARN, f"承認後にツール `{name}` が削除されています", ASI, LLM))
    return findings


def _field_diff(pin, snapshot, name, fields, limit=300):
    old = next(t for t in pin["tools"] if t["name"] == name)
    new = next(tool_view(t) for t in snapshot["tools"] if t["name"] == name)
    out = []
    for f in fields:
        o = json.dumps(old.get(f), ensure_ascii=False)[:limit]
        n = json.dumps(new.get(f), ensure_ascii=False)[:limit]
        out.append(f"{f}:\n  旧: {o}\n  新: {n}")
    return "\n".join(out)
