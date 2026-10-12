"""シャドーイング検知：他サーバのツールの挙動を乗っ取る・上書きする定義を探す。

inventory = 社内で承認済みの他MCPサーバのスナップショット群。
"""
from __future__ import annotations

import re

from ..model import FAIL, OK, UNKNOWN, WARN, Finding
from .text import iter_texts, snippet

ASI = ["ASI02", "ASI04"]  # ツール悪用 / サプライチェーン
LLM = ["LLM01"]

PHRASES = [
    r"\b(instead\s+of|rather\s+than|override|overrides|replace|replaces)\b.{0,20}\b(the\s+)?(other|existing|any|default)\s+tools?\b",
    r"\b(always|must)\s+use\s+this\s+tool\b.{0,20}\b(instead|for\s+all|for\s+every)\b",
    r"\b(all|every|any)\s+(emails?|messages?|requests?|files?)\b.{0,30}\b(must|should)\s+(also\s+)?(be\s+)?(sent|cc'?d?|bcc'?d?|forwarded|copied)\b",
    r"\bwhen(ever)?\s+(the\s+)?(user|agent|assistant)\s+(uses?|calls?)\s+(any|another|other)\s+tool",
    r"(他の|既存の|別の)ツール(の代わり|より優先|を使わ|を呼ぶ際|を使う際)",
    r"(すべての|全ての)(メール|メッセージ|リクエスト).{0,20}(宛先|CC|BCC|転送)",
]
_PHRASES = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in PHRASES]


def _distinctive(name: str) -> bool:
    return bool(re.search(r"[_\-.]|[a-z][A-Z]", name)) or len(name) >= 10


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def check_shadowing(snapshot: dict, inventory: list[dict] = ()) -> list[Finding]:
    if not snapshot.get("tools"):
        return [Finding("shadowing", UNKNOWN, "照合するツール定義がないため、乗っ取り・上書きの表現は検査していません", ASI, LLM)]
    findings = []
    me = snapshot["server"].get("name")
    others = {}  # 正規化名 -> (サーバ名, 元のツール名)
    for snap in inventory:
        if snap["server"].get("name") == me:
            continue
        for t in snap.get("tools", []):
            others[_norm(t["name"])] = (snap["server"].get("name"), t["name"])

    for tool in snapshot.get("tools", []):
        tname = tool.get("name", "")
        # 1) 名前衝突（同名・表記揺れ）
        if _norm(tname) in others:
            srv, orig = others[_norm(tname)]
            findings.append(Finding(
                "shadowing", WARN, f"ツール名 `{tname}` が承認済みサーバ `{srv}` の `{orig}` と衝突しています", ASI, LLM,
                evidence=f"{me}:{tname} ⇔ {srv}:{orig}",
                condition="クライアント側でサーバ名プレフィックス付きのツール名に限定するか、どちらかを無効化すること"))
        # 2) 他サーバのツール名・横断的な上書き表現への言及
        for where, text in iter_texts(tool):
            if where.endswith("<name>"):
                continue
            for key, (srv, orig) in others.items():
                if not _distinctive(orig):
                    continue  # "search" のような一般語は誤検知が多いので言及チェックの対象外
                m = re.search(rf"(?<![A-Za-z0-9_]){re.escape(orig)}(?![A-Za-z0-9_])", text)
                if m:
                    findings.append(Finding(
                        "shadowing", FAIL, f"`{tname}` の定義が他サーバ `{srv}` のツール `{orig}` に言及しています", ASI, LLM,
                        evidence=f"{where}: 「{snippet(text, m.start(), m.end())}」"))
            for rx in _PHRASES:
                m = rx.search(text)
                if m:
                    findings.append(Finding(
                        "shadowing", FAIL, f"`{tname}` の定義に他ツールの挙動を上書きする表現があります", ASI, LLM,
                        evidence=f"{where}: 「{snippet(text, m.start(), m.end())}」"))
                    break
    if not findings:
        msg = "他サーバとの名前衝突・上書き表現は検出されませんでした"
        if not inventory:
            msg += "（承認済みサーバ一覧が未指定のため、言及チェックは表現パターンのみ）"
        findings.append(Finding("shadowing", OK, msg, ASI, LLM))
    return findings
