"""過剰なOAuthスコープ・書き込み系ツールのチェック（最小権限の原則）。"""
from __future__ import annotations

import re

from ..model import FAIL, OK, WARN, Finding

ASI = ["ASI03"]
LLM = ["LLM06"]

BROAD = re.compile(
    r"(^\*$|(^|[:._/])(admin|all|full|root|owner|manage|superuser)($|[:._/])|\.default$|ReadWrite\.All|"
    r"Mail\.Send|Directory\.|Sites\.FullControl|^repo$|offline_access)",
    re.IGNORECASE)
WRITE = re.compile(r"(^|[:._/])(write|delete|send|create|update|modify|post)($|[:._/])", re.IGNORECASE)


def check_scopes(snapshot: dict, q: dict) -> list[Finding]:
    f: list[Finding] = []
    a = q.get("auth", {})
    requested = list(a.get("requested_scopes") or [])
    needed = set(a.get("needed_scopes") or [])
    oauth = snapshot.get("oauth") or {}
    supported = set((oauth.get("protected_resource") or {}).get("scopes_supported") or [])

    for s in requested:
        if BROAD.search(s):
            f.append(Finding("oauth_scope", FAIL if s.strip() == "*" else WARN, f"広すぎるスコープを要求しています: `{s}`", ASI, LLM,
                             condition=f"`{s}` を外した最小スコープで接続すること"))
    if needed:
        extra = [s for s in requested if s not in needed]
        if extra:
            f.append(Finding("oauth_scope", WARN, f"業務上不要なスコープを要求しています: {', '.join(extra)}", ASI, LLM,
                             condition="要求スコープを業務で必要なものだけに絞ること"))
    if q.get("data", {}).get("read_only_intended"):
        w = [s for s in requested if WRITE.search(s)]
        if w:
            f.append(Finding("oauth_scope", WARN, f"参照用途なのに書き込み系スコープがあります: {', '.join(w)}", ASI, LLM,
                             condition="参照系スコープのみに限定すること"))
    if supported and requested:
        unknown = [s for s in requested if s not in supported]
        if unknown:
            f.append(Finding("oauth_scope", WARN, f"サーバが宣言していないスコープを要求しています: {', '.join(unknown)}", ASI, LLM))
    if supported and all(BROAD.search(s) for s in supported):
        f.append(Finding("oauth_scope", WARN, "サーバが広いスコープしか用意していません（細かい権限分離ができない）", ASI, LLM,
                         evidence=", ".join(sorted(supported))))
    if not f:
        f.append(Finding("oauth_scope", OK, "スコープは最小権限の範囲に収まっています" if requested else
                         "要求スコープの申告なし（OAuthを使わない、または未記入）", ASI, LLM))
    return f
