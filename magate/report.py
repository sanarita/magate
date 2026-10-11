"""審査結果を、課長・部長にそのまま渡せる日本語Markdownと、機械処理用JSONに出力する。"""
from __future__ import annotations

import json
import re

from .model import FAIL, OK, UNKNOWN, WARN
from .rubric import CONDITIONAL, DENY, PERMIT, THREAT_LABELS, Result

ICON = {OK: "✅ OK", WARN: "⚠️ 要対応", FAIL: "❌ NG", UNKNOWN: "❔ 未確認"}
VERDICT_ICON = {PERMIT: "✅ 許可", CONDITIONAL: "⚠️ 条件付き許可", DENY: "❌ 不可"}


_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.\-]")


def _safe(x: str, n: int = 96) -> str:
    """審査対象由来の識別子（ツール名・プロパティ名・サーバ名）を、空白も含めて無害化する。"""
    return _SAFE_NAME.sub("_", x)[:n]


def _redact_text(text: str) -> str:
    """Claude向け：本文中の抜粋と、`…` で囲んだ識別子を無害化する。"""
    text = re.sub(r"「[^」]*」", "「（抜粋は伏せ字）」", text)
    return re.sub(r"(?<!`)`([^`\n]+)`(?!`)", lambda m: "`" + _safe(m.group(1), 64) + "`", text)


def _redact_evidence(ev: str) -> list[str]:
    out = []
    for line in ev.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith(("旧:", "新:")):
            out.append(f"{s[:2]} （内容は伏せ字。人間向けレポートを参照）")
        elif "「" in s:
            head = s.split("「", 1)[0].rstrip(" :：")
            if " @ " in head:  # [rule +w] ラベル @ 場所  ← ラベルは maGATE 固定文言なので残す
                label, where = head.rsplit(" @ ", 1)
                out.append(f"{label} @ {_safe(where)}")
            else:
                out.append(_safe(head))
        elif "⇔" in s:
            out.append(" ⇔ ".join(_safe(x.strip()) for x in s.split("⇔")))
        elif s.endswith(":") and " " not in s:   # rugpull のフィールド名（固定集合）
            out.append(s)
        elif s.startswith("https://") and " " not in s:
            out.append(s[:200])
        else:
            out.append(_safe(s, 160))
    return out


def to_markdown(r: Result, redact: bool = False) -> str:
    if redact:
        return _redact_text(_to_markdown(r, redact=True))
    return _to_markdown(r)


def _to_markdown(r: Result, redact: bool = False) -> str:
    s = r.server
    name = _SAFE_NAME.sub("_", str(s.get("name")))[:64] if redact else s.get("name")
    kind = "API" if s.get("source") == "openapi" else "MCP"
    L = [f"# {kind}接続先 審査レポート：{name}", "",
         f"- 接続先URL：`{s.get('url') or '（スナップショット入力）'}`",
         *([f"- 審査対象：API仕様書（{'OpenAPI ' if not str(s.get('spec_version','')).startswith('2') else 'Swagger '}{s.get('spec_version')}、API版数 {s.get('api_version') or '-'}）"] if s.get("source") == "openapi" else []),
         f"- 取得日時：{s.get('fetched_at', '-')}",
         f"- 判定ツール：maGATE（自動判定＋提供元回答に基づく。最終承認は人が行う）", "",
         f"## 総合判定：{VERDICT_ICON[r.verdict]}", ""]
    if r.blockers:
        L += ["### 不可の理由", *[f"- {b}" for b in r.blockers], ""]
    if r.conditions:
        L += ["### 許可の条件（すべて満たした場合に許可）" if r.verdict == CONDITIONAL else "### あわせて対応が必要な事項",
              *[f"{i}. {c}" for i, c in enumerate(r.conditions, 1)], ""]

    L += ["## 評価ルーブリック", "", "| # | 審査項目 | 判定 | OWASP Agentic | OWASP LLM |", "|---|---|---|---|---|"]
    for it in r.items:
        L.append(f"| {it.no} | {it.title} | {ICON[it.status]} | {', '.join(it.asi)} | {', '.join(it.llm)} |")
    L += ["", "## MCP固有の脅威チェック", "", "| 脅威 | 判定 |", "|---|---|"]
    for k, label in THREAT_LABELS.items():
        L.append(f"| {label} | {ICON[r.threats[k]]} |")

    L += ["", "## 詳細"]
    for it in r.items:
        L += ["", f"### {it.no}. {it.title}（{ICON[it.status]}）"]
        for f in it.findings:
            tag = f"[{', '.join(f.asi)}]" if redact else f"`{' '.join(f.asi)}`"
            L.append(f"- {ICON[f.status]} {f.message}  {tag}")
            if f.evidence:
                if redact:
                    L += [f"  - 根拠: {line}" for line in _redact_evidence(f.evidence)]
                else:
                    L += ["  ```", *[f"  {line}" for line in f.evidence.splitlines()], "  ```"]
    L += ["", "---", "※ ASI番号との対応は maGATE の設計上の割り当てです（OWASP公式の対応表ではありません）。",
          "※ ツールの annotations（readOnlyHint等）は提供元の自己申告であり、安全性の保証ではありません。"]
    return "\n".join(L) + "\n"


def to_json(r: Result) -> str:
    return json.dumps({
        "server": r.server, "verdict": r.verdict, "blockers": r.blockers, "conditions": r.conditions,
        "threats": r.threats,
        "items": [{"no": it.no, "title": it.title, "status": it.status, "asi": it.asi, "llm": it.llm,
                   "findings": [f.to_dict() for f in it.findings]} for it in r.items],
    }, ensure_ascii=False, indent=2)
