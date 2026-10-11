"""判定結果の共通データ型。"""
from __future__ import annotations

from dataclasses import dataclass, field

OK, WARN, FAIL, UNKNOWN = "OK", "WARN", "FAIL", "UNKNOWN"
_RANK = {OK: 0, UNKNOWN: 1, WARN: 2, FAIL: 3}


def worst(statuses) -> str:
    statuses = list(statuses)
    return max(statuses, key=lambda s: _RANK[s]) if statuses else OK


@dataclass
class Finding:
    threat: str          # tool_poisoning / rug_pull / shadowing / confused_deputy / oauth_scope / auth / data ...
    status: str          # OK / WARN / FAIL / UNKNOWN
    message: str         # 日本語の説明
    asi: list[str] = field(default_factory=list)   # OWASP Agentic (ASI01-10)
    llm: list[str] = field(default_factory=list)   # OWASP LLM Top 10 (LLM01-10)
    evidence: str = ""   # 根拠（該当箇所など）
    condition: str = ""  # 条件付き許可にする場合の条件

    def to_dict(self) -> dict:
        return self.__dict__.copy()
