"""評価ルーブリック：7項目（＋サプライチェーンの証拠がある場合は8項目）を OWASP Agentic (ASI) / LLM Top 10 に紐づけ、3段階で総合判定する。

ASI番号との対応は本ツールの設計上の割り当て（OWASP公式の対応表ではない）。
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field

from .checks import check_auth, check_poisoning, check_rugpull, check_scopes, check_shadowing, check_supply_chain
from .checks.supply_chain import has_evidence as _has_supply_evidence
from .model import FAIL, OK, UNKNOWN, WARN, Finding, worst

PERMIT, CONDITIONAL, DENY = "許可", "条件付き許可", "不可"
CLASS_RANK = {"public": 0, "internal": 1, "confidential": 2, "secret": 3}
CLASS_JA = {"public": "公開", "internal": "社内限", "confidential": "社外秘", "secret": "極秘"}


@dataclass
class Item:
    no: int
    title: str
    asi: list[str]
    llm: list[str]
    findings: list[Finding] = field(default_factory=list)

    @property
    def status(self) -> str:
        return worst(f.status for f in self.findings)


@dataclass
class Result:
    server: dict
    items: list[Item]
    threats: dict          # MCP固有5脅威 -> 状態
    verdict: str
    conditions: list[str]
    blockers: list[str]
    autofill: dict = field(default_factory=dict)  # 情報カード・接続先の応答から自動入力／照合した項目


# ---------- 1. 運営主体の実在性 ----------
VERIFY_CONDITION = "国税庁 法人番号公表サイト等で実在を確認し verified_by_human を true にすること"  # ブラウザ版は web.py で言い換える

def corporate_number_valid(num: str) -> bool:
    """日本の法人番号（13桁）のチェックデジット検証。"""
    if not re.fullmatch(r"\d{13}", num or ""):
        return False
    base = num[1:]
    total = sum(int(d) * (1 if i % 2 == 0 else 2) for i, d in enumerate(reversed(base)))
    return int(num[0]) == 9 - (total % 9)


def eval_operator(snapshot, q) -> list[Finding]:
    asi, llm = ["ASI04"], ["LLM03"]
    o = q.get("operator", {})
    out = []
    if not o.get("name"):
        return [Finding("operator", UNKNOWN, "運営主体が未記入です", asi, llm, condition="運営主体（法人名）を特定すること")]
    cn = o.get("corporate_number")
    if cn:
        if not corporate_number_valid(cn):
            out.append(Finding("operator", FAIL, f"法人番号 {cn} はチェックデジットが不正です", asi, llm))
    elif not o.get("certifications"):
        out.append(Finding("operator", WARN, "法人番号・第三者認証のいずれも確認できません", asi, llm,
                           condition="法人番号または ISMS / SOC 2 等の認証を確認すること"))
    dom, host = (o.get("domain") or "").lower(), urllib.parse.urlsplit(snapshot["server"].get("url", "")).hostname or ""
    if dom and host and not (host == dom or host.endswith("." + dom)):
        out.append(Finding("operator", WARN, f"接続先ホスト `{host}` が運営主体のドメイン `{dom}` と一致しません", asi, llm,
                           condition="ホスティング委託先であることを提供元に確認すること"))
    if not o.get("security_contact"):
        out.append(Finding("operator", WARN, "脆弱性・インシデントの連絡窓口が不明です", asi, llm,
                           condition="セキュリティ窓口を確認すること"))
    if not o.get("verified_by_human"):
        out.append(Finding("operator", WARN, "運営主体の実在確認が人手で完了していません", asi, llm,
                           condition=VERIFY_CONDITION))
    if not out:
        out.append(Finding("operator", OK, f"運営主体 {o['name']} の実在を確認済み", asi, llm))
    return out


# ---------- 3. 送信されるデータの範囲 ----------
def eval_data(snapshot, q) -> list[Finding]:
    asi, llm = ["ASI02", "ASI03"], ["LLM02"]
    d = q.get("data", {})
    out = []
    sent, allowed = d.get("max_classification_sent"), d.get("allowed_classification")
    if sent is None or allowed is None:
        out.append(Finding("data", UNKNOWN, "送信するデータの機密区分が未記入です", asi, llm,
                           condition="送信するデータの最高機密区分を決めること"))
    elif CLASS_RANK[sent] > CLASS_RANK[allowed]:
        out.append(Finding("data", FAIL, f"送信予定の区分（{CLASS_JA[sent]}）が、この接続先に許される上限（{CLASS_JA[allowed]}）を超えています", asi, llm))
    if d.get("read_only_intended"):
        risky = [t["name"] for t in snapshot.get("tools", [])
                 if (t.get("annotations") or {}).get("destructiveHint") or (t.get("annotations") or {}).get("readOnlyHint") is False]
        if risky:
            names = ", ".join(f"`{n}`" for n in risky)
            out.append(Finding("data", WARN, f"参照用途なのに書き込み・破壊的操作のツールがあります: {names}", asi, llm,
                               condition=f"{names} をクライアント側で無効化すること（annotations は自己申告のため実挙動も確認）"))
    free = [f"`{t['name']}.{p}`" for t in snapshot.get("tools", [])
            for p, s in ((t.get("inputSchema") or {}).get("properties") or {}).items()
            if isinstance(s, dict) and s.get("type") == "string" and "maxLength" not in s and "enum" not in s
            and re.search(r"(content|body|text|document|file|context|note|message|data)", p, re.I)]
    if free:
        out.append(Finding("data", WARN, f"長さ無制限の自由記述パラメータがあり、意図しない大量送信が起こりえます: {', '.join(free)}", asi, llm,
                           condition=f"{', '.join(free)} は長さの上限がないため、DLP・ゲートウェイで送信内容を監視すること"))
    if not out:
        out.append(Finding("data", OK, f"送信データは上限（{CLASS_JA.get(allowed, allowed)}）の範囲内です", asi, llm))
    return out


# ---------- 4. データの保持・学習利用 ----------
def eval_retention(snapshot, q) -> list[Finding]:
    asi, llm = ["ASI04", "ASI06"], ["LLM02"]
    r, d = q.get("retention", {}), q.get("data", {})
    sensitive = CLASS_RANK.get(d.get("max_classification_sent") or "internal", 1) >= 2
    out = []
    t = r.get("used_for_training")
    if t is True:
        out.append(Finding("retention", FAIL if sensitive else WARN, "送信データがモデル学習に利用されます", asi, llm,
                           condition="学習利用のオプトアウトを契約で担保すること"))
    elif t is None:
        out.append(Finding("retention", UNKNOWN, "学習利用の有無が未確認です", asi, llm, condition="利用規約・DPAで学習利用の有無を確認すること"))
    days = r.get("retention_days")
    if days is None:
        out.append(Finding("retention", UNKNOWN, "データ保持期間が未確認です", asi, llm, condition="保持期間を確認すること"))
    elif days > q.get("policy", {}).get("max_retention_days", 30):
        out.append(Finding("retention", WARN, f"保持期間が {days} 日と社内基準を超えています", asi, llm,
                           condition="保持期間の短縮またはゼロ保持オプションを確認すること"))
    if r.get("deletion_on_request") is False:
        out.append(Finding("retention", WARN, "削除依頼に応じない規約です", asi, llm))
    if not out:
        out.append(Finding("retention", OK, "学習利用なし・保持期間は基準内", asi, llm,
                           evidence=r.get("source_url", "")))
    return out


# ---------- 5. ホスティング地域 ----------
def eval_hosting(snapshot, q) -> list[Finding]:
    asi, llm = ["ASI04"], ["LLM02"]
    h = q.get("hosting", {})
    regions, allowed = h.get("regions"), set(h.get("allowed_regions") or ["JP"])
    out = []
    if not regions:
        out.append(Finding("hosting", UNKNOWN, "ホスティング地域が未確認です", asi, llm, condition="データの保存・処理地域を確認すること"))
    else:
        outside = [x for x in regions if x not in allowed]
        if outside:
            out.append(Finding("hosting", WARN, f"許可地域外で処理されます: {', '.join(outside)}", asi, llm,
                               condition="越境移転として社内規程・個人情報保護法上の取扱いを確認し、個人データを送らない運用とすること"))
    if h.get("subprocessors_disclosed") is False:
        out.append(Finding("hosting", WARN, "再委託先（サブプロセッサ）が開示されていません", asi, llm))
    if not out:
        out.append(Finding("hosting", OK, f"処理地域は許可範囲内（{', '.join(regions)}）", asi, llm))
    return out


# ---------- 7. 監査ログ ----------
def eval_audit(snapshot, q) -> list[Finding]:
    asi, llm = ["ASI08", "ASI10"], ["LLM06"]
    a = q.get("audit", {})
    srv, cli = a.get("server_side_audit_log"), a.get("client_side_logging")
    if srv is False and cli is False:
        return [Finding("audit", FAIL, "提供元・自社のどちらにも呼び出しログが残りません（事故時に追跡不能）", asi, llm)]
    if cli is True:
        return [Finding("audit", OK, "自社側（ゲートウェイ等）でツール呼び出しを記録しています", asi, llm)]
    if srv is True:
        exp = a.get("log_export_available")
        return [Finding("audit", OK if exp else WARN, "提供元に監査ログあり" + ("（エクスポート可）" if exp else "（自社で取得できるか不明）"),
                        asi, llm, condition="" if exp else "インシデント時のログ提供条件を確認すること")]
    return [Finding("audit", UNKNOWN, "監査ログの有無が未確認です", asi, llm,
                    condition="ゲートウェイ側でツール呼び出しを記録する設定にすること")]


THREAT_LABELS = {
    "tool_poisoning": "ツールポイズニング",
    "rug_pull": "ラグプル",
    "shadowing": "シャドーイング",
    "confused_deputy": "混乱した代理（トークン中継）",
    "oauth_scope": "過剰なOAuthスコープ",
}


def evaluate(snapshot: dict, q: dict, inventory=(), pins_dir=None, extra_scanners=(), autofill: dict | None = None,
             exploited=()) -> Result:
    poison = check_poisoning(snapshot, extra_scanners)
    shadow = check_shadowing(snapshot, list(inventory))
    rug = check_rugpull(snapshot, pins_dir)
    auth = check_auth(snapshot, q)
    scopes = check_scopes(snapshot, q)

    items = [
        Item(1, "運営主体の実在性", ["ASI04"], ["LLM03"], eval_operator(snapshot, q)),
        Item(2, "認証方式", ["ASI03"], ["LLM06"], auth + scopes),
        Item(3, "送信されるデータの範囲", ["ASI02", "ASI03"], ["LLM02"], eval_data(snapshot, q)),
        Item(4, "データの保持・学習利用ポリシー", ["ASI04", "ASI06"], ["LLM02"], eval_retention(snapshot, q)),
        Item(5, "ホスティング地域（越境移転）", ["ASI04"], ["LLM02"], eval_hosting(snapshot, q)),
        Item(6, "ツール定義の内容", ["ASI01", "ASI02", "ASI04"], ["LLM01", "LLM03"], poison + shadow + rug),
        Item(7, "監査ログの有無", ["ASI08", "ASI10"], ["LLM06"], eval_audit(snapshot, q)),
    ]
    if _has_supply_evidence(snapshot):  # --package / --lockfile 指定時、またはヘッダーで版数が見えた時だけ評価する
        items.append(Item(8, "既知脆弱性・実行環境（サプライチェーン）", ["ASI04"], ["LLM03"],
                          check_supply_chain(snapshot, exploited)))
    all_f = [f for it in items for f in it.findings]
    threats = {k: worst(f.status for f in all_f if f.threat == k) for k in THREAT_LABELS}

    blockers = [f"[{it.title}] {f.message}" for it in items for f in it.findings if f.status == FAIL]
    conditions = []
    for it in items:
        for f in it.findings:
            if f.status in (WARN, UNKNOWN):
                c = f.condition or f"{f.message}について対応・確認すること"
                if c not in conditions:
                    conditions.append(c)
    verdict = DENY if blockers else (CONDITIONAL if conditions else PERMIT)
    return Result(snapshot["server"], items, threats, verdict, conditions, blockers, autofill or {})
