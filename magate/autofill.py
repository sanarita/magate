"""質問票の自動入力：接続先の応答（snapshot）と情報カードから、提供元側の項目だけを埋める。

- 空欄の項目だけを埋める（人が入力した値は上書きしない）
- 人の入力とカードの値が違う場合は「相違」として記録し、レポートに両方を出す
- 自社が決める項目は対象外（COMPANY_KEYS）
"""
from __future__ import annotations

import copy
import datetime as _dt

from .catalog import STALE_DAYS, find_card

LABELS = {
    "operator.name": "運営主体",
    "operator.domain": "運営主体のドメイン",
    "operator.security_contact": "セキュリティ窓口",
    "operator.certifications": "第三者認証",
    "auth.method": "ログインの方式",
    "auth.is_proxy": "中継型のサーバか",
    "retention.used_for_training": "学習に使われるか",
    "retention.retention_days": "保存期間（日）",
    "retention.deletion_on_request": "削除依頼に応じるか",
    "retention.source_url": "根拠にした規約のURL",
    "hosting.regions": "処理する国",
    "hosting.subprocessors_disclosed": "再委託先の公開",
    "audit.server_side_audit_log": "提供元の利用記録",
    "audit.log_export_available": "記録の受け取り",
}
# 自社が決める項目・外から見えない項目。自動入力の対象にしない
COMPANY_KEYS = {
    "operator.verified_by_human", "operator.corporate_number",
    "auth.token_passthrough", "auth.audience_validation", "auth.per_client_consent",
    "auth.requested_scopes", "auth.needed_scopes",
    "data.max_classification_sent", "data.allowed_classification", "data.read_only_intended",
    "hosting.allowed_regions", "audit.client_side_logging", "policy.max_retention_days",
}
FILLED, MATCHES, DIFFERS = "filled", "matches", "differs"
DISPLAY = {"auth.method": {"oauth2.1": "OAuth（ユーザーごとにログイン）", "api_key": "APIキー", "none": "認証なし"}}


def _empty(v) -> bool:
    return v is None or v == "" or v == []


def _same(a, b) -> bool:
    """一覧（認証名など）は順序と大文字小文字を無視して比べる。"""
    if isinstance(a, list) and isinstance(b, list):
        norm = lambda xs: sorted(str(x).strip().casefold() for x in xs)
        return norm(a) == norm(b)
    return a == b


def _derived(snapshot: dict) -> dict:
    """接続先の応答から機械的に分かる項目。"""
    out = {}
    oauth = snapshot.get("oauth") or {}
    obs = snapshot.get("observations") or {}
    src = "接続先の応答（maGATE が取得）"
    if oauth.get("protected_resource"):
        out["auth.method"] = {"value": "oauth2.1", "source": src, "note": "OAuth の保護リソース情報（RFC 9728）を公開している"}
    elif obs.get("unauthenticated_tools_list") and not obs.get("auth_required"):
        out["auth.method"] = {"value": "none", "source": src, "note": "認証なしでツール一覧を取得できた"}
    return out


def autofill(snapshot: dict, q: dict, fill: bool = True, today: _dt.date | None = None) -> tuple[dict, dict]:
    """(埋めた質問票, 自動入力の記録) を返す。fill=False のときは埋めずに照合だけ行う。"""
    q = copy.deepcopy(q or {})
    card = find_card((snapshot.get("server") or {}).get("url"))
    answers = {**_derived(snapshot), **(card["answers"] if card else {})}
    items = []
    for key, a in answers.items():
        if key in COMPANY_KEYS:
            continue
        sec, k = key.split(".", 1)
        cur = (q.get(sec) or {}).get(k)
        if _empty(cur):
            if not fill:
                continue
            q.setdefault(sec, {})[k] = copy.deepcopy(a["value"])
            status = FILLED
        else:
            status = MATCHES if _same(cur, a["value"]) else DIFFERS
        items.append({"key": key, "label": LABELS.get(key, key), "value": a["value"], "answer": cur,
                      "display": DISPLAY.get(key, {}).get(a["value"]) if isinstance(a["value"], str) else None,
                      "status": status, "source": a.get("source", ""), "note": a.get("note", "")})
    info = {"items": items}
    if card:
        today = today or _dt.date.today()
        checked = _dt.date.fromisoformat(card["checked"])
        info["card"] = {"id": card["id"], "title": card["title"], "checked": card["checked"],
                        "stale": (today - checked).days > STALE_DAYS, "notes": card.get("notes", [])}
    return q, (info if items or card else {})
