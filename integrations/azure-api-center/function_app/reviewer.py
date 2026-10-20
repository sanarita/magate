"""台帳（API Center）の「未審査」のMCPサーバを maGATE で審査し、結果を書き戻す。

Azure Functions のタイマーから呼ぶほか、手元のPCで動作確認もできる:
  python reviewer.py --dry-run     # 審査だけ行い、台帳には書き込まない
  python reviewer.py               # 審査して書き込む（az login 済み・環境変数を設定して実行）
"""
from __future__ import annotations

import datetime
import json
import os
import sys

# 配備時は prepare.py が magate/ と writeback.py を同じフォルダに置く。
# リポジトリ内で動かすときは、元の場所から読み込む。
_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(_HERE, ".."), os.path.join(_HERE, "..", "..", "..")):
    if os.path.abspath(_p) not in map(os.path.abspath, sys.path):
        sys.path.append(_p)

from writeback import to_custom_properties  # noqa: E402

PENDING = {None, "", "未審査"}
DEFAULT_TZ = "Asia/Tokyo"  # 台帳を見るのは日本の利用者なので、審査日は日本時間で記録する
TARGET_URL = "magate-target-url"  # 登録時に入力してもらう審査対象のURL（デプロイのURLより優先）
FETCH_FAILED = "自動審査で接続先を取得できませんでした"


def today_local() -> str:
    """審査日（YYYY-MM-DD）を返す。Azure 上の時計は UTC のため、MAGATE_TZ（既定は日本時間）に変換する。"""
    name = os.environ.get("MAGATE_TZ", DEFAULT_TZ)
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(name)
    except Exception:  # noqa: BLE001  タイムゾーンのデータが無い環境でも日本時間は固定の時差で求める
        tz = datetime.timezone(datetime.timedelta(hours=9)) if name == DEFAULT_TZ else datetime.timezone.utc
    return datetime.datetime.now(tz).date().isoformat()


def audit_url(url: str, name: str | None = None) -> dict:
    """maGATE で接続先を審査し、result.json と同じ形の辞書を返す。"""
    from magate.autofill import autofill
    from magate.collect import fetch_http
    from magate.report import to_json
    from magate.rubric import evaluate
    snap = fetch_http(url, name=name)
    q, info = autofill(snap, {}, fill=True)
    return json.loads(to_json(evaluate(snap, q, [], None, autofill=info)))


def run_once(client, audit=audit_url, today: str | None = None, dry_run: bool = False) -> list[str]:
    """未審査のMCPサーバを1回分処理し、処理内容のログ行を返す。"""
    today = today or today_local()
    log = []
    for api in client.list_apis():
        name, p = api.get("name"), api.get("properties") or {}
        cp = p.get("customProperties") or {}
        if str(p.get("kind", "")).lower() != "mcp":
            continue
        if cp.get("magate-verdict") not in PENDING:
            continue  # 審査済み
        if cp.get("magate-reviewed-at") == today and str(cp.get("magate-conditions", "")).startswith(FETCH_FAILED):
            continue  # 今日すでに取得に失敗している（同じ失敗を繰り返さない）

        url = cp.get(TARGET_URL) or client.runtime_url(name)
        if not url:
            log.append(f"{name}: 審査対象URL（{TARGET_URL}）が未登録のためスキップ")
            continue
        try:
            new = to_custom_properties(audit(url, name=p.get("title") or name), reviewed_at=today)
            msg = f"{name}: {new['magate-verdict']}"
        except Exception as e:  # noqa: BLE001  取得失敗（認証必須・接続拒否など）は台帳に理由を残す
            new = {"magate-verdict": "未審査", "magate-reviewed-at": today,
                   "magate-conditions": f"{FETCH_FAILED}（{type(e).__name__}: {e}）。"
                                        "コマンドライン版で認証情報を指定して審査すること"}
            msg = f"{name}: 取得失敗 {type(e).__name__}"
        if not dry_run:
            client.update_custom_properties(name, new)
        log.append(msg + ("（dry-run・未書き込み）" if dry_run else ""))
    return log or ["未審査のMCPサーバはありません"]


if __name__ == "__main__":
    from apic_client import ApiCenterClient
    for line in run_once(ApiCenterClient.from_env(), dry_run="--dry-run" in sys.argv):
        print(line)
