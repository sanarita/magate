"""maGATE の審査結果を Azure API Center のカスタムメタデータに書き戻す。

審査結果の入力は2通り:
  --result FILE  ブラウザ版の「結果を保存（.json）」または `magate audit --json -o FILE` の出力
  --url URL      その場で `magate audit --url URL --json` を実行して、その結果を使う

使い方（リポジトリのルートで）:
  python integrations/azure-api-center/writeback.py --api-id microsoft-learn-mcp-server --result result.json
  python integrations/azure-api-center/writeback.py --api-id microsoft-learn-mcp-server --url https://learn.microsoft.com/api/mcp
  （--dry-run を付けると書き込まずに、書き込む値とコマンドだけを表示）

Azure CLI（apic-extension）でログイン済みであること。標準ライブラリのみで動作する。
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VERDICTS = {"許可", "条件付き許可", "不可"}
# 台帳に載せる審査項目の状態と表示名（未確認も「リスクを否定できていない」ため載せる）
FLAGGED = [("FAIL", "NG"), ("WARN", "要対応"), ("UNKNOWN", "未確認")]


def to_custom_properties(result: dict, reviewed_at: str | None = None) -> dict:
    """maGATE の result.json を API Center のカスタムメタデータ（キー: 値）に変換する。"""
    verdict = result.get("verdict")
    if verdict not in VERDICTS:
        raise ValueError(f"maGATE の審査結果として読めません（verdict={verdict!r}）")

    lines = [f"【不可の理由】{b}" for b in result.get("blockers") or []]
    lines += result.get("conditions") or []
    conditions = " / ".join(f"{i}. {c}" for i, c in enumerate(lines, 1)) or "なし"

    items = result.get("items") or []
    groups = []
    for status, label in FLAGGED:
        asi = sorted({a for it in items if it.get("status") == status for a in it.get("asi") or []})
        if asi:
            groups.append(f"{label}: {', '.join(asi)}")

    return {
        "magate-verdict": verdict,
        "magate-conditions": conditions,
        "magate-reviewed-at": reviewed_at or datetime.date.today().isoformat(),
        "magate-owasp": " / ".join(groups) or "該当なし",
    }


def to_shorthand(props: dict) -> str:
    """Azure CLI の省略記法に変換する。値はシングルクォートで囲み、区切り文字(, :)を含んでも壊れないようにする。"""
    def q(v) -> str:
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return str(v)  # 数値型のメタデータは数値のまま渡す
        return "'" + str(v).replace("'", "’") + "'"
    return "{" + ",".join(f"{k}:{q(v)}" for k, v in props.items()) + "}"


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONIOENCODING="utf-8", **kw.pop("env", {}))  # Windows での文字化け防止
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, **kw)


def audit_url(url: str) -> dict:
    """リポジトリ内の maGATE で接続先を審査し、結果を返す（不可の場合も結果を返す）。"""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        r = _run([sys.executable, "-m", "magate", "audit", "--url", url, "--json", "-o", path],
                 cwd=ROOT, env={"PYTHONPATH": ROOT})
        if r.returncode not in (0, 3):  # 3 = 判定「不可」
            sys.exit(f"審査に失敗しました:\n{r.stderr}")
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    finally:
        os.remove(path)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="maGATE の審査結果を Azure API Center に書き戻す")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--result", help="maGATE の審査結果JSON（ブラウザ版の保存ファイル、または audit --json の出力）")
    src.add_argument("--url", help="この場で審査するMCPサーバのURL")
    p.add_argument("--api-id", required=True, help="API Center に登録した資産のID")
    p.add_argument("-g", "--resource-group", default="magate-rg")
    p.add_argument("-n", "--service-name", default="magate-apic")
    p.add_argument("--dry-run", action="store_true", help="書き込まずに内容だけ表示する")
    a = p.parse_args(argv)

    if a.result:
        with open(a.result, encoding="utf-8") as f:
            result = json.load(f)
    else:
        print(f"審査中: {a.url}", file=sys.stderr)
        result = audit_url(a.url)

    props = to_custom_properties(result)
    print(json.dumps(props, ensure_ascii=False, indent=2))

    target = ["-g", a.resource_group, "-n", a.service_name, "--api-id", a.api_id]
    az = shutil.which("az")
    if not az and not a.dry_run:
        sys.exit("az コマンドが見つかりません。Azure CLI のインストールと PATH を確認してください。")

    # `az apic api update --custom-properties` は既存の値を丸ごと置き換えるため、
    # 審査対象URLなど他のメタデータを先に読み出して残す
    current = {}
    if az:
        r = _run([az, "apic", "api", "show", *target, "--query", "customProperties", "-o", "json"])
        if r.returncode == 0 and r.stdout.strip() not in ("", "null"):
            current = json.loads(r.stdout)
    cmd = ["apic", "api", "update", *target, "--custom-properties", to_shorthand({**current, **props})]
    if a.dry_run:
        print("\n[dry-run] az " + " ".join(cmd))
        return 0
    r = _run([az, *cmd])
    if r.returncode != 0:
        sys.exit(f"書き込みに失敗しました:\n{r.stderr}")
    print(f"\n書き込み完了: {a.api_id}（{props['magate-verdict']}）", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
