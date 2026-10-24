"""MCP サーバを Azure API Center の台帳に「未審査」で登録する（Portal を使わずに登録したい場合）。

登録すると、配備済みの Azure Functions が次の定期実行で審査し、結果を台帳に書き戻す。

使い方（リポジトリのルートで）:
  python integrations/azure-api-center/register.py --url https://learn.microsoft.com/api/mcp --title "Microsoft Learn MCP"
  （--dry-run を付けると、登録せずに送る内容とコマンドだけを表示）

- 2026年10月時点の apic-extension は `az apic api create --type` に mcp を指定できないため、
  管理用 REST API（`az rest`）で種別 mcp の資産を作る。Azure CLI でログイン済みであること。
- 同じ ID の資産がすでにあれば登録しない（既存の審査結果を上書きしないため）。
- 登録前に、Functions の関所（magate/netguard.py）がこのURLを止めるかどうかを表示する。
  止まるURLでも登録はできる（関所の動作確認に使える）。標準ライブラリのみで動作する。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ARM = "https://management.azure.com"
DEFAULT_API_VERSION = "2024-03-01"


def make_api_id(title: str, url: str) -> str:
    """資産のID（英数字とハイフン）を作る。タイトルが日本語などで作れない場合はホスト名から作る。"""
    for src in (title, urllib.parse.urlsplit(url).hostname or ""):
        slug = re.sub(r"[^a-z0-9]+", "-", (src or "").lower()).strip("-")[:80]
        if slug:
            return slug
    return "mcp-server"


def build_body(url: str, title: str, summary: str | None = None) -> dict:
    props = {"title": title, "kind": "mcp",
             "customProperties": {"magate-target-url": url, "magate-verdict": "未審査"}}
    if summary:
        props["summary"] = summary
    return {"properties": props}


def guard_note(url: str) -> str:
    """Functions（既定設定）の関所がこのURLを止めるかどうか。"""
    sys.path.insert(0, ROOT)
    from magate.netguard import ENV, BlockedURL, check_url
    saved = os.environ.pop(ENV, None)  # Functions の既定（社内アドレスを拒否）で確認する
    try:
        check_url(url)
        return "関所：通過（Functions が審査できるURLです）"
    except BlockedURL as e:
        return f"関所：停止（{e}）。Functions は審査せず、台帳に理由を記録します"
    finally:
        if saved is not None:
            os.environ[ENV] = saved


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="MCP サーバを Azure API Center に未審査で登録する")
    p.add_argument("--url", required=True, help="審査対象の MCP サーバの URL")
    p.add_argument("--title", help="台帳での表示名（省略時はホスト名）")
    p.add_argument("--api-id", help="資産のID（英数字とハイフン。省略時はタイトルから作る）")
    p.add_argument("--summary", help="概要（任意）")
    p.add_argument("-g", "--resource-group", default="magate-rg")
    p.add_argument("-n", "--service-name", default="magate-apic")
    p.add_argument("--api-version", default=os.environ.get("APIC_API_VERSION", DEFAULT_API_VERSION))
    p.add_argument("--dry-run", action="store_true", help="登録せずに内容だけ表示する")
    a = p.parse_args(argv)

    if not a.url.lower().startswith(("http://", "https://")):
        sys.exit("--url は http(s) のURLを指定してください")
    title = a.title or urllib.parse.urlsplit(a.url).hostname or a.url
    api_id = a.api_id or make_api_id(title, a.url)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,89}", api_id):
        sys.exit(f"--api-id は英数字とハイフン（90文字以内）にしてください: {api_id}")
    body = build_body(a.url, title, a.summary)

    print(f"資産ID：{api_id}")
    print(guard_note(a.url))
    print(json.dumps(body, ensure_ascii=False, indent=2))

    az = shutil.which("az")
    if not az and not a.dry_run:
        sys.exit("az コマンドが見つかりません。Azure CLI のインストールと PATH を確認してください。")
    sub = "<サブスクリプションID>"
    if az:
        r = _run([az, "account", "show", "--query", "id", "-o", "tsv"])
        if r.returncode != 0:
            sys.exit(f"Azure にログインしていません（az login）:\n{r.stderr}")
        sub = r.stdout.strip()
    res_url = (f"{ARM}/subscriptions/{sub}/resourceGroups/{a.resource_group}/providers/Microsoft.ApiCenter"
               f"/services/{a.service_name}/workspaces/default/apis/{api_id}?api-version={a.api_version}")

    if a.dry_run:
        print(f"\n[dry-run] az rest --method put --url \"{res_url}\" --body @<上の内容>")
        return 0

    if _run([az, "rest", "--method", "get", "--url", res_url]).returncode == 0:
        sys.exit(f"同じID（{api_id}）の資産がすでにあります。上書きしないため中止しました（--api-id で別のIDを指定）")

    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(body, f, ensure_ascii=False)
        r = _run([az, "rest", "--method", "put", "--url", res_url, "--body", f"@{path}",
                  "--headers", "Content-Type=application/json"])
    finally:
        os.remove(path)
    if r.returncode != 0:
        sys.exit(f"登録に失敗しました:\n{r.stderr}")
    kind = (json.loads(r.stdout or "{}").get("properties") or {}).get("kind")
    if str(kind).lower() != "mcp":
        print(f"注意：登録された種別が mcp ではありません（{kind}）。Functions の審査対象になりません", file=sys.stderr)
    print(f"\n登録完了：{api_id}（未審査）。次の定期実行で Functions が審査します", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
