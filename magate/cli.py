"""maGATE コマンドライン。

  audit    接続先を審査してレポートを出す（許可／条件付き許可／不可）
  pin      承認時点のツール定義をハッシュで固定する
  monitor  固定した定義と現在の定義を比較し、差分があれば再審査に回す（終了コード 2）
  draft-q  規約本文から質問票の下書きを作る（LLM使用・任意）
  snapshot 接続先からツール定義とOAuthメタデータを取得して保存する
  cors-check ブラウザ版の「URLから取得」が使えるか（CORS）を調べる
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

from . import __version__
from .checks.rugpull import check_rugpull, save_pin
from .collect import FetchError, fetch_http, load_openapi, load_snapshot
from .model import FAIL, WARN
from .report import to_json, to_markdown
from .rubric import DENY, PERMIT, evaluate

EXIT_OK, EXIT_ERROR, EXIT_CHANGED, EXIT_DENY = 0, 1, 2, 3


def _snapshot(args) -> dict:
    if getattr(args, "openapi", None):
        return load_openapi(args.openapi, name=args.name)
    if args.snapshot:
        return load_snapshot(args.snapshot)
    token = os.environ.get(args.token_env) if args.token_env else None
    return fetch_http(args.url, token=token, name=args.name)


def _inventory(path):
    if not path:
        return []
    return [load_snapshot(p) for p in sorted(glob.glob(os.path.join(path, "*.json")))]


def _write(path, text):
    if path in (None, "-"):
        sys.stdout.write(text)
    else:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"出力: {path}", file=sys.stderr)


def _src(p):
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--url", help="MCPサーバのURL（Streamable HTTP）")
    g.add_argument("--snapshot", help="保存済みスナップショット／tools/list のJSON")
    g.add_argument("--openapi", help="API の仕様書（OpenAPI 3.x / Swagger 2.0 の JSON。ファイルパスまたはURL）")
    p.add_argument("--name", help="サーバ名（pinのファイル名に使う）")
    p.add_argument("--token-env", help="アクセストークンを入れた環境変数名（値を直接渡さない）")


def cmd_snapshot(a):
    _write(a.out, json.dumps(_snapshot(a), ensure_ascii=False, indent=2))
    return EXIT_OK


def cmd_audit(a):
    snap = _snapshot(a)
    q = {}
    if a.questionnaire:
        with open(a.questionnaire, encoding="utf-8") as f:
            q = json.load(f)
    res = evaluate(snap, q, _inventory(a.inventory), a.pins)
    _write(a.out, to_json(res) if a.json else to_markdown(res, redact=a.redact))
    print(f"総合判定: {res.verdict}", file=sys.stderr)
    return EXIT_DENY if res.verdict == DENY else EXIT_OK


def cmd_pin(a):
    snap = _snapshot(a)
    path = save_pin(a.pins, snap, approved_by=a.approved_by or "", note=a.note or "")
    print(f"固定しました: {path}（ツール {len(snap['tools'])} 件）", file=sys.stderr)
    return EXIT_OK


def cmd_monitor(a):
    targets = []
    if a.targets:
        with open(a.targets, encoding="utf-8") as f:
            targets = json.load(f)
    else:
        targets = [{"url": a.url, "snapshot": a.snapshot, "name": a.name, "token_env": a.token_env}]
    changed, lines = False, ["# MCP接続先 定期監視レポート", ""]
    for t in targets:
        ns = argparse.Namespace(url=t.get("url"), snapshot=t.get("snapshot"), openapi=t.get("openapi"),
                                name=t.get("name"), token_env=t.get("token_env"))
        try:
            snap = _snapshot(ns)
        except FetchError as e:
            lines += [f"## {t.get('name') or t.get('url')}", f"- ❔ 取得失敗：{e}", ""]
            changed = True
            continue
        fs = check_rugpull(snap, a.pins)
        bad = [f for f in fs if f.status in (WARN, FAIL)]
        lines.append(f"## {snap['server']['name']}：{'⚠️ 変更あり（再審査が必要）' if bad else '✅ 変更なし'}")
        for f in fs:
            lines.append(f"- {f.message}")
            if f.evidence:
                lines += ["  ```", *[f"  {x}" for x in f.evidence.splitlines()], "  ```"]
        lines.append("")
        changed |= bool(bad)
    _write(a.out, "\n".join(lines) + "\n")
    return EXIT_CHANGED if changed else EXIT_OK


def cmd_cors(a):
    from .corsprobe import DEFAULT_ORIGIN, probe, to_markdown
    urls = list(a.url or [])
    if a.targets:
        with open(a.targets, encoding="utf-8") as f:
            urls += [t["url"] if isinstance(t, dict) else t for t in json.load(f)]
    if not urls:
        print("--url か --targets で接続先を指定してください", file=sys.stderr)
        return EXIT_ERROR
    results = []
    for u in urls:
        print(f"調査中: {u}", file=sys.stderr)
        results.append(probe(u, a.origin or DEFAULT_ORIGIN))
    _write(a.out, json.dumps(results, ensure_ascii=False, indent=2) if a.json else to_markdown(results, a.origin or DEFAULT_ORIGIN))
    return EXIT_OK


def cmd_draft_q(a):
    from .policy_agent import draft
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        print("ANTHROPIC_API_KEY が未設定です", file=sys.stderr)
        return EXIT_ERROR
    with open(a.policy, encoding="utf-8") as f:
        doc = f.read()
    patch = draft(doc, a.source or a.policy, key, a.model)
    _write(a.out, json.dumps(patch, ensure_ascii=False, indent=2))
    return EXIT_OK


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="magate", description="maGATE — MCP・API接続先のセキュリティ審査ツール")
    p.add_argument("--version", action="version", version=f"maGATE {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("snapshot", help="ツール定義とOAuthメタデータを取得して保存")
    _src(s); s.add_argument("--out", "-o")
    s.set_defaults(func=cmd_snapshot)

    s = sub.add_parser("audit", help="接続先を審査してレポートを出す")
    _src(s)
    s.add_argument("--questionnaire", "-q", help="提供元への質問票（回答済みJSON）")
    s.add_argument("--inventory", help="承認済みサーバのスナップショットを置いたフォルダ（シャドーイング検知用）")
    s.add_argument("--pins", help="固定ハッシュの保存フォルダ（ラグプル検知用）")
    s.add_argument("--out", "-o", help="出力先（省略時は標準出力）")
    s.add_argument("--json", action="store_true", help="JSONで出力")
    s.add_argument("--redact", action="store_true",
                   help="審査対象由来の抜粋を伏せ字にする（結果をClaudeやCopilotに貼り付けるとき用）")
    s.set_defaults(func=cmd_audit)

    s = sub.add_parser("pin", help="承認時点のツール定義を固定する")
    _src(s)
    s.add_argument("--pins", required=True)
    s.add_argument("--approved-by"); s.add_argument("--note")
    s.set_defaults(func=cmd_pin)

    s = sub.add_parser("monitor", help="固定した定義との差分を監視する（変更ありで終了コード2）")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--targets", help="監視対象一覧JSON [{name,url,token_env} / {name,snapshot} / {name,openapi}]")
    g.add_argument("--url"); g.add_argument("--snapshot"); g.add_argument("--openapi")
    s.add_argument("--name"); s.add_argument("--token-env")
    s.add_argument("--pins", required=True)
    s.add_argument("--out", "-o")
    s.set_defaults(func=cmd_monitor)

    s = sub.add_parser("cors-check", help="ブラウザ版の「URLから取得」が使えるか（CORS）を調べる")
    s.add_argument("--url", action="append", help="調べるMCPサーバのURL（複数指定可）")
    s.add_argument("--targets", help="URLの一覧JSON（文字列の配列、または {url} の配列）")
    s.add_argument("--origin", help="ブラウザ版の公開元（既定：https://sanarita.github.io）")
    s.add_argument("--out", "-o"); s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_cors)

    s = sub.add_parser("draft-q", help="規約本文から質問票の下書きを作る（LLM使用）")
    s.add_argument("--policy", required=True, help="規約・プライバシーポリシーのテキストファイル")
    s.add_argument("--source", help="規約のURL（記録用）")
    s.add_argument("--model", default=None)
    s.add_argument("--out", "-o")
    s.set_defaults(func=cmd_draft_q)

    a = p.parse_args(argv)
    if getattr(a, "model", "x") is None:
        from .policy_agent import DEFAULT_MODEL
        a.model = DEFAULT_MODEL
    try:
        return a.func(a)
    except FetchError as e:
        print(f"取得エラー: {e}", file=sys.stderr)
        return EXIT_ERROR
