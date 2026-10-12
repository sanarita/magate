"""ブラウザ版の「URLから取得」が使えるか（CORS）を、ブラウザと同じ手順で調べる。

ブラウザは別サイトへ POST する前に、OPTIONS の事前確認（プリフライト）を送り、
応答ヘッダで許可されているかを判定する。この判定をそのまま再現する。
各サーバに送るのは、プリフライト・initialize・tools/list の数回だけ（ツールは実行しない）。
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from . import __version__
from .collect import PROTOCOL_VERSION, UA, _parse_sse

DEFAULT_ORIGIN = "https://sanarita.github.io"
TIMEOUT = 15


def _req(url, method, headers, body=None):
    r = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": UA, **headers})
    try:
        with urllib.request.urlopen(r, timeout=TIMEOUT) as res:
            return res.status, {k.lower(): v for k, v in res.headers.items()}, res.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, e.read().decode("utf-8", "replace")


def _list(v):
    return {x.strip().lower() for x in (v or "").split(",") if x.strip()}


def origin_allowed(h, origin):
    acao = h.get("access-control-allow-origin", "")
    return acao == "*" or acao == origin


def preflight(url, origin, req_headers):
    """ブラウザのプリフライトを再現し、(OK?, 理由) を返す。"""
    status, h, _ = _req(url, "OPTIONS", {
        "Origin": origin, "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": ",".join(sorted(req_headers))})
    if not 200 <= status < 300:
        return False, f"事前確認(OPTIONS)が HTTP {status}"
    if not origin_allowed(h, origin):
        return False, "Access-Control-Allow-Origin がない（ブラウザからの接続を許可していない）"
    methods = _list(h.get("access-control-allow-methods"))
    if methods and "*" not in methods and "post" not in methods:
        return False, "POST が許可されていない"
    allowed = _list(h.get("access-control-allow-headers"))
    missing = [x for x in req_headers if x not in allowed and "*" not in allowed]
    if missing:
        return False, f"ヘッダ {', '.join(missing)} が許可されていない"
    return True, "OK"


def _post(url, origin, headers, payload):
    status, h, text = _req(url, "POST", {"Origin": origin, "Content-Type": "application/json",
                                         "Accept": "application/json, text/event-stream", **headers},
                           json.dumps(payload).encode())
    msg = None
    if status == 200:
        msg = _parse_sse(text, payload.get("id")) if "text/event-stream" in h.get("content-type", "") else _safe_json(text)
    return status, h, msg


def _safe_json(t):
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        return None


def probe(url: str, origin: str = DEFAULT_ORIGIN) -> dict:
    steps = []
    res = {"url": url, "result": "", "tools": None, "steps": steps}

    def done(result):
        res["result"] = result
        return res

    try:
        ok, why = preflight(url, origin, ["content-type"])
        steps.append(f"事前確認（接続開始）: {why}")
        if not ok:
            return done("不可（CORS）")
        status, h, msg = _post(url, origin, {}, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "magate-cors-check", "version": __version__}}})
        if not origin_allowed(h, origin):
            steps.append(f"接続開始: HTTP {status}、応答に Access-Control-Allow-Origin がない")
            return done("不可（CORS：応答がブラウザに渡らない）")
        steps.append(f"接続開始: HTTP {status}")
        if status in (401, 403):
            return done("接続可・ツール一覧は認証が必要")
        if status != 200 or not msg or "result" not in msg:
            return done("不可（MCPの応答が不正）")
        version = msg["result"].get("protocolVersion", PROTOCOL_VERSION)
        sid = h.get("mcp-session-id")
        follow = ["content-type", "mcp-protocol-version"]
        if sid:
            exposed = _list(h.get("access-control-expose-headers"))
            if "mcp-session-id" not in exposed and "*" not in exposed:
                steps.append("セッションIDを返すが、ブラウザから読めない（Access-Control-Expose-Headers 未設定）")
                return done("不可（セッションIDが読めない）")
            follow.append("mcp-session-id")
            steps.append("セッションID: ブラウザから読める")
        ok, why = preflight(url, origin, follow)
        steps.append(f"事前確認（ツール一覧）: {why}")
        if not ok:
            return done("接続開始のみ可（2回目以降がCORSで拒否）")
        headers = {"MCP-Protocol-Version": version, **({"Mcp-Session-Id": sid} if sid else {})}
        _post(url, origin, headers, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        status, h, msg = _post(url, origin, headers, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        if not origin_allowed(h, origin) or status != 200 or not msg or "result" not in msg:
            steps.append(f"ツール一覧: HTTP {status}")
            return done("接続開始のみ可（ツール一覧を取得できない）")
        res["tools"] = len(msg["result"].get("tools", []))
        steps.append(f"ツール一覧: {res['tools']} 件")
        return done("可")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        steps.append(f"接続エラー: {getattr(e, 'reason', e)}")
        return done("不可（接続できない）")


def to_markdown(results: list[dict], origin: str) -> str:
    L = ["# ブラウザ版「URLから取得」の対応状況", "", f"- 調査元（Origin）：`{origin}`", "",
         "| 接続先 | 結果 | ツール数 |", "|---|---|---|"]
    for r in results:
        L.append(f"| `{r['url']}` | {r['result']} | {r['tools'] if r['tools'] is not None else '-'} |")
    L += ["", "## 詳細"]
    for r in results:
        L += ["", f"### {r['url']}", *[f"- {s}" for s in r["steps"]]]
    return "\n".join(L) + "\n"
