"""証拠収集：MCPサーバからツール定義とOAuthメタデータを取得し、スナップショット化する。

- 取得するのは tools/list とメタデータ（RFC 9728 / RFC 8414）だけ。ツールは一切実行しない。
- stdio型（ローカル実行型）サーバは、未審査のコードを動かすことになるため対象外。
  ツール一覧をJSONで書き出したものを --snapshot で渡す。
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import urllib.error
import urllib.parse
import urllib.request

PROTOCOL_VERSION = "2025-11-25"
UA = "mcp-gate/0.3 (+security review; read-only)"
TIMEOUT = 20


class FetchError(RuntimeError):
    pass


def _parse_sse(body: str, want_id) -> dict | None:
    """text/event-stream の data: 行から、指定IDのJSON-RPC応答を取り出す。"""
    for block in re.split(r"\r?\n\r?\n", body):
        data = "\n".join(l[5:].lstrip() for l in block.splitlines() if l.startswith("data:"))
        if not data:
            continue
        try:
            msg = json.loads(data)
        except json.JSONDecodeError:
            continue
        if isinstance(msg, dict) and msg.get("id") == want_id:
            return msg
    return None


def _http(url, method="GET", body=None, headers=None):
    req = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        raise FetchError(f"{url}: {e.reason}") from e


def _get_json(url):
    try:
        status, _, text = _http(url, headers={"Accept": "application/json"})
    except FetchError:
        return None
    if status != 200:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


class _Session:
    def __init__(self, url, token=None):
        self.url, self.token, self.sid, self._id = url, token, None, 0
        self.last_status, self.last_headers = None, {}

    def _headers(self, initialized):
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if initialized:
            h["MCP-Protocol-Version"] = PROTOCOL_VERSION
        if self.sid:
            h["Mcp-Session-Id"] = self.sid
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def call(self, method, params=None, notify=False, initialized=True):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            self._id += 1
            msg["id"] = self._id
        status, headers, text = _http(self.url, "POST", json.dumps(msg).encode(), self._headers(initialized))
        self.last_status, self.last_headers = status, headers
        sid = {k.lower(): v for k, v in headers.items()}.get("mcp-session-id")
        if sid:
            self.sid = sid
        if notify:
            return None
        if status != 200:
            return {"_http_status": status, "_body": text[:500]}
        ctype = {k.lower(): v for k, v in headers.items()}.get("content-type", "")
        resp = _parse_sse(text, msg["id"]) if "text/event-stream" in ctype else json.loads(text)
        if resp is None:
            raise FetchError(f"{method}: 応答を解釈できません")
        return resp


def _resource_metadata_url(www_auth: str | None) -> str | None:
    if not www_auth:
        return None
    m = re.search(r'resource_metadata="?([^",\s]+)"?', www_auth)
    return m.group(1) if m else None


def _well_known(base_url, suffix):
    """RFC 9728 / RFC 8414 のパス挿入方式で well-known URL 候補を作る。"""
    u = urllib.parse.urlsplit(base_url)
    path = u.path.rstrip("/")
    cands = [f"{u.scheme}://{u.netloc}/.well-known/{suffix}{path}"]
    if path:
        cands.append(f"{u.scheme}://{u.netloc}/.well-known/{suffix}")
    return cands


def fetch_oauth(url: str, www_auth: str | None = None) -> dict:
    prm, prm_url = None, _resource_metadata_url(www_auth)
    for cand in ([prm_url] if prm_url else []) + _well_known(url, "oauth-protected-resource"):
        prm = _get_json(cand)
        if prm:
            break
    asm = None
    for issuer in (prm or {}).get("authorization_servers", [])[:1]:
        for cand in _well_known(issuer, "oauth-authorization-server") + _well_known(issuer, "openid-configuration"):
            asm = _get_json(cand)
            if asm:
                break
    return {"protected_resource": prm, "authorization_server": asm}


def fetch_http(url: str, token: str | None = None, name: str | None = None) -> dict:
    """Streamable HTTP の MCP サーバから tools/list を取得してスナップショットを返す。"""
    s = _Session(url, token)
    init = s.call("initialize", {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "mcp-gate", "version": "0.3.0"},
    }, initialized=False)
    obs = {"https": url.lower().startswith("https://"), "token_supplied": bool(token)}
    tools, server_info = [], {}
    www_auth = {k.lower(): v for k, v in s.last_headers.items()}.get("www-authenticate")
    if "_http_status" in init:
        obs["initialize_status"] = init["_http_status"]
        obs["auth_required"] = init["_http_status"] in (401, 403)
    else:
        server_info = init.get("result", {}).get("serverInfo", {})
        obs["auth_required"] = False
        s.call("notifications/initialized", notify=True)
        cursor = None
        for _ in range(50):  # ページング上限
            resp = s.call("tools/list", {"cursor": cursor} if cursor else {})
            if "_http_status" in resp or "error" in resp:
                obs["tools_list_error"] = resp.get("error") or resp.get("_http_status")
                break
            tools.extend(resp["result"].get("tools", []))
            cursor = resp["result"].get("nextCursor")
            if not cursor:
                break
        obs["unauthenticated_tools_list"] = not token and bool(tools)
    return {
        "server": {"name": name or server_info.get("name") or urllib.parse.urlsplit(url).netloc,
                   "url": url, "serverInfo": server_info,
                   "fetched_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")},
        "observations": obs,
        "tools": tools,
        "oauth": fetch_oauth(url, www_auth),
    }


def load_snapshot(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        snap = json.load(f)
    # tools/list の生の応答（{"tools":[...]}）だけを渡された場合も受け付ける
    snap.setdefault("server", {"name": path, "url": ""})
    snap.setdefault("observations", {})
    snap.setdefault("oauth", {"protected_resource": None, "authorization_server": None})
    snap.setdefault("tools", [])
    return snap


def load_openapi(path_or_url: str, name: str | None = None) -> dict:
    """OpenAPI/Swagger の仕様書（JSON）を読み込んでスナップショットにする。

    URL の場合は仕様書ファイルを1回ダウンロードするだけで、API そのものは呼び出さない。
    """
    from .openapi import OpenAPIError, to_snapshot
    if path_or_url.lower().startswith(("http://", "https://")):
        status, _, text = _http(path_or_url, headers={"Accept": "application/json"})
        if status != 200:
            raise FetchError(f"仕様書を取得できません（HTTP {status}）: {path_or_url}")
    else:
        with open(path_or_url, encoding="utf-8-sig") as f:
            text = f.read()
    try:
        spec = json.loads(text)
    except json.JSONDecodeError:
        raise FetchError("仕様書がJSONではありません。YAMLの場合はJSONに変換してから指定してください") from None
    try:
        snap = to_snapshot(spec, name)
    except OpenAPIError as e:
        raise FetchError(str(e)) from None
    snap["server"]["fetched_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    snap["server"]["spec_location"] = path_or_url
    return snap
