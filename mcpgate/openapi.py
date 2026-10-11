"""OpenAPI 3.x / Swagger 2.0 の仕様書（JSON）を、mcp-gate のスナップショット形式に変換する。

API の各操作（GET /patents など）を MCP の「ツール」と同じ形に並べ替えることで、
ポイズニング・ラグプル・シャドーイングの検査と、書き込み系操作の洗い出しをそのまま適用する。
Copilot Studio のカスタムコネクタ（Swagger 2.0 + x-ms-* 拡張）にも対応する。
ネットワークには一切アクセスしない（外部の $ref は解決しない）。
"""
from __future__ import annotations

import re

METHODS = ("get", "put", "post", "delete", "patch", "head", "options", "trace")
READ_ONLY = {"get", "head", "options"}
MAX_DEPTH = 6


class OpenAPIError(ValueError):
    pass


def is_openapi(obj) -> bool:
    return isinstance(obj, dict) and ("openapi" in obj or "swagger" in obj) and isinstance(obj.get("paths"), dict)


def _resolve(spec, node, seen=()):
    """ローカルの $ref（#/components/... や #/definitions/...）だけを解決する。"""
    while isinstance(node, dict) and isinstance(node.get("$ref"), str):
        ref = node["$ref"]
        if not ref.startswith("#/") or ref in seen:
            return {"description": f"(未解決の参照: {ref})"}
        seen = (*seen, ref)
        cur = spec
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(cur, dict) or part not in cur:
                return {"description": f"(未解決の参照: {ref})"}
            cur = cur[part]
        node = cur
    return node


def _schema(spec, node, depth=0, seen=()):
    """モデルが読む文字列（説明・タイトル・列挙値など）を保ったままスキーマを展開する。"""
    if depth > MAX_DEPTH:
        return {}
    if isinstance(node, dict) and isinstance(node.get("$ref"), str):
        ref = node["$ref"]
        if ref in seen:
            return {"description": f"(循環参照: {ref})"}
        return _schema(spec, _resolve(spec, node), depth, (*seen, ref))
    if not isinstance(node, dict):
        return {}
    out = {}
    for k in ("type", "title", "description", "enum", "default", "format", "pattern", "maxLength", "x-ms-summary"):
        if k in node:
            out[k] = node[k]
    if isinstance(node.get("properties"), dict):
        out["properties"] = {k: _schema(spec, v, depth + 1, seen) for k, v in node["properties"].items()}
    if "items" in node:
        out["items"] = _schema(spec, node["items"], depth + 1, seen)
    for k in ("allOf", "anyOf", "oneOf"):
        if isinstance(node.get(k), list):
            out[k] = [_schema(spec, x, depth + 1, seen) for x in node[k]]
    if "x-ms-summary" in out:  # Power Platform の表示名もモデルに渡るので説明として扱う
        out["description"] = f"{out.pop('x-ms-summary')} {out.get('description', '')}".strip()
    return out


def _tool_name(method, path, op, used):
    name = op.get("operationId") or f"{method.upper()} {path}"
    name = re.sub(r"_+", "_", re.sub(r"[^A-Za-z0-9_.\-]", "_", name)).strip("_") or f"{method}_op"
    base, i = name, 2
    while name in used:
        name, i = f"{base}_{i}", i + 1
    used.add(name)
    return name


def _params(spec, method, path_item, op):
    props, required, body_desc = {}, [], []
    params = [_resolve(spec, p) for p in (path_item.get("parameters") or []) + (op.get("parameters") or [])]
    for p in params:
        if not isinstance(p, dict):
            continue
        if p.get("in") == "body":  # Swagger 2.0
            props["body"] = _schema(spec, p.get("schema", {}))
            if p.get("description"):
                props["body"]["description"] = p["description"]
            continue
        name = p.get("name") or "param"
        sch = _schema(spec, p.get("schema", {})) if "schema" in p else {k: p[k] for k in ("type", "enum", "maxLength", "pattern") if k in p}
        desc = " ".join(x for x in (p.get("x-ms-summary"), p.get("description")) if x)
        if desc:
            sch["description"] = desc
        sch["x-in"] = p.get("in")
        props[name] = sch
        if p.get("required"):
            required.append(name)
    rb = _resolve(spec, op.get("requestBody") or {})
    if rb:  # OpenAPI 3.x
        content = rb.get("content") or {}
        media = content.get("application/json") or next(iter(content.values()), {})
        props["body"] = _schema(spec, (media or {}).get("schema", {}))
        if rb.get("description"):
            props["body"]["description"] = rb["description"]
    schema = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return schema


def _security(spec):
    """宣言されている認証方式とスコープを抜き出す。"""
    schemes = (spec.get("components") or {}).get("securitySchemes") or spec.get("securityDefinitions") or {}
    kinds, scopes, flows = set(), set(), set()
    for s in schemes.values():
        s = _resolve(spec, s)
        t = (s.get("type") or "").lower()
        if t == "oauth2":
            kinds.add("oauth2")
            if "flows" in s:  # 3.x
                for fname, f in (s.get("flows") or {}).items():
                    flows.add(fname)
                    scopes.update((f.get("scopes") or {}).keys())
            else:  # 2.0
                flows.add(s.get("flow", ""))
                scopes.update((s.get("scopes") or {}).keys())
        elif t == "apikey":
            kinds.add("api_key")
        elif t in ("http", "basic"):
            kinds.add("basic" if t == "basic" or (s.get("scheme") or "").lower() == "basic" else "http_bearer")
        elif t == "openidconnect":
            kinds.add("openid_connect")
        elif t:
            kinds.add(t)
    return sorted(kinds), sorted(scopes), sorted(x for x in flows if x)


def _server_url(spec):
    if spec.get("servers"):
        return (spec["servers"][0] or {}).get("url", "")
    if spec.get("host"):
        scheme = (spec.get("schemes") or ["https"])[0]
        return f"{scheme}://{spec['host']}{spec.get('basePath', '')}"
    return ""


def to_snapshot(spec: dict, name: str | None = None) -> dict:
    if not is_openapi(spec):
        raise OpenAPIError("OpenAPI（openapi: 3.x）または Swagger（swagger: 2.0）の仕様書ではありません")
    info = spec.get("info") or {}
    tools, used = [], set()
    for path, item in spec["paths"].items():
        item = _resolve(spec, item)
        if not isinstance(item, dict):
            continue
        for method in METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            desc = "\n".join(x for x in (op.get("summary"), op.get("description")) if x)
            tools.append({
                "name": _tool_name(method, path, op, used),
                "title": f"{method.upper()} {path}",
                "description": desc,
                "inputSchema": _params(spec, method, item, op),
                "annotations": {"readOnlyHint": method in READ_ONLY, "destructiveHint": method == "delete",
                                "x-http": f"{method.upper()} {path}",
                                **({"x-ms-visibility": op["x-ms-visibility"]} if "x-ms-visibility" in op else {})},
            })
    kinds, scopes, flows = _security(spec)
    url = _server_url(spec)
    return {
        "server": {"name": name or info.get("title") or "openapi-spec", "url": url,
                   "source": "openapi", "spec_version": spec.get("openapi") or spec.get("swagger"),
                   "api_version": info.get("version")},
        "observations": {"https": url.lower().startswith("https://") if url else None,
                         "api_auth_schemes": kinds, "api_declared_scopes": scopes, "api_oauth_flows": flows,
                         "api_info_description": info.get("description", "")},
        "tools": tools,
        "oauth": {"protected_resource": None, "authorization_server": None},
    }
