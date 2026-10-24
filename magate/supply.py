"""証拠収集（サプライチェーン）：パッケージの既知脆弱性と、実行環境（ランタイム）の情報を集める。

- パッケージ本体や依存ライブラリは一切インストール・実行しない。読むのはレジストリのメタデータと
  OSV（https://osv.dev）の脆弱性データベースだけ。
- 取得結果はスナップショットの "supply_chain" に保存する。判定（checks/supply_chain.py）は
  スナップショットだけを見るので、同じスナップショットなら何度審査しても同じ結果になる。
  脆弱性データベースは日々更新されるため、取得日時（checked_at）を必ず残す。
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import urllib.parse

from .collect import FetchError, _http

OSV = "https://api.osv.dev/v1"
NPM = "https://registry.npmjs.org"
ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI"}
MAX_PACKAGES = 1000   # OSV querybatch の上限
MAX_DETAILS = 200     # 詳細を取りに行く脆弱性の上限（大量に出たら打ち切って記録する）


def parse_spec(spec: str) -> dict:
    """'npm:@scope/name@1.2.3' / 'pypi:name==1.2.3' を分解する。"""
    m = re.fullmatch(r"(npm|pypi):(.+)", spec.strip(), re.I)
    if not m:
        raise FetchError(f"パッケージ指定の形式が違います（例：npm:@scope/name@1.2.3、pypi:name==1.2.3）: {spec}")
    eco, rest = m.group(1).lower(), m.group(2)
    if eco == "npm":
        name, _, ver = rest.rpartition("@") if rest.count("@") > rest.startswith("@") else (rest, "", "")
    else:
        name, _, ver = rest.partition("==")
    if not name:
        raise FetchError(f"パッケージ名がありません: {spec}")
    return {"ecosystem": ECOSYSTEMS[eco], "name": name, "version": ver or None}


def _json(url, method="GET", body=None):
    status, _, text = _http(url, method, json.dumps(body).encode() if body is not None else None,
                            {"Accept": "application/json", **({"Content-Type": "application/json"} if body is not None else {})})
    if status != 200:
        raise FetchError(f"HTTP {status}: {url}")
    return json.loads(text)


def npm_manifest(name: str, version: str | None) -> dict:
    """npmレジストリから、指定版（省略時は latest）の engines と依存一覧を読む。"""
    doc = _json(f"{NPM}/{urllib.parse.quote(name, safe='@')}")
    ver = version or (doc.get("dist-tags") or {}).get("latest")
    man = (doc.get("versions") or {}).get(ver)
    if not man:
        raise FetchError(f"npmに {name}@{ver} が見つかりません")
    return {"version": ver, "engines": man.get("engines") or {}, "dependencies": man.get("dependencies") or {}}


def packages_from_lockfile(path: str) -> list[dict]:
    """package-lock.json（v2/v3）から、実際に入る依存ライブラリと版数を取り出す。"""
    with open(path, encoding="utf-8") as f:
        lock = json.load(f)
    out = {}
    for key, meta in (lock.get("packages") or {}).items():
        if not key or not meta.get("version"):
            continue  # "" はルート（審査対象そのもの）
        name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
        out[(name, meta["version"])] = {"ecosystem": "npm", "name": name, "version": meta["version"]}
    return list(out.values())


def osv_query(pkgs: list[dict]) -> tuple[list[dict], bool]:
    """OSVに一括照会し、該当した脆弱性の詳細を返す。戻り値の2つ目は「上限で打ち切ったか」。"""
    pkgs = [p for p in pkgs if p.get("version")][:MAX_PACKAGES]
    if not pkgs:
        return [], False
    queries = [{"package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": p["version"]} for p in pkgs]
    res = _json(f"{OSV}/querybatch", "POST", {"queries": queries}).get("results", [])
    hits = [(p, v["id"]) for p, r in zip(pkgs, res) for v in (r.get("vulns") or [])]
    truncated = len(hits) > MAX_DETAILS
    details = {}
    for _, vid in hits[:MAX_DETAILS]:
        if vid not in details:
            details[vid] = _json(f"{OSV}/vulns/{urllib.parse.quote(vid)}")
    return [_summarize(details[vid], p) for p, vid in hits[:MAX_DETAILS]], truncated


def _summarize(v: dict, pkg: dict) -> dict:
    fixed = sorted({e["fixed"] for a in v.get("affected", [])
                    if (a.get("package") or {}).get("name") == pkg["name"]
                    for r in a.get("ranges", []) for e in r.get("events", []) if "fixed" in e})
    return {
        "id": v["id"], "aliases": v.get("aliases", []), "summary": (v.get("summary") or "")[:200],
        "severity": ((v.get("database_specific") or {}).get("severity") or "").upper() or None,
        "package": pkg["name"], "ecosystem": pkg["ecosystem"], "version": pkg["version"], "fixed": fixed,
    }


def fetch_supply_chain(spec: str | None = None, lockfile: str | None = None) -> dict:
    """--package / --lockfile の指定から supply_chain を作る。"""
    sc: dict = {"package": None, "engines": {}, "vulns": [], "truncated": False, "sources": ["osv.dev"],
                "checked_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")}
    pkgs: list[dict] = []
    if spec:
        p = parse_spec(spec)
        if p["ecosystem"] == "npm":
            man = npm_manifest(p["name"], p["version"])
            p["version"], sc["engines"] = man["version"], man["engines"]
            sc["sources"].append("registry.npmjs.org")
        sc["package"] = p
        pkgs.append(p)
    if lockfile:
        pkgs += packages_from_lockfile(lockfile)
        sc["lockfile"] = True
    sc["packages_checked"] = len(pkgs)
    sc["vulns"], sc["truncated"] = osv_query(pkgs)
    return sc
