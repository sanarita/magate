"""ブラウザ版（GitHub Pages 用）の docs/index.html を生成する。

magate のうちネットワークを使わないモジュールだけを HTML に埋め込む。
コードを変えたら `python tools/build_web.py` を実行して docs/ をコミットする。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from magate import __version__  # noqa: E402
from magate.checks.rugpull import save_pin  # noqa: E402

# ブラウザ版に含めるモジュール（collect / cli / mcp_server / policy_agent は通信を伴うため含めない）
MODULES = [
    "magate/__init__.py", "magate/hashing.py", "magate/model.py", "magate/rubric.py",
    "magate/report.py", "magate/web.py", "magate/openapi.py", "magate/catalog.py", "magate/autofill.py",
    "magate/checks/__init__.py", "magate/checks/text.py", "magate/checks/poisoning.py",
    "magate/checks/shadowing.py", "magate/checks/rugpull.py", "magate/checks/auth.py", "magate/checks/scopes.py",
    "magate/checks/supply_chain.py", "magate/runtimes.py",
]


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def _json(rel):
    return json.loads(_read(rel))


def _embed(obj) -> str:
    # </script> で途切れないようにエスケープ（JSON として等価）
    return json.dumps(obj, ensure_ascii=False).replace("</", "<\\/")


def build(repo: str, out: str) -> str:
    sources = {m: _read(m) for m in MODULES}
    with tempfile.TemporaryDirectory() as d:
        clean = _json("samples/patent_clean.json")
        with open(save_pin(d, clean, approved_by="情報システム部（例）", note="サンプル"), encoding="utf-8") as f:
            pin = json.load(f)
    samples = {
        "clean": _json("samples/patent_clean.json"),
        "poisoned": _json("samples/patent_poisoned.json"),
        "rugpull": _json("samples/patent_rugpull.json"),
        "questionnaire": _json("samples/questionnaire_patent.json"),
        "template": _json("samples/questionnaire_template.json"),
        "inventory": _json("samples/inventory/corp-mail.json"),
        "pin": pin,
        "openapi_clean": _json("samples/openapi_patent_clean.json"),
        "openapi_poisoned": _json("samples/openapi_connector_poisoned.json"),
    }
    html = (_read("web/template.html")
            .replace("__MAGATE_SOURCES__", _embed(sources))
            .replace("__MAGATE_SAMPLES__", _embed(samples))
            .replace("__MAGATE_VERSION__", __version__)
            .replace("__GITHUB_REPO__", repo))
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="sanarita/magate", help="フッターに表示するGitHubリポジトリ")
    ap.add_argument("--out", default=os.path.join(ROOT, "docs", "index.html"))
    a = ap.parse_args()
    print("生成:", build(a.repo, a.out))
