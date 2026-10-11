"""ブラウザ版（GitHub Pages 用）の docs/index.html を生成する。

mcpgate のうちネットワークを使わないモジュールだけを HTML に埋め込む。
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

from mcpgate import __version__  # noqa: E402
from mcpgate.checks.rugpull import save_pin  # noqa: E402

# ブラウザ版に含めるモジュール（collect / cli / mcp_server / policy_agent は通信を伴うため含めない）
MODULES = [
    "mcpgate/__init__.py", "mcpgate/hashing.py", "mcpgate/model.py", "mcpgate/rubric.py",
    "mcpgate/report.py", "mcpgate/web.py", "mcpgate/openapi.py",
    "mcpgate/checks/__init__.py", "mcpgate/checks/text.py", "mcpgate/checks/poisoning.py",
    "mcpgate/checks/shadowing.py", "mcpgate/checks/rugpull.py", "mcpgate/checks/auth.py", "mcpgate/checks/scopes.py",
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
            .replace("__MCPGATE_SOURCES__", _embed(sources))
            .replace("__MCPGATE_SAMPLES__", _embed(samples))
            .replace("__MCPGATE_VERSION__", __version__)
            .replace("__GITHUB_REPO__", repo))
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="sanarita/mcp-gate", help="フッターに表示するGitHubリポジトリ")
    ap.add_argument("--out", default=os.path.join(ROOT, "docs", "index.html"))
    a = ap.parse_args()
    print("生成:", build(a.repo, a.out))
