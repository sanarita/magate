"""docs/index.html に埋め込んだソースだけで審査が動くこと（Pyodide の環境を模擬）を確認する。

- 埋め込みソースを空のフォルダに展開し、隔離モードの Python で読み込む
- urllib.request / socket / http / ssl / subprocess の読み込みを禁止し、通信系を一切使わないことを保証する
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HTML = os.path.join(ROOT, "docs", "index.html")

PROBE = r'''
import sys, json
class Block:
    BANNED = ("urllib.request", "socket", "http", "subprocess", "ssl")  # urllib.parse は文字列処理のみなので許可
    def find_spec(self, name, path=None, target=None):
        if name in self.BANNED or name.split(".")[0] in ("socket", "http", "subprocess", "ssl"):
            raise ImportError("blocked in browser build: " + name)
sys.meta_path.insert(0, Block())
sys.path.insert(0, sys.argv[1])
import mcpgate.web as w
s = json.loads(open(sys.argv[2], encoding="utf-8").read())
out = json.loads(w.run_json(json.dumps(s["poisoned"]), json.dumps(s["questionnaire"]), json.dumps([json.dumps(s["inventory"])])))
ok = json.loads(w.run_json(json.dumps(s["clean"]), json.dumps(s["questionnaire"]), "[]", json.dumps(s["pin"])))
rug = json.loads(w.run_json(json.dumps(s["rugpull"]), json.dumps(s["questionnaire"]), "[]", json.dumps(s["pin"])))
print(json.dumps([out["result"]["verdict"], ok["result"]["verdict"], rug["result"]["verdict"], "id_rsa" in out["markdown"]]))
'''


def _embedded(html, element_id):
    m = re.search(rf'<script type="application/json" id="{element_id}">(.*?)</script>', html, re.S)
    return json.loads(m.group(1))


class TestWebBundle(unittest.TestCase):
    def test_bundle_runs_without_network_modules(self):
        if not os.path.exists(HTML):
            self.skipTest("docs/index.html 未生成（python tools/build_web.py を実行）")
        with open(HTML, encoding="utf-8") as f:
            html = f.read()
        sources, samples = _embedded(html, "py-sources"), _embedded(html, "samples")
        with tempfile.TemporaryDirectory() as d:
            for rel, code in sources.items():
                os.makedirs(os.path.join(d, os.path.dirname(rel)), exist_ok=True)
                with open(os.path.join(d, rel), "w", encoding="utf-8") as f:
                    f.write(code)
            sp = os.path.join(d, "samples.json")
            with open(sp, "w", encoding="utf-8") as f:
                json.dump(samples, f, ensure_ascii=False)
            p = subprocess.run([sys.executable, "-I", "-c", PROBE, d, sp], capture_output=True, text=True, cwd=d)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout), ["不可", "許可", "不可", True])

    def test_bundle_is_in_sync_with_source(self):
        if not os.path.exists(HTML):
            self.skipTest("docs/index.html 未生成")
        with open(HTML, encoding="utf-8") as f:
            sources = _embedded(f.read(), "py-sources")
        for rel, code in sources.items():
            with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
                self.assertEqual(f.read(), code, f"{rel} が古いままです。python tools/build_web.py を再実行してください")


if __name__ == "__main__":
    unittest.main()
