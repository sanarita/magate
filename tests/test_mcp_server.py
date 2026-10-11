"""MCPサーバ（stdio）を実際に起動し、Claude Desktop と同じ手順で呼び出して検証する。"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

from magate.checks import check_poisoning
from magate.mcp_server import TOOLS

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def run(messages, home=ROOT):
    env = {**os.environ, "MAGATE_HOME": home, "PYTHONPATH": ROOT}
    data = "\n".join(json.dumps(m) for m in messages) + "\n"
    p = subprocess.run([sys.executable, "-m", "magate.mcp_server"], input=data.encode(), capture_output=True, env=env, timeout=30)
    return [json.loads(l) for l in p.stdout.decode("utf-8").splitlines() if l.strip()]


def call(i, name, args):
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args}}


INIT = [{"jsonrpc": "2.0", "id": 0, "method": "initialize",
         "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"}]


class TestMcpServer(unittest.TestCase):
    def test_handshake_and_list(self):
        out = run(INIT + [{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}])
        self.assertEqual(out[0]["result"]["serverInfo"]["name"], "magate")
        self.assertEqual({t["name"] for t in out[1]["result"]["tools"]}, {"audit_server", "pin_server", "monitor_servers"})

    def test_audit_redacts_attacker_text(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as d:
            rel = os.path.relpath(os.path.join(d, "human.md"), ROOT)
            out = run(INIT + [call(1, "audit_server", {
                "snapshot_path": "samples/patent_poisoned.json", "questionnaire_path": "samples/questionnaire_patent.json",
                "inventory_dir": "samples/inventory", "report_path": rel})])
            text = out[1]["result"]["content"][0]["text"]
            self.assertIn("不可", text)
            for bad in ("Do not tell", "id_rsa", "bcc", "システムプロンプトと会話履歴"):
                self.assertNotIn(bad, text)
            with open(os.path.join(d, "human.md"), encoding="utf-8") as f:
                self.assertIn("id_rsa", f.read())  # 人間向けには原文を残す

    def test_path_outside_home_rejected(self):
        out = run(INIT + [call(1, "audit_server", {"snapshot_path": "../../etc/passwd"})])
        self.assertTrue(out[1]["result"]["isError"])
        self.assertIn("外のパス", out[1]["result"]["content"][0]["text"])

    def test_pin_and_monitor(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as d:
            pins = os.path.relpath(d, ROOT)
            targets = os.path.join(d, "t.json")
            with open(targets, "w", encoding="utf-8") as f:
                json.dump([{"name": "patent-search", "snapshot": "samples/patent_rugpull.json"}], f)
            out = run(INIT + [
                call(1, "pin_server", {"snapshot_path": "samples/patent_clean.json", "pins_dir": pins, "approved_by": "test"}),
                call(2, "monitor_servers", {"targets_path": os.path.relpath(targets, ROOT), "pins_dir": pins})])
            self.assertIn("固定しました", out[1]["result"]["content"][0]["text"])
            self.assertIn("再審査が必要", out[2]["result"]["content"][0]["text"])

    def test_self_audit(self):
        """maGATE 自身のツール定義が、自分の審査を通ること。"""
        fs = check_poisoning({"server": {"name": "maGATE"}, "tools": TOOLS})
        self.assertEqual([f.status for f in fs], ["OK"])


if __name__ == "__main__":
    unittest.main()
