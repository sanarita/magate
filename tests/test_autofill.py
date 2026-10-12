"""質問票の自動入力（情報カード・接続先の応答）のテスト。"""
import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import unittest

from magate.autofill import COMPANY_KEYS, DIFFERS, FILLED, LABELS, MATCHES, autofill
from magate.catalog import CARDS, find_card
from magate.report import to_markdown
from magate.rubric import evaluate
from magate.web import autofill_json, run

ROOT = os.path.join(os.path.dirname(__file__), "..")
TODAY = dt.date(2026, 10, 12)


def snap(url, tools=None, oauth=None, obs=None):
    return {"server": {"name": "t", "url": url}, "tools": tools or [{"name": "x", "description": "d"}],
            "observations": obs or {}, "oauth": oauth or {"protected_resource": None, "authorization_server": None}}


class TestCatalog(unittest.TestCase):
    def test_find_card(self):
        cases = {
            "https://learn.microsoft.com/api/mcp": "microsoft-learn",
            "https://mcp.svc.cloud.microsoft/enterprise": "microsoft-mcp-enterprise",
            "https://api.githubcopilot.com/mcp/": "github",
            "https://api.githubcopilot.com/mcp/readonly": "github",
            "https://copilot-api.acme.ghe.com/mcp": "github",
            "https://mcp.atlassian.com/v2/mcp": "atlassian",
            "https://mcp.box.com": "box",
        }
        for url, cid in cases.items():
            self.assertEqual((find_card(url) or {}).get("id"), cid, url)

    def test_no_card(self):
        for url in ("https://learn.microsoft.com/ja-jp/", "https://evil-mcp.box.com.example/", "https://mcp.example.com/mcp", "", None):
            self.assertIsNone(find_card(url), url)

    def test_cards_are_well_formed(self):
        """値には必ず根拠URLがあり、自社が決める項目・人の確認済みフラグは含まない。"""
        for c in CARDS:
            dt.date.fromisoformat(c["checked"])
            for key, a in c["answers"].items():
                self.assertIn(key, LABELS, (c["id"], key))
                self.assertNotIn(key, COMPANY_KEYS, (c["id"], key))
                self.assertTrue(a["source"].startswith("https://"), (c["id"], key))
            for n in c.get("notes", []):
                self.assertTrue(n["source"].startswith("https://"), c["id"])


class TestAutofill(unittest.TestCase):
    def test_fills_only_empty_provider_fields(self):
        q = {"data": {"allowed_classification": "internal"}, "operator": {"verified_by_human": False}}
        out, info = autofill(snap("https://mcp.svc.cloud.microsoft/enterprise"), q, today=TODAY)
        self.assertEqual(out["operator"]["name"], "Microsoft Corporation")
        self.assertIs(out["audit"]["server_side_audit_log"], True)
        self.assertIs(out["operator"]["verified_by_human"], False)       # 人の確認は自動で立てない
        self.assertEqual(out["data"], {"allowed_classification": "internal"})  # 自社の項目は触らない
        self.assertNotIn("token_passthrough", out.get("auth", {}))
        self.assertTrue(all(x["status"] == FILLED for x in info["items"]))
        self.assertFalse(info["card"]["stale"])
        self.assertEqual(q["data"], {"allowed_classification": "internal"})  # 元の質問票は変更しない
        self.assertNotIn("name", q.get("operator", {}))

    def test_keeps_human_answer_and_records_difference(self):
        q = {"operator": {"name": "Microsoft Corporation"}, "auth": {"method": "api_key"}}
        out, info = autofill(snap("https://mcp.svc.cloud.microsoft/enterprise"), q, today=TODAY)
        self.assertEqual(out["auth"]["method"], "api_key")
        st = {x["key"]: x["status"] for x in info["items"]}
        self.assertEqual(st["operator.name"], MATCHES)
        self.assertEqual(st["auth.method"], DIFFERS)

    def test_check_only_mode(self):
        q = {"operator": {"name": "Box, Inc."}}
        out, info = autofill(snap("https://mcp.box.com"), q, fill=False, today=TODAY)
        self.assertEqual(out, q)
        self.assertEqual([x["key"] for x in info["items"]], ["operator.name"])

    def test_stale_card(self):
        _, info = autofill(snap("https://mcp.box.com"), {}, today=TODAY + dt.timedelta(days=181))
        self.assertTrue(info["card"]["stale"])

    def test_derived_from_snapshot_without_card(self):
        s = snap("https://mcp.example.com/mcp", oauth={"protected_resource": {"resource": "x"}, "authorization_server": None})
        out, info = autofill(s, {}, today=TODAY)
        self.assertEqual(out["auth"]["method"], "oauth2.1")
        self.assertNotIn("card", info)
        s = snap("https://mcp.example.com/mcp", obs={"unauthenticated_tools_list": True})
        self.assertEqual(autofill(s, {})[0]["auth"]["method"], "none")

    def test_unknown_server_returns_nothing(self):
        out, info = autofill(snap("https://mcp.example.com/mcp"), {}, today=TODAY)
        self.assertEqual((out, info), ({}, {}))


class TestReportAndEntrances(unittest.TestCase):
    def test_report_section(self):
        s = snap("https://mcp.atlassian.com/v2/mcp")
        q, info = autofill(s, {}, today=TODAY)
        md = to_markdown(evaluate(s, q, autofill=info))
        self.assertIn("## 提供元の公開情報（情報カード：Atlassian Rovo MCP Server、確認日 2026-10-12）", md)
        self.assertIn("| 運営主体 | Atlassian | 自動入力 |", md)
        self.assertIn("補足（提供元の公開情報）", md)

    def test_browser_button_and_review(self):
        s = snap("https://mcp.box.com")
        out = json.loads(autofill_json(json.dumps(s), json.dumps({"operator": {"name": None}})))
        self.assertTrue(out["ok"])
        self.assertEqual(out["questionnaire"]["operator"]["name"], "Box, Inc.")
        res = run(json.dumps(s), json.dumps(out["questionnaire"]))
        self.assertTrue(all(x["status"] == MATCHES for x in res["result"]["autofill"]["items"]))
        self.assertIn("提供元の公開情報", res["markdown"])
        # 審査時は空欄を勝手に埋めない（画面の表示と結果がずれないように）
        res = run(json.dumps(s), "{}")
        self.assertEqual(res["result"]["autofill"]["items"], [])

    def test_cli_autofill_and_opt_out(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(snap("https://mcp.box.com"), f)
            env = {**os.environ, "PYTHONPATH": ROOT, "PYTHONIOENCODING": "utf-8"}
            def audit(*extra):
                r = subprocess.run([sys.executable, "-m", "magate", "audit", "--snapshot", p, "--json", *extra],
                                   capture_output=True, env=env, timeout=60)
                return json.loads(r.stdout.decode("utf-8"))
            on = audit()
            self.assertEqual(on["autofill"]["items"][0]["status"], FILLED)
            self.assertNotIn("運営主体が未記入です", json.dumps(on, ensure_ascii=False))
            off = audit("--no-autofill")
            self.assertEqual(off["autofill"]["items"], [])
            self.assertIn("運営主体が未記入です", json.dumps(off, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
