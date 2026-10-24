"""サプライチェーンのチェック（既知脆弱性・実行環境の版数）。

ネットワークには出ない：OSV・npmレジストリ・MCPサーバはすべてローカルの模擬サーバで代用する。
題材は2026年10月の Node2Shell（CVE-2026-111497）と PHP2Shell（CVE-2026-109618/109619）。
"""
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from magate import supply
from magate.checks.supply_chain import check_supply_chain
from magate.collect import FetchError, fetch_http, load_snapshot
from magate.model import FAIL, OK, UNKNOWN, WARN
from magate.rubric import DENY, evaluate

HERE = os.path.dirname(__file__)
S = lambda n: os.path.join(HERE, "..", "samples", n)


def q():
    with open(S("questionnaire_patent.json"), encoding="utf-8") as f:
        return json.load(f)


def vuln(sev="MODERATE", aliases=("CVE-2026-000001",), fixed=("1.2.4",)):
    return {"id": "GHSA-test-0001", "aliases": list(aliases), "summary": "test", "severity": sev,
            "package": "mcp-sample", "ecosystem": "npm", "version": "1.2.3", "fixed": list(fixed)}


def sc(vulns=(), engines=None):
    return {"package": {"ecosystem": "npm", "name": "mcp-sample", "version": "1.2.3"},
            "engines": engines if engines is not None else {"node": ">=22.23.4"},
            "vulns": list(vulns), "packages_checked": 1, "checked_at": "2026-10-24T00:00:00+00:00"}


def statuses(fs):
    return [f.status for f in fs]


class TestParseSpec(unittest.TestCase):
    def test_variants(self):
        self.assertEqual(supply.parse_spec("npm:@scope/name@1.2.3"), {"ecosystem": "npm", "name": "@scope/name", "version": "1.2.3"})
        self.assertEqual(supply.parse_spec("npm:@scope/name")["version"], None)
        self.assertEqual(supply.parse_spec("npm:name@2.0.0")["name"], "name")
        self.assertEqual(supply.parse_spec("pypi:brotlicffi==1.1.0"), {"ecosystem": "PyPI", "name": "brotlicffi", "version": "1.1.0"})
        with self.assertRaises(FetchError):
            supply.parse_spec("maven:x")


class TestKnownVulns(unittest.TestCase):
    def test_none_is_ok_with_timestamp(self):
        fs = check_supply_chain({"supply_chain": sc()})
        self.assertEqual(statuses(fs), [OK])
        self.assertIn("2026-10-24", fs[0].message)

    def test_moderate_is_warn_with_fix_condition(self):
        fs = check_supply_chain({"supply_chain": sc([vuln()])})
        self.assertEqual(statuses(fs), [WARN])
        self.assertIn("1.2.4 以上に更新", fs[0].condition)

    def test_critical_is_fail(self):
        self.assertEqual(statuses(check_supply_chain({"supply_chain": sc([vuln("CRITICAL")])})), [FAIL])

    def test_exploited_overrides_severity(self):
        """重大度が低くても、悪用確認済み（CVE別名で一致）なら不可。KEV掲載前の情報を手で足せる。"""
        fs = check_supply_chain({"supply_chain": sc([vuln("LOW", aliases=["CVE-2026-109618"])])}, exploited=["cve-2026-109618"])
        self.assertEqual(statuses(fs), [FAIL])
        self.assertIn("悪用が確認されている", fs[0].message)

    def test_no_fix_yet(self):
        fs = check_supply_chain({"supply_chain": sc([vuln(fixed=())])})
        self.assertIn("修正版が未公開", fs[0].condition)


class TestNodeRuntime(unittest.TestCase):
    def test_eol_line_allowed_is_warn(self):
        fs = check_supply_chain({"supply_chain": sc(engines={"node": ">=20"})})
        self.assertEqual(statuses(fs), [WARN])
        self.assertIn("Node2Shell", fs[0].condition)

    def test_supported_line_is_ok(self):
        for rng in (">=22.23.4", "^24.22.1", ">=26"):
            self.assertEqual(statuses(check_supply_chain({"supply_chain": sc(engines={"node": rng})})), [OK], rng)

    def test_missing_engines_is_unknown(self):
        self.assertEqual(statuses(check_supply_chain({"supply_chain": sc(engines={})})), [UNKNOWN])


class TestPhpHeader(unittest.TestCase):
    def _snap(self, xpb):
        return {"observations": {"x_powered_by": xpb}}

    def test_unpatched_php2shell_is_fail(self):
        fs = check_supply_chain(self._snap("PHP/8.4.20"))
        self.assertEqual(statuses(fs), [FAIL, WARN])
        self.assertIn("8.4.27", fs[0].message)

    def test_patched_only_warns_about_exposure(self):
        self.assertEqual(statuses(check_supply_chain(self._snap("PHP/8.4.27"))), [WARN])

    def test_eol_branch_is_fail(self):
        fs = check_supply_chain(self._snap("PHP/7.4.33"))
        self.assertEqual(fs[0].status, FAIL)
        self.assertIn("サポート終了", fs[0].message)


class TestRubricIntegration(unittest.TestCase):
    def test_without_evidence_stays_seven_items(self):
        """--package を使わない従来の審査は、結果が変わらないこと。"""
        res = evaluate(load_snapshot(S("patent_clean.json")), q())
        self.assertEqual(len(res.items), 7)

    def test_critical_vuln_denies(self):
        snap = load_snapshot(S("patent_clean.json"))
        snap["supply_chain"] = sc([vuln("CRITICAL")])
        res = evaluate(snap, q())
        self.assertEqual(len(res.items), 8)
        self.assertEqual(res.items[-1].status, FAIL)
        self.assertEqual(res.verdict, DENY)


# ---------- 収集（模擬サーバ） ----------
VULN_DETAIL = {"id": "GHSA-test-0001", "aliases": ["CVE-2026-000001"], "summary": "Brotli decoder OOB write",
               "database_specific": {"severity": "HIGH"},
               "affected": [{"package": {"name": "mcp-sample", "ecosystem": "npm"},
                             "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.4"}]}]}]}


class Mock(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def version_string(self):
        return "nginx"

    def _send(self, body, headers=()):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def do_GET(self):
        if self.path == "/npm/mcp-sample":
            self._send({"dist-tags": {"latest": "1.2.3"},
                        "versions": {"1.2.3": {"engines": {"node": ">=20"}, "dependencies": {"left-pad": "^1.0.0"}}}})
        elif self.path == "/osv/vulns/GHSA-test-0001":
            self._send(VULN_DETAIL)
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/osv/querybatch":
            self._send({"results": [{"vulns": [{"id": "GHSA-test-0001"}]} if x["package"]["name"] == "mcp-sample" else {}
                                    for x in msg["queries"]]})
        elif self.path == "/mcp" and msg.get("method") == "initialize":
            self._send({"jsonrpc": "2.0", "id": msg["id"], "result": {"serverInfo": {"name": "m"}}},
                       headers=[("X-Powered-By", "PHP/8.3.30")])
        elif self.path == "/mcp" and "id" in msg:
            self._send({"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": []}})
        else:
            self.send_response(202); self.end_headers()


class TestCollect(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Mock)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_package_and_lockfile(self):
        lock = {"lockfileVersion": 3, "packages": {"": {"name": "app"},
                "node_modules/mcp-sample": {"version": "1.2.3"}, "node_modules/left-pad": {"version": "1.3.0"}}}
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(supply, "NPM", self.base + "/npm"), mock.patch.object(supply, "OSV", self.base + "/osv"):
            path = os.path.join(d, "package-lock.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(lock, f)
            got = supply.fetch_supply_chain("npm:mcp-sample", path)
        self.assertEqual(got["package"]["version"], "1.2.3")          # latest を解決
        self.assertEqual(got["engines"], {"node": ">=20"})
        self.assertEqual(got["packages_checked"], 3)
        self.assertEqual({v["severity"] for v in got["vulns"]}, {"HIGH"})
        self.assertEqual(got["vulns"][0]["fixed"], ["1.2.4"])
        fs = check_supply_chain({"supply_chain": got})
        self.assertIn(FAIL, statuses(fs))   # HIGH
        self.assertIn(WARN, statuses(fs))   # engines.node >=20

    def test_response_headers_are_recorded(self):
        snap = fetch_http(self.base + "/mcp")
        self.assertEqual(snap["observations"]["x_powered_by"], "PHP/8.3.30")
        self.assertEqual(snap["observations"]["server_header"], "nginx")
        self.assertEqual(check_supply_chain(snap)[0].status, FAIL)   # 8.3.36 未満


if __name__ == "__main__":
    unittest.main()
