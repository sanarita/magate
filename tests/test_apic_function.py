"""Azure Functions 版（integrations/azure-api-center/function_app）の審査ループのテスト。"""
import importlib.util
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FUNC = os.path.join(ROOT, "integrations", "azure-api-center", "function_app")


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(FUNC, f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


reviewer = _load("reviewer")
apic_client = _load("apic_client")

RESULT = {"verdict": "条件付き許可", "conditions": ["保持期間を確認すること"], "blockers": [],
          "items": [{"status": "WARN", "asi": ["ASI03"]}]}


def _api(name, kind="mcp", **cp):
    return {"name": name, "properties": {"title": name, "kind": kind, "customProperties": cp}}


class FakeClient:
    def __init__(self, apis, urls):
        self.apis, self.urls, self.updates = apis, urls, {}

    def list_apis(self):
        return self.apis

    def runtime_url(self, name):
        return self.urls.get(name)

    def update_custom_properties(self, name, new):
        self.updates[name] = new


class TestRunOnce(unittest.TestCase):
    def test_reviews_only_pending_mcp(self):
        c = FakeClient([_api("new-mcp"), _api("pending", **{"magate-verdict": "未審査"}),
                        _api("done", **{"magate-verdict": "許可"}), _api("petstore", kind="rest")],
                       {"new-mcp": "https://a/mcp", "pending": "https://b/mcp"})
        seen = []
        log = reviewer.run_once(c, audit=lambda url, name=None: seen.append(url) or RESULT, today="2026-10-20")
        self.assertEqual(seen, ["https://a/mcp", "https://b/mcp"])  # 審査済み・REST は対象外
        self.assertEqual(c.updates["new-mcp"]["magate-verdict"], "条件付き許可")
        self.assertEqual(c.updates["new-mcp"]["magate-reviewed-at"], "2026-10-20")
        self.assertEqual(log, ["new-mcp: 条件付き許可", "pending: 条件付き許可"])

    def test_fetch_failure_is_recorded_and_not_retried_same_day(self):
        def fail(url, name=None):
            raise ConnectionError("401 Unauthorized")
        c = FakeClient([_api("oauth")], {"oauth": "https://c/mcp"})
        reviewer.run_once(c, audit=fail, today="2026-10-20")
        u = c.updates["oauth"]
        self.assertEqual(u["magate-verdict"], "未審査")
        self.assertTrue(u["magate-conditions"].startswith(reviewer.FETCH_FAILED))
        # 同じ日の次の実行では再試行しない
        c2 = FakeClient([_api("oauth", **u)], {"oauth": "https://c/mcp"})
        self.assertEqual(reviewer.run_once(c2, audit=fail, today="2026-10-20"), ["未審査のMCPサーバはありません"])

    def test_blocked_url_gets_its_own_message(self):
        """関所で止めた場合は「認証情報を指定して」ではなく、URLの確認を促す（誤解を防ぐ）。"""
        from magate.collect import BlockedFetch

        def blocked(url, name=None):
            from magate.netguard import HINT
            raise BlockedFetch(f"公開されていないアドレスには接続しません: 169.254.169.254（169.254.169.254）。{HINT}")
        c = FakeClient([_api("ssrf-test")], {"ssrf-test": "http://169.254.169.254/latest/meta-data/"})
        log = reviewer.run_once(c, audit=blocked, today="2026-10-24")
        note = c.updates["ssrf-test"]["magate-conditions"]
        self.assertTrue(note.startswith(reviewer.FETCH_FAILED))   # 同じ日の再試行防止はそのまま効く
        self.assertIn("関所で停止", note)
        self.assertIn("登録者に確認", note)
        self.assertNotIn("認証情報", note)
        self.assertEqual(note.count("MAGATE_ALLOW_PRIVATE"), 1)   # 案内は1回だけ
        self.assertIn("169.254.169.254", note)                    # 止めた宛先は残す
        self.assertEqual(log, ["ssrf-test: 関所で停止"])

    def test_real_blocked_fetch_is_classified(self):
        """実際の取得処理で止まった例外も、関所の停止として分類されること。"""
        from unittest import mock
        from magate.collect import BlockedFetch, fetch_http
        with mock.patch.dict(os.environ, {"MAGATE_ALLOW_PRIVATE": "0"}):
            with self.assertRaises(BlockedFetch) as cm:
                fetch_http("http://169.254.169.254/latest/meta-data/")
        note = reviewer.failure_note(cm.exception)
        self.assertIn("関所で停止", note)
        self.assertEqual(note.count("MAGATE_ALLOW_PRIVATE"), 1)

    def test_missing_url_and_dry_run(self):
        c = FakeClient([_api("no-url"), _api("ok")], {"ok": "https://d/mcp"})
        log = reviewer.run_once(c, audit=lambda url, name=None: RESULT, dry_run=True)
        self.assertEqual(c.updates, {})  # dry-run は書き込まない
        self.assertTrue(log[0].startswith("no-url: 審査対象URL"))

    def test_target_url_metadata_is_preferred(self):
        c = FakeClient([_api("a", **{"magate-target-url": "https://meta/mcp"})], {"a": "https://deploy/mcp"})
        seen = []
        reviewer.run_once(c, audit=lambda url, name=None: seen.append(url) or RESULT)
        self.assertEqual(seen, ["https://meta/mcp"])


class TestToday(unittest.TestCase):
    def test_default_is_japan_time(self):
        import datetime
        os.environ.pop("MAGATE_TZ", None)
        jst = datetime.timezone(datetime.timedelta(hours=9))
        self.assertEqual(reviewer.today_local(), datetime.datetime.now(jst).date().isoformat())

    def test_can_switch_to_utc(self):
        import datetime
        os.environ["MAGATE_TZ"] = "UTC"
        try:
            self.assertEqual(reviewer.today_local(), datetime.datetime.now(datetime.timezone.utc).date().isoformat())
        finally:
            os.environ.pop("MAGATE_TZ", None)


class TestClient(unittest.TestCase):
    def test_update_keeps_other_fields(self):
        class Cred:
            def get_token(self, scope):
                return type("T", (), {"token": "x"})()
        c = apic_client.ApiCenterClient("sub", "rg", "svc", "2099-01-01", credential=Cred())
        calls = []

        def fake(method, url, body=None):
            calls.append((method, url, body))
            return {"properties": {"title": "T", "kind": "mcp", "customProperties": {"other": 1, "magate-verdict": "未審査"}}}
        c._request = fake
        c.update_custom_properties("a", {"magate-verdict": "許可"})
        method, url, body = calls[-1]
        self.assertEqual((method, url), ("PUT", "/apis/a"))
        self.assertEqual(body["properties"]["kind"], "mcp")  # 種別は変えない
        self.assertEqual(body["properties"]["customProperties"], {"other": 1, "magate-verdict": "許可"})

    def test_runtime_url(self):
        c = apic_client.ApiCenterClient("s", "r", "v", "x", credential=object())
        c._request = lambda m, u, b=None: {"value": [{"properties": {"server": {"runtimeUri": ["https://e/mcp"]}}}]}
        self.assertEqual(c.runtime_url("a"), "https://e/mcp")

    def test_real_audit_function_shape(self):
        """audit_url が返す形が writeback の変換に通ること（通信なしでスナップショットから確認）。"""
        import json
        from magate.collect import load_snapshot
        from magate.report import to_json
        from magate.rubric import evaluate
        snap = load_snapshot(os.path.join(ROOT, "research", "2026-10-remote-mcp", "snaps", "microsoft-learn.json"))
        res = json.loads(to_json(evaluate(snap, {}, [], None)))
        self.assertIn(reviewer.to_custom_properties(res)["magate-verdict"], {"許可", "条件付き許可", "不可"})


if __name__ == "__main__":
    unittest.main()
