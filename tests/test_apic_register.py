"""Azure API Center への登録（integrations/azure-api-center/register.py）のテスト。Azure には接続しない。"""
import contextlib
import importlib.util
import io
import os
import unittest
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_spec = importlib.util.spec_from_file_location(
    "apic_register", os.path.join(ROOT, "integrations", "azure-api-center", "register.py"))
reg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(reg)


class TestRegister(unittest.TestCase):
    def test_body_is_pending_mcp(self):
        b = reg.build_body("https://learn.microsoft.com/api/mcp", "Microsoft Learn MCP")["properties"]
        self.assertEqual(b["kind"], "mcp")   # Functions は種別 mcp だけを審査する
        self.assertEqual(b["customProperties"], {"magate-target-url": "https://learn.microsoft.com/api/mcp",
                                                 "magate-verdict": "未審査"})

    def test_api_id(self):
        self.assertEqual(reg.make_api_id("Microsoft Learn MCP", "https://x"), "microsoft-learn-mcp")
        self.assertEqual(reg.make_api_id("特許検索", "https://patent.example.co.jp/mcp"), "patent-example-co-jp")

    def test_guard_note_uses_functions_default(self):
        """手元で許可設定にしていても、Functions の既定（拒否）で判定して表示する。"""
        with mock.patch.dict(os.environ, {"MAGATE_ALLOW_PRIVATE": "1"}):
            self.assertIn("停止", reg.guard_note("http://169.254.169.254/latest/meta-data/"))
            self.assertEqual(os.environ["MAGATE_ALLOW_PRIVATE"], "1")   # 元に戻す
        self.assertIn("通過", reg.guard_note("https://8.8.8.8/mcp"))

    def test_dry_run_without_az(self):
        out = io.StringIO()
        with mock.patch.object(reg.shutil, "which", return_value=None), contextlib.redirect_stdout(out):
            self.assertEqual(reg.main(["--url", "http://169.254.169.254/latest/meta-data/",
                                       "--title", "SSRF test", "--dry-run"]), 0)
        text = out.getvalue()
        self.assertIn("ssrf-test", text)
        self.assertIn("az rest --method put", text)

    def test_rejects_bad_api_id(self):
        with self.assertRaises(SystemExit):
            reg.main(["--url", "https://x.example/mcp", "--api-id", "bad id!", "--dry-run"])


if __name__ == "__main__":
    unittest.main()
