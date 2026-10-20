"""Azure API Center 連携（integrations/azure-api-center/writeback.py）の変換処理のテスト。"""
import importlib.util
import json
import os
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_spec = importlib.util.spec_from_file_location(
    "apic_writeback", os.path.join(ROOT, "integrations", "azure-api-center", "writeback.py"))
wb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wb)


def _result(verdict, conditions=(), blockers=(), items=()):
    return {"verdict": verdict, "conditions": list(conditions), "blockers": list(blockers), "items": list(items)}


class TestToCustomProperties(unittest.TestCase):
    def test_conditional(self):
        r = _result("条件付き許可", ["保持期間を確認すること", "地域を確認すること"],
                    items=[{"status": "WARN", "asi": ["ASI04", "ASI06"]},
                           {"status": "OK", "asi": ["ASI01"]},
                           {"status": "FAIL", "asi": ["ASI02", "ASI04"]},
                           {"status": "UNKNOWN", "asi": ["ASI08", "ASI10"]}])
        p = wb.to_custom_properties(r, reviewed_at="2026-10-20")
        self.assertEqual(p["magate-verdict"], "条件付き許可")
        self.assertEqual(p["magate-conditions"], "1. 保持期間を確認すること / 2. 地域を確認すること")
        self.assertEqual(p["magate-reviewed-at"], "2026-10-20")
        # 状態ごとに分けて記録し、OK の項目は含めない
        self.assertEqual(p["magate-owasp"], "NG: ASI02, ASI04 / 要対応: ASI04, ASI06 / 未確認: ASI08, ASI10")

    def test_deny_puts_blockers_first(self):
        p = wb.to_custom_properties(_result("不可", ["条件A"], ["ポイズニングを検出"]))
        self.assertEqual(p["magate-conditions"], "1. 【不可の理由】ポイズニングを検出 / 2. 条件A")
        self.assertEqual(p["magate-owasp"], "該当なし")

    def test_permit_without_conditions(self):
        self.assertEqual(wb.to_custom_properties(_result("許可"))["magate-conditions"], "なし")

    def test_rejects_non_magate_json(self):
        with self.assertRaises(ValueError):
            wb.to_custom_properties({"tools": []})

    def test_shorthand_quotes_values(self):
        s = wb.to_shorthand({"magate-verdict": "許可", "magate-conditions": "1. a, b: c / it's"})
        self.assertEqual(s, "{magate-verdict:'許可',magate-conditions:'1. a, b: c / it’s'}")

    def test_real_audit_result(self):
        """実在サーバのスナップショットを審査した結果がそのまま変換できること。"""
        from magate.collect import load_snapshot
        from magate.report import to_json
        from magate.rubric import evaluate
        snap = load_snapshot(os.path.join(ROOT, "research", "2026-10-remote-mcp", "snaps", "microsoft-learn.json"))
        res = json.loads(to_json(evaluate(snap, {}, [], None)))
        p = wb.to_custom_properties(res)
        self.assertIn(p["magate-verdict"], {"許可", "条件付き許可", "不可"})
        self.assertTrue(p["magate-conditions"].startswith("1. "))


if __name__ == "__main__":
    unittest.main()
