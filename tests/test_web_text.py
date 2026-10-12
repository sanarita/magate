"""ブラウザ版の文面：CLIのコマンドではなく、画面の操作を案内すること。"""
import json
import os
import unittest

from magate.web import run

HERE = os.path.dirname(__file__)
S = lambda n: os.path.join(HERE, "..", "samples", n)


def read(n):
    with open(S(n), encoding="utf-8") as f:
        return f.read()


class TestBrowserWording(unittest.TestCase):
    def test_no_cli_command_without_pin(self):
        out = run(read("patent_poisoned.json"), read("questionnaire_patent.json"))
        text = json.dumps(out["result"], ensure_ascii=False) + out["markdown"]
        self.assertNotIn("magate pin", text)
        self.assertNotIn("`pin`", text)
        rug = [f for it in out["result"]["items"] for f in it["findings"] if f["threat"] == "rug_pull"]
        self.assertEqual([(f["status"], "承認用に定義を固定（.pin.json）" in f["message"]) for f in rug], [("OK", True)])
        self.assertEqual(out["result"]["threats"]["rug_pull"], "OK")
        self.assertNotIn("verified_by_human", text)
