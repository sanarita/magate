"""ブラウザのCORS判定を再現できているかを、設定の異なる模擬MCPサーバで確認する。"""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from magate.corsprobe import probe

ORIGIN = "https://sanarita.github.io"


def make_handler(cors=True, expose=True, allow_headers="content-type, mcp-protocol-version, mcp-session-id",
                 session=True, status=200):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _cors(self):
            if cors:
                self.send_header("Access-Control-Allow-Origin", "*")
                if expose:
                    self.send_header("Access-Control-Expose-Headers", "Mcp-Session-Id")

        def do_OPTIONS(self):
            self.send_response(204)
            if cors:
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE")
                self.send_header("Access-Control-Allow-Headers", allow_headers)
            self.end_headers()

        def do_POST(self):
            msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if status != 200:
                self.send_response(status); self._cors(); self.end_headers(); return
            if "id" not in msg:
                self.send_response(202); self._cors(); self.end_headers(); return
            if msg["method"] == "initialize":
                res = {"protocolVersion": "2025-06-18", "serverInfo": {"name": "mock"}, "capabilities": {}}
            else:
                res = {"tools": [{"name": "a"}, {"name": "b"}]}
            body = json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": res}).encode()
            self.send_response(200); self._cors()
            if session:
                self.send_header("Mcp-Session-Id", "s1")
            self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(body)
    return H


def run(**kw):
    srv = HTTPServer(("127.0.0.1", 0), make_handler(**kw))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        return probe(f"http://127.0.0.1:{srv.server_address[1]}/mcp", ORIGIN)
    finally:
        srv.shutdown(); srv.server_close()


class TestCorsProbe(unittest.TestCase):
    def test_fully_allowed(self):
        r = run()
        self.assertEqual(r["result"], "可"); self.assertEqual(r["tools"], 2)

    def test_stateless_without_session(self):
        self.assertEqual(run(session=False, expose=False)["result"], "可")

    def test_no_cors(self):
        self.assertEqual(run(cors=False)["result"], "不可（CORS）")

    def test_session_not_exposed(self):
        self.assertEqual(run(expose=False)["result"], "不可（セッションIDが読めない）")

    def test_followup_headers_not_allowed(self):
        self.assertEqual(run(allow_headers="content-type")["result"], "接続開始のみ可（2回目以降がCORSで拒否）")

    def test_wildcard_headers(self):
        self.assertEqual(run(allow_headers="*")["result"], "可")

    def test_auth_required(self):
        self.assertEqual(run(status=401)["result"], "接続可・ツール一覧は認証が必要")

    def test_unreachable(self):
        self.assertEqual(probe("http://127.0.0.1:9/mcp", ORIGIN)["result"], "不可（接続できない）")


if __name__ == "__main__":
    unittest.main()
