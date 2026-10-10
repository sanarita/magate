"""ローカルに模擬MCPサーバ（Streamable HTTP, SSE応答＋ページング＋OAuthメタデータ）を立てて取得処理を検証する。"""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from mcpgate.collect import fetch_http

TOOLS = [{"name": f"t{i}", "description": f"tool {i}", "inputSchema": {"type": "object"}} for i in range(3)]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        port = self.server.server_address[1]
        if self.path == "/.well-known/oauth-protected-resource/mcp":
            body = {"resource": f"http://127.0.0.1:{port}/mcp", "authorization_servers": [f"http://127.0.0.1:{port}"]}
        elif self.path == "/.well-known/oauth-authorization-server":
            body = {"issuer": f"http://127.0.0.1:{port}", "code_challenge_methods_supported": ["S256"]}
        else:
            self.send_response(404); self.end_headers(); return
        self._send(200, "application/json", json.dumps(body))

    def do_POST(self):
        msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if "id" not in msg:
            self.send_response(202); self.end_headers(); return
        if msg["method"] == "initialize":
            res = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}, "serverInfo": {"name": "mock", "version": "1"}}
            self.send_response(200)
            self.send_header("Mcp-Session-Id", "abc")
            self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": res}).encode()); return
        assert self.headers.get("Mcp-Session-Id") == "abc"
        cursor = (msg.get("params") or {}).get("cursor")
        page = TOOLS[:2] if not cursor else TOOLS[2:]
        res = {"tools": page, **({"nextCursor": "p2"} if not cursor else {})}
        sse = f"event: message\ndata: {json.dumps({'jsonrpc': '2.0', 'id': msg['id'], 'result': res})}\n\n"
        self._send(200, "text/event-stream", sse)

    def _send(self, code, ctype, text):
        self.send_response(code); self.send_header("Content-Type", ctype); self.end_headers()
        self.wfile.write(text.encode())


class TestCollect(unittest.TestCase):
    def test_fetch(self):
        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            snap = fetch_http(f"http://127.0.0.1:{srv.server_address[1]}/mcp")
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual([t["name"] for t in snap["tools"]], ["t0", "t1", "t2"])
        self.assertEqual(snap["server"]["name"], "mock")
        self.assertTrue(snap["observations"]["unauthenticated_tools_list"])
        self.assertEqual(snap["oauth"]["authorization_server"]["code_challenge_methods_supported"], ["S256"])


if __name__ == "__main__":
    unittest.main()
