"""通信の関所（SSRF対策）のテスト。

本番の既定（MAGATE_ALLOW_PRIVATE なし）で、公開されていないアドレスへの通信が止まることを確かめる。
実際に外部へは接続しない（IPアドレスの直書き・名前解決の差し替え・127.0.0.1 の模擬サーバのみ）。
"""
import os
import socket
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from magate import collect, netguard
from magate.collect import FetchError, _http, fetch_oauth
from magate.netguard import BlockedURL, check_url, derived_url_ok

DENY = {netguard.ENV: "0"}
ALLOW = {netguard.ENV: "1"}


class TestCheckUrl(unittest.TestCase):
    def test_blocks_non_public_addresses(self):
        with mock.patch.dict(os.environ, DENY):
            for url in ["http://127.0.0.1/", "http://localhost:8080/", "http://10.0.0.5/", "http://192.168.1.1/",
                        "http://172.16.0.1/", "http://169.254.169.254/latest/meta-data/",  # クラウドの管理用エンドポイント
                        "http://100.64.0.1/", "http://0.0.0.0/", "http://[::1]/", "http://[fd00::1]/",
                        "http://[::ffff:127.0.0.1]/", "http://224.0.0.1/"]:
                with self.assertRaises(BlockedURL, msg=url):
                    check_url(url)

    def test_allows_public_address(self):
        with mock.patch.dict(os.environ, DENY):
            check_url("https://8.8.8.8/mcp")
            check_url("https://[2001:4860:4860::8888]/mcp")

    def test_hostname_resolving_to_private_is_blocked(self):
        """公開されていそうな名前でも、名前解決の結果が社内アドレスなら止める。"""
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 443))]
        with mock.patch.dict(os.environ, DENY), mock.patch("socket.getaddrinfo", return_value=fake):
            with self.assertRaises(BlockedURL) as cm:
                check_url("https://mcp.example.com/mcp")
        self.assertIn("10.1.2.3", str(cm.exception))

    def test_any_private_record_blocks(self):
        """複数のアドレスが返ったとき、1つでも社内アドレスなら止める。"""
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with mock.patch.dict(os.environ, DENY), mock.patch("socket.getaddrinfo", return_value=fake):
            with self.assertRaises(BlockedURL):
                check_url("https://mixed.example.com/")

    def test_scheme_is_always_checked(self):
        with mock.patch.dict(os.environ, ALLOW):
            for url in ["file:///etc/passwd", "ftp://example.com/", "gopher://127.0.0.1/"]:
                with self.assertRaises(BlockedURL, msg=url):
                    check_url(url)

    def test_allow_private_opt_in(self):
        with mock.patch.dict(os.environ, ALLOW):
            check_url("http://10.0.0.5/mcp")

    def test_cli_message_keeps_hint_and_strip_removes_it(self):
        """CLI では案内を表示し、台帳など別の案内を出す場所では取り除ける。"""
        with mock.patch.dict(os.environ, DENY):
            with self.assertRaises(BlockedURL) as cm:
                check_url("http://169.254.169.254/")
        self.assertIn(netguard.HINT, str(cm.exception))
        stripped = netguard.strip_hint(str(cm.exception))
        self.assertNotIn("MAGATE_ALLOW_PRIVATE", stripped)
        self.assertTrue(stripped.endswith("（169.254.169.254）"))

    def test_http_layer_raises_fetch_error(self):
        with mock.patch.dict(os.environ, DENY):
            with self.assertRaises(FetchError) as cm:
                _http("http://169.254.169.254/latest/meta-data/")
        self.assertIn("公開されていないアドレス", str(cm.exception))


class TestDerivedUrls(unittest.TestCase):
    def test_metadata_urls_must_be_https(self):
        with mock.patch.dict(os.environ, DENY):
            self.assertTrue(derived_url_ok("https://auth.example.com"))
            self.assertFalse(derived_url_ok("http://169.254.169.254/"))

    def test_malicious_metadata_is_not_followed(self):
        """接続先が「認可サーバはこちら」と内部のアドレスを返しても辿らない（二次的なSSRF）。"""
        seen = []

        def fake_get_json(url):
            seen.append(url)
            if "oauth-protected-resource" in url:
                return {"resource": "https://mcp.example.com/mcp", "authorization_servers": ["http://169.254.169.254/latest"]}
            return None

        with mock.patch.dict(os.environ, DENY), mock.patch.object(collect, "_get_json", fake_get_json):
            got = fetch_oauth("https://mcp.example.com/mcp",
                              www_auth='Bearer resource_metadata="http://10.0.0.1/.well-known/oauth-protected-resource"')
        self.assertFalse([u for u in seen if "169.254" in u or "10.0.0.1" in u], seen)
        self.assertIsNone(got["authorization_server"])


class TestRedirect(unittest.TestCase):
    def _handler_call(self, src, dst):
        req = urllib.request.Request(src)
        return netguard._GuardedRedirect().redirect_request(req, None, 302, "Found", {}, dst)

    def test_redirect_to_private_is_blocked(self):
        with mock.patch.dict(os.environ, DENY):
            with self.assertRaises(BlockedURL):
                self._handler_call("https://8.8.8.8/", "https://169.254.169.254/")

    def test_https_to_http_downgrade_is_blocked(self):
        with mock.patch.dict(os.environ, ALLOW):
            with self.assertRaises(BlockedURL):
                self._handler_call("https://example.com/", "http://example.com/")


class Mock(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
        elif self.path == "/big":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"x" * 4096)
        else:
            self.send_response(404); self.end_headers()


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Mock)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_redirect_hop_is_checked(self):
        """1回目の接続先は通っても、リダイレクト先が社内アドレスなら接続する前に止める。"""
        only_metadata = lambda ip: str(ip).startswith("169.254")   # 模擬サーバ（127.0.0.1）だけは通す
        with mock.patch.dict(os.environ, DENY), mock.patch.object(netguard, "_blocked_ip", only_metadata):
            with self.assertRaises(FetchError) as cm:
                _http(self.base + "/redirect")
        self.assertIn("169.254.169.254", str(cm.exception))

    def test_response_size_is_capped(self):
        with mock.patch.dict(os.environ, ALLOW), mock.patch.object(netguard, "MAX_BYTES", 1024):
            with self.assertRaises(FetchError) as cm:
                _http(self.base + "/big")
        self.assertIn("大きすぎ", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
