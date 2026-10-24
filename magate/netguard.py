"""通信の関所：maGATE 自身が、悪意ある接続先の踏み台（SSRF）にならないようにする。

maGATE は利用者が指定したURLだけでなく、接続先の応答に書かれたURL（認可サーバのメタデータなど）にも
アクセスする。Azure Functions で定期審査する構成では、URLは台帳に接続先を登録した人が決める。
そのため、すべての通信の直前に次を確認する。

- 名前解決した結果が、プライベート・ループバック・リンクローカル・予約済みなどの
  「インターネット上の公開アドレスではない」範囲なら拒否する（リダイレクト先も同じ）
- HTTPS から HTTP へのリダイレクト（格下げ）は拒否する
- 応答は上限（既定 5MB）までしか読まない

社内のMCPサーバを審査したい場合は、環境変数 MAGATE_ALLOW_PRIVATE=1（CLIでは --allow-private）で
明示的に許可する。

限界：名前解決と実際の接続の間でアドレスをすり替える攻撃（DNSリバインディング）は、
標準ライブラリだけでは完全には防げない。社内ネットワークへ届く場所で動かす場合は、
ネットワーク側（送信先の制限）でも塞ぐこと。
"""
from __future__ import annotations

import ipaddress
import os
import socket
import urllib.parse
import urllib.request

MAX_BYTES = 5 * 1024 * 1024
ENV = "MAGATE_ALLOW_PRIVATE"


class BlockedURL(ValueError):
    """関所で止めたURL。"""


def allow_private() -> bool:
    return os.environ.get(ENV, "").strip().lower() in ("1", "true", "yes")


def _blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped   # ::ffff:127.0.0.1 のような書き方での回避を防ぐ
    return not ip.is_global or ip.is_multicast


def check_url(url: str) -> None:
    """通信してよいURLかを確認する。だめなら BlockedURL を送出する。"""
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https"):
        raise BlockedURL(f"http(s) 以外のURLには接続しません: {url[:200]}")
    if not u.hostname:
        raise BlockedURL(f"接続先のホスト名がありません: {url[:200]}")
    if allow_private():
        return
    try:
        infos = socket.getaddrinfo(u.hostname, u.port or (443 if u.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as e:
        raise BlockedURL(f"接続先の名前を解決できません: {u.hostname}") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        if _blocked_ip(ip):
            raise BlockedURL(f"公開されていないアドレスには接続しません: {u.hostname}（{ip}）。"
                             f"社内の接続先を審査する場合は {ENV}=1 を設定してください")


def derived_url_ok(url: str) -> bool:
    """接続先の応答に書かれたURL（メタデータ等）を辿ってよいか。HTTPSのみ（開発用の許可時を除く）。"""
    return allow_private() or url.lower().startswith("https://")


class _GuardedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            if req.full_url.lower().startswith("https://") and not newurl.lower().startswith("https://"):
                raise BlockedURL(f"HTTPSからHTTPへのリダイレクトは辿りません: {newurl[:200]}")
            check_url(newurl)
        except BlockedURL:
            if fp is not None:
                fp.close()   # リダイレクト元の応答を閉じてから止める
            raise
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_url(req: urllib.request.Request, timeout: float):
    """関所を通してから開く。リダイレクト先も確認する。"""
    check_url(req.full_url)
    return urllib.request.build_opener(_GuardedRedirect).open(req, timeout=timeout)


def read_limited(resp, limit: int | None = None) -> bytes:
    limit = MAX_BYTES if limit is None else limit
    data = resp.read(limit + 1)
    if len(data) > limit:
        raise BlockedURL(f"応答が大きすぎます（上限 {limit // 1024} KB）")
    return data
