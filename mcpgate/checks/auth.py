"""認証・混乱した代理（confused deputy）・トークン中継のチェック。

外から観測できること（HTTPS、RFC 9728/8414 メタデータ、PKCE対応、認証なしで一覧が取れるか）は自動判定。
サーバ内部の実装（トークンの audience 検証、トークン中継の有無、クライアントごとの同意）は
外から観測できないため、質問票（提供元の回答）で判定し、未回答は UNKNOWN とする。
"""
from __future__ import annotations

import urllib.parse

from ..model import FAIL, OK, UNKNOWN, WARN, Finding

ASI_ID = ["ASI03"]   # アイデンティティ・権限の悪用
LLM = ["LLM06"]      # 過剰なエージェンシー


def check_auth(snapshot: dict, q: dict) -> list[Finding]:
    f: list[Finding] = []
    obs = snapshot.get("observations", {})
    url = snapshot["server"].get("url", "")
    oauth = snapshot.get("oauth") or {}
    prm, asm = oauth.get("protected_resource"), oauth.get("authorization_server")
    a = q.get("auth", {})
    method = a.get("method")

    # --- 通信路 ---
    if url and not url.lower().startswith("https://"):
        f.append(Finding("auth", FAIL, "接続先がHTTPSではありません", ASI_ID, LLM, evidence=url))

    # --- 認証方式 ---
    if obs.get("unauthenticated_tools_list"):
        f.append(Finding("auth", WARN, "認証なしでツール一覧を取得できました", ASI_ID, LLM,
                         condition="公開情報のみを扱うサーバであることを確認し、社外秘以上のデータを送らない運用とすること"))
    if method == "none":
        f.append(Finding("auth", WARN, "提供元回答：認証なし", ASI_ID, LLM,
                         condition="公開情報の検索用途に限定すること"))
    elif method == "api_key":
        f.append(Finding("auth", WARN, "静的APIキー方式です（ユーザー単位の権限分離・失効が難しい）", ASI_ID, LLM,
                         condition="キーの保管場所（Key Vault等）・ローテーション周期・利用者範囲を定めること"))
    elif method is None and not prm:
        f.append(Finding("auth", UNKNOWN, "認証方式が不明です", ASI_ID, LLM, condition="提供元に認証方式を確認すること"))

    # --- OAuth メタデータ（MCP認可仕様：RFC 9728 / RFC 8414 / PKCE） ---
    if method == "oauth2.1" or prm:
        if not prm:
            f.append(Finding("auth", WARN, "OAuth方式だが Protected Resource Metadata（RFC 9728）が取得できません", ASI_ID, LLM,
                             condition="提供元にMCP認可仕様準拠状況を確認すること"))
        else:
            if prm.get("resource") and url and _origin(prm["resource"]) != _origin(url):
                f.append(Finding("auth", WARN, "メタデータの resource が接続先URLと一致しません", ASI_ID, LLM,
                                 evidence=f"resource={prm.get('resource')} / url={url}"))
            if not prm.get("authorization_servers"):
                f.append(Finding("auth", WARN, "認可サーバが宣言されていません", ASI_ID, LLM))
        if prm and not asm:
            f.append(Finding("auth", UNKNOWN, "認可サーバのメタデータ（RFC 8414）が取得できません", ASI_ID, LLM))
        if asm:
            issuer = asm.get("issuer", "")
            if issuer and not issuer.startswith("https://"):
                f.append(Finding("auth", FAIL, "認可サーバの issuer がHTTPSではありません", ASI_ID, LLM, evidence=issuer))
            if "S256" not in (asm.get("code_challenge_methods_supported") or []):
                f.append(Finding("auth", FAIL, "PKCE(S256) への対応が宣言されていません（MCP認可仕様では必須）", ASI_ID, LLM,
                                 evidence=f"code_challenge_methods_supported={asm.get('code_challenge_methods_supported')}"))
            bad = {"implicit", "password"} & set(asm.get("grant_types_supported") or [])
            if bad:
                f.append(Finding("auth", WARN, f"非推奨のグラントタイプが有効です: {', '.join(sorted(bad))}", ASI_ID, LLM,
                                 condition="当該グラントを使わない設定でのみ接続すること"))

    # --- 混乱した代理・トークン中継（外から見えないので回答で判定） ---
    f.extend(check_confused_deputy(q))
    if not f:
        f.append(Finding("auth", OK, "認証方式に問題は見つかりませんでした", ASI_ID, LLM))
    return f


def check_confused_deputy(q: dict) -> list[Finding]:
    a = q.get("auth", {})
    out = []
    asi = ["ASI03"]
    if a.get("method") == "none":
        return out
    tp = a.get("token_passthrough")
    if tp is True:
        out.append(Finding("confused_deputy", FAIL, "受け取ったトークンを下流APIへそのまま中継しています（MCP仕様で明示的に禁止）", asi, LLM))
    elif tp is None:
        out.append(Finding("confused_deputy", UNKNOWN, "トークン中継の有無が未確認です", asi, LLM,
                           condition="提供元から「トークンを下流へ中継しない」旨の書面回答を得ること"))
    av = a.get("audience_validation")
    if av is False:
        out.append(Finding("confused_deputy", FAIL, "トークンの audience（宛先）を検証していません", asi, LLM))
    elif av is None:
        out.append(Finding("confused_deputy", UNKNOWN, "トークンの audience 検証が未確認です", asi, LLM,
                           condition="自サーバ宛てに発行されたトークンのみ受理することを書面で確認すること"))
    if a.get("is_proxy"):
        pc = a.get("per_client_consent")
        if pc is False:
            out.append(Finding("confused_deputy", FAIL, "第三者APIへのプロキシ型なのに、クライアントごとの同意を取っていません", asi, LLM))
        elif pc is None:
            out.append(Finding("confused_deputy", UNKNOWN, "プロキシ型だが、クライアントごとの同意の有無が未確認です", asi, LLM,
                               condition="クライアントごとの同意画面があることを確認すること"))
    if not out:
        out.append(Finding("confused_deputy", OK, "トークン中継なし・audience検証ありと回答されています", asi, LLM))
    return out


def _origin(u: str) -> str:
    p = urllib.parse.urlsplit(u)
    return f"{p.scheme}://{p.netloc}".lower()
