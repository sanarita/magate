"""認証・混乱した代理（confused deputy）・トークン中継のチェック。

外から観測できること（HTTPS、RFC 9728/8414 メタデータ、PKCE対応、認証なしで一覧が取れるか）は自動判定。
サーバ内部の実装（トークンの audience 検証、トークン中継の有無、クライアントごとの同意）は
外から観測できないため、質問票（提供元の回答）で判定し、未回答は UNKNOWN とする。
"""
from __future__ import annotations

import re
import urllib.parse

from ..model import FAIL, OK, UNKNOWN, WARN, Finding

ASI_ID = ["ASI03"]   # アイデンティティ・権限の悪用
LLM = ["LLM06"]      # 過剰なエージェンシー


NO_AUTH_CONDITION = "公開情報のみを扱うサーバであることを確認し、公開情報の検索用途に限定すること（社外秘以上のデータは送らない）"


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
    unauth = obs.get("unauthenticated_tools_list")
    if unauth and method == "none":
        # 接続先の応答と回答（情報カードの自動入力を含む）が一致する場合は、1件にまとめる
        f.append(Finding("auth", WARN, "認証なしで利用できるサーバです（接続先の応答・提供元の回答とも認証なし）", ASI_ID, LLM,
                         condition=NO_AUTH_CONDITION))
    elif unauth:
        f.append(Finding("auth", WARN, "認証なしでツール一覧を取得できました", ASI_ID, LLM,
                         condition="公開情報のみを扱うサーバであることを確認し、社外秘以上のデータを送らない運用とすること"))
    elif method == "none":
        f.append(Finding("auth", WARN, "提供元回答：認証なし", ASI_ID, LLM,
                         condition="公開情報の検索用途に限定すること"))
    if method == "api_key":
        f.append(Finding("auth", WARN, "静的APIキー方式です（ユーザー単位の権限分離・失効が難しい）", ASI_ID, LLM,
                         condition="キーの保管場所（Key Vault等）・ローテーション周期・利用者範囲を定めること"))
    elif method is None and not prm and not obs.get("api_auth_schemes"):
        f.append(Finding("auth", UNKNOWN, "認証方式が不明です", ASI_ID, LLM, condition="提供元に認証方式を確認すること"))

    # --- OAuth メタデータ（MCP認可仕様：RFC 9728 / RFC 8414 / PKCE） ---
    is_api = snapshot["server"].get("source") == "openapi"
    if (method == "oauth2.1" or prm) and not is_api:  # RFC 9728 のメタデータは MCP サーバ向けの要件
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
            f.extend(check_issuer(((prm or {}).get("authorization_servers") or [None])[0], issuer))
            methods = asm.get("code_challenge_methods_supported") or []
            if "S256" not in methods:
                f.append(Finding("auth", FAIL, "PKCE(S256) への対応が宣言されていません（MCP認可仕様では必須）", ASI_ID, LLM,
                                 evidence=f"code_challenge_methods_supported={asm.get('code_challenge_methods_supported')}"))
            elif "plain" in methods:
                f.append(Finding("auth", WARN, "PKCEの弱い方式（plain）も有効になっています（OAuth 2.1 では S256 を使うべき）", ASI_ID, LLM,
                                 condition="接続に使うクライアントが S256 のみを使う設定であることを確認すること",
                                 evidence=f"code_challenge_methods_supported={methods}"))
            bad = {"implicit", "password"} & set(asm.get("grant_types_supported") or [])
            if bad:
                f.append(Finding("auth", WARN, f"非推奨のグラントタイプが有効です: {', '.join(sorted(bad))}", ASI_ID, LLM,
                                 condition="当該グラントを使わない設定でのみ接続すること"))

    # --- OpenAPI 仕様書から読み取った認証方式 ---
    if snapshot["server"].get("source") == "openapi":
        f.extend(_openapi_auth(obs))

    # --- 混乱した代理・トークン中継（外から見えないので回答で判定） ---
    f.extend(check_confused_deputy(q))
    if not f:
        f.append(Finding("auth", OK, "認証方式に問題は見つかりませんでした", ASI_ID, LLM))
    return f


def _openapi_auth(obs: dict) -> list[Finding]:
    kinds, flows = obs.get("api_auth_schemes") or [], obs.get("api_oauth_flows") or []
    out = []
    if not kinds:
        out.append(Finding("auth", WARN, "API仕様書に認証方式の定義がありません", ASI_ID, LLM,
                           condition="認証なしで使えるAPIか、仕様書の記載漏れかを提供元に確認すること"))
    if "basic" in kinds:
        out.append(Finding("auth", WARN, "API仕様書にBasic認証（ID・パスワード）が定義されています", ASI_ID, LLM,
                           condition="共有アカウントのパスワードを生成AIの接続に使わないこと"))
    if "api_key" in kinds:
        out.append(Finding("auth", WARN, "API仕様書にAPIキー認証が定義されています（利用者ごとの権限分離・失効が難しい）", ASI_ID, LLM,
                           condition="キーの保管場所・ローテーション周期・利用者範囲を定めること"))
    bad = {"implicit", "password"} & set(flows)
    if bad:
        out.append(Finding("auth", WARN, f"非推奨のOAuthフローが定義されています: {', '.join(sorted(bad))}", ASI_ID, LLM,
                           condition="authorizationCode（PKCE付き）フローで接続すること"))
    if obs.get("https") is False:
        out.append(Finding("auth", FAIL, "API仕様書の接続先がHTTPSではありません", ASI_ID, LLM))
    return out


def check_issuer(expected: str | None, issuer: str) -> list[Finding]:
    """認可サーバのメタデータの issuer が、MCPサーバの指定した認可サーバと一致するか（RFC 8414 3.3）。

    RFC 8414 では、取得したメタデータの issuer が問い合わせに使った発行元と完全に一致しない場合、
    そのメタデータを使ってはならないと定めている（別の認可サーバへのすり替え＝mix-up 攻撃の防止）。
    - 別ホスト        → 不可（すり替え・設定誤りの可能性があり、厳密なクライアントは接続を拒否する）
    - {tenantid} 等の置き換え前の文字列 → 要対応（Entra ID のマルチテナント窓口などの既知の挙動）
    - 同ホストでパス違い → 要対応
    末尾のスラッシュの有無は同一とみなす。
    """
    if not expected:
        return []
    if not issuer:
        return [Finding("auth", WARN, "認可サーバのメタデータに issuer がありません（RFC 8414 では必須）", ASI_ID, LLM,
                        condition="提供元に認可サーバのメタデータの不備を確認すること")]
    if issuer.rstrip("/") == expected.rstrip("/"):
        return []
    ev = f"指定された認可サーバ={expected} / メタデータの issuer={issuer}"
    if _origin(issuer) != _origin(expected):
        return [Finding("auth", FAIL, "認可サーバの issuer が、MCPサーバの指定した認可サーバと別のホストです（すり替えの可能性）", ASI_ID, LLM,
                        evidence=ev)]
    if re.search(r"\{[^{}]+\}", issuer):
        return [Finding("auth", WARN, "認可サーバの issuer が置き換え前のテンプレート（{tenantid} など）のままで、指定された認可サーバと一致しません", ASI_ID, LLM,
                        condition="テナント固有の認可サーバ（例：…/{テナントID}/v2.0）で接続する設定にし、厳密なクライアントで接続できるか確認すること",
                        evidence=ev)]
    return [Finding("auth", WARN, "認可サーバの issuer が、MCPサーバの指定した認可サーバと一致しません（RFC 8414 では一致が必須）", ASI_ID, LLM,
                    condition="提供元に正しい認可サーバのURLを確認すること", evidence=ev)]


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
