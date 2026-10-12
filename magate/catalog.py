"""主要MCPサーバの情報カード：提供元の公開情報から、質問票の一部を根拠付きで自動入力する。

方針
- 値はすべて、提供元の公式ページ（または公式リポジトリ）で確認できたものだけを入れる。
  確認できなかった項目は入れない（空欄＝未確認のまま審査に回る）。
- 項目ごとに根拠URLを持たせ、カードごとに確認日を記録する。
- 自社が決める項目（送ってよい機密区分、必要なスコープ、自社側のログなど）は入れない。
- 運営主体の「実在確認済み（verified_by_human）」は自動では立てない。最終確認は人が行う。
- 契約プランで条件が変わる項目は note に前提を書く。
"""
from __future__ import annotations

import urllib.parse

STALE_DAYS = 180  # 確認日からこの日数を過ぎたカードは「再確認が必要」と表示する

_MS_ENT = "https://learn.microsoft.com/en-us/graph/mcp-server/overview"
_MS_ENT_START = "https://learn.microsoft.com/en-us/graph/mcp-server/get-started"
_MS_LEARN = "https://github.com/MicrosoftDocs/mcp"
_GH_GOV = "https://github.com/github/github-mcp-server/blob/main/docs/policies-and-governance.md"
_GH_DR = "https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/provide-context/use-mcp/enterprise-configuration"
_ATL_MON = "https://support.atlassian.com/security-and-access-policies/docs/monitor-atlassian-rovo-mcp-server-activity"
_ATL_CTL = "https://support.atlassian.com/security-and-access-policies/docs/control-atlassian-rovo-mcp-server-settings/"
_ATL_DSP = "https://support.atlassian.com/security-and-access-policies/docs/prevent-atlassian-rovo-mcp-server-access/"
_BOX_REPO = "https://github.com/box/mcp-server-box-remote"
_BOX_GUIDE = "https://developer.box.com/guides/box-mcp/remote/"
_RESEARCH = "https://github.com/sanarita/magate/tree/main/research/2026-10-remote-mcp"
_MS_ISO = "https://learn.microsoft.com/compliance/regulatory/offering-iso-27001"
_GH_CERT = "https://github.blog/changelog/2024-06-03-github-copilot-compliance-soc-2-type-1-report-and-iso-iec-270012013-certification-scope/"
_GH_SOC2 = "https://github.blog/2019-08-27-github-has-soc-1-and-soc-2-type-2-reports"
_ATL_ISO = "https://www.atlassian.com/ja/trust/compliance/resources/iso27001"
_BOX_ISO = "https://support.box.com/hc/en-us/articles/360043691774-ISO-27001-Certification-Overview-and-FAQ"
_BOX_ISMAP = "https://www.boxsquare.jp/ismap"
# 第三者認証は会社（またはその主要クラウドサービス）としてのもの。MCPサーバ自体が認証範囲に含まれるかは
# 各社の証明書の適用範囲で確認する必要があるため、note に必ずその旨を書く。
_SCOPE = "会社の主要クラウドサービスとしての認証。このMCPサーバが認証範囲に含まれるかは証明書の適用範囲で要確認"

CARDS = [
    {
        "id": "microsoft-learn",
        "title": "Microsoft Learn MCP Server",
        "match": {"hosts": ["learn.microsoft.com"], "path_prefix": "/api/mcp"},
        "checked": "2026-10-12",
        "answers": {
            "operator.name": {"value": "Microsoft Corporation", "source": _MS_LEARN},
            "operator.domain": {"value": "microsoft.com", "source": _MS_LEARN},
            "operator.security_contact": {"value": "https://github.com/MicrosoftDocs/mcp/blob/main/SECURITY.md",
                                          "source": _MS_LEARN},
            "operator.certifications": {"value": ["ISO/IEC 27001"], "source": _MS_ISO,
                                        "note": _SCOPE + "（Service Trust Portal で確認できる）"},
            "auth.method": {"value": "none", "source": _MS_LEARN, "note": "APIキー・ログイン不要と明記"},
        },
        "notes": [
            {"text": "Microsoft公式の公開ドキュメントとコードサンプルだけを検索・取得するサーバ。社内の情報は扱わない", "source": _MS_LEARN},
            {"text": "利用条件は Microsoft Learn の利用規約。送った検索語の学習利用・保存期間は公開資料で確認できなかった",
             "source": "https://learn.microsoft.com/legal/termsofuse"},
        ],
    },
    {
        "id": "microsoft-mcp-enterprise",
        "title": "Microsoft MCP Server for Enterprise（プレビュー）",
        "match": {"hosts": ["mcp.svc.cloud.microsoft"], "path_prefix": "/enterprise"},
        "checked": "2026-10-12",
        "answers": {
            "operator.name": {"value": "Microsoft Corporation", "source": _MS_ENT},
            "operator.domain": {"value": "cloud.microsoft", "source": _MS_ENT},
            "operator.security_contact": {"value": "https://msrc.microsoft.com/report", "source": "https://msrc.microsoft.com",
                                          "note": "Microsoft全体の脆弱性報告窓口（MSRC）"},
            "operator.certifications": {"value": ["ISO/IEC 27001"], "source": _MS_ISO,
                                        "note": _SCOPE + "。本サービスはプレビュー版のため、範囲外の可能性が高い"},
            "auth.method": {"value": "oauth2.1", "source": _MS_ENT_START, "note": "委任アクセス許可のみ。スコープは管理者がクライアントごとに付与"},
            "audit.server_side_audit_log": {"value": True, "source": _MS_ENT + "#logs",
                                            "note": "Microsoft Graph アクティビティログを有効化した場合。MCPサーバの appId で絞り込める"},
            "audit.log_export_available": {"value": True, "source": _MS_ENT + "#logs",
                                           "note": "Graph アクティビティログを Log Analytics 等に出力して自社で検索できる"},
        },
        "notes": [
            {"text": "プレビュー版。提供条件は製品利用条件ではなく Microsoft APIs Terms of Use。データ保護契約（DPA）の適用範囲は要確認", "source": _MS_ENT},
            {"text": "グローバルサービスのみで、処理地域を選ぶ設定は公開資料に記載がない", "source": _MS_ENT},
            {"text": "Microsoft Entra のディレクトリ情報を読み取り専用で扱う。要求は同社の Microsoft Graph に転送される", "source": _MS_ENT},
            {"text": "認可サーバ（Entra ID）が PKCE(S256) をメタデータで宣言していない（maGATE の調査）", "source": _RESEARCH},
        ],
    },
    {
        "id": "github",
        "title": "GitHub MCP Server（リモート）",
        "match": {"hosts": ["api.githubcopilot.com"], "host_suffixes": [".ghe.com"], "path_prefix": "/mcp"},
        "checked": "2026-10-12",
        "answers": {
            "operator.name": {"value": "GitHub, Inc.", "source": _GH_GOV},
            "operator.domain": {"value": "githubcopilot.com", "source": _GH_GOV,
                                "note": "GitHub の Copilot 用ドメイン。データ所在地オプションでは ghe.com"},
            "operator.security_contact": {"value": "https://github.com/security", "source": "https://github.com/security"},
            "operator.certifications": {"value": ["ISO/IEC 27001", "SOC 2 Type 2"], "source": _GH_CERT,
                                        "note": "ISMS の範囲に Copilot Business／Enterprise を含む。SOC 2 Type 2 は GitHub Enterprise Cloud の報告書（"
                                                + _GH_SOC2 + "）。" + _SCOPE},
            "auth.method": {"value": "oauth2.1", "source": _GH_GOV},
            "audit.server_side_audit_log": {"value": True, "source": _GH_GOV,
                                            "note": "基盤のAPI呼び出しが GitHub の監査ログに記録される（利用可能な場合）。MCPのツール呼び出し単位の記録ではない"},
        },
        "notes": [
            {"text": "組織・企業のポリシー「MCP servers in Copilot」で利用を止められる", "source": _GH_GOV},
            {"text": "GitHub Enterprise Cloud のデータ所在地オプション利用時は、専用URL（copilot-api.<サブドメイン>.ghe.com/mcp）でリモートサーバを使える", "source": _GH_DR},
            {"text": "読み取り専用の接続URL（/mcp/readonly）がある", "source": _RESEARCH},
        ],
    },
    {
        "id": "atlassian",
        "title": "Atlassian Rovo MCP Server",
        "match": {"hosts": ["mcp.atlassian.com"]},
        "checked": "2026-10-12",
        "answers": {
            "operator.name": {"value": "Atlassian", "source": _ATL_CTL},
            "operator.domain": {"value": "atlassian.com", "source": _ATL_CTL},
            "operator.certifications": {"value": ["ISO/IEC 27001", "ISO/IEC 27018"], "source": _ATL_ISO,
                                        "note": "認証の関連製品に Rovo が含まれる。" + _SCOPE},
            "auth.method": {"value": "oauth2.1", "source": _ATL_CTL,
                            "note": "既定は OAuth 2.1。APIトークンでの接続も可能で、管理者が無効化できる"},
            "audit.server_side_audit_log": {"value": True, "source": _ATL_MON,
                                            "note": "ツールの利用ごとに組織の監査ログへ記録。一部の機能は Atlassian Guard が必要"},
            "audit.log_export_available": {"value": True, "source": _ATL_MON, "note": "アクティビティログのエクスポートで、代理実行した利用者を確認できる"},
        },
        "notes": [
            {"text": "APIトークン接続では利用者ごとの監査記録が分かれない場合がある。OAuth のみに制限するのが望ましい", "source": _ATL_MON},
            {"text": "接続元ドメインの許可リスト、IP許可リストで接続を制限できる", "source": _ATL_CTL},
            {"text": "データセキュリティポリシーで、MCP経由の読み取りを製品・分類単位で止められる（Atlassian Guard が必要）", "source": _ATL_DSP},
        ],
    },
    {
        "id": "box",
        "title": "Box MCP Server（リモート）",
        "match": {"hosts": ["mcp.box.com"]},
        "checked": "2026-10-12",
        "answers": {
            "operator.name": {"value": "Box, Inc.", "source": _BOX_REPO},
            "operator.domain": {"value": "box.com", "source": _BOX_REPO},
            "operator.certifications": {"value": ["ISO/IEC 27001", "ISMAP"], "source": _BOX_ISO,
                                        "note": "ISMAP は2021年9月13日に登録、登録範囲に Box Platform と 3rd Party Integration を含む（"
                                                + _BOX_ISMAP + "）。" + _SCOPE},
            "auth.method": {"value": "oauth2.1", "source": _BOX_REPO, "note": "Box の認可サーバによる OAuth 保護"},
        },
        "notes": [
            {"text": "接続時のスコープは root_readwrite・ai.readwrite・docgen.readwrite（書き込みを含む）と案内されている", "source": _BOX_GUIDE},
            {"text": "利用者は、Box上で自分が閲覧・編集できるコンテンツにだけアクセスできる", "source": _BOX_GUIDE},
            {"text": "管理コンソールの「統合」で有効化・設定する方式", "source": _BOX_GUIDE},
        ],
    },
]


def find_card(url: str | None) -> dict | None:
    """接続先URLに一致する情報カードを返す（なければ None）。"""
    if not url:
        return None
    p = urllib.parse.urlsplit(url.strip())
    host, path = (p.hostname or "").lower(), p.path or "/"
    for card in CARDS:
        m = card["match"]
        host_ok = host in m.get("hosts", []) or any(host.endswith(s) for s in m.get("host_suffixes", []))
        if host_ok and path.startswith(m.get("path_prefix", "/")):
            return card
    return None
