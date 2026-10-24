"""実行環境（ランタイム）の「修正済みの最小版数」表。

新しい脆弱性が出たら、この表を更新してテスト（tests/test_supply_chain.py）を追加する。
ブラウザ版にも同梱するため、JSONファイルではなくPythonの定数として持つ。
"""

AS_OF = "2026-10-24"

RUNTIMES = {
    "node": {
        "label": "Node.js",
        # 系列 → 修正済みの最小版数。ここにない系列はサポート終了または修正版なし
        "fixed": {"22": "22.23.4", "24": "24.22.1", "26": "26.12.1"},
        "reason": "CVE-2026-111497（Node2Shell：Brotli解凍処理の境界外書き込み）",
        "source": "https://nodejs.org/en/blog/vulnerability/",
    },
    "php": {
        "label": "PHP",
        "fixed": {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"},
        "reason": "CVE-2026-109618 / CVE-2026-109619（PHP2Shell：認証なしのリモートコード実行。悪用確認済み）",
        "source": "https://www.php.net/",
    },
}
