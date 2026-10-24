"""サプライチェーンのチェック：接続先パッケージ・依存ライブラリの既知脆弱性と、実行環境の版数。

判定はスナップショットの "supply_chain" と observations（応答ヘッダー）だけを見る。ネットワークには出ない。

- 既知脆弱性：重大度 CRITICAL／HIGH、または悪用確認済み（exploited に含まれる）なら NG。
  それ以外は要対応（修正版への更新を条件にする）。
- 実行環境：engines.node が EOL 系列を許す、または応答ヘッダーが修正前の PHP を名乗る場合。
  ヘッダーは自己申告で、隠したり偽ったりできるため「表示がないこと＝安全」とはみなさない。
"""
from __future__ import annotations

import re

from ..model import FAIL, OK, UNKNOWN, WARN, Finding
from ..runtimes import AS_OF, RUNTIMES

ASI_ID = ["ASI04"]   # エージェントのサプライチェーン
LLM = ["LLM03"]      # サプライチェーン
HIGH = {"CRITICAL", "HIGH"}


def _ver(s: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", s)[:3])


def _ids(v: dict) -> str:
    return " / ".join([v["id"], *[a for a in v.get("aliases", []) if a.startswith("CVE-")]])


def has_evidence(snapshot: dict) -> bool:
    obs = snapshot.get("observations", {})
    return bool(snapshot.get("supply_chain") or obs.get("x_powered_by"))


def check_supply_chain(snapshot: dict, exploited=(), runtimes: dict | None = None) -> list[Finding]:
    rt = runtimes or {"as_of": AS_OF, "runtimes": RUNTIMES}
    sc = snapshot.get("supply_chain") or {}
    exploited = {e.upper() for e in exploited}
    f: list[Finding] = []

    # --- 既知脆弱性（OSV） ---
    for v in sc.get("vulns", []):
        ids = {v["id"].upper(), *[a.upper() for a in v.get("aliases", [])]}
        fix = f"{v['package']} を {' / '.join(v['fixed'])} 以上に更新すること" if v.get("fixed") \
            else f"{v['package']} の修正版が未公開のため、提供元に対応予定を確認すること"
        where = f"{v['package']}@{v['version']}（{v['ecosystem']}）"
        if ids & exploited:
            f.append(Finding("supply_chain", FAIL, f"悪用が確認されている脆弱性を含みます：{where}", ASI_ID, LLM,
                             evidence=f"{_ids(v)} {v.get('summary', '')}", condition=fix))
        elif v.get("severity") in HIGH:
            f.append(Finding("supply_chain", FAIL, f"重大度{v['severity']}の既知脆弱性を含みます：{where}", ASI_ID, LLM,
                             evidence=f"{_ids(v)} {v.get('summary', '')}", condition=fix))
        else:
            f.append(Finding("supply_chain", WARN, f"既知脆弱性を含みます（重大度 {v.get('severity') or '不明'}）：{where}",
                             ASI_ID, LLM, evidence=f"{_ids(v)} {v.get('summary', '')}", condition=fix))
    if sc.get("truncated"):
        f.append(Finding("supply_chain", WARN, "脆弱性の件数が多いため、詳細の取得を途中で打ち切りました", ASI_ID, LLM,
                         condition="依存ライブラリ全体を更新してから再審査すること"))

    # --- 実行環境：Node.js（パッケージが宣言する対応版数） ---
    node = rt["runtimes"]["node"]
    rng = (sc.get("engines") or {}).get("node")
    if sc.get("package") and sc["package"].get("ecosystem") == "npm":
        min_fixed = " / ".join(node["fixed"].values())
        if not rng:
            f.append(Finding("supply_chain", UNKNOWN, "対応するNode.jsの版数が宣言されていません（engines.node なし）", ASI_ID, LLM,
                             condition=f"実行環境のNode.jsが {min_fixed} 以上であることを確認すること（{node['reason']}）"))
        else:
            lowest = _ver(rng)[:1]
            if lowest and str(lowest[0]) not in node["fixed"] and lowest[0] < max(map(int, node["fixed"])):
                f.append(Finding("supply_chain", WARN,
                                 f"サポート終了または修正版のないNode.js系列でも動く宣言です（engines.node: {rng}）", ASI_ID, LLM,
                                 evidence=f"修正版がある系列：{min_fixed}（{rt['as_of']}時点）",
                                 condition=f"実行環境のNode.jsを {min_fixed} 以上に固定すること（{node['reason']}）"))

    # --- 実行環境：PHP（接続先の応答ヘッダー。自己申告） ---
    xpb = snapshot.get("observations", {}).get("x_powered_by") or ""
    m = re.search(r"PHP/(\d+)\.(\d+)\.(\d+)", xpb)
    if m:
        php = rt["runtimes"]["php"]
        branch, cur = f"{m.group(1)}.{m.group(2)}", _ver(m.group(0))
        fixed = php["fixed"].get(branch)
        if fixed is None and cur < _ver(min(php["fixed"], key=_ver)):
            f.append(Finding("supply_chain", FAIL, f"接続先がサポート終了のPHPを名乗っています（{m.group(0)}）", ASI_ID, LLM,
                             evidence=f"X-Powered-By: {xpb[:80]}", condition=f"提供元にPHPの更新状況を確認すること（{php['reason']}）"))
        elif fixed and cur < _ver(fixed):
            f.append(Finding("supply_chain", FAIL, f"接続先が修正前のPHPを名乗っています（{m.group(0)}、修正版は {fixed}）", ASI_ID, LLM,
                             evidence=f"X-Powered-By: {xpb[:80]}", condition=f"提供元にPHPの更新状況を確認すること（{php['reason']}）"))
        f.append(Finding("supply_chain", WARN, "接続先が応答ヘッダーで実行環境の版数を公開しています（攻撃者の下調べに使われ得る）",
                         ASI_ID, LLM, evidence=f"X-Powered-By: {xpb[:80]}",
                         condition="提供元に、版数を公開しない設定（expose_php=Off 等）を推奨として伝えること"))

    if sc and not f:
        f.append(Finding("supply_chain", OK,
                         f"既知脆弱性は見つかりませんでした（{sc.get('packages_checked', 0)}件を照会、{sc.get('checked_at', '-')}時点）",
                         ASI_ID, LLM))
    return f
