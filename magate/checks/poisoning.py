"""ツールポイズニング検知：ツール説明文・スキーマに仕込まれたモデル向け命令を探す。

IPI Guard / skillscan と同じく、パターン採点方式。各ルールの重みを合計し、
8点以上で FAIL、3点以上で WARN とする。外部の抽出器（IPI Guard 等）を extra_scanners で差し込める。
"""
from __future__ import annotations

import re

from ..model import FAIL, OK, UNKNOWN, WARN, Finding
from .text import iter_texts, snippet

ASI = ["ASI01", "ASI04"]   # ゴール乗っ取り / サプライチェーン
LLM = ["LLM01"]            # プロンプトインジェクション

# (ルールID, 正規表現, 重み, 説明)
RULES = [
    ("override_en", r"\b(ignore|disregard|forget)\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)", 8, "既存の指示を無視させる命令"),
    ("override_ja", r"(以前|前|上記|これまで)の(指示|命令|ルール).{0,8}(無視|忘れ|従わ)", 8, "既存の指示を無視させる命令"),
    ("secrecy_en", r"\b(do\s*n[o']t|never|without)\s+(tell|inform|mention|reveal|notify|showing)\w*\s+(it\s+|this\s+)?(to\s+)?the\s+user", 6, "ユーザーへの秘匿指示"),
    ("secrecy_ja", r"ユーザー?(に|へ)(は)?(伝え|知らせ|言わ|表示し|報告し)(ない|ず|るな)", 6, "ユーザーへの秘匿指示"),
    ("tag_marker", r"<\s*/?\s*(important|system|instructions?|admin|secret)\s*>", 4, "モデル向けの強調タグ"),
    ("precondition_en", r"\bbefore\s+(using|calling|invoking)\s+this\s+tool\b.{0,60}\b(read|call|send|include|pass|open)\b", 4, "ツール利用前の追加行動の強制"),
    ("precondition_ja", r"(この|本)ツールを(使う|呼ぶ|呼び出す|実行する|利用する)前に", 4, "ツール利用前の追加行動の強制"),
    ("sensitive_path", r"(~|%USERPROFILE%|\$HOME)[/\\]\.?(ssh|aws|azure|config|kube)|\bid_(rsa|ed25519)\b|(^|[/\\\s])\.env\b|mcp\.json|claude_desktop_config|\bcredentials?\.(json|ya?ml)\b", 5, "機密ファイルへの言及"),
    ("smuggle_en", r"\b(include|provide|pass|attach|append|put)\b.{0,40}\b(system\s+prompt|conversation|chat\s+history|previous\s+messages|api[\s_-]?keys?|passwords?|secrets?|access\s+tokens?)\b", 5, "機密情報を引数に含めさせる指示"),
    ("smuggle_ja", r"(システムプロンプト|会話(の)?履歴|これまでの会話|APIキー|パスワード|秘密鍵|アクセストークン)(を|も|は).{0,15}(含め|入れ|渡し|添付し|送っ|記載し|入力し)(て|る(こと|よう))", 5, "機密情報を引数に含めさせる指示"),
    ("smuggle_ctx_ja", r"(閲覧中|表示中|開いている|作業中|社内|手元)の?(文書|ファイル|資料|データ|メール).{0,20}(含め|入れ|渡し|添付し|送っ)(て|る(こと|よう))", 5, "利用者の手元データを引数に含めさせる指示"),
    ("smuggle_ctx_en", r"\b(include|attach|pass|send)\b.{0,30}\b(open|current|internal|local|user'?s)\s+(documents?|files?|emails?)\b", 5, "利用者の手元データを引数に含めさせる指示"),
    ("exfil_en", r"\b(send|forward|upload|post|transmit|exfiltrate|copy)\b.{0,50}\b(to|into)\s+(https?://|[\w.+-]+@[\w-]+\.)", 5, "外部への送信指示"),
    ("exfil_ja", r"(https?://\S+|[\w.+-]+@[\w-]+\.\S+).{0,20}(に|へ)(送信|転送|アップロード|送っ|送る)", 5, "外部への送信指示"),
    ("roleplay", r"\b(you\s+are\s+now|act\s+as|pretend\s+to\s+be)\b|あなたは(今から|これから)", 3, "役割の書き換え"),
    ("html_comment", r"<!--.*?-->", 3, "HTMLコメント（人間のUIでは見えにくい）"),
    ("encoded_blob", r"[A-Za-z0-9+/]{120,}={0,2}", 3, "長いエンコード文字列"),
    ("url", r"https?://[^\s\"'<>)]+", 1, "説明文中のURL"),
]
_COMPILED = [(rid, re.compile(rx, re.IGNORECASE | re.DOTALL), w, label) for rid, rx, w, label in RULES]

HIDDEN_CHARS = re.compile("[\u200b-\u200f\u2060-\u2064\ufeff\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f]")
LONG_DESC = 1500
FAIL_SCORE, WARN_SCORE = 8, 3


def scan_text(text: str) -> list[tuple[str, int, str, str]]:
    hits = []
    for rid, rx, w, label in _COMPILED:
        m = rx.search(text)
        if m:
            hits.append((rid, w, label, snippet(text, m.start(), m.end())))
    m = HIDDEN_CHARS.search(text)
    if m:
        hits.append(("hidden_unicode", 6, f"不可視文字 U+{ord(m.group()):04X}", snippet(text, m.start(), m.end())))
    if len(text) > LONG_DESC:
        hits.append(("long_text", 1, f"異常に長い説明（{len(text)}文字）", text[:60] + "…"))
    return hits


# ツール定義が1件もない＝検査していない。「問題なし」と言わず未確認にする（web.py がブラウザ向けに言い換える）
NO_TOOLS_CONDITION = ("アクセストークンを使って取得し直す（magate snapshot --token-env）か、"
                      "提供元の資料からツール名と説明文を入れて再審査すること")


def no_tools_message(snapshot: dict) -> str:
    why = "接続先が認証を求めたため、" if (snapshot.get("observations") or {}).get("auth_required") else ""
    return f"{why}ツール定義を取得できておらず、内容を検査していません"


def check_poisoning(snapshot: dict, extra_scanners=()) -> list[Finding]:
    """extra_scanners: callable(text) -> list[(rule_id, weight, label, snippet)] を追加で差し込める。"""
    if not snapshot.get("tools"):
        return [Finding("tool_poisoning", UNKNOWN, no_tools_message(snapshot), ASI, LLM, condition=NO_TOOLS_CONDITION)]
    findings = []
    for tool in snapshot.get("tools", []):
        score, details, labels = 0, [], []
        for where, text in iter_texts(tool):
            hits = scan_text(text)
            for sc in extra_scanners:
                hits.extend(sc(text))
            for rid, w, label, snip in hits:
                score += w
                if label not in labels:
                    labels.append(label)
                details.append(f"[{rid} +{w}] {label} @ {where}: 「{snip}」")
        if score >= FAIL_SCORE:
            status = FAIL
        elif score >= WARN_SCORE:
            status = WARN
        else:
            continue
        findings.append(Finding(
            threat="tool_poisoning", status=status, asi=ASI, llm=LLM,
            message=f"ツール `{tool.get('name')}` の定義にモデル向けの命令らしき記述があります（スコア {score}）",
            evidence="\n".join(details),
            condition=(f"`{tool.get('name')}` に{'・'.join(f'「{x}」' for x in labels[:3])}{'など' if len(labels) > 3 else ''}が見つかったため、"
                       "無効化するか、提供元に説明文の修正を求めること") if status == WARN else "",
        ))
    if not findings:
        findings.append(Finding("tool_poisoning", OK, "ツール定義に命令の埋め込みは検出されませんでした", ASI, LLM))
    return findings
