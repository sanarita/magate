"""ブラウザ版（Pyodide）用の入口。ネットワークには一切アクセスしない。

JSONテキストを受け取り、審査結果・人間向けレポート・承認用の固定ハッシュをJSONで返す。
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile

from .checks.rugpull import FIRST_AUDIT_MESSAGE, NO_PIN_CONDITION, NO_PIN_MESSAGE, pin_path, save_pin
from .rubric import VERIFY_CONDITION
from .openapi import OpenAPIError, is_openapi, to_snapshot
from .autofill import autofill
from .report import to_json, to_markdown
from .rubric import evaluate


class InputError(ValueError):
    pass


# CLIのコマンドを案内する文面を、ブラウザ版の操作に置き換える
BROWSER_TEXT = {
    NO_PIN_MESSAGE: "承認したときの記録（.pin.json）が未指定のため、承認後の書き換えは照合していません",
    NO_PIN_CONDITION: "承認が決まったら「承認用に定義を固定（.pin.json）」で保存し、次回の審査で「4. 承認したときの記録」に入れて照合すること",
    FIRST_AUDIT_MESSAGE: "初回審査（照合する記録なし）。承認が決まったら「承認用に定義を固定（.pin.json）」で保存してください",
    VERIFY_CONDITION: "国税庁 法人番号公表サイト等で会社の実在を確認し、質問票の「会社の実在を自分で確認した」にチェックすること",
}


def _for_browser(res):
    for it in res.items:
        for f in it.findings:
            f.message = BROWSER_TEXT.get(f.message, f.message)
            f.condition = BROWSER_TEXT.get(f.condition, f.condition)
    res.conditions = [BROWSER_TEXT.get(c, c) for c in res.conditions]
    res.blockers = [BROWSER_TEXT.get(b, b) for b in res.blockers]
    return res


def _parse(text: str, label: str):
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise InputError(f"{label}がJSONとして読めません（{e.lineno}行目 {e.colno}文字目）") from None


def _snapshot(obj, label="ツール定義") -> dict:
    if isinstance(obj, dict) and "result" in obj and isinstance(obj["result"], dict):
        obj = obj["result"]  # JSON-RPC 応答をそのまま貼った場合
    if not isinstance(obj, dict) or not isinstance(obj.get("tools"), list):
        raise InputError(f"{label}に tools の配列がありません。tools/list の結果を貼ってください")
    for i, t in enumerate(obj["tools"]):
        if not isinstance(t, dict) or not isinstance(t.get("name"), str):
            raise InputError(f"{label}の tools[{i}] に name がありません")
    obj.setdefault("server", {"name": "unnamed-server", "url": ""})
    obj["server"].setdefault("name", "unnamed-server")
    obj.setdefault("observations", {})
    obj.setdefault("oauth", {"protected_resource": None, "authorization_server": None})
    return obj


def run(snapshot_text: str, questionnaire_text: str = "", inventory_texts: list[str] = (), pin_text: str = "") -> dict:
    snap = _snapshot(_parse(snapshot_text, "ツール定義"))
    q = _parse(questionnaire_text, "質問票") if questionnaire_text.strip() else {}
    if not isinstance(q, dict):
        raise InputError("質問票はJSONオブジェクトにしてください")
    inv = [_snapshot(_parse(t, f"承認済み一覧{i + 1}"), f"承認済み一覧{i + 1}") for i, t in enumerate(inventory_texts) if t.strip()]

    work = tempfile.mkdtemp(prefix="magate-")
    try:
        # 記録の指定がなければ「初回審査」として扱う（ブラウザ版は審査のたびに固定用の記録を作れるため）
        pins_dir = os.path.join(work, "pins")
        os.makedirs(pins_dir)
        if pin_text.strip():
            pin = _parse(pin_text, "固定ハッシュ")
            if not isinstance(pin, dict) or "manifest" not in pin or "tools" not in pin:
                raise InputError("固定ハッシュのファイル形式が違います（magate pin で作った .pin.json を指定）")
            # 照合は審査対象のサーバ名で行う
            with open(pin_path(pins_dir, snap["server"]["name"]), "w", encoding="utf-8") as f:
                json.dump(pin, f, ensure_ascii=False)
        # 空欄の提供元側の項目は情報カード・接続先の応答で埋める。埋めた質問票は画面に書き戻す（表示と結果をそろえる）
        q, info = autofill(snap, q, fill=True)
        res = _for_browser(evaluate(snap, q, inv, pins_dir, autofill=info))
        new_pin_dir = os.path.join(work, "newpin")
        with open(save_pin(new_pin_dir, snap, approved_by="", note="ブラウザ版で作成。承認後に承認者を記入して保存すること"),
                  encoding="utf-8") as f:
            new_pin = f.read()
        return {
            "ok": True,
            "result": json.loads(to_json(res)),
            "markdown": to_markdown(res),
            "questionnaire": q,
            "new_pin": new_pin,
            "pin_filename": os.path.basename(pin_path("", snap["server"]["name"])),
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run_json(snapshot_text, questionnaire_text="", inventory_json="[]", pin_text="") -> str:
    """JS から呼ぶ入口。例外も含めて必ずJSON文字列を返す。"""
    try:
        return json.dumps(run(snapshot_text, questionnaire_text, json.loads(inventory_json or "[]"), pin_text), ensure_ascii=False)
    except InputError as e:
        return json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"ok": False, "error": f"審査中にエラーが発生しました: {type(e).__name__}: {e}"}, ensure_ascii=False)


def openapi_json(text: str) -> str:
    """ブラウザ版：OpenAPI/Swagger の JSON をスナップショットに変換して返す（失敗時は error）。"""
    try:
        spec = json.loads(text)
    except json.JSONDecodeError as e:
        return json.dumps({"ok": False, "error": f"JSONとして読めません（{e.lineno}行目）。YAMLの仕様書はJSONに変換してから読み込んでください"}, ensure_ascii=False)
    if not is_openapi(spec):
        return json.dumps({"ok": False, "not_openapi": True}, ensure_ascii=False)
    try:
        return json.dumps({"ok": True, "snapshot": to_snapshot(spec)}, ensure_ascii=False)
    except OpenAPIError as e:
        return json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False)


def autofill_json(snapshot_text: str, questionnaire_text: str = "") -> str:
    """ブラウザ版：「提供元の公開情報で入力」ボタン。空欄だけを埋めた質問票と記録を返す。"""
    try:
        snap = _snapshot(_parse(snapshot_text, "ツール定義"))
        q = _parse(questionnaire_text, "質問票") if questionnaire_text.strip() else {}
        q, info = autofill(snap, q, fill=True)
        return json.dumps({"ok": True, "questionnaire": q, "autofill": info}, ensure_ascii=False)
    except InputError as e:
        return json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False)
