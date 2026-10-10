"""ブラウザ版（Pyodide）用の入口。ネットワークには一切アクセスしない。

JSONテキストを受け取り、審査結果・人間向けレポート・承認用の固定ハッシュをJSONで返す。
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile

from .checks.rugpull import pin_path, save_pin
from .report import to_json, to_markdown
from .rubric import evaluate


class InputError(ValueError):
    pass


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

    work = tempfile.mkdtemp(prefix="mcpgate-")
    try:
        pins_dir = None
        if pin_text.strip():
            pin = _parse(pin_text, "固定ハッシュ")
            if not isinstance(pin, dict) or "manifest" not in pin or "tools" not in pin:
                raise InputError("固定ハッシュのファイル形式が違います（mcp-gate pin で作った .pin.json を指定）")
            pins_dir = os.path.join(work, "pins")
            os.makedirs(pins_dir)
            # 照合は審査対象のサーバ名で行う
            with open(pin_path(pins_dir, snap["server"]["name"]), "w", encoding="utf-8") as f:
                json.dump(pin, f, ensure_ascii=False)
        res = evaluate(snap, q, inv, pins_dir)
        new_pin_dir = os.path.join(work, "newpin")
        with open(save_pin(new_pin_dir, snap, approved_by="", note="ブラウザ版で作成。承認後に承認者を記入して保存すること"),
                  encoding="utf-8") as f:
            new_pin = f.read()
        return {
            "ok": True,
            "result": json.loads(to_json(res)),
            "markdown": to_markdown(res),
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
