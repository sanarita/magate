"""ツール定義の中から、モデルが読む可能性のある文字列をすべて取り出す。"""
from __future__ import annotations


def iter_texts(tool: dict):
    """(場所, 文字列) を列挙する。description だけでなく schema 内の説明・enum・default も対象。"""
    name = tool.get("name", "?")
    for key in ("title", "description"):
        if isinstance(tool.get(key), str):
            yield f"{name}.{key}", tool[key]
    for key in ("inputSchema", "outputSchema"):
        yield from _walk(tool.get(key), f"{name}.{key}")
    ann = tool.get("annotations") or {}
    if isinstance(ann.get("title"), str):
        yield f"{name}.annotations.title", ann["title"]


def _walk(node, path):
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, str) and k in ("description", "title", "default", "const", "pattern", "$comment", "examples"):
                yield f"{path}.{k}", v
            elif k == "properties" and isinstance(v, dict):
                for pname, pschema in v.items():
                    yield f"{path}.properties.{pname}<name>", pname
                    yield from _walk(pschema, f"{path}.properties.{pname}")
            else:
                yield from _walk(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, str):
                yield f"{path}[{i}]", v
            else:
                yield from _walk(v, f"{path}[{i}]")


def snippet(text: str, start: int, end: int, pad: int = 30) -> str:
    s = text[max(0, start - pad): end + pad].replace("\n", " ")
    return ("…" if start > pad else "") + s + ("…" if end + pad < len(text) else "")
