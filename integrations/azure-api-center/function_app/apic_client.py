"""Azure API Center（管理プレーン）の REST API を呼ぶ最小クライアント。

認証は azure-identity の DefaultAzureCredential を使う。
Azure Functions 上ではマネージドID、手元のPCでは `az login` の資格情報が自動で使われる。
"""
from __future__ import annotations

import json
import os
import urllib.request

ARM = "https://management.azure.com"


class ApiCenterClient:
    def __init__(self, subscription_id: str, resource_group: str, service_name: str,
                 api_version: str, credential=None):
        self.base = (f"{ARM}/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
                     f"/providers/Microsoft.ApiCenter/services/{service_name}/workspaces/default")
        self.api_version = api_version
        if credential is None:
            from azure.identity import DefaultAzureCredential  # Functions 実行時だけ必要
            credential = DefaultAzureCredential()
        self._cred = credential

    @classmethod
    def from_env(cls) -> "ApiCenterClient":
        e = os.environ
        return cls(e["AZURE_SUBSCRIPTION_ID"], e.get("APIC_RESOURCE_GROUP", "magate-rg"),
                   e.get("APIC_SERVICE_NAME", "magate-apic"), e["APIC_API_VERSION"])

    def _request(self, method: str, url: str, body: dict | None = None) -> dict:
        if not url.startswith("http"):
            url = f"{self.base}{url}?api-version={self.api_version}"
        token = self._cred.get_token(f"{ARM}/.default").token
        data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            text = r.read().decode("utf-8")
        return json.loads(text) if text else {}

    def list_apis(self) -> list[dict]:
        out, page = [], self._request("GET", "/apis")
        while True:
            out += page.get("value", [])
            if not page.get("nextLink"):
                return out
            page = self._request("GET", page["nextLink"])

    def runtime_url(self, api_name: str) -> str | None:
        """資産のデプロイに登録されたランタイムURL（MCPサーバのURL）を返す。"""
        for d in self._request("GET", f"/apis/{api_name}/deployments").get("value", []):
            uris = ((d.get("properties") or {}).get("server") or {}).get("runtimeUri") or []
            if uris:
                return uris[0]
        return None

    def update_custom_properties(self, api_name: str, new: dict) -> None:
        """現在の内容を取得し、カスタムメタデータだけを差し替えて上書きする（他の項目は変えない）。"""
        cur = self._request("GET", f"/apis/{api_name}")
        props = cur.get("properties") or {}
        props["customProperties"] = {**(props.get("customProperties") or {}), **new}
        self._request("PUT", f"/apis/{api_name}", {"properties": props})
