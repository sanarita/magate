# 公式リモートMCPサーバ調査（2026-10-12）

maGATE で主要な公式リモートMCPサーバ18件を調査したデータです。結果のまとめはリポジトリ直下の [README](../../README.md#実在サーバの調査結果2026年10月) を参照してください。

| ファイル | 内容 |
|---|---|
| `targets.json` | 調査対象18件のURL・運営元・認証方式 |
| `snaps/` | `magate snapshot` で取得したデータ（OAuthメタデータ・ツール一覧） |
| `cors.md` | `magate cors-check` の結果（ブラウザ版「URLから取得」の対応状況） |

- トークンは使わず、公開情報のみを取得しています。ツールは実行していません。
- メタデータは提供元が随時変更するため、調査日時点の記録です。

## 再現手順

```powershell
uv run python -m magate cors-check --targets research/2026-10-remote-mcp/targets.json -o out/cors.md
uv run python -m magate snapshot --url <URL> -o snaps/<名前>.json
```
