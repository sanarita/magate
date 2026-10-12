# ブラウザ版「URLから取得」の対応状況

- 調査元（Origin）：`https://sanarita.github.io`

| 接続先 | 結果 | ツール数 |
|---|---|---|
| `https://learn.microsoft.com/api/mcp` | 可 | 3 |
| `https://docs.mcp.cloudflare.com/mcp` | 不可（CORS） | - |
| `https://mcp.deepwiki.com/mcp` | 可 | 3 |
| `https://huggingface.co/mcp` | 可 | 4 |
| `https://mcp.svc.cloud.microsoft/enterprise` | 不可（CORS） | - |
| `https://api.githubcopilot.com/mcp/` | 接続可・ツール一覧は認証が必要 | - |
| `https://api.githubcopilot.com/mcp/readonly` | 接続可・ツール一覧は認証が必要 | - |
| `https://mcp.box.com` | 不可（CORS：応答がブラウザに渡らない） | - |
| `https://mcp.atlassian.com/v2/mcp` | 接続可・ツール一覧は認証が必要 | - |
| `https://mcp.notion.com/mcp` | 接続可・ツール一覧は認証が必要 | - |
| `https://mcp.linear.app/mcp` | 接続可・ツール一覧は認証が必要 | - |
| `https://mcp.asana.com/sse` | 接続可・ツール一覧は認証が必要 | - |
| `https://mcp.sentry.dev/mcp` | 不可（CORS） | - |
| `https://mcp.stripe.com` | 不可（CORS） | - |
| `https://mcp.supabase.com/mcp?read_only=true` | 不可（CORS） | - |
| `https://mcp.vercel.com` | 不可（CORS） | - |
| `https://observability.mcp.cloudflare.com/sse` | 不可（CORS） | - |
| `https://mcp.airtable.com/mcp` | 不可（CORS） | - |

## 詳細

### https://learn.microsoft.com/api/mcp
- 事前確認（接続開始）: OK
- 接続開始: HTTP 200
- セッションID: ブラウザから読める
- 事前確認（ツール一覧）: OK
- ツール一覧: 3 件

### https://docs.mcp.cloudflare.com/mcp
- 事前確認（接続開始）: 事前確認(OPTIONS)が HTTP 403

### https://mcp.deepwiki.com/mcp
- 事前確認（接続開始）: OK
- 接続開始: HTTP 200
- 事前確認（ツール一覧）: OK
- ツール一覧: 3 件

### https://huggingface.co/mcp
- 事前確認（接続開始）: OK
- 接続開始: HTTP 200
- セッションID: ブラウザから読める
- 事前確認（ツール一覧）: OK
- ツール一覧: 4 件

### https://mcp.svc.cloud.microsoft/enterprise
- 事前確認（接続開始）: 事前確認(OPTIONS)が HTTP 401

### https://api.githubcopilot.com/mcp/
- 事前確認（接続開始）: OK
- 接続開始: HTTP 401

### https://api.githubcopilot.com/mcp/readonly
- 事前確認（接続開始）: OK
- 接続開始: HTTP 401

### https://mcp.box.com
- 事前確認（接続開始）: OK
- 接続開始: HTTP 401、応答に Access-Control-Allow-Origin がない

### https://mcp.atlassian.com/v2/mcp
- 事前確認（接続開始）: OK
- 接続開始: HTTP 401

### https://mcp.notion.com/mcp
- 事前確認（接続開始）: OK
- 接続開始: HTTP 401

### https://mcp.linear.app/mcp
- 事前確認（接続開始）: OK
- 接続開始: HTTP 401

### https://mcp.asana.com/sse
- 事前確認（接続開始）: OK
- 接続開始: HTTP 401

### https://mcp.sentry.dev/mcp
- 事前確認（接続開始）: Access-Control-Allow-Origin がない（ブラウザからの接続を許可していない）

### https://mcp.stripe.com
- 事前確認（接続開始）: Access-Control-Allow-Origin がない（ブラウザからの接続を許可していない）

### https://mcp.supabase.com/mcp?read_only=true
- 事前確認（接続開始）: Access-Control-Allow-Origin がない（ブラウザからの接続を許可していない）

### https://mcp.vercel.com
- 事前確認（接続開始）: Access-Control-Allow-Origin がない（ブラウザからの接続を許可していない）

### https://observability.mcp.cloudflare.com/sse
- 事前確認（接続開始）: 事前確認(OPTIONS)が HTTP 403

### https://mcp.airtable.com/mcp
- 事前確認（接続開始）: 事前確認(OPTIONS)が HTTP 404
