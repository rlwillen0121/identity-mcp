# identity-mcp contract

One Go module, five stdio MCP servers for OpenCode.

- Module: `github.com/rlwillen0121/identity-mcp`
- SDK: `github.com/modelcontextprotocol/go-sdk` v1.8 (`mcp.AddTool`, `mcp.StdioTransport`)
- Shared helpers: `internal/idmcp`
- Logs go to **stderr only**. stdout is the MCP wire.
- Read-only tools. No create/update/delete.
- Secrets only from env. Never print tokens (`OKTA_API_TOKEN`, `AZURE_CLIENT_SECRET`, `LUMOS_API_TOKEN`, `SAILPOINT_CLIENT_SECRET`, `C1_CLIENT_SECRET`).

## Shared API (`internal/idmcp`)

```go
idmcp.NewClient(baseURL string, header http.Header) *idmcp.Client
(*Client).GetJSON(ctx, path string, query url.Values, dest any) (http.Header, error)
(*Client).Get(ctx, path string, query url.Values) ([]byte, http.Header, error)
(*Client).PostForm(ctx, rawURL string, form url.Values) ([]byte, error)
(*Client).PostJSON(ctx, path string, body any, dest any) (http.Header, error) // relative paths only; search-only POST (SailPoint /search and ConductorOne /api/v1/search/*)
idmcp.LinkHeader(hdr http.Header, rel string) string
idmcp.ClampLimit(n int) int // default 50, max 200
idmcp.ClampSize(n, max int) int
idmcp.ParseIntCursor(s string) (int, error)
idmcp.NextPage(page, pages int) string
idmcp.NextOffset(offset, n, limit int) string
idmcp.ReadOnly(title string) *mcp.ToolAnnotations
idmcp.NewServer(name, version string) *mcp.Server
idmcp.RunStdio(server *mcp.Server)
idmcp.MustEnv(keys ...string)
idmcp.Page[T] { Items []T; Next string; Truncated bool }
```

`PostJSON` is a read: SailPoint `POST /search` and ConductorOne search POSTs (`/api/v1/search/*`) only. It refuses absolute URLs the same way `Get` does. Do not add generic mutating POST helpers.

`Page` is still the list envelope. Integer `next` cursors are opaque decimal strings (Lumos `page`, SailPoint `offset`), never URLs. ConductorOne `next` is the opaque `nextPageToken` string, not an integer.

Tool registration pattern:

```go
mcp.AddTool(server, &mcp.Tool{
    Name:        "list_users",
    Title:       "List users",
    Description: "...",
    Annotations: idmcp.ReadOnly("List users"),
}, handler)
```

Handler shape:

```go
func(ctx context.Context, req *mcp.CallToolRequest, in Input) (*mcp.CallToolResult, Output, error)
```

## OpenCode

Local stdio. Command is the built binary. Env vars interpolated with `{env:NAME}`.
