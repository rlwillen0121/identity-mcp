# identity-mcp contract

One Go module, two stdio MCP servers for OpenCode.

- Module: `github.com/rlwillen0121/identity-mcp`
- SDK: `github.com/modelcontextprotocol/go-sdk` v1.8 (`mcp.AddTool`, `mcp.StdioTransport`)
- Shared helpers: `internal/idmcp` — do not change unless necessary
- Logs go to **stderr only**. stdout is the MCP wire.
- Read-only tools. No create/update/delete.
- Secrets only from env. Never print tokens.

## Shared API (`internal/idmcp`)

```go
idmcp.NewClient(baseURL string, header http.Header) *idmcp.Client
(*Client).GetJSON(ctx, path string, query url.Values, dest any) (http.Header, error)
(*Client).Get(ctx, path string, query url.Values) ([]byte, http.Header, error)
(*Client).PostForm(ctx, rawURL string, form url.Values) ([]byte, error)
idmcp.LinkHeader(hdr http.Header, rel string) string
idmcp.ClampLimit(n int) int // default 50, max 200
idmcp.ReadOnly(title string) *mcp.ToolAnnotations
idmcp.NewServer(name, version string) *mcp.Server
idmcp.RunStdio(server *mcp.Server)
idmcp.MustEnv(keys ...string)
idmcp.Page[T] { Items []T; Next string; Truncated bool }
```

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
