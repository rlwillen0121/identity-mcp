# identity-mcp contract

One Go module: five read-only-by-default stdio MCP servers (`okta-mcp`, `entra-mcp`, `lumos-mcp`, `sailpoint-mcp`, `c1-mcp`) with opt-in `--enable-writes` (`IDENTITY_MCP_ENABLE_WRITES=1`) write tools, and one companion zero-trust authorization proxy (`mcp-authz-gateway`).

- Module: `github.com/rlwillen0121/identity-mcp`
- SDK: `github.com/modelcontextprotocol/go-sdk` v1.8 (`mcp.AddTool`, `mcp.StdioTransport`)
- Shared helpers: `internal/idmcp` (upstream servers) and `internal/authz` (`mcp-authz-gateway` policy/JCS/step-up/ledger engine; see [`SPEC-mcp-authz-gateway.md`](SPEC-mcp-authz-gateway.md))
- Logs go to **stderr only**. stdout is the MCP wire.
- The five upstream servers (`okta-mcp`, `entra-mcp`, `lumos-mcp`, `sailpoint-mcp`, `c1-mcp`) register only their 10 read-only tools by default (`NewServer(client)`). Passing `--enable-writes` or `IDENTITY_MCP_ENABLE_WRITES=1` (`NewServerWithOptions(client, true)`) registers 2 opt-in write tools per provider. Any write-enabled server must run behind `mcp-authz-gateway` under a fail-closed policy and pinned lockfile (`examples/authz/`).
- Secrets only from env. Never print tokens (`OKTA_API_TOKEN`, `AZURE_CLIENT_SECRET`, `LUMOS_API_TOKEN`, `SAILPOINT_CLIENT_SECRET`, `C1_CLIENT_SECRET`).

## Shared API (`internal/idmcp`)

```go
idmcp.NewClient(baseURL string, header http.Header) *idmcp.Client
(*Client).GetJSON(ctx, path string, query url.Values, dest any) (http.Header, error)
(*Client).Get(ctx, path string, query url.Values) ([]byte, http.Header, error)
(*Client).PostForm(ctx, rawURL string, form url.Values) ([]byte, error)
(*Client).PostJSON(ctx, path string, body any, dest any) (http.Header, error) // relative paths only; search-only POST (SailPoint /search and ConductorOne /api/v1/search/*)
(*Client).DoWriteJSON(ctx, method, path string, query url.Values, body any, dest any) (http.Header, error) // PUT/POST/PATCH/DELETE for opt-in --enable-writes tools
idmcp.LinkHeader(hdr http.Header, rel string) string
idmcp.ClampLimit(n int) int // default 50, max 200
idmcp.ClampSize(n, max int) int
idmcp.ParseIntCursor(s string) (int, error)
idmcp.NextPage(page, pages int) string
idmcp.NextOffset(offset, n, limit int) string
idmcp.ReadOnly(title string) *mcp.ToolAnnotations
idmcp.Write(title string, idempotent, destructive bool) *mcp.ToolAnnotations
idmcp.WritesEnabled(args []string) bool
idmcp.NewServer(name, version string) *mcp.Server
idmcp.RunStdio(server *mcp.Server)
idmcp.MustEnv(keys ...string)
idmcp.Require(name, value string) error // rejects empty/whitespace, "." / ".." segments, and ASCII control chars
idmcp.Page[T] { Items []T; Next string; Truncated bool }
```

`PostJSON` is a read: SailPoint `POST /search` and ConductorOne search POSTs (`/api/v1/search/*`) only. `DoWriteJSON` is reserved exclusively for opt-in `--enable-writes` tools (`PUT`, `POST`, `PATCH`, `DELETE`). All relative-path helpers (`Get`, `PostJSON`, `DoWriteJSON`) refuse absolute URLs, scheme-relative (`//`) paths, and `.` / `..` dot-segments (`%2e` / `%2e%2e`). All HTTP calls (`Get`, `PostJSON`, `DoWriteJSON`, `PostForm`) disable HTTP redirects (`http.ErrUseLastResponse`) so `Authorization` headers and credentials are never forwarded across redirects, and `PostForm` scrubs `client_secret` from all error surfaces.

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

## Companion Authorization Gateway API (`internal/authz` & `cmd/mcp-authz-gateway`)

 Normative specification: [`SPEC-mcp-authz-gateway.md`](SPEC-mcp-authz-gateway.md).

```go
authz.LoadAndValidatePolicy(policyPath string) (*authz.PolicyV1, error)
authz.ParseAndValidatePolicyBytes(policyPath string, rawBytes []byte) (*authz.PolicyV1, error)
authz.InitState(pol *authz.PolicyV1, now time.Time) (string, error)
authz.PinUpstreamCLI(ctx context.Context, opts authz.PinOptions) (*authz.ManifestLockfileV1, error)
authz.ServeStdio(ctx context.Context, policyPath string) error
authz.NewGateway(ctx context.Context, pol *authz.PolicyV1, lockfile *authz.ManifestLockfileV1, ledger *authz.StateLedger, upstream *mcp.ClientSession, secretEnvValues []string, clock func() time.Time) (*authz.Gateway, error)
authz.SignApprovalFromCLI(opts authz.ApproveOptions) (string, error)
authz.VerifyAuditCLI(pol *authz.PolicyV1) (int64, string, error)
authz.RepairLedgerCLI(pol *authz.PolicyV1, now time.Time) error
authz.RevokeGrantCLI(pol *authz.PolicyV1, subjectID, entitlementID, operatorSub, ticketID string, now time.Time) error
```

Key gateway invariants:
- **TCB File Verification:** `OpenVerifiedFile` opens all policy, lockfile, ledger, env, key, and binary files with `O_NOFOLLOW`, rejects hardlinks (`nlink > 1`), verifies local filesystem mount flags (`MNT_LOCAL` on Darwin, `f_type` denylist on Linux), and walks every ancestor directory to `/`.
- **Canonicalization:** All tool manifests, intent preimages, state records, and audit records are serialized with RFC 8785 JCS (`MarshalJCS`) and decoded via `DecodeStrictJSON` (rejecting duplicate keys, ASCII case-colliding keys, integers outside IEEE-754 `int53`, and C0/C1/Bidi control characters).
- **Zero-Trust Mediation:** Only `initialize`, `notifications/initialized`, `ping`, `notifications/cancelled`, `tools/list`, and `tools/call` are permitted on the host session; `_authz` is stripped before upstream forwarding; and upstream responses are validated and scanned by `SecretScanner`.

## OpenCode

Local stdio. Command is the built binary. Env vars interpolated with `{env:NAME}`.

