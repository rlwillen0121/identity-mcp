# identity-mcp

Two **read-only** [MCP](https://modelcontextprotocol.io) servers in Go for identity work in [OpenCode](https://opencode.ai/docs/mcp-servers/):

| Binary | Directory | Speaks to |
| --- | --- | --- |
| `okta-mcp` | Okta Management API | Users, groups, apps, admins, System Log |
| `entra-mcp` | Microsoft Graph | Entra users, groups, directory roles, service principals, sign-ins |

Official [`go-sdk`](https://github.com/modelcontextprotocol/go-sdk), **stdio** transport, typed tools with `readOnlyHint`, structured JSON output. Small tool sets on purpose — OpenCode loads every tool into context.

No writes. No Okta/Graph SDKs. Tokens stay in env.

## Install

```bash
git clone https://github.com/rlwillen0121/identity-mcp.git
cd identity-mcp
go install ./cmd/okta-mcp ./cmd/entra-mcp
```

Binaries land on `$(go env GOPATH)/bin`. Or:

```bash
go build -o okta-mcp ./cmd/okta-mcp
go build -o entra-mcp ./cmd/entra-mcp
```

## OpenCode

Add to `~/.config/opencode/opencode.json` or a project `opencode.json`. Secrets via `{env:…}` — do not paste tokens into the file.

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "okta": {
      "type": "local",
      "command": ["okta-mcp"],
      "enabled": true,
      "timeout": 15000,
      "environment": {
        "OKTA_ORG_URL": "{env:OKTA_ORG_URL}",
        "OKTA_API_TOKEN": "{env:OKTA_API_TOKEN}"
      }
    },
    "entra": {
      "type": "local",
      "command": ["entra-mcp"],
      "enabled": true,
      "timeout": 15000,
      "environment": {
        "AZURE_TENANT_ID": "{env:AZURE_TENANT_ID}",
        "AZURE_CLIENT_ID": "{env:AZURE_CLIENT_ID}",
        "AZURE_CLIENT_SECRET": "{env:AZURE_CLIENT_SECRET}"
      }
    }
  }
}
```

If `okta-mcp` / `entra-mcp` are not on `PATH`, use the absolute path from `go install`.

Then: `use okta` / `use entra` in a prompt, or name the server (`okta`, `entra`).

## Okta

Env:

| Variable | Meaning |
| --- | --- |
| `OKTA_ORG_URL` | `https://your-org.okta.com` |
| `OKTA_API_TOKEN` | SSWS API token (Admin → Security → API → Tokens) |

Token needs read on users, groups, apps, logs. `list_admins` needs an admin token with IAM/role read (`okta.roles.read` if you use OAuth instead of SSWS).

| Tool | Use when |
| --- | --- |
| `list_users` | Search the directory (`search` / `filter`, page with `after`) |
| `get_user` | You already have an id or login |
| `list_user_groups` | Groups for one user |
| `list_groups` | Find a group by name |
| `list_group_users` | Members of a group |
| `list_apps` | Find an SSO app |
| `list_app_users` | Who is assigned to an app |
| `list_admins` | Privileged-access review (IAM assignees) |
| `find_stale_users` | No login / login older than N days / staged-provisioned-expired |
| `list_logs` | System Log (cap 100) |

## Entra ID

App registration, **client credentials**, Microsoft Graph application permissions (admin consent):

- `Directory.Read.All` — users, groups, roles, service principals
- `AuditLog.Read.All` — sign-in logs and `signInActivity` (stale users)

Env:

| Variable | Meaning |
| --- | --- |
| `AZURE_TENANT_ID` | Tenant GUID |
| `AZURE_CLIENT_ID` | App (client) id |
| `AZURE_CLIENT_SECRET` | Client secret |
| `GRAPH_BASE_URL` | Optional, default `https://graph.microsoft.com/v1.0` |

| Tool | Use when |
| --- | --- |
| `list_users` | Search/page users (`$search` / `$filter`) |
| `get_user` | Profile plus up to 50 `memberOf` groups |
| `list_user_groups` | Groups for one user |
| `list_groups` | Find groups |
| `list_group_members` | Members (user / group / servicePrincipal) |
| `list_directory_roles` | Activated directory roles |
| `list_role_members` | Who holds a directory role |
| `list_service_principals` | NHI / enterprise apps |
| `find_stale_users` | Disabled, never signed in, or last sign-in older than N days |
| `list_sign_ins` | Audit sign-in rows (cap 50) |

If Graph rejects `signInActivity` (license / 400), list/get user retry without it.

## MCP notes

- Transport: stdio. Logs go to stderr. Do not print on stdout.
- Tools are annotated `readOnlyHint=true`, `idempotentHint=true`, `openWorldHint=true`.
- Pagination: Okta `after` (from `Link: rel=next`). Graph `$skiptoken` / `@odata.nextLink`.
- Default page size 50, max 200 (logs/sign-ins are tighter).

## Tests

```bash
go test ./...
```

HTTP is mocked with `httptest`. No live Okta/Graph calls.

## License

MIT. See [LICENSE](LICENSE).
