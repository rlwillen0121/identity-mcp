# identity-mcp

[![test](https://github.com/rlwillen0121/identity-mcp/actions/workflows/test.yml/badge.svg)](https://github.com/rlwillen0121/identity-mcp/actions/workflows/test.yml)
[![Go 1.26+](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Two **read-only** [MCP](https://modelcontextprotocol.io) servers in Go for identity work in [OpenCode](https://opencode.ai/docs/mcp-servers/):

| Binary | API | Covers |
| --- | --- | --- |
| `okta-mcp` | Okta Management API | Users, groups, apps, admins, System Log |
| `entra-mcp` | Microsoft Graph | Entra users, groups, directory roles, service principals, sign-ins |

Official [`go-sdk`](https://github.com/modelcontextprotocol/go-sdk), **stdio** transport, typed tools with `readOnlyHint`, structured JSON output. Small tool sets on purpose — OpenCode loads every tool into context.

No writes. No Okta/Graph SDKs. Tokens stay in env.

## Install

Requires **Go 1.26+**. No other runtime dependencies.

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

## Agent lanes

Contributor work and operator work run in separate lanes, so that coding agents never hold live IdP credentials and the operator agent never edits the repo.

| Agent | Kind | Job |
| --- | --- | --- |
| `orchestrate` | primary | Coordinate contributors. No source edits, no IdP MCP. |
| `implement` | subagent | Write Go/tests. |
| `review` | subagent | Compose hidden lanes: rules, security, completeness, eng-core, mcp. |
| `iga-operator` | primary | Live Okta/Entra reads. No repo edits. |

See [AGENTS.md](AGENTS.md). Hidden `lane-*` agents stay off operator chat.

## Configure your host

Copy the example that matches your host. Secrets are passed by env reference — never paste tokens into these files.

| Host | Example | Drop in |
| --- | --- | --- |
| OpenCode | [`examples/opencode.json`](examples/opencode.json) | `opencode.json` |
| Claude Code | [`examples/claude.mcp.json`](examples/claude.mcp.json), [`examples/claude.settings.json`](examples/claude.settings.json), [`examples/claude.agents/`](examples/claude.agents/) | `.mcp.json`, `.claude/settings.json`, `.claude/agents/` |
| Codex | [`examples/codex.config.toml`](examples/codex.config.toml) | `~/.codex/config.toml` (merge) |

A minimal OpenCode MCP block:

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
    }
  }
}
```

Binaries must be on `PATH` (`go install ./cmd/okta-mcp ./cmd/entra-mcp`); otherwise give an absolute path in `command`.

OpenCode keeps Okta/Entra MCP **off** for contributor agents and **on** only for `iga-operator` — tab to `iga-operator` for directory work. The repo-root [`opencode.json`](opencode.json) wires this up with the schema's `agent` + `permission` keys. Codex does not gate MCP per lane; keep IdP tools off coding sessions by convention.

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

## Security

These are local stdio processes that hold IdP tokens in memory. Use least-privilege read-only credentials, keep secrets in env, and do not expose the binaries as remote MCP without your own auth layer. See [SECURITY.md](SECURITY.md) for the full posture and how to report a vulnerability.

## Contributing

[CONTRACT.md](CONTRACT.md) defines the module contract — shared `internal/idmcp` helpers, stderr-only logging, read-only tools. [AGENTS.md](AGENTS.md) covers the agent lanes. Run `go test ./...` before opening a PR.

## License

MIT. See [LICENSE](LICENSE).
