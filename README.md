# identity-mcp

[![test](https://github.com/rlwillen0121/identity-mcp/actions/workflows/test.yml/badge.svg)](https://github.com/rlwillen0121/identity-mcp/actions/workflows/test.yml)
[![Go 1.26+](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Two read-only [MCP](https://modelcontextprotocol.io) servers that let a coding agent answer questions about your identity provider — who can reach which app, which accounts went stale, who holds an admin role — without giving it any way to change them.

| Binary | API | Covers |
| --- | --- | --- |
| `okta-mcp` | Okta Management API | Users, groups, apps, admins, System Log |
| `entra-mcp` | Microsoft Graph | Users, groups, directory roles, service principals, sign-ins |

> [!IMPORTANT]
> Every tool is a read. There are no create, update, or delete paths in the codebase, the servers never ask for write scopes, and tokens come from the environment and are never logged. See [SECURITY.md](SECURITY.md).

## Quickstart

Install the binaries — requires **Go 1.26+**, no other runtime dependencies:

```bash
go install github.com/rlwillen0121/identity-mcp/cmd/okta-mcp@latest
go install github.com/rlwillen0121/identity-mcp/cmd/entra-mcp@latest
```

Export a read-only token for whichever directory you use:

```bash
export OKTA_ORG_URL="https://your-org.okta.com"
export OKTA_API_TOKEN="…"        # Admin → Security → API → Tokens
```

Point your agent at the server. For OpenCode, in `opencode.json`:

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

Then ask for something you would otherwise click through four admin screens to get:

> Which Okta admins haven't signed in for 90 days?

The agent calls `list_admins`, follows up with `find_stale_users`, and answers from structured JSON — no scraping, no write access, no console.

> [!TIP]
> Binaries must be on `PATH`. If they are not, use an absolute path in `command` — `$(go env GOPATH)/bin/okta-mcp`.

## Tools

Deliberately small sets. Every tool a host loads costs context on every turn, so these cover the questions that actually come up in access reviews rather than wrapping the whole API.

**`okta-mcp`**

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
| `find_stale_users` | Never logged in, dormant past N days, or provisioning expired |
| `list_logs` | System Log (cap 100) |

**`entra-mcp`**

| Tool | Use when |
| --- | --- |
| `list_users` | Search/page users (`$search` / `$filter`) |
| `get_user` | Profile plus up to 50 `memberOf` groups |
| `list_user_groups` | Groups for one user |
| `list_groups` | Find groups |
| `list_group_members` | Members (user / group / servicePrincipal) |
| `list_directory_roles` | Activated directory roles |
| `list_role_members` | Who holds a directory role |
| `list_service_principals` | Non-human identities and enterprise apps |
| `find_stale_users` | Disabled, never signed in, or last sign-in past N days |
| `list_sign_ins` | Audit sign-in rows (cap 50) |

## Configuration

### Okta

| Variable | Meaning |
| --- | --- |
| `OKTA_ORG_URL` | `https://your-org.okta.com` |
| `OKTA_API_TOKEN` | SSWS API token (Admin → Security → API → Tokens) |

The token needs read on users, groups, apps, and logs. `list_admins` additionally needs an admin token with IAM role read — `okta.roles.read` if you use OAuth rather than SSWS.

### Entra ID

Register an app, use **client credentials**, and grant these Microsoft Graph *application* permissions with admin consent:

- `Directory.Read.All` — users, groups, roles, service principals
- `AuditLog.Read.All` — sign-in logs and `signInActivity` (needed for stale users)

| Variable | Meaning |
| --- | --- |
| `AZURE_TENANT_ID` | Tenant GUID |
| `AZURE_CLIENT_ID` | App (client) id |
| `AZURE_CLIENT_SECRET` | Client secret |
| `GRAPH_BASE_URL` | Optional, defaults to `https://graph.microsoft.com/v1.0` |

> [!NOTE]
> If your tenant rejects `signInActivity` — it needs the right license and returns 400 without it — `list_users` and `get_user` automatically retry without that field rather than failing.

## Keeping credentials away from coding agents

An agent that can edit your repo should not also hold a live directory token. The two jobs run in separate lanes, enforced by host permissions rather than by asking the model nicely:

| Agent | Kind | May edit source | May call Okta/Entra |
| --- | --- | --- | --- |
| `orchestrate` | primary | no | no |
| `implement` | subagent | yes | no |
| `review` | subagent | no | no |
| `iga-operator` | primary | no | **yes** |

Contributor agents get the MCP servers switched **off**; only `iga-operator` gets them on. Tab to `iga-operator` for directory work and back for code. Full rules in [AGENTS.md](AGENTS.md).

## Host setup

Copy the example matching your host. Secrets are passed by environment reference — never paste a token into these files.

<details>
<summary><b>OpenCode</b> — <code>opencode.json</code></summary>

Start from [`examples/opencode.json`](examples/opencode.json). The repo-root [`opencode.json`](opencode.json) is a working copy that also wires up the lane split above using the schema's `agent` and `permission` keys.

</details>

<details>
<summary><b>Claude Code</b> — <code>.mcp.json</code>, <code>.claude/</code></summary>

Copy [`examples/claude.mcp.json`](examples/claude.mcp.json) to `.mcp.json`, [`examples/claude.settings.json`](examples/claude.settings.json) to `.claude/settings.json`, and [`examples/claude.agents/`](examples/claude.agents/) to `.claude/agents/`.

</details>

<details>
<summary><b>Codex</b> — <code>~/.codex/config.toml</code></summary>

Merge [`examples/codex.config.toml`](examples/codex.config.toml) into `~/.codex/config.toml`. Codex does not gate MCP servers per agent, so keep the identity tools out of coding sessions by convention.

</details>

## Design notes

- **Transport** is stdio. Logs go to stderr; stdout is the MCP wire and is never printed to.
- **Annotations** — every tool is marked `readOnlyHint`, `idempotentHint`, and `openWorldHint`, so hosts can reason about safety without special-casing.
- **Pagination** — Okta uses `after` cursors parsed from `Link: rel=next`; Graph uses `$skiptoken` from `@odata.nextLink`. Cursors are opaque: absolute URLs are rejected rather than followed.
- **Page sizes** default to 50 and cap at 200, with tighter caps on logs (100) and sign-ins (50).
- **No vendor SDKs** — just `net/http` and the official [`go-sdk`](https://github.com/modelcontextprotocol/go-sdk), which keeps the dependency surface small and the failure modes visible.

## Development

```bash
go test ./...
```

HTTP is mocked with `httptest`; the suite makes no live Okta or Graph calls.

## Security

These are local stdio processes that hold directory tokens in memory. Use least-privilege read-only credentials, keep secrets in the environment, and do not expose the binaries as remote MCP without putting your own authentication in front. [SECURITY.md](SECURITY.md) covers the full posture and how to report a vulnerability.

## Contributing

[CONTRACT.md](CONTRACT.md) defines the module contract — shared `internal/idmcp` helpers, stderr-only logging, read-only tools — and [AGENTS.md](AGENTS.md) covers the agent lanes. Run `go test ./...` before opening a PR.

---

MIT licensed. See [LICENSE](LICENSE).
