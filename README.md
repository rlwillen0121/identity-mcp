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

The default repository profiles are contributor-safe: they start no enabled
identity MCP process. Do not export directory credentials in a coding shell. For a
directory read, use a separate operator process and the explicit operator
profile described below.

```bash
# Example contributor launch: remove any inherited IdP variables first.
env -u OKTA_ORG_URL -u OKTA_API_TOKEN \
  -u AZURE_TENANT_ID -u AZURE_CLIENT_ID -u AZURE_CLIENT_SECRET \
  -u GRAPH_BASE_URL -u OPENCODE_CONFIG -u OPENCODE_CONFIG_DIR \
  -u OPENCODE_CONFIG_CONTENT opencode

# Claude contributor launch: use only the empty MCP profile, even if a global
# Claude MCP configuration exists on the host.
env -u OKTA_ORG_URL -u OKTA_API_TOKEN \
  -u AZURE_TENANT_ID -u AZURE_CLIENT_ID -u AZURE_CLIENT_SECRET \
  -u GRAPH_BASE_URL claude --setting-sources project \
  --strict-mcp-config --mcp-config examples/claude.mcp.json
```

For an operator-only read, load `examples/opencode.operator.json` from a
separate process when both providers are configured. If only one provider is
configured, use `examples/opencode.okta.operator.json` or
`examples/opencode.entra.operator.json`; each starts only its selected server.
Never combine an operator profile with a contributor process or
repository-editing agent.

Then, in that operator process, ask for something you would otherwise click
through four admin screens to get:

> Which Okta admins haven't signed in for 90 days?

The agent calls `list_admins`, follows up with `find_stale_users`, and answers
from structured JSON — no scraping, no write access, no console.

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
| `OKTA_ORG_URL` | `https://your-org.okta.com`; production must use an HTTPS Okta domain |
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
| `GRAPH_BASE_URL` | Optional, defaults to `https://graph.microsoft.com/v1.0`; production must use `https://graph.microsoft.com/v1.0` or `/beta` |

> [!NOTE]
> If your tenant rejects `signInActivity` — it needs the right license and returns 400 without it — `list_users` and `get_user` automatically retry without that field rather than failing. Stale-user output then marks `last_sign_in` as unknown and returns only evidence it can support; it must not infer a date. Any `truncated` result is incomplete evidence and must be paged or explicitly reported as incomplete.

## Keeping credentials away from coding agents

An agent that can edit your repo should not also hold a live directory token.
The profiles and process launch boundary make that separation explicit where the
host supports it; a tool-deny rule alone is not a credential boundary.

| Agent | Kind | May edit source | May call Okta/Entra |
| --- | --- | --- | --- |
| `orchestrate` | primary | no | no |
| `implement` | subagent | yes | no |
| `review` | subagent | no | no |
| `iga-operator` | primary | no | **yes** |

Contributor profiles contain no enabled IdP MCP servers. Only the explicit
operator profile starts `okta-mcp` or `entra-mcp`. Run it separately, with credentials
loaded from a protected local source, and unset all IdP variables before any
contributor launch. Full rules in [AGENTS.md](AGENTS.md).

## Host setup

Copy the example matching your host. Secrets are passed by environment reference — never paste a token into these files.

For the operator process, keep the variables in a mode-600 file outside the
repository (for example, `~/.config/identity-mcp/operator.env`) and pass only
the selected names through a clean environment. This prevents an inherited
shell value from silently changing the tenant or endpoint:

```bash
set -a; . "$HOME/.config/identity-mcp/operator.env"; set +a

# Okta-only operator process: the Entra server is not enabled or started.
env -i HOME="$HOME" PATH="$PATH" \
  OKTA_ORG_URL="$OKTA_ORG_URL" OKTA_API_TOKEN="$OKTA_API_TOKEN" \
  OPENCODE_CONFIG="$PWD/examples/opencode.okta.operator.json" opencode

# Entra-only operator process: the Okta server is not enabled or started.
env -i HOME="$HOME" PATH="$PATH" \
  AZURE_TENANT_ID="$AZURE_TENANT_ID" AZURE_CLIENT_ID="$AZURE_CLIENT_ID" \
  AZURE_CLIENT_SECRET="$AZURE_CLIENT_SECRET" GRAPH_BASE_URL="$GRAPH_BASE_URL" \
  OPENCODE_CONFIG="$PWD/examples/opencode.entra.operator.json" opencode
```

The combined operator profile starts both servers and therefore requires both
credential sets; use the provider-specific profiles above when only one
provider is configured. Do not reuse this launch environment for a contributor
session.

<details>
<summary><b>OpenCode</b> — <code>opencode.json</code></summary>

Start from the contributor-safe [`examples/opencode.json`](examples/opencode.json)
or the repo-root [`opencode.json`](opencode.json). They define the known IdP
servers as disabled and provide no credentials. For explicit operator work, use [`examples/opencode.operator.json`](examples/opencode.operator.json)
in a separate process when both providers are configured. For a single
provider, use [`examples/opencode.okta.operator.json`](examples/opencode.okta.operator.json)
or [`examples/opencode.entra.operator.json`](examples/opencode.entra.operator.json).
The host's config-selection mechanism must point to one operator file rather
than merging it into the contributor profile.

</details>

<details>
<summary><b>Claude Code</b> — <code>.mcp.json</code>, <code>.claude/</code></summary>

Copy the contributor-safe [`examples/claude.mcp.json`](examples/claude.mcp.json)
to `.mcp.json`, [`examples/claude.settings.json`](examples/claude.settings.json)
to `.claude/settings.json`, and [`examples/claude.agents/`](examples/claude.agents/)
to `.claude/agents/`. It disables project MCP by default. For operator work,
pass [`examples/claude.operator.mcp.json`](examples/claude.operator.mcp.json)
with Claude Code's `--strict-mcp-config`,
`--settings examples/claude.operator.settings.json`, and `--agent iga-operator`
in a separate process when both providers are configured. For one provider,
pass [`examples/claude.okta.operator.mcp.json`](examples/claude.okta.operator.mcp.json)
or [`examples/claude.entra.operator.mcp.json`](examples/claude.entra.operator.mcp.json)
instead. For the single-provider case, use the corresponding clean environment
invocation (after sourcing the protected operator env file above):

```bash
env -i HOME="$HOME" PATH="$PATH" \
  OKTA_ORG_URL="$OKTA_ORG_URL" OKTA_API_TOKEN="$OKTA_API_TOKEN" \
  claude --setting-sources project --strict-mcp-config \
  --mcp-config examples/claude.okta.operator.mcp.json \
  --settings examples/claude.operator.settings.json --agent iga-operator

env -i HOME="$HOME" PATH="$PATH" \
  AZURE_TENANT_ID="$AZURE_TENANT_ID" AZURE_CLIENT_ID="$AZURE_CLIENT_ID" \
  AZURE_CLIENT_SECRET="$AZURE_CLIENT_SECRET" \
  claude --setting-sources project --strict-mcp-config \
  --mcp-config examples/claude.entra.operator.mcp.json \
  --settings examples/claude.operator.settings.json --agent iga-operator
```

Do not use an operator MCP file for contributor work.

</details>

<details>
<summary><b>Codex</b> — <code>~/.codex/config.toml</code></summary>

Merge the contributor-only [`examples/codex.config.toml`](examples/codex.config.toml)
into `~/.codex/config.toml`. It has no identity MCP servers. Codex does not
provide a per-agent MCP boundary; use [`examples/codex.operator.config.toml`](examples/codex.operator.config.toml)
only in a separate operator process when both providers are configured. For one
provider, use [`examples/codex.okta.operator.config.toml`](examples/codex.okta.operator.config.toml)
or [`examples/codex.entra.operator.config.toml`](examples/codex.entra.operator.config.toml).

</details>

## Design notes

- **Transport** is stdio. Logs go to stderr; stdout is the MCP wire and is never printed to.
- **Annotations** — every tool is marked `readOnlyHint`, `idempotentHint`, and `openWorldHint`, so hosts can reason about safety without special-casing.
- **Pagination** — Okta uses `after` cursors parsed from `Link: rel=next`; Graph uses `$skiptoken` from `@odata.nextLink`. Graph absolute next links are accepted only when they match the configured public `graph.microsoft.com` authority and exact collection path; the client extracts and replays their query values rather than fetching an arbitrary URL. Other absolute cursors are rejected.
- **Endpoint boundary** — shipped entrypoints accept HTTPS vendor endpoints only: recognized Okta domains (without a path, port, query, or fragment) and the public Microsoft Graph authority at `/v1.0` or `/beta`. Custom/private or sovereign Graph-compatible endpoints are rejected by the commands; trusted tests can opt in only through an explicitly injected client. Do not put endpoint overrides in contributor profiles.
- **Page sizes** default to 50 and cap at 200, with tighter caps on logs (100) and sign-ins (50).
- **No vendor SDKs** — just `net/http` and the official [`go-sdk`](https://github.com/modelcontextprotocol/go-sdk), which keeps the dependency surface small and the failure modes visible.

## Development

```bash
go test ./...
```

HTTP is mocked with `httptest`; the suite makes no live Okta or Graph calls.

## Security

These are local stdio processes that hold directory tokens in memory. Use
least-privilege read-only credentials, keep secrets in a protected operator
environment, and do not expose the binaries as remote MCP without putting your
own authentication in front. [SECURITY.md](SECURITY.md) covers the full
posture, endpoint opt-in, incomplete-evidence behavior, and reporting.

## Contributing

[CONTRACT.md](CONTRACT.md) defines the module contract — shared `internal/idmcp` helpers, stderr-only logging, read-only tools — and [AGENTS.md](AGENTS.md) covers the agent lanes. Run `go test ./...` before opening a PR.

---

MIT licensed. See [LICENSE](LICENSE).
