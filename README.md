# identity-mcp

[![test](https://github.com/rlwillen0121/identity-mcp/actions/workflows/test.yml/badge.svg)](https://github.com/rlwillen0121/identity-mcp/actions/workflows/test.yml)
[![Go 1.26+](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![M8ven Score](https://m8ven.ai/badge/mcp/rlwillen0121/identity-mcp)](https://m8ven.ai/mcp/rlwillen0121/identity-mcp)

Five read-only [MCP](https://modelcontextprotocol.io) servers that let a coding agent answer identity-governance questions — who can reach which app, which accounts went stale, who holds privileged access — without giving it any way to change them.

| Binary | API | Covers |
| --- | --- | --- |
| `okta-mcp` | Okta Management API | Users, groups, apps, admins, System Log |
| `entra-mcp` | Microsoft Graph | Users, groups, directory roles, service principals, sign-ins |
| `lumos-mcp` | Lumos REST (`api.lumos.com`) | Users, app accounts, groups, access reviews, activity logs |
| `sailpoint-mcp` | SailPoint ISC **v2026** | Identities, accounts, entitlements, sources, search, account activities |
| `c1-mcp` | ConductorOne API (`/api/v1`) | Users, app accounts, entitlements, access reviews, tasks |

> [!IMPORTANT]
> Every tool is a read. There are no create, update, or delete paths in the codebase, the servers never ask for write scopes, and tokens come from the environment and are never logged. See [SECURITY.md](SECURITY.md).

## Quickstart

Install the binaries — requires **Go 1.26+**, no other runtime dependencies:

```bash
go install github.com/rlwillen0121/identity-mcp/cmd/okta-mcp@latest
go install github.com/rlwillen0121/identity-mcp/cmd/entra-mcp@latest
go install github.com/rlwillen0121/identity-mcp/cmd/lumos-mcp@latest
go install github.com/rlwillen0121/identity-mcp/cmd/sailpoint-mcp@latest
go install github.com/rlwillen0121/identity-mcp/cmd/c1-mcp@latest
```

Export credentials for the provider you use. For example, an Okta setup is:

```bash
export OKTA_ORG_URL="https://your-org.okta.com"
export OKTA_API_TOKEN="…"        # Admin → Security → API → Tokens
```

The other servers use the variables documented in [Configuration](#configuration): Entra ID uses client credentials, while Lumos, SailPoint ISC, and ConductorOne use their respective read-only credentials.

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

**`lumos-mcp`**

| Tool | Use when |
| --- | --- |
| `list_users` | Find people in Lumos (`search_term`, integer `page` cursor) |
| `get_user` | You already have a Lumos user id |
| `get_user_access` | What this person has: profile, Lumos roles, app accounts (cap 50) |
| `list_apps` | Apps Lumos knows about |
| `list_app_accounts` | Who has an account on an app |
| `list_groups` | Groups synced from connected integrations |
| `list_group_members` | Members of a Lumos group |
| `find_stale_accounts` | Suspended/archived/deprovisioned, never used, or last login past N days |
| `list_access_reviews` | Open or recent access-review campaigns |
| `list_activity_logs` | Who requested, approved, or provisioned access (cap 100) |

**`sailpoint-mcp`**

| Tool | Use when |
| --- | --- |
| `list_identities` | Find ISC identities (`filters`, `defaultFilter=CORRELATED_ONLY`) |
| `get_identity` | You already have an identity id |
| `get_identity_access` | What this identity has across sources: accounts, entitlements, roles (cap 50 each) |
| `list_accounts` | Accounts by a raw ISC `filters` string (`detailLevel=SLIM`) |
| `list_uncorrelated_accounts` | Accounts not correlated to an identity |
| `list_sources` | Connected sources |
| `search` | First-class ISC search (`POST /search`, cap 50) |
| `find_stale_identities` | Inactive lifecycle/state plus a bounded uncorrelated-account sample |
| `list_account_activities` | Provisioning / access-request evidence (cap 100). A least-privilege PAT gets 403; use `search` with the `accountactivities` index instead |
| `list_entitlements` | Find an entitlement before asking who has it |

**`c1-mcp`**

| Tool | Use when |
| --- | --- |
| `list_users` | Find ConductorOne users (`query`, `email`, `user_status`, `role_id`) |
| `get_user` | You already have a user id; includes `role_ids` and best-effort `role_names` |
| `get_user_access` | What this person has: slim user, app accounts, and grants (cap 50 each) |
| `list_apps` | Apps ConductorOne knows about |
| `list_app_users` | Accounts on one app (`status`, `type`) |
| `list_entitlements` | Entitlements, optionally for one app |
| `list_uncorrelated_accounts` | App accounts with no responsible party |
| `find_stale_accounts` | Disabled, deleted, never used, or last usage past N days (scans at most 500) |
| `list_access_reviews` | Access-review campaigns |
| `list_tasks` | Open or closed tasks (cap 10); read-only, no task actions |

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

### Lumos

Create an API token in Lumos (Settings → API Tokens). Tokens are prefixed `lsk_` and inherit the creating user's role.

| Variable | Meaning |
| --- | --- |
| `LUMOS_API_TOKEN` | Bearer token (`lsk_…`) |
| `LUMOS_BASE_URL` | Optional, https. Defaults to `https://api.lumos.com` |

### SailPoint Identity Security Cloud

Use a **personal access token**. `GET /identities` is `userAuth` / `idn:identity:read` — API-management clients without user context 403. Least-privilege scopes:

- `idn:identity:read`
- `idn:accounts:read`
- `idn:sources:read`
- `idn:entitlement:read`
- `sp:search:read`

A PAT with only `idn:identity:read`, `idn:accounts:read`, `idn:sources:read`, `idn:entitlement:read`, and `sp:search:read` gets 403 from `list_account_activities`. Use the `search` tool with the `accountactivities` index instead.

Do not grant `sp:scopes:all`.

| Variable | Meaning |
| --- | --- |
| `SAILPOINT_TENANT` | Required unless both `SAILPOINT_BASE_URL` and `SAILPOINT_TOKEN_URL` are set (`acme` → `https://acme.api.identitynow.com`) |
| `SAILPOINT_CLIENT_ID` | PAT id |
| `SAILPOINT_CLIENT_SECRET` | PAT secret |
| `SAILPOINT_BASE_URL` | Optional https override. Default `https://{tenant}.api.identitynow.com/v2026` |
| `SAILPOINT_TOKEN_URL` | Optional. Default `https://{tenant}.api.identitynow.com/oauth/token` |

The token URL is unversioned (`/oauth/token`). Resource calls are under `/v2026`.

### ConductorOne

Use a **Read-Only Administrator** credential. Do not grant Full Permissions.

The client id looks like `<random>@<hostname>/<use>`. The hostname in that id is parsed to build the API and token URLs. EU tenants already have `c1eu.ai` in the hostname, so the defaults are `https://<hostname>/api/v1` and `https://<hostname>/auth/v1/token`. Set `C1_BASE_URL` or `C1_TOKEN_URL` only to override; explicit https URLs win.

Client credentials are posted as a form body (`client_id`, `client_secret`, `grant_type=client_credentials`), not HTTP Basic.

| Variable | Meaning |
| --- | --- |
| `C1_CLIENT_ID` | Client id (`<random>@<hostname>/<use>`) |
| `C1_CLIENT_SECRET` | Client secret |
| `C1_BASE_URL` | Optional https API root, including `/api/v1` |
| `C1_TOKEN_URL` | Optional https token URL |

## Keeping credentials away from coding agents

An agent that can edit your repo should not also hold a live directory or IGA token. The two jobs run in separate lanes, enforced by host permissions rather than by asking the model nicely:

| Agent | Kind | May edit source | May call Okta/Entra/Lumos/SailPoint/C1 |
| --- | --- | --- | --- |
| `orchestrate` | primary | no | no |
| `implement` | subagent | yes | no |
| `review` | subagent | no | no |
| `iga-operator` | primary | no | **yes** |

Contributor agents get the MCP servers switched **off**; only `iga-operator` gets them on. Tab to `iga-operator` for directory and IGA work and back for code. Full rules in [AGENTS.md](AGENTS.md).

## Host setup

Copy the example matching your host. The examples enable all five provider servers, so disable or remove providers you have not configured; each binary requires its provider-specific environment variables at startup. Secrets are passed by environment reference — never paste a token into these files.

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
- **Pagination** — Okta uses `after` cursors parsed from `Link: rel=next`; Graph uses `$skiptoken` from `@odata.nextLink`; Lumos list endpoints use 1-based `page`/`size` (size max 100), while `list_activity_logs` uses `limit`/`offset` and `next` is the next offset (never follow `links.next` URLs); SailPoint uses `limit`/`offset` (next is the next offset; search sends `sort: ["id"]` with limit/offset); ConductorOne search and access reviews use an opaque `page_token`, and `next` is `nextPageToken` (not an integer cursor). Cursors are opaque: absolute URLs are rejected rather than followed.
- **Page sizes** default to 50 and cap at 200, with tighter caps on logs (100), Lumos size (100), SailPoint search (50), and Entra sign-ins (50). ConductorOne sends `pageSize` 10 when the caller asks under 10, 100 when over 100, and 50 by default; `list_tasks` sends at most 10.
- **No vendor SDKs** — just `net/http` and the official [`go-sdk`](https://github.com/modelcontextprotocol/go-sdk), which keeps the dependency surface small and the failure modes visible. Lumos hosted MCP, `github.com/sailpoint-oss/golang-sdk`, ConductorOne hosted MCP, and `conductorone-sdk-go` are out of scope.
- **Composed tools** — `get_user_access`, `get_identity_access`, and Okta `list_admins` call several upstream reads and return one slim object. ConductorOne `get_user_access` is the user, one app-user search, and one grants search.

## Development

```bash
go test ./...
```

HTTP is mocked with `httptest`; the suite makes no live Okta, Graph, Lumos, ISC, or ConductorOne calls.

## Security

These are local stdio processes that hold directory and IGA tokens in memory. Use least-privilege read-only credentials, keep secrets in the environment, and do not expose the binaries as remote MCP without putting your own authentication in front. [SECURITY.md](SECURITY.md) covers the full posture and how to report a vulnerability.

## Contributing

[CONTRACT.md](CONTRACT.md) defines the module contract — shared `internal/idmcp` helpers, stderr-only logging, read-only tools — and [AGENTS.md](AGENTS.md) covers the agent lanes. Run `go test ./...` before opening a PR.

---

MIT licensed. See [LICENSE](LICENSE).
