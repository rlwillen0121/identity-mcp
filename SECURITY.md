# Security

These MCP servers are **read-only** local stdio processes. They hold IdP and IGA tokens in memory and send them to Okta, Microsoft Graph, Lumos, SailPoint ISC, or ConductorOne.

## Do

- Use a least-privilege token:
  - Okta: read users/groups/apps/logs/roles.
  - Entra: `Directory.Read.All`; add `AuditLog.Read.All` for sign-in logs and `signInActivity`.
  - Lumos: an API token whose creator has only the admin views you need (tokens inherit that user's role).
  - SailPoint PAT scopes: `idn:identity:read`, `idn:accounts:read`, `idn:sources:read`, `idn:entitlement:read`, `sp:search:read`. A PAT with only these scopes gets 403 from `list_account_activities`. Use the `search` tool with the `accountactivities` index instead. Do not grant `sp:scopes:all`.
  - ConductorOne: **Read-Only Administrator**. Do not grant Full Permissions.
- Pass secrets through OpenCode `environment` / `{env:…}`, not committed files.
- Keep the process local. These binaries speak MCP on stdin/stdout; they are not HTTP servers.

## Do not

- Put `OKTA_API_TOKEN`, `AZURE_CLIENT_SECRET`, `LUMOS_API_TOKEN`, `SAILPOINT_CLIENT_SECRET`, or `C1_CLIENT_SECRET` in git, screenshots, or tool output.
- Grant write scopes (`okta.*.manage`, `Directory.ReadWrite.All`, Lumos mutating AppStore/review endpoints, SailPoint manage scopes, ConductorOne Full Permissions or task actions).
- Expose these as remote MCP without your own auth layer.

## Report a vulnerability

Open a private GitHub security advisory on [rlwillen0121/identity-mcp](https://github.com/rlwillen0121/identity-mcp).
