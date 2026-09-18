# Security

These MCP servers are **read-only** local stdio processes. They hold IdP tokens in memory and send them to Okta or Microsoft Graph.

## Do

- Use a least-privilege token (Okta: read users/groups/apps/logs/roles. Entra: `Directory.Read.All`; add `AuditLog.Read.All` for sign-in logs and `signInActivity`).
- Pass secrets through OpenCode `environment` / `{env:…}`, not committed files.
- Keep the process local. These binaries speak MCP on stdin/stdout; they are not HTTP servers.

## Do not

- Put `OKTA_API_TOKEN` or `AZURE_CLIENT_SECRET` in git, screenshots, or tool output.
- Grant write scopes (`okta.*.manage`, `Directory.ReadWrite.All`).
- Expose these as remote MCP without your own auth layer.

## Report a vulnerability

Open a private GitHub security advisory on [rlwillen0121/identity-mcp](https://github.com/rlwillen0121/identity-mcp).
