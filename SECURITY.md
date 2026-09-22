# Security

These MCP servers are **read-only** local stdio processes. They hold IdP tokens
in memory and send them to Okta or Microsoft Graph. The security boundary has
two parts: server-side read-only behavior and endpoint validation, plus a
host-specific process/config boundary that keeps credentials out of contributor
sessions. A model instruction or tool-deny rule is not a credential boundary.

## Do

- Use a least-privilege token (Okta: read users/groups/apps/logs/roles. Entra: `Directory.Read.All`; add `AuditLog.Read.All` for sign-in logs and `signInActivity`).
- Run contributor sessions from the contributor profiles. They contain no
  enabled IdP MCP definitions. Before launch, remove inherited
  `OKTA_ORG_URL`, `OKTA_API_TOKEN`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
  `AZURE_CLIENT_SECRET`, and `GRAPH_BASE_URL`.
- Pass operator secrets through protected environment references
  (`{env:…}`/`${…}`), not committed files. Keep operator credentials in a
  mode-600 local source outside the repository and launch the operator profile
  in a separate process.
- Keep the process local. These binaries speak MCP on stdin/stdout; they are not HTTP servers.
- Use the explicit operator profile only when you intend a live read. Claude
  Code's `--strict-mcp-config` and the separate OpenCode/Codex operator files
  prevent accidental contributor loading to the extent the host supports it.
- Shipped entrypoints accept only HTTPS recognized Okta authorities (no
  path/port/query/fragment) or the public `graph.microsoft.com` authority
  (Graph path `/v1.0` or `/beta`). Custom/private or sovereign
  Graph-compatible endpoints are rejected by the
  commands; trusted tests can opt in only through an explicitly injected
  client. Never set one through a contributor profile or an unreviewed
  inherited shell.

## Do not

- Put `OKTA_API_TOKEN` or `AZURE_CLIENT_SECRET` in git, screenshots, or tool output.
- Grant write scopes (`okta.*.manage`, `Directory.ReadWrite.All`).
- Expose these as remote MCP without your own auth layer.
- Do not treat a result with `truncated: true`, an empty/unknown sign-in value,
  or a provider fallback note as complete evidence. Page the result or report
  the limitation explicitly; never infer missing dates or membership.

## Evidence boundary

The servers expose observations, not authorization decisions. Pagination,
provider permission failures, unsupported `signInActivity`, and provider-side
fallbacks can leave evidence incomplete. Consumers must preserve `next`,
`truncated`, `note`, and `unknown` fields in their answer and say what was not
verified. A successful MCP call proves only that the provider returned that
response; it does not prove a complete directory or current policy state.

## Report a vulnerability

Open a private GitHub security advisory on [rlwillen0121/identity-mcp](https://github.com/rlwillen0121/identity-mcp).
