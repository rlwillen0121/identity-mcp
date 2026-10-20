# Security

These MCP servers are **read-only by default** local stdio processes. They hold IdP and IGA tokens in memory and send them to Okta, Microsoft Graph, Lumos, SailPoint ISC, or ConductorOne. When started with `--enable-writes` (or `IDENTITY_MCP_ENABLE_WRITES=1`), each server additionally registers 2 opt-in write tools designed to be mediated by `mcp-authz-gateway`.

## Do

- Use a least-privilege token:
  - Okta: read users/groups/apps/logs/roles (add group-membership/user-lifecycle manage scope only when running `okta-mcp --enable-writes` behind `mcp-authz-gateway`).
  - Entra: `Directory.Read.All`; add `AuditLog.Read.All` for sign-in logs and `signInActivity` (add `GroupMember.ReadWrite.All` / `User.RevokeSessions.All` only when running `entra-mcp --enable-writes` behind `mcp-authz-gateway`).
  - Lumos: an API token whose creator has only the admin views you need (tokens inherit that user's role).
  - SailPoint PAT scopes: `idn:identity:read`, `idn:accounts:read`, `idn:sources:read`, `idn:entitlement:read`, `sp:search:read`. A PAT with only these scopes gets 403 from `list_account_activities`. Use the `search` tool with the `accountactivities` index instead. Do not grant `sp:scopes:all`.
  - ConductorOne: **Read-Only Administrator** by default. Do not grant Full Permissions.
- Pass secrets through OpenCode `environment` / `{env:…}`, not committed files.
- Keep the process local. These binaries speak MCP on stdin/stdout; they are not HTTP servers.

## Do not

- Put `OKTA_API_TOKEN`, `AZURE_CLIENT_SECRET`, `LUMOS_API_TOKEN`, `SAILPOINT_CLIENT_SECRET`, or `C1_CLIENT_SECRET` in git, screenshots, or tool output.
- Enable `--enable-writes` (`IDENTITY_MCP_ENABLE_WRITES=1`) without wrapping the server behind `mcp-authz-gateway` (`examples/authz/*-write-policy.json`) with Tier-0 protection, Separation of Duties (`sod_rules`), and human step-up approval (`mcp-authz-gateway approve`).
- Expose these as remote MCP without your own auth layer.

## Companion Authorization Proxy (`mcp-authz-gateway`)

When wrapping an MCP server behind `cmd/mcp-authz-gateway` (specified in [`SPEC-mcp-authz-gateway.md`](SPEC-mcp-authz-gateway.md)):

- Always initialize the ledger (`mcp-authz-gateway init-state --policy /abs/path/to/policy.json`), pin the upstream binary and tool manifest (`mcp-authz-gateway pin --policy /abs/path/to/policy.json`), and sign `(policy.json, mcp-authz.lock.json)` with an offline Ed25519 admin key when `tcb.admin_pubkey` and `tcb.policy_sig_path` are configured.
- Enforce Separation of Duties (`sod_rules`) and offline Ed25519 step-up approval (`mcp-authz-gateway approve`) for any `write:low-risk` (`require_step_up: true`), `write:high-risk`, or `destructive` tool.
- Use `tcb.isolation_mode: "mode_b_uid_boundary"` (dedicated `service_uid` owning `state_db_path`, `audit_log_path`, `challenge_dir`, and `empty_home_dir` with `0700` directory / `0600` file permissions, and `root`-owned `policy.json` / `mcp-authz.lock.json`) whenever wrapping write-capable tools, or `"mode_a_readonly_local"` for read-only local wrapping where the LLM host enforces a command/file allowlist.
- Verify the hash-chained audit log (`mcp-authz-gateway verify-audit --policy /abs/path/to/policy.json`) regularly, use `mcp-authz-gateway repair` for single-record crash recovery, and use `mcp-authz-gateway revoke-grant` for emergency break-glass SoD revocation.

## Built-In Hardening Controls

- **No HTTP Redirects or Credential Leaks:** `internal/idmcp` disables HTTP redirects on all requests (`Get`, `PostJSON`, `PostForm`) so `Authorization` headers are never forwarded across redirects, and redacts bearer tokens and OAuth `client_secret` values from all error messages.
- **Path Traversal & Tenant Validation:** `idmcp.Require` and `validateRelativePath` reject `.` / `..` dot-segments (`%2e` / `%2e%2e`), control characters, and absolute URLs; `entra-mcp` strictly validates `AZURE_TENANT_ID` (`ValidateTenantID`); and `sailpoint-mcp` rejects quotes/backslashes/control characters in filter IDs.
- **Filesystem & Cryptographic TCB (`internal/authz`):** `OpenVerifiedFile` enforces `O_NOFOLLOW`, rejects hardlinks (`nlink > 1`) and network filesystems (`NFS`/`SMB`/`FUSE`), rejects placeholder and low-order Ed25519 torsion keys, enforces RSA key bounds (`2048..8192` bits, odd exponent), and sanitizes C0/C1/Bidi characters before appending to `audit.jsonl`.

## Report a vulnerability

Open a private GitHub security advisory on [rlwillen0121/identity-mcp](https://github.com/rlwillen0121/identity-mcp).

