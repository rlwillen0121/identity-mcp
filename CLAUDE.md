Follow [AGENTS.md](AGENTS.md). Same lanes, same MCP/token rules.

Contributor work: orchestrate → implement → review (rules, security, completeness, plus eng-core and mcp when Go/protocol changes).

Operator work: use the `iga-operator` agent. Read-only-by-default Okta/Entra/Lumos/SailPoint/C1 MCP (opt-in `--enable-writes` tools must run behind `mcp-authz-gateway` with `examples/authz/*-write-policy.json`). ConductorOne default scope is Read-Only Administrator, not Full Permissions. Do not edit this repo from that lane.

Never log `OKTA_API_TOKEN`, `AZURE_CLIENT_SECRET`, `LUMOS_API_TOKEN`, `SAILPOINT_CLIENT_SECRET`, or `C1_CLIENT_SECRET`.

For the companion authorization proxy (`cmd/mcp-authz-gateway`, `internal/authz`), follow [`SPEC-mcp-authz-gateway.md`](SPEC-mcp-authz-gateway.md) and `examples/authz/`.
