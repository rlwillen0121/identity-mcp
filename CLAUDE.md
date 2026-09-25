Follow [AGENTS.md](AGENTS.md). Same lanes, same MCP/token rules.

Contributor work: orchestrate → implement → review (rules, security, completeness, plus eng-core and mcp when Go/protocol changes).

Operator work: use the `iga-operator` agent. Read-only Okta/Entra/Lumos/SailPoint/C1 MCP only. ConductorOne scope is Read-Only Administrator, not Full Permissions. Do not edit this repo from that lane.

Never log `OKTA_API_TOKEN`, `AZURE_CLIENT_SECRET`, `LUMOS_API_TOKEN`, `SAILPOINT_CLIENT_SECRET`, or `C1_CLIENT_SECRET`.
