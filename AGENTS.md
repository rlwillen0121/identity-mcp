# identity-mcp agent lanes

ALWAYS treat this repo as two products: **read-only MCP servers** (contributors) and an **IGA operator** that uses those servers (operators).

ALWAYS route work by lane. NEVER let one session mix operator MCP calls with contributor source edits unless the user named both.

## Position

- A parentless main agent is the **orchestrate** lane.
- An implementation child is the **implement** lane.
- A review child is the **review** composer; it may spawn the hidden blind lanes.
- A hidden `lane-*` child is one independent blind review lane. It does not edit.
- NEVER run full multi-lane review as a parentless root role. The orchestrate lane delegates it to review.

## Contributor lanes

| Lane | Who | May edit source | May call Okta/Entra MCP |
| --- | --- | --- | --- |
| `orchestrate` | main | no (delegates) | no |
| `implement` | subagent | yes | no |
| `review` | subagent review composer | no | no |
| `lane-rules` | hidden blind | no | no |
| `lane-security` | hidden blind | no | no |
| `lane-completeness` | hidden blind | no | no |
| `lane-eng-core` | hidden blind | no | no |
| `lane-mcp` | hidden blind | no | no |

ALWAYS-on review lanes: **rules**, **security**, **completeness**.  
When Go or MCP protocol files change, also run **eng-core** and **mcp**.

Internal lanes are not operator tools. OpenCode marks them hidden; Claude's
custom-agent format may still expose their names, so the shipped Claude blind
definitions are read-only and deny both editing and IdP MCP regardless.

## Operator lane

| Lane | Who | May edit source | May call Okta/Entra MCP |
| --- | --- | --- | --- |
| `iga-operator` | primary | no | yes (read-only tools) |

`iga-operator` answers directory questions: stale users, admin assignments, group membership, sign-in/log evidence. It does not provision, delete, or patch identities (these servers expose no write tools).

## Proof

ALWAYS run `go test ./...` before claiming an implementation checkpoint.

NEVER claim the repo is public-ready without a review verdict. Default visibility is private until that verdict is `Proven for publication`.

NEVER log, commit, or paste `OKTA_API_TOKEN` or `AZURE_CLIENT_SECRET`.

## Config and process boundary

Contributor and operator work use separate host profiles and separate process
launches. The contributor profile has no enabled IdP MCP servers configured. The
operator profile is an explicit opt-in and is the only profile that starts
`okta-mcp` or `entra-mcp`; it must be launched from a protected environment
containing the least-privilege credentials. Do not rely on an agent prompt or a
tool deny rule to protect a token inherited from the shell.

Claude Code supports an explicit `--strict-mcp-config` boundary; contributor
launches must point it at the empty contributor MCP file. OpenCode uses
separate config files with the known IdP servers disabled in the contributor
profile. Codex project config does not provide a per-agent MCP
boundary, so the contributor Codex profile intentionally has no identity MCP
servers; use the separate operator profile only in an operator-only process.
Unset `OKTA_ORG_URL`, `OKTA_API_TOKEN`, `AZURE_TENANT_ID`,
`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, and `GRAPH_BASE_URL` before starting
any contributor process.

## Config examples

- OpenCode contributor: `opencode.json` / `examples/opencode.json` and `.opencode/agents/`; operator: the combined `examples/opencode.operator.json` or provider-specific operator profile in a separate process.
- Claude Code contributor: `examples/claude.mcp.json` → `.mcp.json`, `examples/claude.settings.json` → `.claude/settings.json`, `examples/claude.agents/` → `.claude/agents/`; operator: the combined or provider-specific `examples/claude.*.operator.mcp.json` plus the `iga-operator` agent in a separate process.
- Codex contributor: `examples/codex.config.toml` (no identity MCP); operator-only: the combined or provider-specific `examples/codex.*.operator.config.toml`.
- `CLAUDE.md` is a short pointer to this file. `AGENTS.md` is canonical when wording differs.
