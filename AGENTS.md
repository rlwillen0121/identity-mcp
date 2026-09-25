# identity-mcp agent lanes

ALWAYS treat this repo as two products: **read-only MCP servers** (contributors) and an **IGA operator** that uses those servers (operators).

ALWAYS route work by lane. NEVER let one session mix operator MCP calls with contributor source edits unless the user named both.

## Position

- A **main** agent with no parent is **orchestrate**.
- A **subagent** is **implement**, or a single **blind review lane**.
- NEVER run full multi-lane review as a parentless root role. Orchestrate (or implement) composes it.

## Contributor lanes

| Lane | Who | May edit source | May call Okta/Entra/Lumos/SailPoint/C1 MCP |
| --- | --- | --- | --- |
| `orchestrate` | main | no (delegates) | no |
| `implement` | subagent | yes | no |
| `review` | subagent parent of lanes | no | no |
| `lane-rules` | hidden blind | no | no |
| `lane-security` | hidden blind | no | no |
| `lane-completeness` | hidden blind | no | no |
| `lane-eng-core` | hidden blind | no | no |
| `lane-mcp` | hidden blind | no | no |

ALWAYS-on review lanes: **rules**, **security**, **completeness**.  
When Go or MCP protocol files change, also run **eng-core** and **mcp**.

Internal lanes stay hidden from operator-facing chat unless the user asks for audit/debug.

## Operator lane

| Lane | Who | May edit source | May call Okta/Entra/Lumos/SailPoint/C1 MCP |
| --- | --- | --- | --- |
| `iga-operator` | primary | no | yes (read-only tools) |

`iga-operator` answers directory and IGA questions: stale users/accounts, admin assignments, group membership, uncorrelated accounts, access reviews, sign-in/log evidence. It does not provision, delete, or patch identities (these servers expose no write tools).

## Proof

ALWAYS run `go test ./...` before claiming an implementation checkpoint.

NEVER claim the repo is public-ready without a review verdict. Default visibility is private until that verdict is `Proven for publication`.

NEVER log, commit, or paste `OKTA_API_TOKEN`, `AZURE_CLIENT_SECRET`, `LUMOS_API_TOKEN`, `SAILPOINT_CLIENT_SECRET`, or `C1_CLIENT_SECRET`.

ConductorOne credentials are **Read-Only Administrator**, not Full Permissions.

## Config examples

- OpenCode: `opencode.json` / `examples/opencode.json` and `.opencode/agents/`
- Claude Code: `examples/claude.mcp.json` → `.mcp.json`, `examples/claude.settings.json` → `.claude/settings.json`, `examples/claude.agents/` → `.claude/agents/`, skill at `.claude/skills/iga-operator/`
- Codex: `examples/codex.config.toml` (MCP is not lane-gated in Codex; follow AGENTS.md by convention)
- CLAUDE.md mirrors this file
