# identity-mcp agent lanes

ALWAYS treat this repo as two products: **read-only-by-default MCP servers** with companion `mcp-authz-gateway` enforcement (contributors) and an **IGA operator** that uses those servers (operators).

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
| `iga-operator` | primary | no | yes (read-only by default; opt-in writes via `mcp-authz-gateway`) |

`iga-operator` answers directory and IGA questions: stale users/accounts, admin assignments, group membership, uncorrelated accounts, access reviews, sign-in/log evidence. By default the five servers expose only their 10 read-only tools; the 2 opt-in write tools per server (`--enable-writes` / `IDENTITY_MCP_ENABLE_WRITES=1`) must only be exposed behind `mcp-authz-gateway` (`examples/authz/*-write-policy.json`).

## Proof

ALWAYS run `go test ./...` before claiming an implementation checkpoint.

NEVER claim the repo is public-ready without a review verdict. Default visibility is private until that verdict is `Proven for publication`.

NEVER log, commit, or paste `OKTA_API_TOKEN`, `AZURE_CLIENT_SECRET`, `LUMOS_API_TOKEN`, `SAILPOINT_CLIENT_SECRET`, or `C1_CLIENT_SECRET`.

ConductorOne credentials are **Read-Only Administrator**, not Full Permissions.

## Config examples

- OpenCode: `opencode.json` / `examples/opencode.json` and `.opencode/agents/`
- Claude Code: `examples/claude.mcp.json` → `.mcp.json`, `examples/claude.settings.json` → `.claude/settings.json`, `examples/claude.agents/` → `.claude/agents/`, skill at `.claude/skills/iga-operator/`
- Codex: `examples/codex.config.toml` (MCP is not lane-gated in Codex; follow AGENTS.md by convention)
- Authorization Gateway (`cmd/mcp-authz-gateway`, `internal/authz`): [`SPEC-mcp-authz-gateway.md`](SPEC-mcp-authz-gateway.md), `examples/authz/okta-read-policy.json`, `examples/authz/okta-write-policy.json`, `examples/authz/entra-write-policy.json`, `examples/authz/lumos-write-policy.json`, `examples/authz/sailpoint-write-policy.json`, `examples/authz/c1-write-policy.json`
- CLAUDE.md mirrors this file
