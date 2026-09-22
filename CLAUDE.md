`AGENTS.md` is canonical for this repository's lanes, process boundary, MCP
configuration, and token rules. Read it before acting; this file is only the
Claude Code entrypoint and intentionally does not duplicate the policy.

Contributor work follows `orchestrate` → `implement` → `review`; review
composes the rules, security, and completeness lanes, plus eng-core and mcp for
Go/protocol changes.

Operator work uses a separate, explicit operator profile and the
`iga-operator` agent. It may perform read-only Okta/Entra MCP calls, but never
edits this repo. Never mix a contributor process with an operator process or
inherit IdP credentials into the contributor shell.
