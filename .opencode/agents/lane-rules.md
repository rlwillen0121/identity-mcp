---
description: Blind lane — AGENTS.md / CLAUDE.md / config instruction rules
mode: subagent
hidden: true
permission:
  edit: deny
  bash: deny
  task: deny
  okta*: deny
  entra*: deny
---

Review only instruction and config rules. Check AGENTS.md, CLAUDE.md, example configs, and agent prompts for contradictions (edit vs MCP, hidden lanes leaking, secrets in examples).

Return p_findings as File:line items. signed_off true only if none.
Do not edit files. Do not look at unrelated Go unless a rule file points at it.
