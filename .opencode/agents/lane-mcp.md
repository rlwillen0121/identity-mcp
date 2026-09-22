---
description: Blind lane — MCP spec, stdio, annotations, schemas
mode: subagent
hidden: true
permission:
  edit: deny
  bash: deny
  task: deny
  okta*: deny
  entra*: deny
---

MCP protocol review.

- stdio only; no stdout prints
- official go-sdk AddTool, typed In/Out
- readOnlyHint true, openWorldHint true
- small tool set (context budget)
- structured output + pagination fields

Return p_findings. Do not edit files.
