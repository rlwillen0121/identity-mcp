---
description: Blind lane — MCP spec, stdio, annotations, schemas
mode: subagent
hidden: true
permission:
  edit: deny
  okta*: deny
  entra*: deny
  lumos*: deny
  sailpoint*: deny
  c1*: deny
---

MCP protocol review.

- stdio only; no stdout prints
- official go-sdk AddTool, typed In/Out
- `idmcp.ReadOnly` (`readOnlyHint: true`) on default read tools; `idmcp.Write` (`readOnlyHint: false`) on opt-in `--enable-writes` tools; `openWorldHint: true`
- small tool set (10 read-only tools by default, +2 opt-in write tools with `--enable-writes`)
- structured output + pagination fields

Return p_findings. Do not edit files.
