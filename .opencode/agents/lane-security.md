---
description: Blind lane — tokens, auth headers, error leakage, write-surface
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

Security-only review.

- SSWS / Bearer only from env
- errors and logs must not include tokens (`OKTA_API_TOKEN`, `AZURE_CLIENT_SECRET`, `LUMOS_API_TOKEN`, `SAILPOINT_CLIENT_SECRET`, `C1_CLIENT_SECRET`)
- no write/delete/provision tools
- example configs use {env:...} not literal secrets
- Graph/SailPoint client-credentials cache must not race into a missing Authorization header

Return p_findings. Do not edit files.
