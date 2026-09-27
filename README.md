# SIH 2026 — PS 26163
## Security Assessment of World Monitor

**Team:** [Your Team Name]
**Theme:** Smart Automation
**Organization:** NTRO

---
## Target Application

This security assessment was performed against **World Monitor v2.10.0**.

- **Upstream repository:** https://github.com/koala73/worldmonitor
- **License:** AGPL-3.0-only
- **Copyright:** © 2024-2026 Elie Habib
- **Author:** Elie Habib

The `worldmonitor-source/` folder in this repository contains a **curated
subset** of World Monitor's source code — only the files relevant to our
security findings (CORS middleware, rate limiter, CSV export function,
MCP proxy). The complete upstream source is available at the original
repository.

**Attribution:** All World Monitor source code remains the property of
Elie Habib and contributors, licensed under AGPL-3.0-only.
## What This Project Is

A security assessment toolkit for the World Monitor platform
(open-source, AGPL-3.0). We verify documented CVE status and
present findings via a live dashboard.

**Target:** github.com/koala73/worldmonitor (provided in PS scope)

## What We Built (Original Work)

- `audit.sh` — 5 targeted security tests (bash)
- `audit-app/` — FastAPI + HTML dashboard (deployed to Vercel)
- `docs/` — assessment report
- `screenshots/` — evidence of testing

## Live Demo

- **Dashboard:** https://sih-26163-audit-app-2026.vercel.app
- **GitHub:** https://github.com/dhruvoberoi6/SIH-26163-AuditApp-2026

## CWEs Tested

| CWE | Description | Status |
|-----|-------------|--------|
| CWE-1236 | CSV Formula Injection | PATCHED |
| CWE-346 | Rate Limit Bypass | PATCHED |
| CWE-306 | MCP Proxy Unauth | PATCHED |
| CWE-942 | CORS Misconfiguration | CORRECT |
| CWE-1427 | LLM Prompt Injection | RESIDUAL RISK |

## How to Run Locally

### Deploy World Monitor (target)
```bash
git clone https://github.com/koala73/worldmonitor.git
cd worldmonitor
echo "RELAY_SHARED_SECRET=$(openssl rand -hex 32)" >> .env
echo "REDIS_PASSWORD=$(openssl rand -hex 32)" >> .env
echo "REDIS_TOKEN=$(openssl rand -hex 32)" >> .env
echo "WM_SESSION_SECRET=$(openssl rand -hex 32)" >> .env
docker compose up -d
