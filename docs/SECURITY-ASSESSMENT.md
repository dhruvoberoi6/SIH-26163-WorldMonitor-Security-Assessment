# Security Assessment Report — World Monitor

**Problem Statement:** SIH 2026 PS 26163
**Organization:** NTRO
**Assessor:** Dhruv Oberoi
**Date:** 2026-09-28

## Executive Summary

Assessment of World Monitor (open-source intelligence platform, AGPL-3.0)
against 5 documented CWEs. Four are patched; one is a documented residual risk.

## Findings

| CWE | Vulnerability | Status |
|-----|--------------|--------|
| CWE-1236 | CSV Formula Injection | PATCHED |
| CWE-346 | Rate Limit Bypass | PATCHED |
| CWE-306 | MCP Proxy Unauth | PATCHED |
| CWE-942 | CORS Misconfiguration | CORRECTLY CONFIGURED |
| CWE-1427 | LLM Prompt Injection | DOCUMENTED RESIDUAL RISK |

## Methodology

1. Deployed World Monitor locally via Docker Compose (4 containers)
2. Built automated audit script (audit.sh) with 5 targeted tests
3. Verified each CWE against current codebase
4. Published findings via live dashboard (Vercel)

## Deliverables

- `audit.sh` — automated test script
- `audit-app/` — live dashboard (Python + HTML)
- Live URL: https://sih-26163-audit-app-2026.vercel.app
- GitHub: https://github.com/dhruvoberoi6/SIH-26163-WorldMonitor-Security-Assessment

## Scope

Testing was performed only on an isolated local Docker environment.
No production systems were accessed.
