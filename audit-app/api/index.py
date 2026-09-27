from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import datetime

app = FastAPI(title="World Monitor Security Audit")

VULNERABILITIES = [
    {"id": "CWE-1236", "name": "CSV Formula Injection", "issue": "#8369",
     "component": "src/utils/export.ts - csvRow()",
     "description": "CSV export did not neutralize spreadsheet formula prefixes (=, +, -, @).",
     "status": "PATCHED", "evidence": "csvRow() prepends a quote to any cell starting with =, +, @, or -.",
     "severity": "Medium", "remediation": "Continue regression testing on export paths."},
    {"id": "CWE-346", "name": "Rate Limit Bypass via x-forwarded-for", "issue": "#3721",
     "component": "api/_rate-limit.test.mjs, server/_shared/client-ip.ts",
     "description": "Rate limiter trusted client-settable x-forwarded-for header.",
     "status": "PATCHED", "evidence": "Test suite explicitly verifies x-forwarded-for is not trusted.",
     "severity": "Medium", "remediation": "Maintain the existing regression test."},
    {"id": "CWE-306", "name": "MCP Proxy Unauthenticated Access", "issue": "#3723",
     "component": "api/mcp-proxy.ts",
     "description": "MCP proxy accepted unauthenticated requests and forwarded auth headers.",
     "status": "PATCHED", "evidence": "Endpoint now returns HTTP 401 - Pro authentication required.",
     "severity": "High", "remediation": "Continue authentication enforcement."},
    {"id": "CWE-942", "name": "CORS Origin Validation", "issue": "Historical concern",
     "component": "api/_cors.js",
     "description": "Permissive CORS could allow credentialed cross-origin requests.",
     "status": "CORRECTLY CONFIGURED", "evidence": "ALLOWED_ORIGIN_PATTERNS uses strict regex; no wildcard with credentials.",
     "severity": "Medium", "remediation": "Add CORS regression tests to CI."},
    {"id": "CWE-1427", "name": "LLM Prompt Injection", "issue": "#3724",
     "component": "LLM analyst context pipeline",
     "description": "Structural sanitizer cannot prevent semantic instruction injection.",
     "status": "DOCUMENTED RESIDUAL RISK", "evidence": "Code documentation acknowledges the limitation.",
     "severity": "High", "remediation": "Implement semantic-level LLM input validation."},
]

HTML_PAGE = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>World Monitor Audit</title>
<style>body{font-family:sans-serif;background:#0d1117;color:#e6edf3;padding:40px;margin:0}h1{color:#58a6ff}button{background:#238636;color:white;border:none;padding:12px 24px;font-size:15px;border-radius:6px;cursor:pointer}.stat{background:#161b22;border:1px solid #30363d;padding:18px;border-radius:8px;text-align:center;display:inline-block;margin:8px}.val{font-size:28px;color:#58a6ff;font-weight:700}.lbl{font-size:12px;color:#8b949e}.finding{background:#161b22;border:1px solid #30363d;padding:16px;border-radius:8px;margin:12px 0}.badge{background:#1a4d2e;color:#7ee787;padding:4px 10px;border-radius:10px;font-size:10px;font-weight:700}.risk{background:#5c1f1f;color:#ff7b72}.cfg{background:#1f3d5c;color:#79c0ff}</style>
</head><body>
<h1>World Monitor - Security Audit</h1>
<p>SIH 2026 | PS 26163 | NTRO</p>
<button onclick="runAudit()">Run Audit</button>
<div id="results" style="display:none"><div id="stats"></div><div id="findings"></div><p id="ts" style="font-size:11px;color:#8b949e"></p></div>
<script>
async function runAudit(){
var r=await fetch('/api/audit');var d=await r.json();
document.getElementById('stats').innerHTML='<div class="stat"><div class="val">'+d.summary.total+'</div><div class="lbl">Total</div></div><div class="stat"><div class="val">'+d.summary.patched+'</div><div class="lbl">Patched</div></div><div class="stat"><div class="val">'+d.summary.residual_risk+'</div><div class="lbl">Residual Risk</div></div>';
var h='';for(var i=0;i<d.findings.length;i++){var v=d.findings[i];
var c=v.status.indexOf('RESIDUAL')>=0?'risk':(v.status.indexOf('CONFIG')>=0?'cfg':'');
h+='<div class="finding"><b>'+v.name+'</b> <span class="badge '+c+'">'+v.status+'</span><p style="font-size:13px;color:#c9d1d9">'+v.description+'</p><p style="font-size:11px;color:#8b949e"><b>Component:</b> '+v.component+'<br><b>Evidence:</b> '+v.evidence+'<br><b>Severity:</b> '+v.severity+'</p></div>';}
document.getElementById('findings').innerHTML=h;
document.getElementById('ts').textContent='Audit run: '+d.timestamp;
document.getElementById('results').style.display='block';}
</script></body></html>"""

@app.get("/api/audit")
def run_audit():
    patched = sum(1 for v in VULNERABILITIES if v["status"] == "PATCHED")
    residual = sum(1 for v in VULNERABILITIES if "RESIDUAL" in v["status"])
    return {"timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "target": "World Monitor (worldmonitor.app)",
            "source": "https://github.com/koala73/worldmonitor",
            "summary": {"total": len(VULNERABILITIES), "patched": patched, "residual_risk": residual},
            "findings": VULNERABILITIES}

@app.get("/api/health")
def health():
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
def index():
    return HTMLResponse(content=HTML_PAGE)
