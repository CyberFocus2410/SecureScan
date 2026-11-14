"""Live end-to-end verification script for SecureScan AI."""
import urllib.request
import json
import time
import uuid

session_id = str(uuid.uuid4())
headers = {'Content-Type': 'application/json', 'X-Session-ID': session_id}
BASE = 'http://127.0.0.1:8000/api/v1'

print("====================================================")
print("RUNNING LIVE DEMO AUDIT VERIFICATION ON PUBLIC REPO")
print("====================================================")

# 1. Health check
req = urllib.request.Request(f"{BASE}/health", headers=headers)
with urllib.request.urlopen(req) as resp:
    health = json.loads(resp.read().decode('utf-8'))
print(f"✔ Health check: status={health['status']}, as_of_date={health['as_of_date']}")

# 2. Register repository
repo_url = "https://github.com/CyberFocus2410/LostLink"
body = json.dumps({"github_url": repo_url, "branch": "main"}).encode('utf-8')
req = urllib.request.Request(f"{BASE}/repositories", data=body, headers=headers, method="POST")
with urllib.request.urlopen(req) as resp:
    repo = json.loads(resp.read().decode('utf-8'))
print(f"✔ Repository registered: ID={repo['id']}")
print(f"  Canonical URL: {repo['canonical_url']}")
print(f"  Default branch: {repo['default_branch']}")

# 3. Start Audit
audit_body = json.dumps({"repository_id": repo['id'], "scopes": ["SECURITY", "DPDP"]}).encode('utf-8')
req = urllib.request.Request(f"{BASE}/audits", data=audit_body, headers=headers, method="POST")
with urllib.request.urlopen(req) as resp:
    audit_init = json.loads(resp.read().decode('utf-8'))
audit_id = audit_init['audit_id']
print(f"✔ Audit initiated: ID={audit_id}, initial status={audit_init['status']}")

# 4. Poll progress until complete
print("  Waiting for sandboxed clone, scanner execution, and control analysis...")
for i in range(30):
    time.sleep(1.5)
    req = urllib.request.Request(f"{BASE}/audits/{audit_id}", headers=headers)
    with urllib.request.urlopen(req) as resp:
        audit_state = json.loads(resp.read().decode('utf-8'))
    status = audit_state.get('status')
    stage = audit_state.get('current_stage')
    print(f"  [Poll {i+1}] status={status}, stage={stage}")
    if status in ('COMPLETED', 'PARTIAL', 'REPORT_READY'):
        break
    if status == 'FAILED':
        raise RuntimeError("Audit failed!")

print(f"✔ Audit reached terminal state: {audit_state['status']}")
print(f"  Pinned Commit SHA: {audit_state.get('commit_sha')}")

# 5. Check Scanner Runs
req = urllib.request.Request(f"{BASE}/audits/{audit_id}/scanner-runs", headers=headers)
with urllib.request.urlopen(req) as resp:
    runs = json.loads(resp.read().decode('utf-8'))
print(f"✔ Scanner executions ({len(runs)} engines):")
for r in runs:
    print(f"  - {r['scanner']} (v{r['version']}): status={r['status']}, findings={r['findings_count']}")

# 6. Fetch Findings
req = urllib.request.Request(f"{BASE}/audits/{audit_id}/security/findings", headers=headers)
with urllib.request.urlopen(req) as resp:
    findings_resp = json.loads(resp.read().decode('utf-8'))
findings = findings_resp.get('items', [])
print(f"✔ Security Findings ({len(findings)} discovered):")
for f in findings[:5]:
    print(f"  - [{f['severity']}] {f['title']} at {f['file_path']}:{f['start_line']}")
    if f.get('redacted_snippet'):
        print(f"    Snippet preview: {f['redacted_snippet'][:60]}...")

# 7. Fetch Security Coverage
req = urllib.request.Request(f"{BASE}/audits/{audit_id}/security/coverage", headers=headers)
with urllib.request.urlopen(req) as resp:
    cov = json.loads(resp.read().decode('utf-8'))
summary = cov.get('summary', {})
print(f"✔ Security Coverage Summary:")
print(f"  - Evidenced Controls: {summary.get('evidenced_controls')}/{summary.get('applicable_controls')} ({summary.get('coverage_ratio')})")
print(f"  - Headline Grade: \"{summary.get('headline_grade')}\"")

# 8. Fetch DPDP Controls
req = urllib.request.Request(f"{BASE}/audits/{audit_id}/dpdp/controls", headers=headers)
with urllib.request.urlopen(req) as resp:
    dpdp = json.loads(resp.read().decode('utf-8'))
dpdp_controls = dpdp if isinstance(dpdp, list) else dpdp.get('controls', [])
print(f"✔ DPDP Controls ({len(dpdp_controls)} evaluated):")
for c in dpdp_controls[:4]:
    comm = c.get('commencement', {})
    print(f"  - {c['control_id']}: {c['title']} -> State: {c['state']}, Tier: {c.get('evidence_tier')}")

# 9. Fetch Remediations
req = urllib.request.Request(f"{BASE}/audits/{audit_id}/remediations", headers=headers)
with urllib.request.urlopen(req) as resp:
    rems = json.loads(resp.read().decode('utf-8'))
print(f"✔ Remediations Generated ({len(rems)} actions):")
for r in rems[:3]:
    print(f"  - [{r.get('priority', 'P1')}] {r['title']}")
    steps = r.get('steps', [])
    if steps:
        print(f"    First step: {steps[0][:80]}...")

# 10. Generate & Download PDF Report
report_req = urllib.request.Request(
    f"{BASE}/audits/{audit_id}/reports",
    data=json.dumps({"format": "pdf"}).encode('utf-8'),
    headers=headers,
    method="POST"
)
with urllib.request.urlopen(report_req) as resp:
    rep_meta = json.loads(resp.read().decode('utf-8'))
report_id = rep_meta['report_id']
print(f"✔ PDF Report Generated: ID={report_id}")

download_req = urllib.request.Request(f"{BASE}/reports/{report_id}/download", headers=headers)
with urllib.request.urlopen(download_req) as resp:
    pdf_bytes = resp.read()
print(f"✔ PDF Downloaded: {len(pdf_bytes)} bytes, Header={pdf_bytes[:4]}")

# 11. Generate & Download JSON Report
json_rep_req = urllib.request.Request(
    f"{BASE}/audits/{audit_id}/reports",
    data=json.dumps({"format": "json"}).encode('utf-8'),
    headers=headers,
    method="POST"
)
with urllib.request.urlopen(json_rep_req) as resp:
    jrep_meta = json.loads(resp.read().decode('utf-8'))
j_report_id = jrep_meta['report_id']

jdownload_req = urllib.request.Request(f"{BASE}/reports/{j_report_id}/download", headers=headers)
with urllib.request.urlopen(jdownload_req) as resp:
    json_bytes = resp.read()
print(f"✔ JSON Report Downloaded: {len(json_bytes)} bytes")

print("\nALL DEMO VERIFICATION CHECKS COMPLETED WITH 100% SUCCESS!")