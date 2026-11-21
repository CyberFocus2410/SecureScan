"""Step 4 Gate Tests: Multi-language SAST, TruffleHog git-history secrets, and SBOM (CycloneDX 1.6 / SPDX 2.3)."""
import json
import subprocess
from pathlib import Path
import pytest

from app.core.security import assert_no_raw_secret
from app.scanners.custom import CustomRulesScanner
from app.scanners.trufflehog import TruffleHogAdapter
from app.scanners.osv import OsvScannerAdapter
from app.services.sbom import (
    parse_lockfile_components,
    generate_cyclonedx_1_6_json,
    generate_spdx_2_3_json
)


def test_custom_sast_expanded_detectors(tmp_path):
    """
    Verify expanded SAST detectors across Python, JS/TS, and Java:
    - Command Injection
    - SSRF
    - Path Traversal
    - Insecure Deserialization
    - Weak Cryptography
    - Insecure JWT
    - Mass Assignment
    - Debug Mode
    - Flask SSTI & Django CSRF / Raw SQL
    - Spring CORS & JdbcTemplate SQLi
    """
    # 1. Python source file with multiple vulnerable patterns
    py_code = '''
import os, subprocess, requests, pickle, hashlib, jwt
from flask import Flask, render_template_string, request

app = Flask(__name__)
DEBUG = True

@app.route("/cmd")
def run_command():
    user_input = request.args.get("cmd")
    os.system("echo " + user_input)
    return "ok"

@app.route("/ssrf")
def probe():
    target = request.args.get("url")
    return requests.get(target).text

@app.route("/read")
def read_file():
    fn = request.args.get("file")
    with open("/data/" + fn) as f:
        return f.read()

@app.route("/deserialize")
def load_data():
    raw = request.args.get("data")
    return pickle.loads(raw)

@app.route("/weak_crypto")
def hash_pass():
    p = request.args.get("pass")
    return hashlib.md5(p.encode()).hexdigest()

@app.route("/jwt")
def check_jwt():
    token = request.args.get("token")
    return jwt.decode(token, verify=False)

@app.route("/ssti")
def ssti_vuln():
    tpl = request.args.get("tpl")
    return render_template_string("Hello " + tpl)
'''
    (tmp_path / "app.py").write_text(py_code, encoding="utf-8")

    # 2. Django patterns
    django_code = '''
from django.views.decorators.csrf import csrf_exempt
from myapp.models import User

@csrf_exempt
def api_view(request):
    uid = request.GET.get("id")
    users = User.objects.raw(f"SELECT * FROM users WHERE id = {uid}")
    user = users[0]
    user.update(request.json)
    return "ok"
'''
    (tmp_path / "views.py").write_text(django_code, encoding="utf-8")

    # 3. Java Spring Boot patterns
    java_code = '''
package com.example.demo;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.jdbc.core.JdbcTemplate;

@RestController
@CrossOrigin(origins = "*")
public class ApiController {
    private JdbcTemplate jdbcTemplate;

    @GetMapping("/search")
    public String search(String query) {
        jdbcTemplate.query("SELECT * FROM items WHERE name = '" + query + "'");
        return "done";
    }
}
'''
    (tmp_path / "ApiController.java").write_text(java_code, encoding="utf-8")

    scanner = CustomRulesScanner()
    res = scanner.execute(
        worktree_dir=tmp_path,
        context={
            "detected_languages": ["Python", "Java"],
            "detected_frameworks": ["Flask", "Django", "Spring"]
        }
    )

    findings = res.raw_findings
    rule_ids = {f.rule_id for f in findings}

    # Verify each detector triggered with valid CWE
    assert "sec-sast-command-injection-source-sink" in rule_ids
    assert "sec-sast-ssrf-source-sink" in rule_ids
    assert "sec-sast-path-traversal-source-sink" in rule_ids
    assert "sec-sast-insecure-deserialization" in rule_ids
    assert "sec-sast-weak-crypto-hash" in rule_ids
    assert "sec-sast-insecure-jwt-verification" in rule_ids
    assert "sec-sast-debug-mode-enabled" in rule_ids
    assert "sec-flask-ssti-render-template-string" in rule_ids
    assert "sec-django-csrf-exempt" in rule_ids
    assert "sec-django-raw-sql-concatenation" in rule_ids
    assert "sec-sast-mass-assignment" in rule_ids
    assert "sec-spring-wildcard-cors" in rule_ids
    assert "sec-spring-jdbc-sqli" in rule_ids

    # Every finding must have CWE IDs and OWASP refs
    for f in findings:
        assert len(f.cwe_ids) > 0
        assert len(f.owasp_refs) > 0
        assert f.technical_fix is not None


def test_git_history_deleted_secret_detection_and_redaction(tmp_path):
    """
    Gate: A seeded deleted-secret in git history is found and redacted.
    No raw secret appears anywhere in outputs (extends AT-03).
    """
    # 1. Initialize a real git repo
    subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "TestSec"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "testsec@example.com"], cwd=str(tmp_path), check=True, capture_output=True)

    # 2. Commit a file containing a real AWS secret key pattern
    raw_secret = "AKIAIOSFODNN7EXAMPLE"
    secret_file = tmp_path / "config.py"
    secret_file.write_text(f"AWS_KEY = '{raw_secret}'\n", encoding="utf-8")
    subprocess.run(["git", "add", "config.py"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "add aws credentials"], cwd=str(tmp_path), check=True, capture_output=True)

    # 3. Delete the file in a second commit to simulate an attempt to scrub it
    subprocess.run(["git", "rm", "config.py"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "remove credentials"], cwd=str(tmp_path), check=True, capture_output=True)

    # Verify the file is physically deleted from the working tree
    assert not secret_file.exists()

    # 4. Run TruffleHogAdapter on the repo
    adapter = TruffleHogAdapter()
    result = adapter.execute(worktree_dir=tmp_path, context={})

    # 5. Assertions: the deleted secret was detected from git history
    findings = result.raw_findings
    assert len(findings) >= 1
    found = False
    for f in findings:
        if "git_history" in f.rule_id or "Git History" in f.title:
            found = True
            # Mandatory AT-03 Secret Redaction Guarantee:
            assert_no_raw_secret(f.raw_snippet, raw_secret)
            assert raw_secret not in f.title
            assert raw_secret not in f.description
            assert raw_secret not in f.technical_fix
            assert "[REDACTED" in f.raw_snippet or "AKIA" not in f.raw_snippet

    assert found is True, "Expected TruffleHog to detect the deleted AWS credential from Git history."


def test_sbom_cyclonedx_and_spdx_generation(tmp_path):
    """
    Gate: SBOM generation parses lockfiles and produces compliant CycloneDX 1.6 and SPDX 2.3 JSON.
    """
    # 1. Seed sample package-lock.json (Node)
    pkg_lock_data = {
        "name": "ecommerce-api",
        "version": "1.2.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "ecommerce-api",
                "version": "1.2.0"
            },
            "node_modules/express": {
                "version": "4.19.2",
                "license": "MIT",
                "dev": False
            },
            "node_modules/lodash": {
                "version": "4.17.21",
                "license": "MIT",
                "dev": False
            },
            "node_modules/jest": {
                "version": "29.7.0",
                "license": "MIT",
                "dev": True
            }
        }
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(pkg_lock_data, indent=2), encoding="utf-8")

    # 2. Seed requirements.txt (Python)
    (tmp_path / "requirements.txt").write_text(
        "fastapi==0.111.0\nuvicorn==0.30.1\npydantic==2.7.4\n# comment\n",
        encoding="utf-8"
    )

    # 3. Parse lockfile components
    components = parse_lockfile_components(tmp_path)
    comp_names = {c["name"] for c in components}
    assert "express" in comp_names
    assert "lodash" in comp_names
    assert "jest" in comp_names
    assert "fastapi" in comp_names
    assert "uvicorn" in comp_names
    assert "pydantic" in comp_names

    # Check scopes
    jest_comp = next(c for c in components if c["name"] == "jest")
    assert jest_comp["scope"] == "dev"
    express_comp = next(c for c in components if c["name"] == "express")
    assert express_comp["scope"] == "prod"
    assert express_comp["license"] == "MIT"

    # 4. Generate CycloneDX 1.6 JSON
    cdx = generate_cyclonedx_1_6_json("ecommerce-api", "1.2.0", components)
    assert cdx["bomFormat"] == "CycloneDX"
    assert cdx["specVersion"] == "1.6"
    assert cdx["serialNumber"].startswith("urn:uuid:")
    assert cdx["metadata"]["component"]["name"] == "ecommerce-api"
    assert len(cdx["components"]) == len(components)
    for comp in cdx["components"]:
        assert "purl" in comp
        assert comp["purl"].startswith("pkg:")
        assert "bom-ref" in comp
    assert len(cdx["dependencies"]) == len(components)

    # 5. Generate SPDX 2.3 JSON
    spdx = generate_spdx_2_3_json("ecommerce-api", "1.2.0", components)
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["dataLicense"] == "CC0-1.0"
    assert spdx["SPDXID"] == "SPDXRef-DOCUMENT"
    assert len(spdx["packages"]) == len(components) + 1  # root package + components
    assert len(spdx["relationships"]) == len(components) + 1


def test_missing_lockfile_yields_not_verified(tmp_path):
    """
    Gate: Missing lockfile => NOT_VERIFIED, never '0 CVEs' or 'Pass' (FR-SCN-04).
    """
    # Create empty repo without any package-lock.json or requirements.txt
    (tmp_path / "main.py").write_text("print('hello world')\n", encoding="utf-8")

    adapter = OsvScannerAdapter()
    ctx = adapter.prepare(tmp_path)
    assert len(ctx.get("lockfiles", [])) == 0

    res = adapter.execute(tmp_path, ctx)
    assert res.status == "NOT_VERIFIED"
    assert "No recognized dependency lockfile found" in res.error_message
    assert len(res.raw_findings) == 0
