"""Attack Chain Correlator & Multi-Vulnerability Narrative Generator (Step 12, ADR-002)."""
from dataclasses import dataclass, field
import hashlib
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class AttackChain:
    chain_id: str
    title: str
    severity: str  # Always P0 / CRITICAL for correlated chains
    narrative_story: str
    traversal_steps: List[str]
    linked_finding_rules: List[str]
    linked_finding_ids: List[str]
    remediation_strategy: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "severity": self.severity,
            "narrative_story": self.narrative_story,
            "traversal_steps": self.traversal_steps,
            "linked_finding_rules": self.linked_finding_rules,
            "linked_finding_ids": self.linked_finding_ids,
            "remediation_strategy": self.remediation_strategy,
        }


class AttackChainCorrelator:
    """Detects multi-stage exploit chains across disparate scanner findings."""

    @classmethod
    def correlate(cls, findings: List[Dict[str, Any]]) -> List[AttackChain]:
        chains: List[AttackChain] = []

        rules_present = {f.get("rule_id", ""): f for f in findings}
        rule_keys = list(rules_present.keys())

        # 1. Cloud Credential & Storage Exfiltration Chain
        has_aws_key = any("aws" in r.lower() or "secret" in r.lower() or "gitleaks" in r.lower() for r in rule_keys)
        has_s3_bucket = any("s3" in r.lower() or "bucket" in r.lower() or "storage" in r.lower() for r in rule_keys)

        if has_aws_key and has_s3_bucket:
            f_key = next((f for f in findings if "aws" in f.get("rule_id", "").lower() or "secret" in f.get("rule_id", "").lower()), {})
            f_s3 = next((f for f in findings if "s3" in f.get("rule_id", "").lower() or "bucket" in f.get("rule_id", "").lower()), {})

            chain_id = "chain-aws-cloud-exfiltration"
            chains.append(AttackChain(
                chain_id=chain_id,
                title="Critical Cloud Credential & Unrestricted S3 Storage Exfiltration Chain",
                severity="P0",
                narrative_story=(
                    "An external attacker acquires the static AWS credentials discovered in the repository, "
                    "then leverages them against the misconfigured, unauthenticated S3 bucket to exfiltrate private storage objects."
                ),
                traversal_steps=[
                    "Step 1: Attacker extracts hardcoded AWS access credentials from repository commit or source code.",
                    "Step 2: Attacker queries public cloud endpoints to locate the unauthenticated S3 bucket.",
                    "Step 3: Attacker uses acquired IAM credentials to authenticate, bypass restrictions, and dump cloud storage assets."
                ],
                linked_finding_rules=[f_key.get("rule_id", "secret-aws-key"), f_s3.get("rule_id", "iac-s3-public-bucket")],
                linked_finding_ids=[str(f_key.get("id", "f1")), str(f_s3.get("id", "f2"))],
                remediation_strategy="Immediately revoke the exposed AWS credentials in AWS IAM; enable S3 Block Public Access on the storage bucket."
            ))

        # 2. Database Takeover & Exfiltration Chain
        has_sqli = any("sql" in r.lower() or "injection" in r.lower() for r in rule_keys)
        has_db_port = any("db-exposure" in r.lower() or "postgres" in r.lower() or "mysql" in r.lower() or "database" in r.lower() for r in rule_keys)

        if has_sqli and has_db_port:
            f_sqli = next((f for f in findings if "sql" in f.get("rule_id", "").lower()), {})
            f_db = next((f for f in findings if "db" in f.get("rule_id", "").lower()), {})

            chain_id = "chain-database-takeover"
            chains.append(AttackChain(
                chain_id=chain_id,
                title="Application SQL Injection & Exposed Database Infrastructure Chain",
                severity="P0",
                narrative_story=(
                    "An attacker executes arbitrary SQL injection payloads through the web application, "
                    "then leverages the exposed database listener to establish direct external network connectivity and exfiltrate tables."
                ),
                traversal_steps=[
                    "Step 1: Attacker probes unparameterized web endpoints to trigger SQL syntax or boolean differentials.",
                    "Step 2: Attacker extracts database credentials and schema definitions via UNION-based or blind SQLi.",
                    "Step 3: Attacker connects directly to the publicly exposed database port on the host to dump tenant tables."
                ],
                linked_finding_rules=[f_sqli.get("rule_id", "sast-sql-injection"), f_db.get("rule_id", "db-port-publicly-exposed")],
                linked_finding_ids=[str(f_sqli.get("id", "f3")), str(f_db.get("id", "f4"))],
                remediation_strategy="Parameterize all SQL queries using prepared statements/ORM; bind database listener strictly to loopback or private VPC."
            ))

        # 3. AI Agent Remote Code Execution Chain
        has_prompt_injection = any("prompt-injection" in r.lower() for r in rule_keys)
        has_insecure_output = any("insecure-output" in r.lower() or "eval" in r.lower() for r in rule_keys)

        if has_prompt_injection and has_insecure_output:
            f_pi = next((f for f in findings if "prompt-injection" in f.get("rule_id", "").lower()), {})
            f_eval = next((f for f in findings if "insecure-output" in f.get("rule_id", "").lower() or "eval" in f.get("rule_id", "").lower()), {})

            chain_id = "chain-ai-rce-takeover"
            chains.append(AttackChain(
                chain_id=chain_id,
                title="Remote Code Execution via AI Prompt Injection & Unsafe Output Evaluation",
                severity="P0",
                narrative_story=(
                    "An adversary submits an adversarial prompt that overrides model system instructions, "
                    "crafting a payload returned in the model completion that is directly evaluated by the server runtime, resulting in RCE."
                ),
                traversal_steps=[
                    "Step 1: Adversary supplies prompt injection input that hijacks model completion context.",
                    "Step 2: Model outputs an executable Python or shell command formatted to bypass application logic.",
                    "Step 3: Server evaluates model output directly via eval() / exec(), granting arbitrary remote code execution on the host."
                ],
                linked_finding_rules=[f_pi.get("rule_id", "llm-prompt-injection-concatenation"), f_eval.get("rule_id", "llm-insecure-output-handling-eval")],
                linked_finding_ids=[str(f_pi.get("id", "f5")), str(f_eval.get("id", "f6"))],
                remediation_strategy="Enforce parameterization and delimiters on prompt inputs; strictly parse model responses using Pydantic schemas; remove eval()."
            ))

        # 4. Session Hijack Chain (XSS + Insecure Cookie)
        has_xss = any("xss" in r.lower() for r in rule_keys)
        has_insecure_cookie = any("cookie" in r.lower() or "httponly" in r.lower() for r in rule_keys)

        if has_xss and has_insecure_cookie:
            f_xss = next((f for f in findings if "xss" in f.get("rule_id", "").lower()), {})
            f_cook = next((f for f in findings if "cookie" in f.get("rule_id", "").lower()), {})

            chain_id = "chain-session-hijack"
            chains.append(AttackChain(
                chain_id=chain_id,
                title="Account Takeover via Reflected/DOM XSS & Missing Cookie HttpOnly Flag",
                severity="P0",
                narrative_story=(
                    "An attacker injects malicious client-side JavaScript that executes in victim browsers, "
                    "then accesses authentication session tokens stored in cookies lacking the HttpOnly protection flag."
                ),
                traversal_steps=[
                    "Step 1: Attacker entices an authenticated victim to click a link with reflected XSS payloads.",
                    "Step 2: Script executes in victim's browser context with access to document.cookie.",
                    "Step 3: Attacker exfiltrates session token to an external listener and impersonates the victim."
                ],
                linked_finding_rules=[f_xss.get("rule_id", "dast-frontend-xss-sink"), f_cook.get("rule_id", "dast-cookie-missing-httponly")],
                linked_finding_ids=[str(f_xss.get("id", "f7")), str(f_cook.get("id", "f8"))],
                remediation_strategy="Sanitize all user inputs before DOM rendering; set HttpOnly and Secure flags on all session cookies."
            ))

        return chains
