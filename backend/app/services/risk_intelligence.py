"""Risk Intelligence Engine & Multi-Dimensional Scoring (Step 12, ADR-002, prompt2_0.md)."""
from dataclasses import dataclass, field
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class SecondaryScores:
    security_score: int
    privacy_score: int
    infrastructure_score: int
    supply_chain_score: int
    dpdp_readiness_score: int
    overall_rating: str  # Critical Risk, High Risk, Moderate Risk, Good
    hard_cap_applied: bool
    hard_cap_reasons: List[str]
    methodology: str


@dataclass
class RiskIntelligenceReport:
    priority_counts: Dict[str, int]  # P0, P1, P2, P3
    severity_counts: Dict[str, int]  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    scores: SecondaryScores
    findings_count: int
    confirmed_exploitable_count: int


class RiskIntelligenceEngine:
    """
    Computes priority counts (P0-P3), multi-dimensional scores (0-100),
    and enforces the Section 6 Hard Cap Rule.
    """

    @classmethod
    def classify_domain(cls, f: Dict[str, Any]) -> str:
        """
        Dynamically maps a finding to its architectural posture domain:
        - supply_chain: dependency CVEs, SCA, outdated/vulnerable packages, lockfiles
        - infrastructure: IaC, Dockerfile, Compose, Kubernetes, Terraform, cloud configs
        - privacy: PII, PAN, Passport, Aadhaar, data exposure, tenant isolation, DPDP
        - security: SAST, code injection, secrets, authentication/authorization, AI security
        """
        cat = str(f.get("category", "")).lower()
        engine = str(f.get("engine", "") or f.get("scanner_name", "")).lower()
        rule_id = str(f.get("rule_id", "")).lower()
        file_path = str(f.get("file_path", "")).lower()
        title = str(f.get("title", "")).lower()

        # 1. Supply Chain
        if (
            cat in ("sca", "dependencies", "dependency", "supply_chain", "sbom")
            or engine in ("osv-scanner", "osv", "sca", "sbom")
            or any(k in rule_id for k in ("cve-", "osv-", "ghsa-", "npm-", "pypi-", "dependency"))
            or any(file_path.endswith(p) for p in ("package.json", "package-lock.json", "requirements.txt", "yarn.lock", "pnpm-lock.yaml", "go.sum", "pom.xml", "cargo.lock", "gemfile.lock"))
        ):
            return "supply_chain"

        # 2. Infrastructure & Cloud
        if (
            cat in ("iac", "container", "ci", "infrastructure", "cloud")
            or engine in ("iac", "container", "ci", "iac_config", "cloud")
            or any(k in rule_id for k in ("iac", "docker", "k8s", "kubernetes", "terraform", "container", "s3", "firestore", "cloud", "aws", "gcp", "azure"))
            or any(k in file_path for k in ("dockerfile", "compose", "k8s", "kubernetes", ".tf", "terraform", "vercel.json", "netlify.toml", ".github/workflows", "firestore.rules"))
        ):
            return "infrastructure"

        # 3. Privacy & Data Protection
        if (
            cat in ("privacy", "dpdp", "pii", "data_exposure")
            or engine in ("privacy", "dpdp", "pii")
            or any(k in rule_id for k in ("pii", "dpdp", "pan", "passport", "aadhaar", "ssn", "data_exposure", "plaintext-pii", "sensitive-field", "tenant-isolation"))
            or any(k in title for k in ("pii", "pan", "passport", "aadhaar", "personal data", "sensitive field", "tenant/owner isolation"))
        ):
            return "privacy"

        # 4. Core Security (SAST, Injection, Secrets, Auth, LLM, Crypto, etc.)
        return "security"

    @classmethod
    def evaluate(
        cls,
        findings: List[Dict[str, Any]],
        dpdp_readiness_score: Optional[int] = None
    ) -> RiskIntelligenceReport:
        priority_counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        category_penalties = {
            "security": 0,
            "privacy": 0,
            "infrastructure": 0,
            "supply_chain": 0,
        }

        has_p0 = False
        confirmed_exploitable = 0

        for f in findings:
            prio = f.get("priority", "P2")
            if prio in priority_counts:
                priority_counts[prio] += 1
            if prio == "P0":
                has_p0 = True

            sev = str(f.get("severity", "MEDIUM")).upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

            # Weight penalty based on severity
            weight = 15 if sev == "CRITICAL" else (10 if sev == "HIGH" else (5 if sev == "MEDIUM" else 2))

            if prio == "P0":
                weight += 10
            if f.get("verified_state") == "CONFIRMED":
                weight += 5
                confirmed_exploitable += 1

            domain = cls.classify_domain(f)
            category_penalties[domain] += weight

        # Base scores (100 - penalties) clamped between 0 and 100
        sec_score = max(0, 100 - category_penalties["security"])
        priv_score = max(0, 100 - category_penalties["privacy"])
        infra_score = max(0, 100 - category_penalties["infrastructure"])
        sc_score = max(0, 100 - category_penalties["supply_chain"])

        if dpdp_readiness_score is not None:
            dpdp_score = dpdp_readiness_score
        else:
            try:
                from app.dpdp.readiness import DpdpReadinessEngine
                dpdp_eval = DpdpReadinessEngine.evaluate(security_findings=findings)
                dpdp_score = dpdp_eval.get("readiness_score", priv_score)
            except Exception:
                dpdp_score = priv_score


        # Section 6 Hard Cap Rule:
        # If ANY P0 finding is confirmed/likely, the relevant score cannot exceed 60
        # and the overall rating cannot be "Good" or "Strong".
        hard_cap_applied = False
        hard_cap_reasons: List[str] = []

        if has_p0:
            hard_cap_applied = True
            hard_cap_reasons.append("Hard Cap applied: Confirmed or likely P0 critical vulnerabilities exist.")

            if sec_score > 60:
                sec_score = 60
                hard_cap_reasons.append("Security score capped at 60 due to active P0 finding.")
            if priv_score > 60:
                priv_score = 60
            if dpdp_score > 60:
                dpdp_score = 60
            if infra_score > 60 and category_penalties["infrastructure"] > 0:
                infra_score = 60
            if sc_score > 60 and category_penalties["supply_chain"] > 0:
                sc_score = 60

        # Overall rating calculation
        avg_score = (sec_score + priv_score + infra_score + sc_score + dpdp_score) / 5.0
        if has_p0 or avg_score < 50:
            overall_rating = "Critical Risk" if priority_counts["P0"] > 1 else "High Risk"
        elif avg_score < 75:
            overall_rating = "Moderate Risk"
        else:
            overall_rating = "Good"

        scores = SecondaryScores(
            security_score=sec_score,
            privacy_score=priv_score,
            infrastructure_score=infra_score,
            supply_chain_score=sc_score,
            dpdp_readiness_score=dpdp_score,
            overall_rating=overall_rating,
            hard_cap_applied=hard_cap_applied,
            hard_cap_reasons=hard_cap_reasons,
            methodology=(
                "Scores (0-100) are derived by deducting weighted severity points per domain from a baseline of 100. "
                "Hard Cap Rule: If any confirmed/likely P0 finding exists, security and privacy scores are hard-capped at 60 max, "
                "and overall rating is prevented from being marked 'Good'."
            )
        )

        return RiskIntelligenceReport(
            priority_counts=priority_counts,
            severity_counts=severity_counts,
            scores=scores,
            findings_count=len(findings),
            confirmed_exploitable_count=confirmed_exploitable,
        )
