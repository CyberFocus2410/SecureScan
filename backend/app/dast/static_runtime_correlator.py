"""Static <-> Runtime Security Finding Correlator (Step 7, ADR-002, Section 6)."""
import logging
from typing import Dict, List, Any, Optional

from app.schemas.enums import Severity, Confidence
from app.services.finding_engine import compute_unified_priority

logger = logging.getLogger(__name__)


class StaticRuntimeCorrelator:
    """
    Correlates static findings (codebase SAST/IaC) with runtime findings (DAST web testing).
    Upgrades confidence to CONFIRMED, records multi-engine verification signals,
    and links related finding IDs.
    """

    @classmethod
    def correlate(
        cls,
        static_findings: List[Dict[str, Any]],
        runtime_findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Correlates static findings with runtime findings.
        Returns the unified correlated finding list.
        """
        all_findings: List[Dict[str, Any]] = [dict(f) for f in static_findings]
        correlated_runtime_indices = set()

        for s_idx, s_finding in enumerate(all_findings):
            s_cwes = set(s_finding.get("cwe_ids") or [])
            s_category = (s_finding.get("category") or "").lower()
            s_path = (s_finding.get("file_path") or "").lower()
            s_rule = (s_finding.get("rule_id") or "").lower()

            for r_idx, r_finding in enumerate(runtime_findings):
                r_cwes = set(r_finding.get("cwe_ids") or [])
                r_category = (r_finding.get("category") or "").lower()
                r_url = (r_finding.get("file_path") or "").lower()
                r_rule = (r_finding.get("rule_id") or "").lower()

                # Correlation conditions:
                # 1. Matching CWEs or same vulnerability category
                common_cwes = s_cwes.intersection(r_cwes)
                category_match = bool(s_category and r_category and s_category == r_category)
                
                if not (common_cwes or category_match):
                    continue

                # 2. Check for route/name overlap or both being injection/xss/secrets
                route_match = False
                for token in s_path.replace("\\", "/").split("/"):
                    token_clean = token.split(".")[0].strip()
                    if len(token_clean) > 3 and token_clean in r_url:
                        route_match = True
                        break

                rule_match = any(
                    k in s_rule and k in r_rule
                    for k in ["sqli", "sql", "xss", "secret", "env", "token", "redirect"]
                )

                if route_match or rule_match or (common_cwes and category_match):
                    # Correlated Match!
                    correlated_runtime_indices.add(r_idx)

                    # Upgrade confidence & verified state
                    s_finding["confidence"] = "CONFIRMED"
                    s_finding["verified_state"] = "CONFIRMED"

                    # Signals
                    existing_signals = s_finding.get("signals") or [f"Static detection in {s_finding.get('file_path')}"]
                    runtime_signal = f"Confirmed via live runtime response on {r_finding.get('file_path')}"
                    if runtime_signal not in existing_signals:
                        existing_signals.append(runtime_signal)
                    s_finding["signals"] = existing_signals

                    # Link related IDs
                    r_id = r_finding.get("id") or r_finding.get("fingerprint")
                    if r_id:
                        related = s_finding.get("related_finding_ids") or []
                        if r_id not in related:
                            related.append(r_id)
                        s_finding["related_finding_ids"] = related

                    # Evidence
                    if not s_finding.get("response_evidence") and r_finding.get("raw_snippet"):
                        s_finding["response_evidence"] = r_finding.get("raw_snippet")

                    # Recompute priority with public exposure
                    s_finding["exposure"] = "public"
                    s_finding["priority"] = compute_unified_priority(
                        severity=s_finding.get("severity", "HIGH"),
                        confidence="CONFIRMED",
                        exposure="public",
                        data_sensitivity=s_finding.get("data_sensitivity", "none")
                    )

        # Append non-correlated runtime findings
        for r_idx, r_finding in enumerate(runtime_findings):
            if r_idx not in correlated_runtime_indices:
                rf_copy = dict(r_finding)
                rf_copy["engine"] = rf_copy.get("engine") or "dast"
                rf_copy["exposure"] = "public"
                rf_copy["priority"] = compute_unified_priority(
                    severity=rf_copy.get("severity", "MEDIUM"),
                    confidence=rf_copy.get("confidence", "CONFIRMED"),
                    exposure="public",
                    data_sensitivity=rf_copy.get("data_sensitivity", "none")
                )
                all_findings.append(rf_copy)

        return all_findings
