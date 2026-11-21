"""Unified Finding Engine: normalization, deduplication, correlation, priority, and standards mapping (Section 6, ADR-002)."""
import hashlib
import json
import logging
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime

from app.schemas.enums import Severity, Confidence
from app.models.models import FindingModel
from app.services.policy_loader import load_and_validate_policies

logger = logging.getLogger(__name__)


def generate_finding_fingerprint(
    rule_or_cwe: str,
    location: str,
    extra_context: str = ""
) -> str:
    """Generate a stable 64-char SHA-256 fingerprint for finding deduplication and cross-scan tracking."""
    norm_loc = location.replace("\\", "/").strip().lower()
    norm_id = rule_or_cwe.strip().lower()
    raw = f"{norm_id}|{norm_loc}|{extra_context.strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def compute_unified_priority(
    severity: str,
    confidence: str,
    exposure: str = "unknown",
    data_sensitivity: str = "none"
) -> str:
    """
    Enforce Section 6 Priority Rules:
    - P0: confirmed or likely-exploitable AND (exposed publicly OR touches credentials/personal data)
    - P1: high impact/severity but needs specific conditions
    - P2: moderate/hardening
    - P3: low/informational
    """
    sev = severity.upper()
    conf = confidence.upper()
    expo = exposure.lower()
    sens = data_sensitivity.lower()

    is_confirmed_or_likely = conf in ("CONFIRMED", "LIKELY", "HIGH")
    touches_critical_data = sens in ("credentials", "personal", "sensitive")
    is_public = expo in ("public", "internet")

    if (sev in ("CRITICAL", "HIGH") and is_confirmed_or_likely) and (is_public or touches_critical_data):
        return "P0"
    elif sev in ("CRITICAL", "HIGH"):
        return "P1"
    elif sev == "MEDIUM":
        return "P2"
    else:
        return "P3"


def enrich_standards_mapping(cwe_ids: List[str], owasp_refs: List[str]) -> Dict[str, Any]:
    """Look up standards mapping from policies/owasp_mappings.yaml for unified finding attribution."""
    standards: Dict[str, Any] = {
        "cwe": list(cwe_ids),
        "owasp_top10": [r for r in owasp_refs if "2025" in r or "2021" in r],
        "owasp_asvs": [r for r in owasp_refs if r.startswith("V")],
        "owasp_api_top10": [r for r in owasp_refs if "API" in r],
        "owasp_llm_top10": [r for r in owasp_refs if "LLM" in r],
        "nist_csf": [],
        "dpdp_controls": []
    }

    try:
        bundle = load_and_validate_policies()
        mappings = bundle.owasp_mappings.mappings

        for cwe in cwe_ids:
            clean_cwe = cwe.upper()
            for m in mappings:
                if m.standard == "CWE" and m.external_ref.upper() == clean_cwe:
                    # Map to related NIST or other standards if available
                    for m2 in mappings:
                        if m2.internal_control_id == m.internal_control_id:
                            if m2.standard == "NIST CSF" and m2.external_ref not in standards["nist_csf"]:
                                standards["nist_csf"].append(m2.external_ref)
                            if m2.standard == "OWASP Top 10" and m2.external_ref not in standards["owasp_top10"]:
                                standards["owasp_top10"].append(m2.external_ref)
    except Exception as exc:
        logger.warning("Could not enrich standards from policies: %s", exc)

    return standards


def correlate_and_deduplicate_findings(raw_findings: List[Dict[str, Any]], audit_id: str) -> List[Dict[str, Any]]:
    """
    Correlate and merge findings from multiple tools:
    - Same CWE/category + same location/endpoint -> merged into one finding with signals list.
    - Upgrades confidence and verified_state when multiple independent tools confirm the vulnerability.
    """
    merged_map: Dict[str, Dict[str, Any]] = {}

    for rf in raw_findings:
        # Determine correlation key: file_path + start_line (or affected locator) + primary CWE
        cwe_key = (rf.get("cwe_ids") or ["generic"])[0]
        loc_key = rf.get("affected") or f"{rf.get('file_path', '')}:{rf.get('start_line', 0)}"
        correlation_key = f"{cwe_key}|{loc_key}".lower()

        scanner_signal = f"Confirmed by {rf.get('tool') or rf.get('scanner_name', 'scanner')}"
        if rf.get("rule_id"):
            scanner_signal += f" ({rf.get('rule_id')})"

        if correlation_key in merged_map:
            existing = merged_map[correlation_key]
            # Merge signals
            signals = existing.get("signals") or []
            if scanner_signal not in signals:
                signals.append(scanner_signal)
            existing["signals"] = signals

            # Upgrade confidence and verified_state
            existing["confidence"] = "CONFIRMED"
            existing["verified_state"] = "CONFIRMED"

            # Upgrade severity if higher
            sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            if sev_rank.get(rf.get("severity", "LOW").upper(), 0) > sev_rank.get(existing.get("severity", "LOW").upper(), 0):
                existing["severity"] = rf.get("severity")

            # Merge CWEs and OWASP refs
            for cwe in rf.get("cwe_ids", []):
                if cwe not in existing["cwe_ids"]:
                    existing["cwe_ids"].append(cwe)
            for ow in rf.get("owasp_refs", []):
                if ow not in existing["owasp_refs"]:
                    existing["owasp_refs"].append(ow)

            # Recompute priority
            existing["priority"] = compute_unified_priority(
                severity=existing["severity"],
                confidence=existing["confidence"],
                exposure=existing.get("exposure", "unknown"),
                data_sensitivity=existing.get("data_sensitivity", "none")
            )
        else:
            item = dict(rf)
            item["audit_id"] = audit_id
            item["fingerprint"] = item.get("fingerprint") or generate_finding_fingerprint(cwe_key, loc_key)
            item["signals"] = [scanner_signal]
            item["verified_state"] = item.get("verified_state") or ("CONFIRMED" if item.get("confidence") == "CONFIRMED" else "LIKELY")
            item["priority"] = compute_unified_priority(
                severity=item.get("severity", "MEDIUM"),
                confidence=item.get("confidence", "CONFIRMED"),
                exposure=item.get("exposure", "unknown"),
                data_sensitivity=item.get("data_sensitivity", "none")
            )
            item["standards"] = enrich_standards_mapping(item.get("cwe_ids", []), item.get("owasp_refs", []))
            merged_map[correlation_key] = item

    return list(merged_map.values())
