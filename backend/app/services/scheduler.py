"""Scheduled Re-scans & Change Detection Service (Step 15, ADR-002).

Performs periodic re-scans of verified targets, compares against previous baseline
audits using cryptographic fingerprints, and triggers HMAC-signed webhook notifications
when new vulnerabilities or regressions are detected.
"""
from typing import Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models.models import AuditModel, FindingModel, TargetModel
from app.services.webhooks import WebhookService


class ScheduledScanResult:
    """Encapsulates the comparison result of a scheduled re-scan."""

    def __init__(
        self,
        target_id: str,
        current_audit_id: str,
        baseline_audit_id: str | None,
        new_findings: list[dict[str, Any]],
        fixed_findings: list[dict[str, Any]],
        unchanged_findings: list[dict[str, Any]],
        regressed_findings: list[dict[str, Any]],
        webhook_delivered: bool = False
    ):
        self.target_id = target_id
        self.current_audit_id = current_audit_id
        self.baseline_audit_id = baseline_audit_id
        self.new_findings = new_findings
        self.fixed_findings = fixed_findings
        self.unchanged_findings = unchanged_findings
        self.regressed_findings = regressed_findings
        self.webhook_delivered = webhook_delivered

    @property
    def has_new_issues(self) -> bool:
        return len(self.new_findings) > 0 or len(self.regressed_findings) > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "current_audit_id": self.current_audit_id,
            "baseline_audit_id": self.baseline_audit_id,
            "has_new_issues": self.has_new_issues,
            "counts": {
                "new": len(self.new_findings),
                "fixed": len(self.fixed_findings),
                "unchanged": len(self.unchanged_findings),
                "regressed": len(self.regressed_findings)
            },
            "new_findings": self.new_findings,
            "fixed_findings": self.fixed_findings,
            "regressed_findings": self.regressed_findings,
            "webhook_delivered": self.webhook_delivered
        }


class ScheduledScanService:
    """Orchestrates scheduled scan comparison, change detection, and alert delivery."""

    @classmethod
    def compare_audits(
        cls,
        baseline_findings: list[FindingModel],
        current_findings: list[FindingModel]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Detect new, fixed, unchanged, and regressed findings between audits."""
        baseline_map = {f.fingerprint: f for f in baseline_findings}
        current_map = {f.fingerprint: f for f in current_findings}

        new_findings = []
        unchanged_findings = []
        fixed_findings = []
        regressed_findings = []

        now_utc = datetime.now(timezone.utc)

        # Check current findings against baseline
        for fp, cur_f in current_map.items():
            base_f = baseline_map.get(fp)
            finding_dict = {
                "id": str(cur_f.id),
                "fingerprint": cur_f.fingerprint,
                "rule_id": cur_f.rule_id,
                "title": cur_f.title,
                "severity": str(cur_f.severity),
                "priority": getattr(cur_f, "priority", None) or "P2",
                "file_path": cur_f.file_path,
                "status": getattr(cur_f, "status", "open")
            }

            if not base_f:
                # Completely new finding in current scan
                new_findings.append(finding_dict)
            else:
                # Finding existed in baseline
                base_status = getattr(base_f, "status", "open")
                if base_status == "fixed":
                    # Was previously resolved but reappeared!
                    regressed_findings.append(finding_dict)
                elif base_status in {"accepted-risk", "false-positive"}:
                    # Check if risk acceptance has expired
                    expiry = getattr(base_f, "status_expires_at", None)
                    if expiry and expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=timezone.utc)
                    if expiry and expiry < now_utc:
                        # Expired acceptance -> counts as regressed / newly active
                        regressed_findings.append(finding_dict)
                    else:
                        unchanged_findings.append(finding_dict)
                else:
                    unchanged_findings.append(finding_dict)

        # Findings in baseline not in current scan are considered fixed
        for fp, base_f in baseline_map.items():
            if fp not in current_map:
                fixed_findings.append({
                    "id": str(base_f.id),
                    "fingerprint": base_f.fingerprint,
                    "rule_id": base_f.rule_id,
                    "title": base_f.title,
                    "severity": str(base_f.severity),
                    "priority": getattr(base_f, "priority", None) or "P2",
                    "file_path": base_f.file_path,
                    "status": "fixed"
                })

        return new_findings, fixed_findings, unchanged_findings, regressed_findings

    @classmethod
    def execute_scheduled_change_detection(
        cls,
        current_audit_id: str,
        baseline_audit_id: str | None,
        target_id: str,
        db: Session,
        webhook_url: str | None = None
    ) -> ScheduledScanResult:
        """Run change detection between current audit and baseline audit."""
        current_findings = db.query(FindingModel).filter(FindingModel.audit_id == current_audit_id).all()
        baseline_findings = (
            db.query(FindingModel).filter(FindingModel.audit_id == baseline_audit_id).all()
            if baseline_audit_id else []
        )

        new_f, fixed_f, unchanged_f, regressed_f = cls.compare_audits(baseline_findings, current_findings)

        webhook_sent = False
        if webhook_url:
            payload_data = {
                "target_id": target_id,
                "current_audit_id": current_audit_id,
                "baseline_audit_id": baseline_audit_id,
                "has_new_issues": (len(new_f) + len(regressed_f)) > 0,
                "counts": {
                    "new": len(new_f),
                    "fixed": len(fixed_f),
                    "unchanged": len(unchanged_f),
                    "regressed": len(regressed_f)
                },
                "new_findings": new_f
            }
            res = WebhookService.deliver_webhook(webhook_url, "audit.rescan_change_detected", payload_data)
            webhook_sent = res.get("success", False)

        return ScheduledScanResult(
            target_id=target_id,
            current_audit_id=current_audit_id,
            baseline_audit_id=baseline_audit_id,
            new_findings=new_f,
            fixed_findings=fixed_f,
            unchanged_findings=unchanged_f,
            regressed_findings=regressed_f,
            webhook_delivered=webhook_sent
        )
