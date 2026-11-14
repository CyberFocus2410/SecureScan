"""Deterministic remediation engine for findings and security controls."""
import uuid
from typing import List
from sqlalchemy.orm import Session

from app.models.models import FindingModel, ControlResultModel, RemediationActionModel
from app.schemas.remediation import RemediationAction


def generate_deterministic_remediations(db: Session, audit_id: str) -> list[RemediationActionModel]:
    """
    Generates structured, actionable technical and organizational remediations
    for findings and failed / potential-gap controls.
    """
    findings = db.query(FindingModel).filter(FindingModel.audit_id == audit_id).all()
    controls = db.query(ControlResultModel).filter(
        ControlResultModel.audit_id == audit_id,
        ControlResultModel.domain == "SECURITY"
    ).all()

    # Clear existing remediations for this audit
    db.query(RemediationActionModel).filter(RemediationActionModel.audit_id == audit_id).delete()

    remediations: list[RemediationActionModel] = []

    # 1. Finding-specific technical fixes
    for f in findings:
        steps: list[str] = []
        if f.technical_fix:
            steps.append(f.technical_fix)
        if f.file_path and f.start_line:
            steps.append(f"Target location: {f.file_path} at line {f.start_line}.")
        if not steps:
            steps.append(f"Review and eliminate security flaw identified by rule {f.rule_id}.")

        validation = f.validation_steps or "Re-run static scanner locally to verify finding is resolved."

        priority = "P0" if f.severity in ("CRITICAL", "HIGH") else "P1"

        rem = RemediationActionModel(
            id=str(uuid.uuid4()),
            audit_id=audit_id,
            priority=priority,
            action_type="ENGINEERING",
            target_id=f.id,
            title=f"Fix: {f.title}",
            steps_json=steps,
            validation_method=validation
        )
        db.add(rem)
        remediations.append(rem)

    # 2. Control-level remediations for gaps
    for c in controls:
        if c.state in ("FAIL_EVIDENCED", "POTENTIAL_GAP"):
            if c.control_id == "SEC-005":
                rem = RemediationActionModel(
                    id=str(uuid.uuid4()),
                    audit_id=audit_id,
                    priority="P0",
                    action_type="ENGINEERING",
                    target_id=c.control_id,
                    title="Implement API Rate Limiting Guards",
                    steps_json=[
                        "Configure middleware or decorator-based rate limiting (e.g. SlowAPI in FastAPI or express-rate-limit).",
                        "Alternatively, configure an upstream reverse proxy (NGINX/Cloudflare) or API Gateway with explicit rate limits.",
                        "Document rate limit headers returned to clients (e.g. RateLimit-Limit, RateLimit-Remaining)."
                    ],
                    validation_method="Send bursts of requests exceeding threshold; assert HTTP 429 Too Many Requests response."
                )
                db.add(rem)
                remediations.append(rem)

            elif c.control_id == "SEC-007":
                rem = RemediationActionModel(
                    id=str(uuid.uuid4()),
                    audit_id=audit_id,
                    priority="P0",
                    action_type="ENGINEERING",
                    target_id=c.control_id,
                    title="Enforce Authentication on Administrative Routes",
                    steps_json=[
                        "Review route decorators on admin or internal endpoints.",
                        "Add authentication and role-check dependencies (e.g. Depends(require_admin_role))."
                    ],
                    validation_method="Invoke endpoint with no authorization header; assert HTTP 401 Unauthorized."
                )
                db.add(rem)
                remediations.append(rem)

    db.commit()
    return remediations
