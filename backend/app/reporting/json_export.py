"""JSON report export generator (FR-RPT, FR-ACC)."""
import json
from typing import Any
from sqlalchemy.orm import Session

from app.reporting.collector import collect_audit_report_data
from app.core.security import redact_text


def generate_json_report(audit_id: str, db: Session) -> str:
    """Generate canonical JSON report for an audit, guaranteeing secret redaction."""
    data = collect_audit_report_data(audit_id, db)

    # Perform defensive safety pass: dump and check/redact
    raw_json = json.dumps(data, indent=2, ensure_ascii=False)
    sanitized = redact_text(raw_json)

    return sanitized
