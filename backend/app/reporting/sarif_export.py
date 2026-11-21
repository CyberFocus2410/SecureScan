"""SARIF 2.1.0 Report Exporter adhering to OASIS SARIF standard (Step 13, ADR-002)."""
import json
import logging
from typing import Any, Dict, List
from sqlalchemy.orm import Session

from app.models.models import AuditModel, FindingModel
from app.core.security import redact_text

logger = logging.getLogger(__name__)

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def map_severity_to_sarif_level(severity: str) -> str:
    sev = str(severity).upper()
    if sev in ("CRITICAL", "HIGH"):
        return "error"
    elif sev == "MEDIUM":
        return "warning"
    else:
        return "note"


def generate_sarif_report(audit_id: str, db: Session) -> str:
    """Generates standard SARIF 2.1.0 JSON representation of scan findings."""
    audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
    findings = db.query(FindingModel).filter(FindingModel.audit_id == audit_id).all()

    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in findings:
        rule_id = f.rule_id
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description or f.title},
                "defaultConfiguration": {
                    "level": map_severity_to_sarif_level(f.severity)
                },
                "help": {
                    "text": f"Remediation: {f.how_to_fix or f.technical_fix or 'Review code and apply input validation.'}"
                },
                "properties": {
                    "tags": ["security", f.category or "sast"] + (f.cwe_ids or []),
                    "precision": "high",
                }
            }

        start_line = max(1, int(f.start_line or 1))
        end_line = max(start_line, int(f.end_line or start_line))

        result_entry = {
            "ruleId": rule_id,
            "level": map_severity_to_sarif_level(f.severity),
            "message": {
                "text": f.description or f.title
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": (f.file_path or "unknown").replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": start_line,
                            "endLine": end_line
                        }
                    }
                }
            ]
        }
        results.append(result_entry)

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecureScan",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/CyberFocus2410/SecureScan",
                        "rules": list(rules.values())
                    }
                },
                "results": results
            }
        ]
    }

    raw_json = json.dumps(sarif_doc, indent=2)
    return redact_text(raw_json)
