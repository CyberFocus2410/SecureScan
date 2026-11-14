"""DPDP candidate personal data asset and data flow extractor (FR-DPD-04)."""
import ast
import os
import re
from pathlib import Path
from typing import Any, List
from pydantic import BaseModel


PERSONAL_DATA_FIELD_PATTERNS = [
    (re.compile(r"\b(?:email|mail|e_mail)\b", re.IGNORECASE), "contact", "Email address"),
    (re.compile(r"\b(?:phone|mobile|telephone|cell|contact_no|phone_number)\b", re.IGNORECASE), "contact", "Phone / Mobile number"),
    (re.compile(r"\b(?:name|first_name|last_name|full_name|username)\b", re.IGNORECASE), "identity", "Individual name / handle"),
    (re.compile(r"\b(?:address|street|city|state|zipcode|pincode|postal_code)\b", re.IGNORECASE), "location", "Physical address"),
    (re.compile(r"\b(?:dob|date_of_birth|birthdate|age)\b", re.IGNORECASE), "demographic", "Date of birth / Age"),
    (re.compile(r"\b(?:aadhar|aadhaar|ssn|national_id|pan|passport|voter_id)\b", re.IGNORECASE), "government_id", "National / Government Identity Number"),
    (re.compile(r"\b(?:gender|sex)\b", re.IGNORECASE), "demographic", "Gender information"),
    (re.compile(r"\b(?:ip_address|client_ip|device_id|mac_address)\b", re.IGNORECASE), "technical_identifier", "Network / Device Identifier")
]


class DataFlowItem(BaseModel):
    field_name: str
    category: str
    description: str
    file_path: str
    line_number: int
    purpose: str = "unknown"
    processor: str = "unknown"
    retention_period: str = "unknown"


def extract_data_flows_from_worktree(worktree_dir: Path) -> list[DataFlowItem]:
    """
    Extracts candidate personal data fields and routes from models, schemas, and endpoints.
    Conservative mandate (FR-DPD-04):
    - Purpose and Processor stay strictly "unknown".
    - Retention period stays strictly "unknown".
    """
    flows: list[DataFlowItem] = []
    seen = set()

    for root, _, files in os.walk(worktree_dir):
        if ".git" in root or "node_modules" in root or "venv" in root:
            continue
        for fname in files:
            fpath = Path(root) / fname
            ext = fpath.suffix.lower()
            if ext not in (".py", ".js", ".ts", ".json", ".sql"):
                continue

            try:
                rel_path = str(fpath.resolve().relative_to(Path(worktree_dir).resolve())).replace("\\", "/")
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()

                for idx, line in enumerate(lines, start=1):
                    # Skip comment-only lines
                    stripped = line.strip()
                    if stripped.startswith(("#", "//", "/*", "*")):
                        continue

                    for regex, cat, desc in PERSONAL_DATA_FIELD_PATTERNS:
                        match = regex.search(line)
                        if match:
                            field_token = match.group(0).lower()
                            key = (field_token, rel_path, idx)
                            if key not in seen:
                                seen.add(key)
                                flows.append(DataFlowItem(
                                    field_name=field_token,
                                    category=cat,
                                    description=desc,
                                    file_path=rel_path,
                                    line_number=idx,
                                    purpose="unknown",
                                    processor="unknown",
                                    retention_period="unknown"
                                ))
            except Exception:
                continue

    return flows

