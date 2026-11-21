"""API Endpoint Inventory Exporter (JSON & CSV) (Step 8, ADR-002, Gate 8)."""
import csv
import io
import json
from typing import List, Dict, Any, Union

from app.services.api_discovery import DiscoveredEndpoint


class ApiInventoryExporter:
    """Exports discovered API endpoint inventory into JSON or CSV formats."""

    @staticmethod
    def to_json(endpoints: List[Union[DiscoveredEndpoint, Dict[str, Any]]], indent: int = 2) -> str:
        data = []
        for ep in endpoints:
            if hasattr(ep, "to_dict"):
                data.append(ep.to_dict())
            elif isinstance(ep, dict):
                data.append(ep)
        return json.dumps({"endpoints": data, "total_count": len(data)}, indent=indent)

    @staticmethod
    def to_csv(endpoints: List[Union[DiscoveredEndpoint, Dict[str, Any]]]) -> str:
        fieldnames = [
            "method", "path", "auth_required", "authz_checks_seen",
            "object_id_params", "pii_fields", "rate_limited",
            "input_validation", "discovered_via", "is_shadow",
            "is_deprecated", "risk", "source_file", "source_line"
        ]

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()

        for ep in endpoints:
            d = ep.to_dict() if hasattr(ep, "to_dict") else dict(ep)
            row = {
                "method": d.get("method", "GET"),
                "path": d.get("path", ""),
                "auth_required": d.get("auth_required", "UNKNOWN"),
                "authz_checks_seen": str(d.get("authz_checks_seen", False)),
                "object_id_params": ";".join(d.get("object_id_params") or []),
                "pii_fields": ";".join(d.get("pii_fields") or []),
                "rate_limited": d.get("rate_limited", "UNKNOWN"),
                "input_validation": d.get("input_validation", "UNKNOWN"),
                "discovered_via": d.get("discovered_via", "SOURCE"),
                "is_shadow": str(d.get("is_shadow", False)),
                "is_deprecated": str(d.get("is_deprecated", False)),
                "risk": d.get("risk", "LOW"),
                "source_file": d.get("source_file", ""),
                "source_line": d.get("source_line", "")
            }
            writer.writerow(row)

        return output.getvalue()
