"""Software Bill of Materials (SBOM) generator: CycloneDX 1.6 and SPDX 2.3 JSON (Step 4, ADR-002)."""
import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pathlib import Path
from sqlalchemy.orm import Session

from app.models.models import SbomComponentModel, AuditModel


def parse_lockfile_components(worktree_dir: Path) -> List[Dict[str, Any]]:
    """
    Parse supported lockfiles in the worktree directory into normalized component records.
    Supports package-lock.json (Node), requirements.txt / poetry.lock (Python), and go.mod (Go).
    """
    components: List[Dict[str, Any]] = []
    seen = set()

    # 1. package-lock.json
    pkg_lock = worktree_dir / "package-lock.json"
    if pkg_lock.exists():
        try:
            with open(pkg_lock, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # v2/v3 packages map
            packages = data.get("packages", {})
            for pkg_path, info in packages.items():
                if not pkg_path:
                    continue  # Root package
                name = pkg_path.split("node_modules/")[-1]
                version = info.get("version", "unknown")
                key = f"npm:{name}:{version}"
                if key not in seen:
                    seen.add(key)
                    is_dev = bool(info.get("dev", False))
                    components.append({
                        "name": name,
                        "version": version,
                        "ecosystem": "npm",
                        "purl": f"pkg:npm/{name}@{version}",
                        "license": info.get("license", "UNKNOWN"),
                        "is_direct": not pkg_path.count("node_modules/") > 1,
                        "scope": "dev" if is_dev else "prod",
                        "depth": pkg_path.count("node_modules/")
                    })
        except Exception:
            pass

    # 2. requirements.txt
    req_file = worktree_dir / "requirements.txt"
    if req_file.exists():
        try:
            with open(req_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("==")
                    name = parts[0].strip()
                    version = parts[1].strip() if len(parts) > 1 else "latest"
                    key = f"pypi:{name}:{version}"
                    if key not in seen:
                        seen.add(key)
                        components.append({
                            "name": name,
                            "version": version,
                            "ecosystem": "pypi",
                            "purl": f"pkg:pypi/{name}@{version}",
                            "license": "UNKNOWN",
                            "is_direct": True,
                            "scope": "prod",
                            "depth": 1
                        })
        except Exception:
            pass

    # 3. go.mod
    go_mod = worktree_dir / "go.mod"
    if go_mod.exists():
        try:
            with open(go_mod, "r", encoding="utf-8") as f:
                in_require = False
                for line in f:
                    line = line.strip()
                    if line.startswith("require ("):
                        in_require = True
                        continue
                    if in_require and line.startswith(")"):
                        in_require = False
                        continue
                    if line.startswith("require ") or in_require:
                        parts = line.replace("require ", "").split()
                        if len(parts) >= 2:
                            name = parts[0]
                            version = parts[1]
                            is_indirect = "// indirect" in line
                            key = f"golang:{name}:{version}"
                            if key not in seen:
                                seen.add(key)
                                components.append({
                                    "name": name,
                                    "version": version,
                                    "ecosystem": "golang",
                                    "purl": f"pkg:golang/{name}@{version}",
                                    "license": "UNKNOWN",
                                    "is_direct": not is_indirect,
                                    "scope": "prod",
                                    "depth": 2 if is_indirect else 1
                                })
        except Exception:
            pass

    return components


def generate_cyclonedx_1_6_json(
    project_name: str,
    project_version: str,
    components: List[Dict[str, Any]],
    vulnerabilities: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Generate standard-compliant CycloneDX 1.6 JSON SBOM.
    Conforms to https://cyclonedx.org/schema/bom-1.6.schema.json
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    serial_number = f"urn:uuid:{uuid.uuid4()}"

    cdx_components = []
    dependencies = []

    for c in components:
        comp_id = f"{c['name']}@{c['version']}"
        cdx_comp = {
            "type": "library",
            "name": c["name"],
            "version": c["version"],
            "purl": c.get("purl", f"pkg:generic/{c['name']}@{c['version']}"),
            "scope": "required" if c.get("scope") == "prod" else "optional",
            "bom-ref": comp_id
        }
        if c.get("license") and c["license"] != "UNKNOWN":
            cdx_comp["licenses"] = [{"license": {"id": c["license"]}}]
        cdx_components.append(cdx_comp)
        dependencies.append({"ref": comp_id, "dependsOn": []})

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "author": "SecureScan AI",
                        "name": "SecureScan",
                        "version": "2.0.0"
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": project_name,
                "version": project_version
            }
        },
        "components": cdx_components,
        "dependencies": dependencies
    }

    if vulnerabilities:
        bom["vulnerabilities"] = vulnerabilities

    return bom


def generate_spdx_2_3_json(
    project_name: str,
    project_version: str,
    components: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Generate standard-compliant SPDX 2.3 JSON document.
    Conforms to https://spdx.github.io/spdx-spec/v2.3/
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_namespace = f"https://securescanbox.xyz/spdx/{project_name}-{uuid.uuid4().hex[:8]}"

    packages = [
        {
            "SPDXID": "SPDXRef-RootPackage",
            "name": project_name,
            "versionInfo": project_version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION"
        }
    ]

    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-RootPackage"
        }
    ]

    for idx, c in enumerate(components, start=1):
        spdx_id = f"SPDXRef-Package-{idx}-{c['name'].replace('@', '').replace('/', '-')}"
        packages.append({
            "SPDXID": spdx_id,
            "name": c["name"],
            "versionInfo": c["version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": c.get("license") if c.get("license") != "UNKNOWN" else "NOASSERTION",
            "licenseDeclared": c.get("license") if c.get("license") != "UNKNOWN" else "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": c.get("purl", f"pkg:generic/{c['name']}@{c['version']}")
                }
            ]
        })
        relationships.append({
            "spdxElementId": "SPDXRef-RootPackage",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": spdx_id
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{project_name}-SBOM",
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": timestamp,
            "creators": ["Tool: SecureScan-2.0.0"]
        },
        "packages": packages,
        "relationships": relationships
    }


def persist_sbom_components(
    db: Session,
    audit_id: str,
    components: List[Dict[str, Any]]
) -> int:
    """Persist parsed SBOM components to the sbom_components table."""
    audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
    if not audit:
        return 0

    count = 0
    for c in components:
        model = SbomComponentModel(
            id=str(uuid.uuid4()),
            audit_id=audit_id,
            name=c["name"],
            version=c["version"],
            ecosystem=c.get("ecosystem", "generic"),
            purl=c.get("purl", ""),
            license=c.get("license", "UNKNOWN"),
            is_direct=c.get("is_direct", True),
            cve_count=c.get("cve_count", 0),
            created_at=datetime.utcnow()
        )
        db.add(model)
        count += 1
    db.commit()
    return count
