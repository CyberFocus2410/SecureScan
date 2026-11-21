"""API Endpoint Discovery Engine (Step 8, ADR-002, OWASP API Top 10)."""
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
import yaml

logger = logging.getLogger(__name__)

# Common PII keywords in parameters/schemas
PII_KEYWORDS = {
    "email", "phone", "mobile", "ssn", "aadhaar", "pan", "passport",
    "credit_card", "card_number", "cvv", "dob", "birth_date", "address",
    "first_name", "last_name", "password", "token", "secret"
}

OBJECT_ID_PARAM_REGEX = re.compile(r"""(?:\{|:)([a-zA-Z0-9_]*(?:id|uuid|pk|key|code)[a-zA-Z0-9_]*)(?:\}|$)""", re.IGNORECASE)


@dataclass
class DiscoveredEndpoint:
    method: str
    path: str
    auth_required: str  # "YES", "NO", "UNKNOWN"
    authz_checks_seen: bool
    object_id_params: List[str] = field(default_factory=list)
    pii_fields: List[str] = field(default_factory=list)
    rate_limited: str = "UNKNOWN"  # "YES", "NO", "UNKNOWN"
    input_validation: str = "UNKNOWN"  # "VALIDATED", "UNVALIDATED", "UNKNOWN"
    discovered_via: str = "SOURCE"  # "OPENAPI", "POSTMAN", "SOURCE", "CRAWL"
    is_shadow: bool = False
    is_deprecated: bool = False
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    risk: str = "LOW"  # "HIGH", "MEDIUM", "LOW"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method.upper(),
            "path": self.path,
            "auth_required": self.auth_required,
            "authz_checks_seen": self.authz_checks_seen,
            "object_id_params": self.object_id_params,
            "pii_fields": self.pii_fields,
            "rate_limited": self.rate_limited,
            "input_validation": self.input_validation,
            "discovered_via": self.discovered_via,
            "is_shadow": self.is_shadow,
            "is_deprecated": self.is_deprecated,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "risk": self.risk
        }


class ApiDiscoveryEngine:
    """Discovers endpoints across OpenAPI/Swagger specifications, Postman collections, and multi-framework source code."""

    @classmethod
    def discover_from_repo(cls, repo_path: str) -> List[DiscoveredEndpoint]:
        repo_dir = Path(repo_path)
        if not repo_dir.exists():
            return []

        endpoints: List[DiscoveredEndpoint] = []
        openapi_paths: Set[str] = set()

        # 1. Discover from OpenAPI / Swagger Specifications
        openapi_endpoints = cls._discover_from_openapi_files(repo_dir)
        endpoints.extend(openapi_endpoints)
        for ep in openapi_endpoints:
            openapi_paths.add(f"{ep.method.upper()} {ep.path.lower()}")

        # 2. Discover from Postman Collections
        postman_endpoints = cls._discover_from_postman_files(repo_dir)
        endpoints.extend(postman_endpoints)

        # 3. Discover from Source Code Routes (FastAPI, Flask, Django, Express, Spring, Next.js)
        source_endpoints = cls._discover_from_source_code(repo_dir)

        # Tag Shadow Endpoints (in source code but missing from OpenAPI)
        if openapi_paths:
            for sep in source_endpoints:
                sig = f"{sep.method.upper()} {sep.path.lower()}"
                if sig not in openapi_paths:
                    sep.is_shadow = True
                    if sep.risk == "LOW":
                        sep.risk = "MEDIUM"

        endpoints.extend(source_endpoints)

        # Deduplicate endpoints by method + path
        deduped: Dict[str, DiscoveredEndpoint] = {}
        for ep in endpoints:
            key = f"{ep.method.upper()}:{ep.path.lower()}"
            if key not in deduped:
                deduped[key] = ep
            else:
                # Merge metadata if one has source and another has openapi
                existing = deduped[key]
                if ep.is_shadow:
                    existing.is_shadow = True
                if ep.auth_required != "UNKNOWN":
                    existing.auth_required = ep.auth_required
                if ep.authz_checks_seen:
                    existing.authz_checks_seen = True
                if ep.pii_fields:
                    existing.pii_fields = list(set(existing.pii_fields + ep.pii_fields))
                if ep.source_file and not existing.source_file:
                    existing.source_file = ep.source_file
                    existing.source_line = ep.source_line

        return list(deduped.values())

    @classmethod
    def _discover_from_openapi_files(cls, repo_dir: Path) -> List[DiscoveredEndpoint]:
        endpoints: List[DiscoveredEndpoint] = []
        spec_patterns = ["*openapi*.json", "*openapi*.yaml", "*openapi*.yml", "*swagger*.json", "*swagger*.yaml", "*swagger*.yml"]

        candidate_files: List[Path] = []
        for pat in spec_patterns:
            candidate_files.extend(repo_dir.glob(f"**/{pat}"))

        for fpath in set(candidate_files):
            try:
                rel = fpath.relative_to(repo_dir).as_posix()
                parts = rel.split("/")
                # Skip test directories, node_modules, and virtualenvs
                if any(p in ("tests", "test", "node_modules", ".venv") for p in parts):
                    continue
                # Skip fixture directory if scanning a full project containing backend source
                if "fixtures" in parts and (repo_dir / "backend").exists():
                    continue

                content = fpath.read_text(encoding="utf-8", errors="ignore")
                data = None
                if fpath.suffix.lower() == ".json":
                    data = json.loads(content)
                else:
                    data = yaml.safe_load(content)

                if not isinstance(data, dict) or "paths" not in data:
                    continue

                for path_str, path_item in data.get("paths", {}).items():
                    if not isinstance(path_item, dict):
                        continue
                    for method_name, op in path_item.items():
                        if method_name.lower() not in ("get", "post", "put", "delete", "patch", "options", "head"):
                            continue
                        if not isinstance(op, dict):
                            continue

                        # Extract Auth
                        security = op.get("security") or data.get("security", [])
                        auth_req = "YES" if bool(security) else "NO"

                        # Extract Object-ID params
                        obj_params = [m.group(1) for m in OBJECT_ID_PARAM_REGEX.finditer(path_str)]

                        # Extract PII in parameters or schema
                        pii: List[str] = []
                        for param in op.get("parameters", []):
                            p_name = param.get("name", "").lower()
                            if any(kw in p_name for kw in PII_KEYWORDS):
                                pii.append(p_name)

                        # Deprecation
                        is_dep = bool(op.get("deprecated", False)) or ("/v1/" in path_str and "/v2/" in str(data.get("paths", {}).keys()))

                        ep = DiscoveredEndpoint(
                            method=method_name.upper(),
                            path=path_str,
                            auth_required=auth_req,
                            authz_checks_seen=False,
                            object_id_params=obj_params,
                            pii_fields=list(set(pii)),
                            rate_limited="UNKNOWN",
                            input_validation="VALIDATED",
                            discovered_via="OPENAPI",
                            is_deprecated=is_dep,
                            source_file=str(fpath.relative_to(repo_dir)),
                            source_line=1,
                            risk="HIGH" if obj_params and auth_req == "NO" else ("MEDIUM" if obj_params else "LOW")
                        )
                        endpoints.append(ep)
            except Exception as e:
                logger.debug(f"Failed parsing OpenAPI spec {fpath}: {e}")

        return endpoints

    @classmethod
    def _discover_from_postman_files(cls, repo_dir: Path) -> List[DiscoveredEndpoint]:
        endpoints: List[DiscoveredEndpoint] = []
        for fpath in repo_dir.glob("**/*collection*.json"):
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                data = json.loads(content)
                if not isinstance(data, dict) or "item" not in data:
                    continue

                def parse_items(items):
                    for it in items:
                        if "item" in it:
                            parse_items(it["item"])
                        elif "request" in it:
                            req = it["request"]
                            method = req.get("method", "GET").upper()
                            url_obj = req.get("url", {})
                            path_str = ""
                            if isinstance(url_obj, str):
                                path_str = url_obj
                            elif isinstance(url_obj, dict):
                                path_str = "/" + "/".join(url_obj.get("path", []))

                            auth_req = "YES" if req.get("auth") else "UNKNOWN"
                            obj_params = [m.group(1) for m in OBJECT_ID_PARAM_REGEX.finditer(path_str)]

                            endpoints.append(DiscoveredEndpoint(
                                method=method,
                                path=path_str,
                                auth_required=auth_req,
                                authz_checks_seen=False,
                                object_id_params=obj_params,
                                discovered_via="POSTMAN",
                                source_file=str(fpath.relative_to(repo_dir)),
                                source_line=1
                            ))

                parse_items(data.get("item", []))
            except Exception as e:
                logger.debug(f"Failed parsing Postman collection {fpath}: {e}")

        return endpoints

    @classmethod
    def _discover_from_source_code(cls, repo_dir: Path) -> List[DiscoveredEndpoint]:
        endpoints: List[DiscoveredEndpoint] = []

        # FastAPI & Flask Regexes
        PY_ROUTE_REGEX = re.compile(
            r"""@(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]""",
            re.IGNORECASE
        )
        FLASK_ROUTE_REGEX = re.compile(
            r"""@(?:app|blueprint|bp)\.route\s*\(\s*['"]([^'"]+)['"](?:\s*,\s*methods\s*=\s*\[([^\]]+)\])?""",
            re.IGNORECASE
        )

        # Express / NestJS Regexes
        JS_ROUTE_REGEX = re.compile(
            r"""(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]""",
            re.IGNORECASE
        )

        # Spring Boot Regexes
        JAVA_ROUTE_REGEX = re.compile(
            r"""@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*\(\s*(?:value\s*=\s*)?['"]([^'"]+)['"]""",
            re.IGNORECASE
        )

        for fpath in repo_dir.rglob("*"):
            if not fpath.is_file():
                continue
            if any(skip in fpath.parts for skip in [".git", "node_modules", "venv", ".venv", "dist", "build"]):
                continue

            suffix = fpath.suffix.lower()
            if suffix not in (".py", ".js", ".ts", ".jsx", ".tsx", ".java"):
                continue

            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()

                # Python Files
                if suffix == ".py":
                    for idx, line in enumerate(lines, 1):
                        # FastAPI
                        for match in PY_ROUTE_REGEX.finditer(line):
                            method = match.group(1).upper()
                            path_str = match.group(2)
                            obj_params = [m.group(1) for m in OBJECT_ID_PARAM_REGEX.finditer(path_str)]
                            # Look ahead for function signature to capture Depends / get_session_id / get_current_user
                            sig_window = "\n".join(lines[max(0, idx - 1):min(idx + 6, len(lines))])
                            has_auth = any(kw in sig_window for kw in ["Depends(", "Security(", "get_current_user", "get_session_id", "oauth2_scheme", "HTTPBearer", "APIKeyHeader"])
                            
                            # Inspect function body below for authz/tenant check (e.g. user_id ==, audit.session_id != session_id)
                            fn_body = "\n".join(lines[idx:min(idx + 35, len(lines))])
                            authz_seen = bool(re.search(r"""(?:user_id\s*==|current_user\.id|owner_id|tenant_id|session_id\s*==|session_id\s*!=|\.session_id)""", fn_body))
                            has_rate_limit = bool(re.search(r"""@limiter\.limit|RateLimitMiddleware""", sig_window))

                            endpoints.append(DiscoveredEndpoint(
                                method=method,
                                path=path_str,
                                auth_required="YES" if has_auth else ("UNKNOWN" if obj_params else "NO"),
                                authz_checks_seen=authz_seen,
                                object_id_params=obj_params,
                                rate_limited="YES" if has_rate_limit else "NO",
                                input_validation="VALIDATED",
                                discovered_via="SOURCE",
                                source_file=str(fpath.relative_to(repo_dir)),
                                source_line=idx,
                                risk="HIGH" if obj_params and not authz_seen else "LOW"
                            ))

                        # Flask
                        for match in FLASK_ROUTE_REGEX.finditer(line):
                            path_str = match.group(1)
                            methods_str = match.group(2) or "'GET'"
                            methods = [m.strip("'\" ") for m in methods_str.split(",")]
                            obj_params = [m.group(1) for m in OBJECT_ID_PARAM_REGEX.finditer(path_str)]
                            
                            fn_body = "\n".join(lines[idx:min(idx + 15, len(lines))])
                            authz_seen = bool(re.search(r"""(?:current_user\.id|session\['user_id'\])""", fn_body))

                            for m in methods:
                                endpoints.append(DiscoveredEndpoint(
                                    method=m.upper(),
                                    path=path_str,
                                    auth_required="YES" if "@login_required" in "\n".join(lines[max(0, idx-3):idx]) else "NO",
                                    authz_checks_seen=authz_seen,
                                    object_id_params=obj_params,
                                    discovered_via="SOURCE",
                                    source_file=str(fpath.relative_to(repo_dir)),
                                    source_line=idx,
                                    risk="HIGH" if obj_params and not authz_seen else "LOW"
                                ))

                # Node.js / Express / Next.js
                elif suffix in (".js", ".ts", ".jsx", ".tsx"):
                    for idx, line in enumerate(lines, 1):
                        for match in JS_ROUTE_REGEX.finditer(line):
                            method = match.group(1).upper()
                            path_str = match.group(2)
                            obj_params = [m.group(1) for m in OBJECT_ID_PARAM_REGEX.finditer(path_str)]
                            has_auth = any(kw in line for kw in ["authenticate", "auth", "passport", "jwt", "verifyToken"])

                            fn_body = "\n".join(lines[idx:min(idx + 15, len(lines))])
                            authz_seen = bool(re.search(r"""(?:req\.user\.id|userId\s*===|tenantId)""", fn_body))

                            endpoints.append(DiscoveredEndpoint(
                                method=method,
                                path=path_str,
                                auth_required="YES" if has_auth else "NO",
                                authz_checks_seen=authz_seen,
                                object_id_params=obj_params,
                                discovered_via="SOURCE",
                                source_file=str(fpath.relative_to(repo_dir)),
                                source_line=idx,
                                risk="HIGH" if obj_params and not authz_seen else "LOW"
                            ))

                # Java / Spring Boot
                elif suffix == ".java":
                    for idx, line in enumerate(lines, 1):
                        for match in JAVA_ROUTE_REGEX.finditer(line):
                            mapping_type = match.group(1)
                            path_str = match.group(2)
                            method = "GET"
                            if "Post" in mapping_type:
                                method = "POST"
                            elif "Put" in mapping_type:
                                method = "PUT"
                            elif "Delete" in mapping_type:
                                method = "DELETE"
                            elif "Patch" in mapping_type:
                                method = "PATCH"

                            obj_params = [m.group(1) for m in OBJECT_ID_PARAM_REGEX.finditer(path_str)]
                            has_auth = "@PreAuthorize" in "\n".join(lines[max(0, idx-3):idx+1]) or "@Secured" in line

                            endpoints.append(DiscoveredEndpoint(
                                method=method,
                                path=path_str,
                                auth_required="YES" if has_auth else "UNKNOWN",
                                authz_checks_seen=has_auth,
                                object_id_params=obj_params,
                                discovered_via="SOURCE",
                                source_file=str(fpath.relative_to(repo_dir)),
                                source_line=idx
                            ))
            except Exception as e:
                logger.debug(f"Route extraction failed on {fpath}: {e}")

        return endpoints
