"""Attack Surface Topology Generator (Feature 1).
Maps discovered routes, databases, cloud storage, and external third-party processors
into an interactive topology graph with risk levels derived from actual audit findings.
"""
from typing import Any, Dict, List, Optional, Set
import re


class AttackSurfaceGenerator:
    """Builds node-and-edge topology representation of the audited application."""

    @classmethod
    def generate(
        cls,
        findings: List[Dict[str, Any]],
        repo_name: Optional[str] = None
    ) -> Dict[str, Any]:
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        seen_node_ids: Set[str] = set()

        def add_node(nid: str, label: str, ntype: str, risk_level: str, details: str, findings_count: int = 0):
            if nid in seen_node_ids:
                # Update risk if new risk is higher
                for n in nodes:
                    if n["id"] == nid:
                        if risk_level == "high" or (risk_level == "medium" and n["risk_level"] != "high"):
                            n["risk_level"] = risk_level
                        n["findings_count"] += findings_count
                return
            seen_node_ids.add(nid)
            nodes.append({
                "id": nid,
                "label": label,
                "type": ntype,
                "risk_level": risk_level,
                "details": details,
                "findings_count": findings_count,
            })

        def add_edge(source: str, target: str):
            if source != target and not any(e["source"] == source and e["target"] == target for e in edges):
                edges.append({"source": source, "target": target})

        # Determine overall root risk
        has_p0 = any(f.get("priority") == "P0" or str(f.get("severity", "")).upper() == "CRITICAL" for f in findings)
        has_p1 = any(f.get("priority") == "P1" or str(f.get("severity", "")).upper() == "HIGH" for f in findings)
        root_risk = "high" if has_p0 else ("medium" if has_p1 else "low")

        root_id = "root"
        app_label = repo_name or "Target Application"
        add_node(
            nid=root_id,
            label=app_label,
            ntype="root",
            risk_level=root_risk,
            details=f"Core application entrypoint for {app_label}",
            findings_count=len(findings)
        )

        # 1. Extract API routes from findings
        route_pattern = re.compile(r"(/[\w\-\.\{\}]+(?:/[\w\-\.\{\}]+)*)")
        extracted_routes: Dict[str, Dict[str, Any]] = {}

        for f in findings:
            title = f.get("title", "")
            desc = f.get("description", "")
            fpath = f.get("file_path", "")
            prio = f.get("priority", "P2")
            sev = str(f.get("severity", "MEDIUM")).upper()

            item_risk = "high" if prio in ("P0", "P1") or sev in ("CRITICAL", "HIGH") else ("medium" if prio == "P2" else "low")

            # Check for routes in title, description, or file_path
            matches = route_pattern.findall(title) or route_pattern.findall(desc)
            for r in matches:
                if len(r) > 2 and not r.startswith("//") and not r.endswith((".py", ".js", ".ts", ".json", ".md", ".yml", ".yaml")):
                    clean_r = r.split()[0].rstrip(",.;:'\")")
                    if clean_r not in extracted_routes:
                        extracted_routes[clean_r] = {
                            "risk": item_risk,
                            "count": 1,
                            "findings": [title]
                        }
                    else:
                        extracted_routes[clean_r]["count"] += 1
                        if item_risk == "high":
                            extracted_routes[clean_r]["risk"] = "high"

        # Add top route nodes
        for r_path, r_info in list(extracted_routes.items())[:8]:
            slug = re.sub(r"[^\w]", "_", r_path.strip("/")).lower() or "endpoint"
            nid = f"route_{slug}"
            add_node(
                nid=nid,
                label=r_path,
                ntype="route",
                risk_level=r_info["risk"],
                details=f"Discovered endpoint: {r_path} ({r_info['count']} finding(s))",
                findings_count=r_info["count"]
            )
            add_edge(root_id, nid)

        # If no routes extracted from findings, provide default API Gateway & Service nodes
        if not extracted_routes:
            add_node("route_api_gateway", "/api/v1 (API Gateway)", "route", "low", "Central API Gateway & Routing", 0)
            add_edge(root_id, "route_api_gateway")

        # 2. Extract Databases / Storage / Models
        db_keywords = {
            "postgres": ("db_postgres", "PostgreSQL Database", "database"),
            "mysql": ("db_mysql", "MySQL Database", "database"),
            "sqlite": ("db_sqlite", "SQLite Database", "database"),
            "mongo": ("db_mongo", "MongoDB Cluster", "database"),
            "firestore": ("db_firestore", "Google Firestore", "database"),
            "s3": ("db_s3", "Amazon S3 Storage", "external"),
            "cloud storage": ("db_gcs", "Google Cloud Storage", "external"),
            "redis": ("db_redis", "Redis Cache / Session Store", "database"),
            "usermodel": ("model_user", "User Data Model", "database"),
            "ordermodel": ("model_order", "Order Data Model", "database"),
            "schema": ("db_schema", "Relational Schema Store", "database"),
        }

        detected_dbs: Set[str] = set()
        for f in findings:
            blob = (f.get("title", "") + " " + f.get("description", "") + " " + f.get("file_path", "")).lower()
            prio = f.get("priority", "P2")
            sev = str(f.get("severity", "MEDIUM")).upper()
            item_risk = "high" if prio in ("P0", "P1") or sev in ("CRITICAL", "HIGH") else ("medium" if prio == "P2" else "low")

            for kw, (nid, label, ntype) in db_keywords.items():
                if kw in blob and nid not in detected_dbs:
                    detected_dbs.add(nid)
                    add_node(
                        nid=nid,
                        label=label,
                        ntype=ntype,
                        risk_level=item_risk,
                        details=f"Persistent data entity: {label}",
                        findings_count=1
                    )
                    # Connect to nearest route or root
                    matching_routes = [n["id"] for n in nodes if n["type"] == "route"]
                    if matching_routes:
                        add_edge(matching_routes[0], nid)
                    else:
                        add_edge(root_id, nid)

        # 3. Extract External Services / 3rd Party Processors
        ext_keywords = {
            "openai": ("ext_openai", "OpenAI LLM API", "external"),
            "anthropic": ("ext_anthropic", "Anthropic Claude API", "external"),
            "razorpay": ("ext_razorpay", "Razorpay Payments", "external"),
            "stripe": ("ext_stripe", "Stripe Payment Gateway", "external"),
            "aws": ("ext_aws", "AWS Cloud Infrastructure", "external"),
            "google cloud": ("ext_gcp", "Google Cloud Platform", "external"),
            "github": ("ext_github", "GitHub API / Webhooks", "external"),
            "mixpanel": ("ext_mixpanel", "Mixpanel Analytics", "external"),
        }

        detected_ext: Set[str] = set()
        for f in findings:
            blob = (f.get("title", "") + " " + f.get("description", "") + " " + f.get("file_path", "")).lower()
            prio = f.get("priority", "P2")
            sev = str(f.get("severity", "MEDIUM")).upper()
            item_risk = "high" if prio in ("P0", "P1") or sev in ("CRITICAL", "HIGH") else ("medium" if prio == "P2" else "low")

            for kw, (nid, label, ntype) in ext_keywords.items():
                if kw in blob and nid not in detected_ext:
                    detected_ext.add(nid)
                    add_node(
                        nid=nid,
                        label=label,
                        ntype=ntype,
                        risk_level=item_risk,
                        details=f"Third-party integration: {label}",
                        findings_count=1
                    )
                    # Connect to root or route
                    matching_routes = [n["id"] for n in nodes if n["type"] == "route"]
                    if matching_routes and len(matching_routes) > 1:
                        add_edge(matching_routes[1], nid)
                    else:
                        add_edge(root_id, nid)

        # If graph is still very sparse (< 4 nodes), add standard container/web tier nodes
        if len(nodes) < 4:
            add_node("tier_web", "Web App Frontend", "route", "low", "Client UI Tier", 0)
            add_node("tier_db", "Primary Database", "database", "low", "Application Database", 0)
            add_edge(root_id, "tier_web")
            add_edge(root_id, "tier_db")

        return {
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "high_risk_components": sum(1 for n in nodes if n["risk_level"] == "high"),
            "medium_risk_components": sum(1 for n in nodes if n["risk_level"] == "medium"),
            "low_risk_components": sum(1 for n in nodes if n["risk_level"] in ("low", "safe")),
        }
