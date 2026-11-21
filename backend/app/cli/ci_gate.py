"""SecureScan CI Gate CLI (Step 15, ADR-002).

Evaluates audit findings against configurable risk thresholds (P0, P1, P2, P3).
Filters out non-expired accepted risks and false positives.
Outputs pass/fail exit codes for CI/CD pipelines (GitHub Actions, GitLab CI, etc.).
"""
import sys
import argparse
from datetime import datetime, timezone
from typing import Any
from sqlalchemy.orm import Session

from app.core.db import SessionLocal
from app.models.models import AuditModel, FindingModel
from app.services.github_pr_comment import GitHubPrCommentGenerator


class CiGateEvaluator:
    """Evaluates audit findings against priority thresholds."""

    PRIORITY_LEVELS = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}

    @classmethod
    def evaluate(
        cls,
        audit_id: str,
        fail_on: str = "P0",
        max_p0: int = 0,
        max_p1: int = 0,
        db: Session | None = None
    ) -> dict[str, Any]:
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True

        try:
            audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
            if not audit:
                return {
                    "passed": False,
                    "error": f"Audit '{audit_id}' not found.",
                    "p_counts": {"P0": 0, "P1": 0, "P2": 0, "P3": 0},
                    "active_findings": []
                }

            findings = db.query(FindingModel).filter(FindingModel.audit_id == audit_id).all()
            now_utc = datetime.now(timezone.utc)

            active_findings = []
            p_counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}

            for f in findings:
                status = getattr(f, "status", "open")
                if status == "fixed":
                    continue
                if status in {"accepted-risk", "false-positive"}:
                    expiry = getattr(f, "status_expires_at", None)
                    if expiry:
                        if expiry.tzinfo is None:
                            expiry = expiry.replace(tzinfo=timezone.utc)
                        if expiry >= now_utc:
                            # Still active accepted risk or verified false positive -> skip gate fail
                            continue
                        # If expired -> count as active!

                priority = getattr(f, "priority", None) or "P2"
                if priority in p_counts:
                    p_counts[priority] += 1

                active_findings.append({
                    "id": str(f.id),
                    "fingerprint": f.fingerprint,
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "plain_title": getattr(f, "plain_title", None),
                    "severity": str(f.severity),
                    "priority": priority,
                    "file_path": f.file_path,
                    "start_line": f.start_line,
                    "status": status
                })

            threshold_rank = cls.PRIORITY_LEVELS.get(fail_on.upper(), 0)
            passed = True
            reasons = []

            # Check priority threshold
            for p, rank in cls.PRIORITY_LEVELS.items():
                if rank <= threshold_rank and p_counts[p] > 0:
                    passed = False
                    reasons.append(f"{p_counts[p]} {p} finding(s) detected (fails on {fail_on.upper()})")

            # Check explicit max overrides
            if p_counts["P0"] > max_p0:
                passed = False
                reasons.append(f"P0 count ({p_counts['P0']}) exceeds max allowed ({max_p0})")
            if p_counts["P1"] > max_p1:
                passed = False
                reasons.append(f"P1 count ({p_counts['P1']}) exceeds max allowed ({max_p1})")

            return {
                "passed": passed,
                "fail_on": fail_on.upper(),
                "p_counts": p_counts,
                "reasons": reasons,
                "active_findings": active_findings,
                "total_findings": len(findings)
            }
        finally:
            if close_db:
                db.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SecureScan CI Security Gate")
    parser.add_argument("--audit-id", required=True, help="UUID of the audit to evaluate")
    parser.add_argument("--fail-on", default="P0", choices=["P0", "P1", "P2", "P3"],
                        help="Fail build if active findings meet or exceed this priority (default: P0)")
    parser.add_argument("--max-p0", type=int, default=0, help="Maximum allowed P0 findings (default: 0)")
    parser.add_argument("--max-p1", type=int, default=0, help="Maximum allowed P1 findings (default: 0)")
    parser.add_argument("--output-comment", default=None, help="File path to write GitHub PR comment markdown")

    args = parser.parse_args(argv)

    print(f"[*] Evaluating SecureScan CI Gate for audit: {args.audit_id}")
    print(f"[*] Threshold: fail on {args.fail_on} | max P0: {args.max_p0} | max P1: {args.max_p1}")

    result = CiGateEvaluator.evaluate(
        audit_id=args.audit_id,
        fail_on=args.fail_on,
        max_p0=args.max_p0,
        max_p1=args.max_p1
    )

    if "error" in result:
        print(f"[!] Error: {result['error']}", file=sys.stderr)
        return 1

    counts = result["p_counts"]
    print(f"[*] Findings summary: P0={counts['P0']}, P1={counts['P1']}, P2={counts['P2']}, P3={counts['P3']}")

    if args.output_comment:
        comment = GitHubPrCommentGenerator.generate_comment(
            audit_id=args.audit_id,
            gate_passed=result["passed"],
            fail_on_threshold=args.fail_on,
            findings=result["active_findings"]
        )
        try:
            with open(args.output_comment, "w", encoding="utf-8") as f:
                f.write(comment)
            print(f"[+] Wrote PR comment summary to {args.output_comment}")
        except Exception as e:
            print(f"[!] Failed to write PR comment file: {e}", file=sys.stderr)

    if result["passed"]:
        print("[+] CI GATE PASSED: All findings within allowed thresholds.")
        return 0
    else:
        print("[-] CI GATE FAILED:")
        for r in result["reasons"]:
            print(f"    - {r}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
