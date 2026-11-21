"""SecureScan Tool Doctor CLI (Step 2, ADR-002, Section 5).

Usage:
    python -m app.cli.doctor
    securescan doctor
"""
import sys
from app.services.tool_doctor import run_tool_diagnostics


def main() -> int:
    print("=" * 80)
    print(" SECURESCAN 2.0 — TOOL DOCTOR & SANDBOX DIAGNOSTICS")
    print("=" * 80)

    report = run_tool_diagnostics()
    sandbox = report["sandbox"]

    print(f"\n[SANDBOX ENVIRONMENT]")
    print(f"  Active Engine:         {sandbox['active_engine']}")
    print(f"  Host Environment:      {sandbox['environment']}")
    print(f"  Fail-Closed Enforced:  {sandbox['fail_closed_enforced']}")

    print(f"\n[TOOL MATRIX & FALLBACK STATUS]")
    header = f"{'AREA':<26} | {'STATUS':<15} | {'ACTIVE ENGINE':<32} | {'PRIMARY VERSION'}"
    print("-" * 105)
    print(header)
    print("-" * 105)

    for t in report["tools"]:
        cat = t["category"]
        st = t["status"]
        engine = t["active_engine"]
        ver = t["primary_version"] or "Not installed"
        print(f"{cat:<26} | {st:<15} | {engine:<32} | {ver}")

    print("-" * 105)
    print(f"Summary: {report['total_areas']} areas checked | {report['primary_count']} Primary Active | {report['fallback_count']} Fallback Active | {report['failed_count']} Failed")
    print(f"Overall Status: {report['status']}")
    print("=" * 105)

    if report["failed_count"] > 0:
        print("\nERROR: One or more tools failed diagnostic self-tests without operational fallback.")
        return 1

    print("\nSUCCESS: All security tools operational (Primary or Validated Fallback). Ready for audits.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
