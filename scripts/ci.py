"""CI verification script: lint check, schema validation, and unit tests."""
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "backend"


def run_step(step_name: str, cmd: list[str], cwd: Path = ROOT_DIR) -> None:
    print(f"\n==========================================")
    print(f"RUNNING STEP: {step_name}")
    print(f"COMMAND: {' '.join(cmd)}")
    print(f"==========================================")
    result = subprocess.run(cmd, cwd=cwd)
    if result.returncode != 0:
        print(f"\n❌ Step '{step_name}' failed with exit code {result.returncode}")
        sys.exit(result.returncode)
    print(f"✔ Step '{step_name}' passed.")


def main():
    print("Starting SecureScan AI CI verification suite...")

    # Step 1: Syntax compilation check across backend
    run_step(
        "Python Syntax Compilation",
        [sys.executable, "-m", "compileall", "-q", "app"],
        cwd=BACKEND_DIR
    )

    # Step 2: Policy files YAML syntax and schema validation
    run_step(
        "Policy YAML Schema Validation",
        [sys.executable, "-c", "import sys; sys.path.insert(0, 'backend'); from app.services.policy_loader import load_and_validate_policies; b = load_and_validate_policies(); print('Loaded policy bundle with', len(b.security_controls.controls), 'controls and', len(b.penalty_schedule.items), 'penalty items.')"],
        cwd=ROOT_DIR
    )

    # Step 3: Run Pytest test suite (unit + integration)
    run_step(
        "Pytest Test Suite (unit + integration)",
        [sys.executable, "-m", "pytest", "tests", "-v", "--tb=short"],
        cwd=BACKEND_DIR
    )

    print("\n🎉 ALL CI STEPS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    main()

