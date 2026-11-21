#!/usr/bin/env python3
"""SecureScan CLI dispatcher."""
import os
import sys

# Ensure backend directory is in python path
backend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print("Usage: securescan <command>")
        print("Available commands:")
        print("  doctor    Run tool self-tests and sandbox diagnostics")
        print("  ci        Evaluate CI gate thresholds against an audit")
        sys.exit(0)

    cmd = args[0]
    if cmd == "doctor":
        from app.cli.doctor import main as doctor_main
        sys.exit(doctor_main())
    elif cmd == "ci":
        from app.cli.ci_gate import main as ci_main
        sys.exit(ci_main(args[1:]))
    else:
        print(f"Unknown command: '{cmd}'. Run 'securescan --help' for available commands.")
        sys.exit(1)
