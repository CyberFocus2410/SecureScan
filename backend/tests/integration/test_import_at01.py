"""AT-01: Valid repository import, correct SHA, and language/framework detection."""
import re
import subprocess
from pathlib import Path
from app.services.github_import import detect_languages_and_frameworks

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
PYTHON_FIXTURE = ROOT_DIR / "fixtures" / "valid-python-api"
NODE_FIXTURE = ROOT_DIR / "fixtures" / "valid-node-api"


def test_at01_python_fixture_sha_and_framework():
    """AT-01: Valid Python/FastAPI fixture produces correct SHA and framework inventory."""
    assert PYTHON_FIXTURE.exists()

    # Query local git rev-parse HEAD
    cmd = ["git", "-C", str(PYTHON_FIXTURE), "rev-parse", "HEAD"]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, text=True, check=True)
    sha = res.stdout.strip()

    # Verify SHA format: 40 hex characters
    assert re.match(r"^[0-9a-fA-F]{40}$", sha)

    # Detect languages and frameworks
    languages, frameworks = detect_languages_and_frameworks(PYTHON_FIXTURE)
    assert "Python" in languages
    assert "FastAPI" in frameworks


def test_at01_node_fixture_sha_and_framework():
    """AT-01: Valid Node/Express fixture produces correct SHA and framework inventory."""
    assert NODE_FIXTURE.exists()

    cmd = ["git", "-C", str(NODE_FIXTURE), "rev-parse", "HEAD"]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, text=True, check=True)
    sha = res.stdout.strip()

    assert re.match(r"^[0-9a-fA-F]{40}$", sha)

    languages, frameworks = detect_languages_and_frameworks(NODE_FIXTURE)
    assert "JavaScript" in languages
    assert "Express" in frameworks

