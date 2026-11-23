#!/usr/bin/env bash
# Exit on error
set -o errexit

export PIP_PREFER_BINARY=1
export CARGO_HOME=/tmp/.cargo

echo "==> Upgrading pip, setuptools, and wheel..."
python -m pip install --upgrade pip setuptools wheel

echo "==> Installing backend dependencies with pre-built binary wheels..."
python -m pip install --prefer-binary -r requirements.txt

echo "==> Installing pinned primary security scanner tools (tools.lock)..."
python scripts/install_tools.py
if [ -f "scripts/install_tools.py" ]; then
    python scripts/install_tools.py
elif [ -f "backend/scripts/install_tools.py" ]; then
    python backend/scripts/install_tools.py
fi

echo "==> Build successful!"
