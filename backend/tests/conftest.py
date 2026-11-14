"""Global pytest configuration: set up sys.path and test database isolation."""
import sys
from pathlib import Path

# Add backend and root directories to sys.path
backend_dir = Path(__file__).resolve().parent.parent
root_dir = backend_dir.parent

if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

import pytest
from app.core.db import SessionLocal


@pytest.fixture
def db_session():
    """Yield an isolated database session for unit and integration tests."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


