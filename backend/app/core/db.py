"""SQLAlchemy database engine, session management, and Base model."""
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.core.config import settings

# Configure engine with SQLite check_same_thread compatibility if running locally
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

# Normalize SQLite relative database URL to absolute path rooted at project BASE_DIR
db_url = settings.DATABASE_URL
if db_url.startswith("sqlite:///./"):
    abs_db = (settings.BASE_DIR / "securescan_dev.db").resolve()
    db_url = f"sqlite:///{abs_db.as_posix()}"

engine = create_engine(
    db_url,
    connect_args=connect_args,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Dependency yielding a database session for requests."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

