"""Health and readiness check endpoint."""
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.db import get_db

router = APIRouter()


@router.get("/health")
def get_health(db: Session = Depends(get_db)):
    """Health status and service readiness check."""
    # Check database connectivity
    db_status = "CONNECTED"
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        db_status = f"ERROR: {str(exc)}"

    return {
        "status": "OK",
        "version": settings.VERSION,
        "as_of_date": settings.AS_OF_DATE,
        "services": {
            "database": db_status,
            "redis": "CONFIGURED"
        }
    }

