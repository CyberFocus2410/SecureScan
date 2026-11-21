"""Secure Database Models Fixture with Encryption, Password Hashing, RLS, and Tenant Isolation."""
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Index
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()


class SecureUserModel(Base):
    """User model using strong password hashing and encrypted sensitive data."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, nullable=False, index=True)
    username = Column(String(50), unique=True, nullable=False)
    # Pwd stored as bcrypt/argon2 hash digest
    password_hash = Column(String(255), nullable=False)
    # Sensitive PII encrypted at rest using application envelope or database KMS
    aadhaar_encrypted = Column(String(512), nullable=False)
    pan_encrypted = Column(String(512), nullable=True)

    # Explicit tenant index for query scoping
    __table_args__ = (
        Index("idx_users_tenant_username", "tenant_id", "username"),
    )


class AuditLogModel(Base):
    """Audit table logging security and sensitive data access events."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, nullable=False)
    user_id = Column(Integer, nullable=False)
    action = Column(String(50), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)


def secure_query(db_session, user_input_id, tenant_id):
    """Safe parameterized query enforcing tenant boundary."""
    return db_session.query(SecureUserModel).filter(
        SecureUserModel.id == user_input_id,
        SecureUserModel.tenant_id == tenant_id
    ).first()
