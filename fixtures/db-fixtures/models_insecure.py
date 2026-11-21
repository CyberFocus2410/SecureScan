"""Insecure Database Models Fixture for Step 6 Static DB Security Scanner."""
from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class InsecureUserModel(Base):
    """User model storing unhashed password and plaintext PII without encryption."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    # Flaw 1: Unhashed plaintext password
    password = Column(String(100), nullable=False)
    # Flaw 2: Plaintext national identifier (Aadhaar / SSN) without encryption
    aadhaar_number = Column(String(12), nullable=False)
    # Flaw 3: Plaintext credit card number without encryption
    credit_card = Column(String(16), nullable=True)
    cvv = Column(String(4), nullable=True)
    # Flaw 4: Missing tenant / ownership isolation column (no user_id or org_id)


class InsecureOrderModel(Base):
    """Order table lacking ownership column and audit trail."""
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True)
    total_amount = Column(Integer, nullable=False)
    status = Column(String(20), default="pending")


def insecure_query(db_session, user_input_id):
    """Flaw 5: Raw SQL query string concatenation without parameterization."""
    query = f"SELECT * FROM users WHERE id = {user_input_id}"
    return db_session.execute(query)
