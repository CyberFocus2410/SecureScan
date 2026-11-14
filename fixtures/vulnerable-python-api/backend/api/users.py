from pydantic import BaseModel
from fastapi import APIRouter, HTTPException

router = APIRouter()


class UserResponse(BaseModel):
    id: int
    email: str
    password_hash: str  # Sensitive DTO field leak (AT-06)
    national_id: str


@router.get("/users/search")
def search_users(email: str):
    # Intentional SQL Injection flaw (AT-04)
    # Lacks in-code rate limiting (AT-05)
    query = f"SELECT * FROM users WHERE email = '{email}'"
    return {"executed_query": query}


@router.get("/users/{user_id}", response_model=UserResponse)
def get_user(user_id: int):
    # Returns sensitive response model
    return {
        "id": user_id,
        "email": "user@example.com",
        "password_hash": "mock_hash_value",
        "national_id": "000-11-2222"
    }
