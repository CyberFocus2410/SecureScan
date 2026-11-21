"""Vulnerable multi-user application with seeded horizontal IDOR and vertical BFLA."""
from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="Insecure Multi-User Document API")

DOCUMENTS = {
    "doc-user-a-1": {"owner": "user_a", "title": "User A Financial Plan"},
    "doc-user-b-1": {"owner": "user_b", "title": "User B Medical History"}
}

def get_current_role(authorization: str = Header(None)) -> str:
    if not authorization:
        return "anon"
    if "test_token_a" in authorization:
        return "user_a"
    if "test_token_b" in authorization:
        return "user_b"
    if "test_token_admin" in authorization:
        return "admin"
    return "anon"

# Protected endpoint open to anon
@app.get("/api/v1/profile")
def get_profile(authorization: str = Header(None)):
    role = get_current_role(authorization)
    # Bug: returns data even if anon
    return {"status": "ok", "role": role, "profile": "public_data"}

# Horizontal IDOR: User A can read User B's document
@app.get("/api/v1/documents/{id}")
def get_document(id: str, authorization: str = Header(None)):
    role = get_current_role(authorization)
    if role == "anon":
        raise HTTPException(status_code=401, detail="Authentication required")
    # Bug: No ownership check! Any authenticated user can read any document.
    if id in DOCUMENTS:
        return DOCUMENTS[id]
    raise HTTPException(status_code=404, detail="Not found")

# Vertical BFLA: Regular User A can access admin endpoint
@app.get("/api/v1/admin/stats")
def get_admin_stats(authorization: str = Header(None)):
    role = get_current_role(authorization)
    if role == "anon":
        raise HTTPException(status_code=401, detail="Authentication required")
    # Bug: Checks if authenticated, but forgets to check if role == 'admin'!
    return {"total_users": 1000, "revenue": 500000}
