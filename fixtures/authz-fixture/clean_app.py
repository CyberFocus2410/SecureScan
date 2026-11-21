"""Hardened multi-user application enforcing horizontal ownership and vertical role boundaries."""
from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="Clean Multi-User Document API")

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

@app.get("/api/v1/profile")
def get_profile_clean(authorization: str = Header(None)):
    role = get_current_role(authorization)
    if role == "anon":
        raise HTTPException(status_code=401, detail="Authentication required")
    return {"status": "ok", "role": role}

@app.get("/api/v1/documents/{id}")
def get_document_clean(id: str, authorization: str = Header(None)):
    role = get_current_role(authorization)
    if role == "anon":
        raise HTTPException(status_code=401, detail="Authentication required")
    if id not in DOCUMENTS:
        raise HTTPException(status_code=404, detail="Not found")
    
    doc = DOCUMENTS[id]
    # Enforce horizontal ownership: only owner or admin can read
    if doc["owner"] != role and role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden: You do not own this document")
    return doc

@app.get("/api/v1/admin/stats")
def get_admin_stats_clean(authorization: str = Header(None)):
    role = get_current_role(authorization)
    if role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden: Administrative privileges required")
    return {"total_users": 1000, "revenue": 500000}
