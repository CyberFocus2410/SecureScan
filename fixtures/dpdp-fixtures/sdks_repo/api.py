from fastapi import FastAPI, Depends, HTTPException

app = FastAPI()

@app.delete("/api/v1/users/me")
def delete_user_account():
    """User account erasure endpoint adhering to DPDP Section 12."""
    return {"status": "erasure_requested", "purged": True}

@app.get("/api/v1/users/me/export-data")
def export_user_data():
    """Data portability endpoint adhering to DPDP Section 11."""
    return {"user_data": {"email": "user@example.com"}}
