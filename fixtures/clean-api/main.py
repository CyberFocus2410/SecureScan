from fastapi import FastAPI
from sqlalchemy import text

app = FastAPI(title="Clean API")

@app.get("/users")
def get_user(email: str):
    # Parameterized query with safe bind variable
    stmt = text("SELECT * FROM users WHERE email = :email")
    return {"query_prepared": True}

