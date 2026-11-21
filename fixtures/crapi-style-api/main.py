"""Vulnerable FastAPI application modeling crAPI vulnerability patterns."""
from fastapi import FastAPI, HTTPException

app = FastAPI(title="crAPI Vehicle Workshop")

# API1:2023 BOLA - accepts order_id without checking whether current user owns it
@app.get("/api/v1/orders/{order_id}")
def get_order(order_id: str):
    # Insecure direct object reference (BOLA) - no user/tenant check
    return {"order_id": order_id, "amount": 100, "status": "CONFIRMED"}

# API2:2023 Broken Authentication - Sensitive user list exposed without auth dependency
@app.get("/api/v1/users")
def list_users():
    return [{"id": "u-1", "email": "admin@crapi.io", "role": "admin"}]

# API4:2023 Unrestricted Resource Consumption - missing pagination parameters
@app.get("/api/v1/transactions")
def get_transactions():
    return [{"tx_id": i} for i in range(1000)]

# API6:2023 Sensitive Business Flow - missing rate limiting on coupon redemption
@app.post("/api/v1/coupons/apply")
def apply_coupon(code: str):
    return {"discount": 20, "applied": True}

# API9:2023 Shadow Endpoint - implemented in source code but omitted from openapi.json
@app.post("/api/v1/internal/admin/wipe")
def shadow_admin_wipe():
    return {"status": "wiped"}
