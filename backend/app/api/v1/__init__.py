"""API v1 router registry."""
from fastapi import APIRouter
from app.api.v1.health import router as health_router
from app.api.v1.repositories import router as repositories_router
from app.api.v1.audits import router as audits_router
from app.api.v1.findings import router as findings_router
from app.api.v1.security import router as security_router
from app.api.v1.dpdp import router as dpdp_router
from app.api.v1.reports import router as reports_router

api_v1_router = APIRouter()
api_v1_router.include_router(health_router, tags=["Health"])
api_v1_router.include_router(repositories_router)
api_v1_router.include_router(audits_router)
api_v1_router.include_router(findings_router)
api_v1_router.include_router(security_router)
api_v1_router.include_router(dpdp_router)
api_v1_router.include_router(reports_router)
