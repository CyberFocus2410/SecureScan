"""Pydantic schemas for Target Management, Verification, Scope, and Consent (Step 3)."""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class TargetCreate(BaseModel):
    url: str = Field(..., description="Target URL, hostname, or Git repo URL.")
    target_type: str = Field("WEBSITE", description="Target type: WEBSITE, API, REPOSITORY, IP_CIDR, CLOUD_ASSET.")
    name: Optional[str] = Field(None, description="Friendly name for the target.")


class TargetResponse(BaseModel):
    id: str
    session_id: str
    name: Optional[str]
    target_type: str
    url: str
    verified: bool
    verified_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class VerificationChallengeRequest(BaseModel):
    method: str = Field("DNS_TXT", description="Verification method: DNS_TXT, WELL_KNOWN_FILE, META_TAG, REPO_TOKEN.")


class VerificationChallengeResponse(BaseModel):
    id: str
    target_id: str
    verification_method: str
    token: str
    status: str
    proof_details: Optional[Dict[str, Any]] = None
    expires_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class VerifyChallengeRequest(BaseModel):
    verification_id: Optional[str] = None
    proof: Optional[Dict[str, Any]] = None


class VerifyChallengeResponse(BaseModel):
    verified: bool
    target_id: str
    status: str
    message: str


class ScopeConfigRequest(BaseModel):
    allowed_hosts: Optional[List[str]] = None
    allowed_paths: Optional[List[str]] = None
    excluded_paths: Optional[List[str]] = None
    max_rps: int = Field(5, ge=1, le=50)
    max_crawl_depth: int = Field(3, ge=1, le=10)


class ScopeResponse(BaseModel):
    id: str
    target_id: str
    allowed_hosts: List[str]
    allowed_paths: List[str]
    excluded_paths: List[str]
    max_rps: int
    max_crawl_depth: int

    class Config:
        from_attributes = True


class ConsentRequest(BaseModel):
    user_id: str = Field(..., description="Identity of the consenting party.")
    terms_version: str = Field("2.0", description="Version of Terms of Authorization accepted.")


class ConsentResponse(BaseModel):
    id: str
    target_id: str
    user_id: str
    terms_version: str
    scope_hash: str
    accepted_at: datetime

    class Config:
        from_attributes = True
