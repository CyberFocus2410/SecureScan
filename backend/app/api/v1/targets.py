"""Target management, ownership verification, scope, and consent API routes (Architecture §5, ADR-002, Step 3)."""
from typing import List, Optional
from fastapi import APIRouter, Depends, Request, status, HTTPException
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.session import get_session_id
from app.core.errors import (
    TargetNotFoundError,
    TargetNotVerifiedError,
    SSRFBlockedError,
    UnauthorizedSessionError,
    OutOfScopeError,
    ConsentRequiredError
)
from app.models.models import (
    TargetModel,
    TargetVerificationModel,
    ScanScopeModel,
    ConsentRecordModel
)
from app.schemas.target import (
    TargetCreate,
    TargetResponse,
    VerificationChallengeRequest,
    VerificationChallengeResponse,
    VerifyChallengeRequest,
    VerifyChallengeResponse,
    ScopeConfigRequest,
    ScopeResponse,
    ConsentRequest,
    ConsentResponse
)
from app.services.targets import (
    register_target,
    create_verification_challenge,
    verify_target_ownership,
    configure_scan_scope,
    record_scan_consent
)

router = APIRouter(prefix="/targets", tags=["Targets & Verification"])


def _get_target_for_session(db: Session, target_id: str, session_id: str) -> TargetModel:
    target = db.query(TargetModel).filter(TargetModel.id == target_id).first()
    if not target:
        raise TargetNotFoundError(f"Target '{target_id}' not found.")
    if target.session_id != session_id:
        raise UnauthorizedSessionError("Unauthorized session access to target.")
    return target


@router.post("", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def create_target(
    payload: TargetCreate,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Register a new target with SSRF and private-network checks (ADR-002, Step 3)."""
    return register_target(
        db=db,
        session_id=session_id,
        url=payload.url,
        target_type=payload.target_type,
        name=payload.name
    )


@router.get("", response_model=List[TargetResponse])
def list_targets(
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """List all registered targets for the current session."""
    return db.query(TargetModel).filter(
        TargetModel.session_id == session_id
    ).order_by(TargetModel.created_at.desc()).all()


@router.get("/{target_id}", response_model=TargetResponse)
def get_target(
    target_id: str,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Retrieve target details for current session."""
    return _get_target_for_session(db, target_id, session_id)


@router.post("/{target_id}/challenges", response_model=VerificationChallengeResponse, status_code=status.HTTP_201_CREATED)
def request_verification_challenge(
    target_id: str,
    payload: VerificationChallengeRequest,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Generate a 30-day verification token (DNS TXT, well-known file, meta tag, or repo token)."""
    _get_target_for_session(db, target_id, session_id)
    return create_verification_challenge(
        db=db,
        target_id=target_id,
        method=payload.method
    )


@router.post("/{target_id}/verify", response_model=VerifyChallengeResponse)
def verify_target(
    target_id: str,
    payload: VerifyChallengeRequest,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Attempt ownership verification for a target."""
    _get_target_for_session(db, target_id, session_id)
    verified = verify_target_ownership(
        db=db,
        target_id=target_id,
        verification_id=payload.verification_id,
        mock_proof=payload.proof
    )
    if verified:
        return VerifyChallengeResponse(
            verified=True,
            target_id=target_id,
            status="VERIFIED",
            message="Ownership successfully verified."
        )
    return VerifyChallengeResponse(
        verified=False,
        target_id=target_id,
        status="FAILED",
        message="Verification token or proof could not be confirmed."
    )


@router.post("/{target_id}/scope", response_model=ScopeResponse)
def set_target_scope(
    target_id: str,
    payload: ScopeConfigRequest,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Configure allowed/excluded URL paths, crawl limits, and rate limits."""
    _get_target_for_session(db, target_id, session_id)
    return configure_scan_scope(
        db=db,
        target_id=target_id,
        allowed_hosts=payload.allowed_hosts,
        allowed_paths=payload.allowed_paths,
        excluded_paths=payload.excluded_paths,
        max_rps=payload.max_rps,
        max_crawl_depth=payload.max_crawl_depth
    )


@router.get("/{target_id}/scope", response_model=Optional[ScopeResponse])
def get_target_scope(
    target_id: str,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Get the active scope configuration for a target."""
    _get_target_for_session(db, target_id, session_id)
    scope = db.query(ScanScopeModel).filter(ScanScopeModel.target_id == target_id).first()
    return scope


@router.post("/{target_id}/consent", response_model=ConsentResponse, status_code=status.HTTP_201_CREATED)
def record_consent(
    target_id: str,
    payload: ConsentRequest,
    request: Request,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Record immutable legal consent before scan execution."""
    _get_target_for_session(db, target_id, session_id)
    client_ip = request.client.host if request.client else "127.0.0.1"
    return record_scan_consent(
        db=db,
        target_id=target_id,
        user_id=payload.user_id,
        client_ip=client_ip,
        terms_version=payload.terms_version
    )


@router.get("/{target_id}/consent", response_model=List[ConsentResponse])
def list_consent_records(
    target_id: str,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Retrieve recorded consent records for a target."""
    _get_target_for_session(db, target_id, session_id)
    return db.query(ConsentRecordModel).filter(
        ConsentRecordModel.target_id == target_id
    ).order_by(ConsentRecordModel.accepted_at.desc()).all()
