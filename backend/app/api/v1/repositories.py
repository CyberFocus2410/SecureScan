"""Repository submission and discovery endpoints."""
import uuid
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from app.core.db import get_db
from app.core.errors import RepoNotFoundError
from app.models.models import RepositoryModel
from app.schemas.audit import Repository, RepositoryCreate
from app.services.github_import import parse_and_validate_github_url, validate_branch

router = APIRouter(prefix="/repositories", tags=["Repositories"])


@router.post("", response_model=Repository, status_code=status.HTTP_200_OK)
def create_or_get_repository(
    payload: RepositoryCreate,
    db: Session = Depends(get_db)
):
    """
    Submit a public GitHub repository URL for audit (FR-IMP-01).
    Validates host, path, and scheme strictly before network fetch.
    """
    raw_url = str(payload.github_url)
    owner, repo_name, canonical_url = parse_and_validate_github_url(raw_url)
    branch = validate_branch(payload.branch)

    # Check if repository already registered
    existing = db.query(RepositoryModel).filter(
        RepositoryModel.canonical_url == canonical_url
    ).first()

    if existing:
        return existing

    new_repo = RepositoryModel(
        id=str(uuid.uuid4()),
        github_owner=owner,
        github_repo=repo_name,
        canonical_url=canonical_url,
        default_branch=branch,
        detected_languages=[],
        detected_frameworks=[]
    )
    db.add(new_repo)
    db.commit()
    db.refresh(new_repo)
    return new_repo


@router.get("/{repo_id}", response_model=Repository)
def get_repository(
    repo_id: str,
    db: Session = Depends(get_db)
):
    """Retrieve repository metadata and detected frameworks."""
    repo = db.query(RepositoryModel).filter(RepositoryModel.id == repo_id).first()
    if not repo:
        raise RepoNotFoundError(f"Repository with ID '{repo_id}' not found.")
    return repo

