"""Repository submission, local upload, and discovery endpoints."""
import shutil
import uuid
from fastapi import APIRouter, Depends, Request, UploadFile, status
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.db import get_db
from app.core.session import get_session_id
from app.core.errors import RepoNotFoundError, SecureScanException, ErrorCode
from app.models.models import RepositoryModel
from app.schemas.audit import Repository, RepositoryCreate
from app.services.github_import import parse_and_validate_github_url, validate_branch
from app.services.repo_upload import (
    extract_zip_safely,
    save_uploaded_files,
    sanitize_project_name,
)

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


@router.post("/upload", response_model=Repository, status_code=status.HTTP_201_CREATED)
async def upload_repository(
    request: Request,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db),
):
    """
    Upload a local repository as a .zip archive or folder files for static & DPDP scanning.
    Enforces Zip-Slip, symlink, file-count, and size-cap boundaries before staging.
    """
    form = await request.form()
    single_file = form.get("file")
    multi_files = [item for item in form.getlist("files") if hasattr(item, "read")]
    relative_paths = [str(p) for p in form.getlist("relative_paths")]
    raw_project_name = form.get("project_name")
    project_name = str(raw_project_name) if raw_project_name else None

    has_single = single_file is not None and hasattr(single_file, "read")
    if not has_single and not multi_files:
        raise SecureScanException(
            code=ErrorCode.ERR_VALIDATION_ERROR,
            message="Please attach a .zip archive or select a repository folder to upload.",
        )

    repo_id = str(uuid.uuid4())
    staged_dir = settings.WORKTREE_STORAGE_DIR / "uploads" / repo_id

    try:
        if has_single:
            uf: UploadFile = single_file  # type: ignore[assignment]
            filename = uf.filename or "uploaded-repo.zip"
            if not filename.lower().endswith(".zip"):
                raise SecureScanException(
                    code=ErrorCode.ERR_VALIDATION_ERROR,
                    message="Archive uploads must be a .zip file.",
                )
            safe_name = sanitize_project_name(project_name or filename)
            meta = extract_zip_safely(uf.file, staged_dir)
        else:
            entries = []
            for idx, uf in enumerate(multi_files):
                rel = (
                    relative_paths[idx]
                    if idx < len(relative_paths) and relative_paths[idx]
                    else (getattr(uf, "filename", None) or f"file_{idx}")
                )
                content = await uf.read()
                entries.append((rel, content))

            inferred_name = project_name
            if not inferred_name and entries:
                first_part = entries[0][0].replace("\\", "/").lstrip("/").split("/")[0]
                inferred_name = first_part or "uploaded-folder"
            safe_name = sanitize_project_name(inferred_name)
            meta = save_uploaded_files(entries, staged_dir)
    except Exception:
        shutil.rmtree(staged_dir, ignore_errors=True)
        raise

    new_repo = RepositoryModel(
        id=repo_id,
        github_owner="local-upload",
        github_repo=safe_name,
        canonical_url=f"upload://{session_id[:8]}/{repo_id}/{safe_name}",
        default_branch="uploaded",
        last_commit_sha=meta["content_sha"],
        detected_languages=meta["languages"],
        detected_frameworks=meta["frameworks"],
    )
    db.add(new_repo)
    db.commit()
    db.refresh(new_repo)
    return new_repo


@router.get("/{repo_id}", response_model=Repository)
def get_repository(
    repo_id: str,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Retrieve repository metadata and detected frameworks."""
    repo = db.query(RepositoryModel).filter(RepositoryModel.id == repo_id).first()
    if not repo:
        raise RepoNotFoundError(f"Repository with ID '{repo_id}' not found.")
    return repo

