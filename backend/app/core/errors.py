"""Typed error model and custom exceptions matching frozen API contracts."""
import logging
from enum import Enum
from typing import Any
from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError


class ErrorCode(str, Enum):
    """Frozen application error codes from docs/api_contracts.md."""
    ERR_INVALID_REPO_URL = "ERR_INVALID_REPO_URL"
    ERR_UNSUPPORTED_PROTOCOL = "ERR_UNSUPPORTED_PROTOCOL"
    ERR_INVALID_BRANCH = "ERR_INVALID_BRANCH"
    ERR_UNAUTHORIZED_SESSION = "ERR_UNAUTHORIZED_SESSION"
    ERR_REPO_NOT_FOUND = "ERR_REPO_NOT_FOUND"
    ERR_AUDIT_NOT_FOUND = "ERR_AUDIT_NOT_FOUND"
    ERR_REPORT_NOT_FOUND = "ERR_REPORT_NOT_FOUND"
    ERR_DUPLICATE_ACTIVE_AUDIT = "ERR_DUPLICATE_ACTIVE_AUDIT"
    ERR_REPO_TOO_LARGE = "ERR_REPO_TOO_LARGE"
    ERR_VALIDATION_ERROR = "ERR_VALIDATION_ERROR"
    ERR_QUOTA_EXCEEDED = "ERR_QUOTA_EXCEEDED"
    ERR_CLONE_TIMEOUT = "ERR_CLONE_TIMEOUT"
    ERR_SCANNER_EXECUTION_FAILED = "ERR_SCANNER_EXECUTION_FAILED"
    ERR_POLICY_LOAD_FAILED = "ERR_POLICY_LOAD_FAILED"
    ERR_REPORT_GENERATION_FAILED = "ERR_REPORT_GENERATION_FAILED"
    ERR_AI_PROVIDER_UNAVAILABLE = "ERR_AI_PROVIDER_UNAVAILABLE"
    ERR_INTERNAL_SERVER_ERROR = "ERR_INTERNAL_SERVER_ERROR"


class SecureScanException(Exception):
    """Base exception for all domain and operational errors."""
    def __init__(
        self,
        code: ErrorCode,
        message: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        details: Any = None
    ):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details


class InvalidRepoUrlError(SecureScanException):
    def __init__(self, message: str = "Invalid GitHub repository URL format", details: Any = None):
        super().__init__(
            code=ErrorCode.ERR_INVALID_REPO_URL,
            message=message,
            status_code=status.HTTP_400_BAD_REQUEST,
            details=details
        )


class UnauthorizedSessionError(SecureScanException):
    def __init__(self, message: str = "Unauthorized session access to resource", details: Any = None):
        super().__init__(
            code=ErrorCode.ERR_UNAUTHORIZED_SESSION,
            message=message,
            status_code=status.HTTP_403_FORBIDDEN,
            details=details
        )


class RepoNotFoundError(SecureScanException):
    def __init__(self, message: str = "Repository not found or inaccessible", details: Any = None):
        super().__init__(
            code=ErrorCode.ERR_REPO_NOT_FOUND,
            message=message,
            status_code=status.HTTP_404_NOT_FOUND,
            details=details
        )


class AuditNotFoundError(SecureScanException):
    def __init__(self, message: str = "Audit ID not found", details: Any = None):
        super().__init__(
            code=ErrorCode.ERR_AUDIT_NOT_FOUND,
            message=message,
            status_code=status.HTTP_404_NOT_FOUND,
            details=details
        )


class DuplicateActiveAuditError(SecureScanException):
    def __init__(self, message: str = "An audit for this commit is already in progress", details: Any = None):
        super().__init__(
            code=ErrorCode.ERR_DUPLICATE_ACTIVE_AUDIT,
            message=message,
            status_code=status.HTTP_409_CONFLICT,
            details=details
        )


class RepoTooLargeError(SecureScanException):
    def __init__(self, message: str = "Repository exceeds maximum size or file count limits", details: Any = None):
        super().__init__(
            code=ErrorCode.ERR_REPO_TOO_LARGE,
            message=message,
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            details=details
        )


class QuotaExceededError(SecureScanException):
    def __init__(self, message: str = "Session scan quota exceeded. Please wait before submitting more audits.", details: Any = None):
        super().__init__(
            code=ErrorCode.ERR_QUOTA_EXCEEDED,
            message=message,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            details=details
        )


class PolicyLoadError(SecureScanException):
    def __init__(self, message: str = "Policy configuration failed schema validation", details: Any = None):
        super().__init__(
            code=ErrorCode.ERR_POLICY_LOAD_FAILED,
            message=message,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            details=details
        )


async def securescan_exception_handler(_: Request, exc: SecureScanException) -> JSONResponse:
    """Format domain exceptions according to ErrorResponse schema."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.code.value,
                "message": exc.message,
                "details": exc.details
            }
        }
    )


async def validation_exception_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    """Format FastAPI validation errors into the typed error response schema."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": {
                "code": ErrorCode.ERR_VALIDATION_ERROR.value,
                "message": "Request validation failed",
                "details": exc.errors()
            }
        }
    )


logger = logging.getLogger("securescan")


async def unhandled_exception_handler(_: Request, exc: Exception) -> JSONResponse:
    """Generic error handler: logs details server-side without leaking stack traces or internal details to clients (Playbook §20)."""
    logger.error("Unhandled server exception: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": ErrorCode.ERR_INTERNAL_SERVER_ERROR.value,
                "message": "An internal server error occurred.",
                "details": None
            }
        }
    )


