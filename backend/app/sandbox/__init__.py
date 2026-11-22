"""Sandbox backend abstraction module (Architecture §5, ADR-002)."""
import logging
import os
from typing import Optional

from app.core.config import settings
from app.sandbox.base import SandboxEngine, SandboxUnavailableError
from app.sandbox.docker import DockerSandbox
from app.sandbox.bubblewrap import BubblewrapSandbox
from app.sandbox.subprocess_dev import SubprocessDevSandbox
from app.sandbox.hosted_container import HostedContainerSandbox

logger = logging.getLogger(__name__)

__all__ = [
    "SandboxEngine",
    "SandboxUnavailableError",
    "DockerSandbox",
    "BubblewrapSandbox",
    "SubprocessDevSandbox",
    "HostedContainerSandbox",
    "get_sandbox_engine",
]

_active_engine: Optional[SandboxEngine] = None


def get_sandbox_engine(force_backend: Optional[str] = None) -> SandboxEngine:
    """
    Resolve active sandbox engine following ADR-002:
    1. If explicit backend requested or configured, evaluate it.
    2. If 'auto':
       - Select DockerSandbox if Docker/Podman is available.
       - Select BubblewrapSandbox if bwrap/nsjail is available.
       - Select HostedContainerSandbox if running on hosted PaaS (Render / SANDBOX_ALLOW_HOSTED_SUBPROCESS).
       - Fall back to SubprocessDevSandbox in non-production environments.
       - FAIL-CLOSED in production if no sandbox engine is available.
    """
    backend_choice = (force_backend or getattr(settings, "SANDBOX_BACKEND", "auto")).lower()
    is_prod = getattr(settings, "ENVIRONMENT", "development").lower() == "production"

    if backend_choice == "docker":
        engine = DockerSandbox()
        if not engine.is_available():
            raise SandboxUnavailableError("Docker sandbox requested but docker/podman daemon is unavailable.")
        return engine

    if backend_choice == "bubblewrap":
        engine = BubblewrapSandbox()
        if not engine.is_available():
            raise SandboxUnavailableError("Bubblewrap sandbox requested but bwrap/nsjail binary is unavailable.")
        return engine

    if backend_choice in ("hosted", "hosted-container"):
        hosted = HostedContainerSandbox()
        if not hosted.is_available():
            raise SandboxUnavailableError("Hosted container sandbox requested but not available/enabled.")
        return hosted

    if backend_choice in ("subprocess-dev", "subprocess"):
        if is_prod and not (getattr(settings, "SANDBOX_ALLOW_HOSTED_SUBPROCESS", False) or os.environ.get("RENDER", "").lower() == "true"):
            raise SandboxUnavailableError(
                "Insecure subprocess-dev sandbox engine cannot be run in production. Fail-closed policy enforced."
            )
        return SubprocessDevSandbox()

    # auto resolution
    docker = DockerSandbox()
    if docker.is_available():
        logger.info("Auto-selected Docker sandbox engine.")
        return docker

    bwrap = BubblewrapSandbox()
    if bwrap.is_available():
        logger.info("Auto-selected Bubblewrap sandbox engine.")
        return bwrap

    hosted = HostedContainerSandbox()
    if hosted.is_available():
        logger.info("Auto-selected HostedContainerSandbox (PaaS cloud container isolation).")
        return hosted

    if not is_prod:
        logger.warning("No container sandbox detected. Using SubprocessDevSandbox for development/testing.")
        return SubprocessDevSandbox()

    # Fail closed in production
    raise SandboxUnavailableError(
        "Production environment detected with no secure sandbox (Docker/Bubblewrap). "
        "Fail-closed policy enforced: scan cannot execute unsandboxed."
    )
