"""Scanner adapter base interface and data structures."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional
from app.schemas.enums import ScannerName, Severity, Confidence
from app.schemas.finding import FindingCreate, FindingRemediation


@dataclass
class ScannerMetadata:
    name: ScannerName
    version: str
    rules_version: str
    supported_languages: list[str]


@dataclass
class RawFinding:
    rule_id: str
    title: str
    description: str
    category: str
    severity: Severity
    confidence: Confidence
    file_path: str
    start_line: int
    end_line: int
    raw_snippet: str
    cwe_ids: list[str] = field(default_factory=list)
    owasp_refs: list[str] = field(default_factory=list)
    technical_fix: Optional[str] = None
    validation_steps: Optional[str] = None
    raw_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScannerExecutionResult:
    scanner: ScannerName
    version: str
    status: str  # COMPLETED, FAILED, TIMEOUT, SKIPPED
    duration_ms: int
    raw_findings: list[RawFinding] = field(default_factory=list)
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    stdout: str = ""
    stderr: str = ""


class BaseScannerAdapter(ABC):
    """
    Abstract contract for scanner integrations (FR-SCN).
    Enforces supports/prepare/execute/parse/normalize/metadata lifecycle.
    """
    @abstractmethod
    def metadata(self) -> ScannerMetadata:
        """Return scanner identification and version metadata."""
        pass

    @abstractmethod
    def supports(self, detected_languages: list[str], detected_frameworks: list[str]) -> bool:
        """Evaluate whether this scanner applies to the target repository."""
        pass

    @abstractmethod
    def prepare(self, worktree_dir: Path) -> dict[str, Any]:
        """Pre-scan validation and argument preparation."""
        pass

    @abstractmethod
    def execute(self, worktree_dir: Path, context: dict[str, Any]) -> ScannerExecutionResult:
        """Execute scanner within sandboxed environment."""
        pass

    @abstractmethod
    def parse(self, execution_result: ScannerExecutionResult) -> list[RawFinding]:
        """Parse scanner-native output into normalized raw findings."""
        pass

    @abstractmethod
    def normalize(self, raw_findings: list[RawFinding], audit_id: str) -> list[FindingCreate]:
        """Convert raw findings into persisted FindingCreate models with parser redaction."""
        pass

