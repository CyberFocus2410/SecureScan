"""Frozen domain enumerations matching docs/api_contracts.md."""
from enum import Enum


class Severity(str, Enum):
    """Vulnerability severity classification."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    """Detection confidence."""
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    EXPERIMENTAL = "EXPERIMENTAL"


class ControlState(str, Enum):
    """Mandatory six-state control result model (Rules.md §C, Architecture §3)."""
    PASS_EVIDENCED = "PASS_EVIDENCED"
    FAIL_EVIDENCED = "FAIL_EVIDENCED"
    POTENTIAL_GAP = "POTENTIAL_GAP"
    NOT_VERIFIED = "NOT_VERIFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


class EvidenceTier(str, Enum):
    """Evidence taxonomy tiers E1 through E5."""
    E1_SOURCE_CODE = "E1_SOURCE_CODE"
    E2_CONFIG_MANIFEST = "E2_CONFIG_MANIFEST"
    E3_SUPPLIED_DOCS = "E3_SUPPLIED_DOCS"
    E4_ORG_ATTESTATION = "E4_ORG_ATTESTATION"
    E5_RUNTIME_TEST = "E5_RUNTIME_TEST"


class AuditStatus(str, Enum):
    """Lifecycle states of an audit run."""
    QUEUED = "QUEUED"
    IMPORTING = "IMPORTING"
    SCANNING = "SCANNING"
    NORMALIZING = "NORMALIZING"
    SECURITY_MAPPING = "SECURITY_MAPPING"
    DPDP_MAPPING = "DPDP_MAPPING"
    REPORT_READY = "REPORT_READY"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class EffectiveDateStatus(str, Enum):
    """DPDP statutory commencement status relative to as_of_date."""
    IN_FORCE = "IN_FORCE"
    UPCOMING = "UPCOMING"
    NOT_DETERMINED = "NOT_DETERMINED"


class ScannerName(str, Enum):
    """Permitted scanner engine identifiers."""
    SEMGREP = "semgrep"
    GITLEAKS = "gitleaks"
    OSV_SCANNER = "osv-scanner"
    BANDIT = "bandit"
    CUSTOM = "custom"


class AuditScope(str, Enum):
    """Audit analysis scope."""
    SECURITY = "SECURITY"
    DPDP = "DPDP"

