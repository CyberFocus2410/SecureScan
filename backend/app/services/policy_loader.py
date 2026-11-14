"""Policy loader: reads and schema-validates policies/*.yaml."""
from pathlib import Path
from typing import Any
import yaml
from pydantic import BaseModel, Field, ValidationError
from app.core.config import settings
from app.core.errors import PolicyLoadError


class SecurityControlPolicyItem(BaseModel):
    id: str
    title: str
    category: str
    method: str
    evidence_class: str
    mvp_priority: str
    owasp_refs: list[str] = Field(default_factory=list)


class SecurityControlsPolicy(BaseModel):
    version: str
    as_of_date: str
    controls: list[SecurityControlPolicyItem]


class OwaspMappingItem(BaseModel):
    internal_control_id: str
    standard: str
    standard_version: str
    external_ref: str
    rationale: str


class OwaspMappingsPolicy(BaseModel):
    version: str
    mappings: list[OwaspMappingItem]


class DpdpControlItem(BaseModel):
    id: str
    title: str
    act_section: str
    rules_ref: str
    evidence_tier: str
    mvp_priority: str
    legal_source: dict[str, Any] | None = None


class DpdpControlsPolicy(BaseModel):
    version: str
    as_of_date: str
    controls: list[DpdpControlItem]


class DpdpCommencementPhase(BaseModel):
    date: str
    status_label: str
    gazette_id: str
    provisions: list[str]


class DpdpCommencementPolicy(BaseModel):
    version: str
    phases: list[DpdpCommencementPhase]


class PenaltyScheduleItem(BaseModel):
    schedule_item: int
    breach: str
    related_act_section: str
    ceiling_inr: str
    mandatory_caveat: str = "Potential legal category; applicability and liability not determined."
    legal_source: dict[str, Any] | None = None


class PenaltySchedulePolicy(BaseModel):
    version: str
    source: str
    caveat: str
    items: list[PenaltyScheduleItem]


class PolicyBundle(BaseModel):
    security_controls: SecurityControlsPolicy
    owasp_mappings: OwaspMappingsPolicy
    dpdp_controls: DpdpControlsPolicy
    dpdp_commencement: DpdpCommencementPolicy
    penalty_schedule: PenaltySchedulePolicy


def load_yaml(file_path: Path) -> dict[str, Any]:
    """Safely parse YAML file."""
    if not file_path.exists():
        raise PolicyLoadError(f"Policy file not found: {file_path}")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if not isinstance(data, dict):
                raise PolicyLoadError(f"Malformed YAML in {file_path}: expected dictionary root")
            return data
    except yaml.YAMLError as exc:
        raise PolicyLoadError(f"YAML parsing syntax error in {file_path}: {exc}")


def load_and_validate_policies(policy_dir: Path | None = None) -> PolicyBundle:
    """Load and validate all policies/*.yaml files."""
    base = policy_dir or settings.POLICY_DIR
    try:
        sec_data = load_yaml(base / "security_controls.yaml")
        security_controls = SecurityControlsPolicy.model_validate(sec_data)

        owasp_data = load_yaml(base / "owasp_mappings.yaml")
        owasp_mappings = OwaspMappingsPolicy.model_validate(owasp_data)

        dpdp_data = load_yaml(base / "dpdp_controls.yaml")
        dpdp_controls = DpdpControlsPolicy.model_validate(dpdp_data)

        comm_data = load_yaml(base / "dpdp_commencement.yaml")
        dpdp_commencement = DpdpCommencementPolicy.model_validate(comm_data)

        pen_data = load_yaml(base / "penalty_schedule.yaml")
        penalty_schedule = PenaltySchedulePolicy.model_validate(pen_data)

        return PolicyBundle(
            security_controls=security_controls,
            owasp_mappings=owasp_mappings,
            dpdp_controls=dpdp_controls,
            dpdp_commencement=dpdp_commencement,
            penalty_schedule=penalty_schedule
        )
    except ValidationError as exc:
        raise PolicyLoadError(f"Policy schema validation failed: {exc}")


_cached_bundle: PolicyBundle | None = None


def get_policy_bundle(policy_dir: Path | None = None, force_reload: bool = False) -> PolicyBundle:
    """Return cached singleton policy bundle, loading it if not yet initialized."""
    global _cached_bundle
    if _cached_bundle is None or force_reload:
        _cached_bundle = load_and_validate_policies(policy_dir)
    return _cached_bundle

