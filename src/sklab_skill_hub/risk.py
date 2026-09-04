"""Deterministic risk classification. Policy signal, not malware verdict."""

from __future__ import annotations

from sklab_skill_hub.models import RiskLevel, SkillManifest


def classify_risk(manifest: SkillManifest, has_executable: bool = False) -> RiskLevel:
    p = manifest.permissions
    # CRITICAL: secrets combined with network/shell/exfiltration scope.
    if p.secrets and (p.network or p.shell or p.web_access or p.provider_access):
        return RiskLevel.CRITICAL
    if p.provider_access and p.network:
        return RiskLevel.CRITICAL
    # HIGH: shell+network, git write, docker, secrets alone with exec scope.
    if p.docker:
        return RiskLevel.HIGH
    if p.shell and (p.network or p.web_access):
        return RiskLevel.HIGH
    if p.git_write and (p.shell or p.network):
        return RiskLevel.HIGH
    if p.secrets:
        return RiskLevel.HIGH
    if has_executable and (p.shell or p.network):
        return RiskLevel.HIGH
    # MEDIUM: filesystem write, limited shell recipe, git write alone, mcp.
    if p.filesystem_write or p.shell or p.git_write or p.mcp or has_executable:
        return RiskLevel.MEDIUM
    # LOW: read-only declarative prompt/checklist/knowledge.
    return RiskLevel.LOW


RISK_ORDER = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}


def risk_allows(risk: RiskLevel, max_risk: RiskLevel) -> bool:
    return RISK_ORDER[risk] <= RISK_ORDER[max_risk]


def parse_risk(value: str) -> RiskLevel:
    return RiskLevel[str(value).strip().upper()]
