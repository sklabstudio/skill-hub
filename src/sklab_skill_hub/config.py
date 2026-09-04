"""Strict hub configuration (sklab-skills.yaml)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from sklab_skill_hub.models import AutoMode
from sklab_skill_hub.risk import parse_risk


class RegistryConfig(BaseModel):
    model_config = {"extra": "forbid"}
    data_dir: str = "~/.sklab/skills"


class AutoInstallConfig(BaseModel):
    model_config = {"extra": "forbid"}
    mode: AutoMode = AutoMode.SAFE
    allow_trust: list[str] = Field(default_factory=lambda: ["BUILTIN", "VERIFIED"])
    max_risk: str = "LOW"
    permanent_enable: bool = False
    task_scoped_enable: bool = True

    @field_validator("mode", mode="before")
    @classmethod
    def _mode(cls, v: Any) -> AutoMode:
        if isinstance(v, AutoMode):
            return v
        return AutoMode[str(v).strip().upper()]

    def max_risk_level(self):  # -> RiskLevel (avoid circular import at module load)
        from sklab_skill_hub.models import RiskLevel

        return RiskLevel[str(self.max_risk).strip().upper()]


class SourcesConfig(BaseModel):
    model_config = {"extra": "forbid"}
    builtin: bool = True
    coding_lab: bool = True
    local: list[str] = Field(default_factory=list)
    catalogs: list[str] = Field(default_factory=list)


class SecurityConfig(BaseModel):
    model_config = {"extra": "forbid"}
    block_secret_network_combo: bool = True
    quarantine_executable_community: bool = True


class HubConfig(BaseModel):
    model_config = {"extra": "forbid"}
    schema_version: int = 1
    registry: RegistryConfig = Field(default_factory=RegistryConfig)
    auto_install: AutoInstallConfig = Field(default_factory=AutoInstallConfig)
    categories: dict[str, AutoInstallConfig] = Field(default_factory=dict)
    sources: SourcesConfig = Field(default_factory=SourcesConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, v: int) -> int:
        if v != 1:
            raise ValueError(f"unsupported schema_version: {v!r}")
        return v


DEFAULT_CONFIG_YAML = """\
schema_version: 1

registry:
  data_dir: ~/.sklab/skills

auto_install:
  mode: safe
  allow_trust:
    - BUILTIN
    - VERIFIED
  max_risk: low
  permanent_enable: false
  task_scoped_enable: true

sources:
  builtin: true
  coding_lab: true
  local: []

security:
  block_secret_network_combo: true
  quarantine_executable_community: true
"""


def _normalize_mode_strings(data: Any) -> Any:
    if isinstance(data, dict):
        out: dict[str, Any] = {}
        for k, v in data.items():
            if k == "mode" and isinstance(v, str):
                out[k] = v.strip().upper()
            elif k == "max_risk" and isinstance(v, str):
                out[k] = v.strip().upper()
            elif k in ("allow_trust",) and isinstance(v, list):
                out[k] = [str(x).strip().upper() for x in v]
            else:
                out[k] = _normalize_mode_strings(v)
        return out
    if isinstance(data, list):
        return [_normalize_mode_strings(v) for v in data]
    return data


def load_config(path: Path | None = None, data_dir: Path | None = None) -> HubConfig:
    candidates: list[Path] = []
    if path is not None:
        candidates.append(Path(path).expanduser())
    if data_dir is not None:
        candidates.append(Path(data_dir) / "sklab-skills.yaml")
    candidates.append(Path.cwd() / "sklab-skills.yaml")
    for cand in candidates:
        if cand.is_file():
            try:
                raw = yaml.safe_load(cand.read_text(encoding="utf-8")) or {}
            except OSError:
                continue
            raw = _normalize_mode_strings(raw)
            # Validate max_risk early for a clear error.
            mr = (raw.get("auto_install") or {}).get("max_risk", "LOW")
            parse_risk(str(mr))
            return HubConfig.model_validate(raw)
    return HubConfig()


def save_config(config: HubConfig, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = config.model_dump(mode="json")
    # Lowercase enums for friendliness.
    def _lower(o: Any) -> Any:
        if isinstance(o, dict):
            return {k: _lower(v) for k, v in o.items()}
        if isinstance(o, list):
            return [_lower(v) for v in o]
        if isinstance(o, str) and o in ("OFF", "SAFE", "SMART", "FULL", "LOW", "MEDIUM", "HIGH", "CRITICAL",
                                        "BUILTIN", "VERIFIED", "COMMUNITY", "LOCAL"):
            return o.lower()
        return o
    path.write_text(yaml.safe_dump(_lower(data), sort_keys=False), encoding="utf-8")


def effective_auto_config(config: HubConfig, category: str = "") -> AutoInstallConfig:
    base = config.auto_install
    if category:
        override = config.categories.get(category.lower()) or config.categories.get(category)
        if override is not None:
            return override
    return base
