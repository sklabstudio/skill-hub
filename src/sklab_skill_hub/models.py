"""Strict Pydantic models: manifest, permissions, provenance, config-adjacent types."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

SKILL_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)([-+][0-9A-Za-z.-]+)?$")


class SkillType(StrEnum):
    PROMPT = "PROMPT"
    WORKFLOW = "WORKFLOW"
    CHECKLIST = "CHECKLIST"
    KNOWLEDGE = "KNOWLEDGE"
    TOOL_WRAPPER = "TOOL_WRAPPER"
    MCP_REFERENCE = "MCP_REFERENCE"
    COMMAND_RECIPE = "COMMAND_RECIPE"
    RULE_PACK = "RULE_PACK"
    TEMPLATE = "TEMPLATE"
    COMPOSITE = "COMPOSITE"


class TrustLevel(StrEnum):
    BUILTIN = "BUILTIN"
    VERIFIED = "VERIFIED"
    COMMUNITY = "COMMUNITY"
    LOCAL = "LOCAL"
    QUARANTINED = "QUARANTINED"
    BLOCKED = "BLOCKED"


class SourceType(StrEnum):
    BUILTIN = "BUILTIN"
    LOCAL_DIRECTORY = "LOCAL_DIRECTORY"
    GIT_REPOSITORY = "GIT_REPOSITORY"
    GITHUB = "GITHUB"
    HTTP_ARCHIVE = "HTTP_ARCHIVE"
    MCP_METADATA = "MCP_METADATA"
    AGENT_NATIVE = "AGENT_NATIVE"


class AutoMode(StrEnum):
    OFF = "OFF"
    SAFE = "SAFE"
    SMART = "SMART"
    FULL = "FULL"


class EnableState(StrEnum):
    INSTALLED = "INSTALLED"
    ENABLED_GLOBAL = "ENABLED_GLOBAL"
    ENABLED_FOR_TASK = "ENABLED_FOR_TASK"
    DISABLED = "DISABLED"
    QUARANTINED = "QUARANTINED"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class InspectVerdict(StrEnum):
    VALID = "VALID"
    INVALID = "INVALID"
    SUSPICIOUS = "SUSPICIOUS"
    INCOMPATIBLE = "INCOMPATIBLE"
    QUARANTINE_RECOMMENDED = "QUARANTINE_RECOMMENDED"


TYPE_ALIASES: dict[str, SkillType] = {
    "prompt": SkillType.PROMPT,
    "workflow": SkillType.WORKFLOW,
    "checklist": SkillType.CHECKLIST,
    "knowledge": SkillType.KNOWLEDGE,
    "tool_wrapper": SkillType.TOOL_WRAPPER,
    "tool-wrapper": SkillType.TOOL_WRAPPER,
    "mcp_reference": SkillType.MCP_REFERENCE,
    "mcp-reference": SkillType.MCP_REFERENCE,
    "command_recipe": SkillType.COMMAND_RECIPE,
    "command-recipe": SkillType.COMMAND_RECIPE,
    "rule_pack": SkillType.RULE_PACK,
    "rule-pack": SkillType.RULE_PACK,
    "template": SkillType.TEMPLATE,
    "composite": SkillType.COMPOSITE,
}


def normalize_skill_type(v: Any) -> SkillType:
    if isinstance(v, SkillType):
        return v
    s = str(v).strip()
    if s in SkillType.__members__:
        return SkillType[s]
    low = s.lower()
    if low in TYPE_ALIASES:
        return TYPE_ALIASES[low]
    up = s.upper()
    if up in SkillType.__members__:
        return SkillType[up]
    raise ValueError(f"unknown skill type: {v!r}")


def normalize_trust_source(v: Any) -> TrustLevel:
    if isinstance(v, TrustLevel):
        return v
    s = str(v).strip().upper()
    if s in TrustLevel.__members__:
        return TrustLevel[s]
    raise ValueError(f"unknown trust source: {v!r}")


class Permissions(BaseModel):
    model_config = {"populate_by_name": True, "extra": "forbid"}

    filesystem_read: bool = False
    filesystem_write: bool = False
    shell: bool = False
    network: bool = False
    git_read: bool = False
    git_write: bool = False
    docker: bool = False
    mcp: bool = False
    secrets: bool = False
    provider_access: bool = False
    web_access: bool = False
    allowed_paths: list[str] = Field(default_factory=list)
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_commands: list[str] = Field(default_factory=list)
    allowed_mcp_servers: list[str] = Field(default_factory=list)
    allowed_secret_refs: list[str] = Field(default_factory=list)
    secret_refs: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _expand_nested(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        d: dict[str, Any] = dict(data)
        fs = d.pop("filesystem", None)
        if isinstance(fs, dict):
            if "read" in fs:
                d.setdefault("filesystem_read", bool(fs["read"]))
            if "write" in fs:
                d.setdefault("filesystem_write", bool(fs["write"]))
        git = d.pop("git", None)
        if isinstance(git, dict):
            if "read" in git:
                d.setdefault("git_read", bool(git["read"]))
            if "write" in git:
                d.setdefault("git_write", bool(git["write"]))
        sec = d.get("secrets")
        # Allow `secrets: {references: [...]}` shape as "requires access".
        if isinstance(sec, dict):
            refs = sec.get("references") or sec.get("refs") or []
            d["secrets"] = True
            existing = list(d.get("allowed_secret_refs") or [])
            for r in refs if isinstance(refs, list) else []:
                existing.append(str(r))
            d["allowed_secret_refs"] = existing
            if "references" in d:
                d.pop("references", None)
        refs_top = d.pop("references", None)
        if isinstance(refs_top, list):
            d.setdefault("allowed_secret_refs", [str(r) for r in refs_top])
        return d

    def has_elevated(self) -> bool:
        return bool(
            self.shell
            or self.network
            or self.docker
            or self.secrets
            or self.provider_access
            or self.filesystem_write
            or self.git_write
        )

    def is_declarative_safe(self) -> bool:
        return not self.has_elevated() and not self.mcp and not self.web_access

    def to_flat(self) -> dict[str, bool]:
        return {
            "filesystem_read": self.filesystem_read,
            "filesystem_write": self.filesystem_write,
            "shell": self.shell,
            "network": self.network,
            "git_read": self.git_read,
            "git_write": self.git_write,
            "docker": self.docker,
            "mcp": self.mcp,
            "secrets": self.secrets,
            "provider_access": self.provider_access,
            "web_access": self.web_access,
        }


class Provenance(BaseModel):
    model_config = {"populate_by_name": True, "extra": "forbid"}

    source_type: SourceType = SourceType.LOCAL_DIRECTORY
    source_url: str = ""
    source_ref: str = ""
    license: str = "LICENSE_UNKNOWN"
    author: str = ""
    imported_at: str = ""
    imported_by: str = ""
    original_fingerprint: str = ""

    @field_validator("source_type", mode="before")
    @classmethod
    def _coerce_source(cls, v: Any) -> Any:
        if isinstance(v, SourceType):
            return v
        s = str(v).strip().upper().replace("-", "_")
        if s in SourceType.__members__:
            return SourceType[s]
        # lowercase aliases like "github"
        s2 = str(v).strip().lower()
        mapping = {
            "github": SourceType.GITHUB,
            "git": SourceType.GIT_REPOSITORY,
            "local": SourceType.LOCAL_DIRECTORY,
            "builtin": SourceType.BUILTIN,
        }
        if s2 in mapping:
            return mapping[s2]
        raise ValueError(f"unknown source_type: {v!r}")


class AgentRequirement(BaseModel):
    model_config = {"extra": "forbid"}

    capability: str

    @field_validator("capability", mode="before")
    @classmethod
    def _upper(cls, v: Any) -> str:
        return str(v).strip().upper()


class Compatibility(BaseModel):
    model_config = {"extra": "forbid"}

    sklab: str = ">=0.1"
    agents: list[AgentRequirement] = Field(default_factory=list)


class SkillEntry(BaseModel):
    model_config = {"extra": "forbid"}

    file: str = "SKILL.md"
    kind: str = "markdown"


class SkillManifest(BaseModel):
    """Strict skill manifest (skill.yaml, schema_version 1)."""

    model_config = {"populate_by_name": True, "extra": "forbid"}

    schema_version: int = Field(default=1)
    id: str
    name: str
    version: str = "1.0.0"
    description: str = ""
    type: SkillType = SkillType.WORKFLOW
    category: str = "general"
    tags: list[str] = Field(default_factory=list)
    trust: dict[str, Any] = Field(default_factory=lambda: {"source": "LOCAL"})
    compatibility: Compatibility = Field(default_factory=Compatibility)
    permissions: Permissions = Field(default_factory=Permissions)
    inputs: list[str] = Field(default_factory=list)
    outputs: list[str] = Field(default_factory=list)
    entry: SkillEntry = Field(default_factory=SkillEntry)
    provenance: Provenance = Field(default_factory=Provenance)
    requires_tools: list[str] = Field(default_factory=list, alias="requires_tools")
    tools: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    requires_capabilities: list[str] = Field(default_factory=list)
    signature_status: str = "unsigned"
    signer: str = ""
    generated_by: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    validation_status: str = "unvalidated"

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, v: int) -> int:
        if v != 1:
            raise ValueError(f"unsupported schema_version: {v!r} (expected 1)")
        return v

    @field_validator("id")
    @classmethod
    def _skill_id(cls, v: str) -> str:
        vv = str(v).strip()
        if not SKILL_ID_RE.match(vv):
            raise ValueError(f"invalid skill id {v!r}: must match [a-z0-9][a-z0-9-]{{2,63}}")
        return vv

    @field_validator("version", mode="before")
    @classmethod
    def _version(cls, v: Any) -> str:
        vv = str(v).strip()
        if not SEMVER_RE.match(vv):
            raise ValueError(f"invalid version {v!r}: expected semantic version x.y.z")
        return vv

    @field_validator("type", mode="before")
    @classmethod
    def _type(cls, v: Any) -> SkillType:
        return normalize_skill_type(v)

    @field_validator("category", mode="before")
    @classmethod
    def _category(cls, v: Any) -> str:
        return str(v).strip().lower().replace(" ", "-") if v else "general"

    @model_validator(mode="before")
    @classmethod
    def _flatten_requires(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        d: dict[str, Any] = dict(data)
        req = d.get("requires")
        if isinstance(req, dict):
            tools = req.get("tools") or []
            if tools and not d.get("requires_tools"):
                d["requires_tools"] = list(tools)
            skills = req.get("skills") or req.get("depends_on") or []
            if skills and not d.get("depends_on"):
                d["depends_on"] = list(skills)
            d.pop("requires", None)
        if "requires" in d and isinstance(d["requires"], list):
            # `requires: [git, semgrep]` shorthand -> tools
            if not d.get("requires_tools"):
                d["requires_tools"] = list(d["requires"])
            d.pop("requires", None)
        # merge tools aliases
        merged_tools: list[str] = []
        for key in ("requires_tools", "tools"):
            val = d.get(key)
            if isinstance(val, list):
                merged_tools.extend(str(t) for t in val)
        if merged_tools:
            d["requires_tools"] = sorted(set(merged_tools))
            d.pop("tools", None)
        # merge depends_on aliases
        deps = d.get("depends_on")
        if isinstance(deps, str):
            d["depends_on"] = [deps]
        # compatibility.agents may be ["files_read"] strings -> normalize
        comp = d.get("compatibility")
        if isinstance(comp, dict):
            agents = comp.get("agents")
            if isinstance(agents, list):
                normed = []
                for a in agents:
                    if isinstance(a, str):
                        normed.append({"capability": a})
                    else:
                        normed.append(a)
                comp["agents"] = normed
        # entry may be a string filename
        if isinstance(d.get("entry"), str):
            d["entry"] = {"file": d["entry"]}
        return d

    @field_validator("trust", mode="before")
    @classmethod
    def _trust_shape(cls, v: Any) -> dict[str, Any]:
        if isinstance(v, str):
            return {"source": v}
        if isinstance(v, dict):
            d = dict(v)
            d.setdefault("source", "LOCAL")
            return d
        return {"source": "LOCAL"}

    def trust_level(self, installed_trust: TrustLevel | None = None) -> TrustLevel:
        if installed_trust is not None:
            return installed_trust
        try:
            return normalize_trust_source(self.trust.get("source", "LOCAL"))
        except ValueError:
            return TrustLevel.LOCAL

    def required_capabilities(self) -> list[str]:
        caps: list[str] = []
        p = self.permissions
        if p.filesystem_read:
            caps.append("FILES_READ")
        if p.filesystem_write:
            caps.append("FILES_WRITE")
        if p.shell:
            caps.append("SHELL")
        if p.git_read or p.git_write:
            caps.append("GIT")
        if p.mcp:
            caps.append("MCP")
        if p.web_access or p.network:
            caps.append("WEB_ACCESS")
        for a in self.compatibility.agents:
            c = a.capability.upper()
            if c not in caps:
                caps.append(c)
        for c in self.requires_capabilities:
            cu = str(c).upper()
            if cu not in caps:
                caps.append(cu)
        return sorted(caps)

    def to_normalized_dict(self) -> dict[str, Any]:
        data = self.model_dump(mode="json", by_alias=False)
        # Remove volatile provenance timestamps for fingerprinting separately.
        return data
