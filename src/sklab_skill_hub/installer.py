"""Install / enable / disable / uninstall / update flows with hard security gates."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from sklab_skill_hub.config import HubConfig, effective_auto_config
from sklab_skill_hub.importer import InspectedSkill, default_trust_for
from sklab_skill_hub.models import AutoMode, EnableState, RiskLevel, TrustLevel
from sklab_skill_hub.registry import Registry, utcnow_iso
from sklab_skill_hub.risk import RISK_ORDER, risk_allows
from sklab_skill_hub.scanners import has_hard_block


def _risk(s: str) -> RiskLevel:
    return RiskLevel[str(s).upper()]


def auto_decision(
    trust: TrustLevel,
    risk: RiskLevel,
    has_executable: bool,
    mode: AutoMode,
    allow_trust: list[str],
    max_risk: RiskLevel,
    block_secret_network_combo: bool = True,
) -> tuple[bool, str]:
    """Return (allowed, reason). FULL never bypasses hard gates — enforced by caller."""
    if trust in (TrustLevel.BLOCKED, TrustLevel.QUARANTINED):
        return False, f"trust {trust.value} never auto-installs"
    if mode == AutoMode.OFF:
        return False, "auto-install OFF"
    trusts = {t.upper() for t in allow_trust}
    if mode == AutoMode.SAFE:
        if trust.value not in trusts:
            return False, f"SAFE: trust {trust.value} not in allow_trust"
        if not risk_allows(risk, max_risk):
            return False, f"SAFE: risk {risk.value} exceeds max {max_risk.value}"
        if has_executable and trust != TrustLevel.BUILTIN:
            return False, "SAFE: executable non-builtin requires review"
        if risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            return False, f"SAFE: risk {risk.value} requires explicit approval"
        return True, "SAFE: declarative low-risk verified/builtin"
    if mode == AutoMode.SMART:
        if trust == TrustLevel.COMMUNITY and (has_executable or risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)):
            return False, "SMART: community executable/elevated quarantined for review"
        if not risk_allows(risk, RiskLevel.HIGH) and risk == RiskLevel.CRITICAL:
            return False, "SMART: critical risk requires explicit approval"
        return True, "SMART: discovery with review for elevated"
    if mode == AutoMode.FULL:
        # Broader, but hard gates (BLOCKED/QUARANTINED/CRITICAL-secret combos) still enforced by caller.
        if risk == RiskLevel.CRITICAL:
            return False, "FULL: critical risk still requires explicit approval"
        return True, "FULL: broad discovery within hard gates"
    return False, "unknown mode"


def check_hard_gates(inspected: InspectedSkill, config: HubConfig) -> tuple[bool, str]:
    """Return (blocked, reason). True means must quarantine/block."""
    if has_hard_block(inspected.findings):
        return True, "hard block: credential theft / destructive / MFA-bypass / exfiltration pattern"
    if config.security.block_secret_network_combo:
        p = inspected.manifest.permissions
        if p.secrets and (p.network or p.web_access):
            return True, "hard block: secrets + network requested"
    if inspected.path_violations:
        return True, f"hard block: path safety violations: {inspected.path_violations[:2]}"
    if inspected.secret_findings:
        return True, "hard block: inline secret values in manifest"
    return False, ""


def install_inspected(
    inspected: InspectedSkill,
    registry: Registry,
    data_dir: Path,
    config: HubConfig,
    explicit: bool = False,
    requested_trust: TrustLevel | None = None,
) -> dict[str, Any]:
    src_dir = inspected.skill_dir
    if src_dir is None or not src_dir.is_dir():
        raise RuntimeError("inspected skill has no source directory")
    blocked, reason = check_hard_gates(inspected, config)
    trust = requested_trust or default_trust_for(
        __import__("sklab_skill_hub.models", fromlist=["SourceType"]).SourceType(
            inspected.provenance.get("source_type", "LOCAL_DIRECTORY")),
        inspected.provenance.get("trust_hint", "LOCAL"),
    )
    if blocked and not explicit:
        quarantine_inspected(inspected, data_dir, reason)
        registry.upsert(_record(inspected, trust, TrustLevel.QUARANTINED, data_dir, quarantined=True, note=reason))
        return {"installed": False, "quarantined": True, "reason": reason,
                "skill_id": inspected.skill_id, "version": inspected.version}
    if blocked and explicit:
        # Explicit user install of a hard-blocked skill -> quarantine, never enable.
        quarantine_inspected(inspected, data_dir, reason)
        registry.upsert(_record(inspected, trust, TrustLevel.QUARANTINED, data_dir, quarantined=True, note=reason))
        return {"installed": False, "quarantined": True, "reason": reason,
                "skill_id": inspected.skill_id, "version": inspected.version}
    # Policy gate for non-explicit installs.
    if not explicit:
        auto = effective_auto_config(config)
        allowed, why = auto_decision(
            trust, _risk(inspected.risk), inspected.has_executable,
            auto.mode, auto.allow_trust, auto.max_risk_level())
        if not allowed:
            quarantine = inspected.has_executable or _risk(inspected.risk) in (RiskLevel.HIGH, RiskLevel.CRITICAL)
            if quarantine:
                quarantine_inspected(inspected, data_dir, why)
                registry.upsert(_record(inspected, trust, TrustLevel.QUARANTINED, data_dir, quarantined=True, note=why))
                return {"installed": False, "quarantined": True, "reason": why,
                        "skill_id": inspected.skill_id, "version": inspected.version}
            return {"installed": False, "quarantined": False, "reason": why,
                    "skill_id": inspected.skill_id, "version": inspected.version}
    # Quarantine community executables unless explicitly allowed.
    if config.security.quarantine_executable_community and inspected.has_executable \
            and trust == TrustLevel.COMMUNITY and not explicit:
        why = "community executable quarantined pending review"
        quarantine_inspected(inspected, data_dir, why)
        registry.upsert(_record(inspected, trust, TrustLevel.QUARANTINED, data_dir, quarantined=True, note=why))
        return {"installed": False, "quarantined": True, "reason": why,
                "skill_id": inspected.skill_id, "version": inspected.version}
    dest = data_dir / "installed" / inspected.skill_id / inspected.version
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src_dir, dest, ignore_dangling_symlinks=True,
                    ignore=lambda _d, names: {".git"} & set(names))
    # Record fingerprints + provenance.
    registry.upsert(_record(inspected, trust, trust, data_dir, quarantined=False, note="installed"))
    registry.record_trust_decision(inspected.skill_id, inspected.content_fingerprint,
                                   "install", scope="explicit" if explicit else "auto")
    return {"installed": True, "quarantined": False, "reason": "installed",
            "skill_id": inspected.skill_id, "version": inspected.version,
            "path": str(dest)}


def _record(inspected: InspectedSkill, requested: TrustLevel, stored_trust: TrustLevel,
            data_dir: Path, quarantined: bool, note: str) -> dict[str, Any]:
    return {
        "skill_id": inspected.skill_id,
        "version": inspected.version,
        "name": inspected.manifest.name,
        "category": inspected.manifest.category,
        "skill_type": inspected.manifest.type.value,
        "trust": stored_trust.value,
        "requested_trust": requested.value,
        "risk": inspected.risk,
        "verdict": inspected.verdict.value,
        "manifest": inspected.manifest_dict,
        "manifest_fingerprint": inspected.manifest_fingerprint,
        "skill_fingerprint": inspected.content_fingerprint,
        "source_type": inspected.provenance.get("source_type", ""),
        "source_url": inspected.provenance.get("source_url", ""),
        "source_ref": inspected.provenance.get("source_ref", ""),
        "license": inspected.manifest.provenance.license,
        "install_path": f"installed/{inspected.skill_id}/{inspected.version}" if not quarantined else "",
        "quarantine_path": f"quarantine/{inspected.skill_id}-{inspected.version}" if quarantined else "",
        "enabled_state": EnableState.QUARANTINED.value if quarantined else EnableState.INSTALLED.value,
        "has_executable": inspected.has_executable,
        "permissions": inspected.manifest.permissions.to_flat(),
        "required_capabilities": inspected.manifest.required_capabilities(),
        "requires_tools": list(inspected.manifest.requires_tools),
        "depends_on": list(inspected.manifest.depends_on),
        "findings": [f.to_dict() for f in inspected.findings],
        "installed_at": utcnow_iso(),
        "updated_at": utcnow_iso(),
        "note": note,
        "signature_status": inspected.manifest.signature_status,
        "signer": inspected.manifest.signer,
        "generated_by": inspected.manifest.generated_by,
        "evidence_refs": list(inspected.manifest.evidence_refs),
        "validation_status": inspected.manifest.validation_status,
    }


def quarantine_inspected(inspected: InspectedSkill, data_dir: Path, reason: str) -> Path:
    dest = data_dir / "quarantine" / f"{inspected.skill_id}-{inspected.version}"
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if inspected.skill_dir is not None and inspected.skill_dir.is_dir():
        shutil.copytree(inspected.skill_dir, dest, ignore_dangling_symlinks=True,
                        ignore=lambda _d, names: {".git"} & set(names))
    (dest / "QUARANTINE_REASON.txt").write_text(reason + "\n", encoding="utf-8")
    return dest


def enable_skill(registry: Registry, skill_id: str, version: str | None = None,
                 task_scoped: bool = False, force: bool = False) -> dict[str, Any]:
    rec = registry.get(skill_id, version)
    if rec is None:
        raise KeyError(f"skill not installed: {skill_id}")
    if rec.get("trust") in ("QUARANTINED", "BLOCKED") or rec.get("enabled_state") == "QUARANTINED":
        raise PermissionError(f"skill {skill_id} is quarantined/blocked and cannot be enabled")
    if _risk(str(rec.get("risk", "LOW"))) in (RiskLevel.HIGH, RiskLevel.CRITICAL) and not force:
        raise PermissionError(
            f"skill {skill_id} has risk {rec.get('risk')}: requires explicit confirmation (--force)")
    state = EnableState.ENABLED_FOR_TASK if task_scoped else EnableState.ENABLED_GLOBAL
    registry.set_enabled(skill_id, str(rec["version"]), state)
    return {"skill_id": skill_id, "version": rec["version"], "enabled": state.value}


def disable_skill(registry: Registry, skill_id: str, version: str | None = None) -> dict[str, Any]:
    rec = registry.get(skill_id, version)
    if rec is None:
        raise KeyError(f"skill not installed: {skill_id}")
    registry.set_enabled(skill_id, str(rec["version"]), EnableState.DISABLED)
    return {"skill_id": skill_id, "version": rec["version"], "enabled": "DISABLED"}


def uninstall_skill(registry: Registry, data_dir: Path, skill_id: str,
                    version: str | None = None) -> dict[str, Any]:
    rec = registry.get(skill_id, version)
    if rec is None:
        raise KeyError(f"skill not installed: {skill_id}")
    if rec.get("enabled_state") in ("ENABLED_GLOBAL", "ENABLED_FOR_TASK"):
        raise PermissionError(f"skill {skill_id} is currently enabled; disable first")
    rel = rec.get("install_path", "")
    if rel:
        full = data_dir / str(rel)
        # Safety: only delete inside installed/<id>/.
        expected = (data_dir / "installed" / skill_id).resolve()
        try:
            if expected in (full.resolve(), *full.resolve().parents):
                shutil.rmtree(full, ignore_errors=True)
        except OSError:
            pass
    registry.remove(skill_id, str(rec["version"]))
    return {"skill_id": skill_id, "version": rec["version"], "uninstalled": True}


def diff_permissions(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    keys = sorted(set(old) | set(new))
    added = [k for k in keys if bool(new.get(k)) and not bool(old.get(k))]
    removed = [k for k in keys if bool(old.get(k)) and not bool(new.get(k))]
    escalated = bool(added)
    return {"added": added, "removed": removed, "escalated": escalated}


def plan_update(old_rec: dict[str, Any], inspected: InspectedSkill) -> dict[str, Any]:
    old_perms = {k: v for k, v in (old_rec.get("permissions") or {}).items() if isinstance(v, bool)}
    new_perms = inspected.manifest.permissions.to_flat()
    perm_diff = diff_permissions(old_perms, new_perms)
    fp_changed = old_rec.get("skill_fingerprint") != inspected.content_fingerprint
    old_risk = _risk(str(old_rec.get("risk", "LOW")))
    new_risk = _risk(inspected.risk)
    risk_up = RISK_ORDER[new_risk] > RISK_ORDER[old_risk]
    blocked, reason = has_hard_block(inspected.findings), ""
    needs_review = bool(
        perm_diff["escalated"] or risk_up or fp_changed and _risk(inspected.risk) in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        or blocked)
    status = "SECURITY_REVIEW_REQUIRED" if (perm_diff["escalated"] or risk_up or blocked) else (
        "UPDATE_AVAILABLE" if fp_changed or inspected.version != old_rec.get("version") else "UP_TO_DATE")
    if blocked:
        reason = "hard-block findings in update"
    elif perm_diff["escalated"]:
        reason = f"PERMISSION_ESCALATION: +{perm_diff['added']}"
    return {
        "skill_id": inspected.skill_id,
        "from_version": old_rec.get("version"),
        "to_version": inspected.version,
        "fingerprint_changed": fp_changed,
        "permission_diff": perm_diff,
        "risk_changed": [old_risk.value, new_risk.value],
        "status": status,
        "reason": reason,
        "needs_review": needs_review,
    }
