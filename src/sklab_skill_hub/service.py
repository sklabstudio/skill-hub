"""Python service API for Web UI + Orchestrator (no subprocess, no secrets)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sklab_skill_hub import installer as _installer
from sklab_skill_hub import resolver as _resolver
from sklab_skill_hub.config import HubConfig
from sklab_skill_hub.importer import inspect_source
from sklab_skill_hub.packs import get_pack, list_packs
from sklab_skill_hub.registry import Registry

SECRET_KEYS = {"secret", "token", "api_key", "credential", "password"}


def _registry(data_dir: Path) -> Registry:
    return Registry(data_dir)


def _record_to_dto(rec: dict[str, Any]) -> dict[str, Any]:
    """Public DTO: safe subset, never raw secrets or host metadata."""
    manifest = dict(rec.get("manifest") or {})
    return {
        "skill_id": rec.get("skill_id"),
        "name": rec.get("name"),
        "version": rec.get("version"),
        "category": rec.get("category"),
        "skill_type": rec.get("skill_type"),
        "trust": rec.get("trust"),
        "risk": rec.get("risk"),
        "verdict": rec.get("verdict"),
        "enabled_state": rec.get("enabled_state"),
        "source_type": rec.get("source_type"),
        "source_url": rec.get("source_url"),
        "source_ref": rec.get("source_ref"),
        "license": rec.get("license"),
        "permissions": rec.get("permissions"),
        "required_capabilities": rec.get("required_capabilities"),
        "requires_tools": rec.get("requires_tools"),
        "depends_on": rec.get("depends_on"),
        "manifest_fingerprint": rec.get("manifest_fingerprint"),
        "skill_fingerprint": rec.get("skill_fingerprint"),
        "has_executable": rec.get("has_executable"),
        "findings": rec.get("findings"),
        "description": manifest.get("description", ""),
        "tags": manifest.get("tags", []),
        "signature_status": rec.get("signature_status", "unsigned"),
        "signer": rec.get("signer", ""),
    }


def list_skills(data_dir: Path, filters: dict[str, str] | None = None) -> list[dict[str, Any]]:
    regs = _registry(data_dir).list_all()
    f = filters or {}
    out = []
    for rec in regs:
        if f.get("category") and str(rec.get("category")) != f["category"]:
            continue
        if f.get("trust") and str(rec.get("trust")).upper() != f["trust"].upper():
            continue
        if f.get("enabled") and str(rec.get("enabled_state")).upper() != f["enabled"].upper():
            continue
        if f.get("type") and str(rec.get("skill_type")).upper() != f["type"].upper():
            continue
        if f.get("risk") and str(rec.get("risk")).upper() != f["risk"].upper():
            continue
        out.append(_record_to_dto(rec))
    return sorted(out, key=lambda r: str(r.get("skill_id")))


def get_skill(data_dir: Path, skill_id: str, version: str | None = None) -> dict[str, Any]:
    rec = _registry(data_dir).get(skill_id, version)
    if rec is None:
        raise KeyError(f"unknown skill: {skill_id}")
    return _record_to_dto(rec)


def search_skills(data_dir: Path, query: str) -> list[dict[str, Any]]:
    q = query.lower()
    out = []
    for rec in _registry(data_dir).list_all():
        manifest = rec.get("manifest") or {}
        hay = " ".join([str(rec.get("skill_id", "")), str(rec.get("name", "")),
                        str(manifest.get("description", "")), str(rec.get("category", "")),
                        " ".join(str(t) for t in (manifest.get("tags") or []))]).lower()
        if q in hay:
            out.append(_record_to_dto(rec))
    return sorted(out, key=lambda r: str(r.get("skill_id")))


def inspect_source_api(source: str) -> list[dict[str, Any]]:
    return [s.to_dict() for s in inspect_source(source)]


def install_skill(data_dir: Path, config: HubConfig, source: str, explicit: bool = True) -> list[dict[str, Any]]:
    from sklab_skill_hub.store import ensure_layout

    paths = ensure_layout(data_dir)
    reg = Registry(data_dir)
    results = []
    for inspected in inspect_source(source):
        results.append(_installer.install_inspected(inspected, reg, paths["root"], config, explicit=explicit))
    return results


def enable_skill_api(data_dir: Path, skill_id: str, task_scoped: bool = False, force: bool = False) -> dict[str, Any]:
    return _installer.enable_skill(_registry(data_dir), skill_id, None, task_scoped, force)


def disable_skill_api(data_dir: Path, skill_id: str) -> dict[str, Any]:
    return _installer.disable_skill(_registry(data_dir), skill_id)


def update_skill_api(data_dir: Path, config: HubConfig, skill_id: str, source: str) -> dict[str, Any]:
    from sklab_skill_hub.store import ensure_layout

    paths = ensure_layout(data_dir)
    reg = Registry(data_dir)
    rec = reg.get(skill_id)
    if rec is None:
        raise KeyError(f"unknown skill: {skill_id}")
    inspected_list = inspect_source(source)
    target = None
    for ins in inspected_list:
        if ins.skill_id == skill_id:
            target = ins
            break
    if target is None:
        target = inspected_list[0]
    plan = _installer.plan_update(rec, target)
    if plan["status"] == "SECURITY_REVIEW_REQUIRED":
        return {**plan, "applied": False}
    res = _installer.install_inspected(target, reg, paths["root"], config, explicit=True)
    return {**plan, "applied": bool(res.get("installed")), "install": res}


def audit_skill(data_dir: Path, skill_id: str) -> dict[str, Any]:
    reg = _registry(data_dir)
    rec = reg.get(skill_id)
    if rec is None:
        raise KeyError(f"unknown skill: {skill_id}")
    findings = rec.get("findings", [])
    high = [f for f in findings if f.get("severity") in ("HIGH", "CRITICAL")]
    action = "OK"
    if rec.get("trust") in ("QUARANTINED", "BLOCKED"):
        action = "BLOCKED"
    elif high:
        action = "REVIEW_REQUIRED"
    return {
        "skill_id": skill_id,
        "version": rec.get("version"),
        "trust": rec.get("trust"),
        "risk": rec.get("risk"),
        "license": rec.get("license"),
        "provenance": {"source_type": rec.get("source_type"), "source_url": rec.get("source_url"),
                       "source_ref": rec.get("source_ref")},
        "fingerprints": {"manifest": rec.get("manifest_fingerprint"), "skill": rec.get("skill_fingerprint")},
        "permissions": rec.get("permissions"),
        "findings": findings,
        "dependencies": rec.get("depends_on"),
        "requires_tools": rec.get("requires_tools"),
        "compatibility": (rec.get("manifest") or {}).get("compatibility"),
        "recommended_action": action,
    }


def get_auto_policy(config: HubConfig) -> dict[str, Any]:
    return {
        "mode": config.auto_install.mode.value,
        "allow_trust": list(config.auto_install.allow_trust),
        "max_risk": config.auto_install.max_risk,
        "permanent_enable": config.auto_install.permanent_enable,
        "task_scoped_enable": config.auto_install.task_scoped_enable,
    }


def set_auto_policy(config: HubConfig, mode: str) -> dict[str, Any]:
    from sklab_skill_hub.models import AutoMode

    config.auto_install.mode = AutoMode[str(mode).upper()]
    return get_auto_policy(config)


def resolve_for_task(
    data_dir: Path,
    task: str,
    category: str = "",
    required_capabilities: list[str] | None = None,
    agent_capabilities: list[str] | None = None,
    limit: int = 5,
) -> list[dict[str, Any]]:
    records = _registry(data_dir).list_all()
    # Builtin skills are always resolvable even before install: caller may
    # merge builtin pseudo-records. Here we resolve installed only.
    return _resolver.resolve_skills(task, records, category, required_capabilities, agent_capabilities, limit)


def list_packs_api() -> list[dict[str, object]]:
    return list_packs()


def get_pack_api(pack_id: str) -> dict[str, object]:
    return get_pack(pack_id)
