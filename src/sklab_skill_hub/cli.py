"""sklab-skills CLI — typed thin layer over service/installer/resolver."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Optional, cast

import typer
from rich.console import Console
from rich.table import Table

from sklab_skill_hub import __version__
from sklab_skill_hub import installer as _installer
from sklab_skill_hub import resolver as _resolver
from sklab_skill_hub.builtins import builtin_dir, list_builtin_ids
from sklab_skill_hub.config import HubConfig, load_config, save_config
from sklab_skill_hub.importer import inspect_skill_dir, inspect_source, staged_source
from sklab_skill_hub.integrations import (
    coding_lab_skills,
    compatible_agents,
    load_agent_capabilities,
    orchestrator_skill_payload,
    reprobox_execution_plan,
)
from sklab_skill_hub.models import AutoMode, TrustLevel
from sklab_skill_hub.packs import get_pack, list_packs
from sklab_skill_hub.registry import Registry
from sklab_skill_hub.store import ensure_layout, resolve_data_dir

app = typer.Typer(add_completion=False, help="Safe, agent-agnostic registry for reusable AI engineering skills.")
console = Console()
err_console = Console(stderr=True)


def _ctx(data_dir: str | None, config_path: str | None) -> tuple[Path, HubConfig, Registry]:
    dd = resolve_data_dir(data_dir)
    paths = ensure_layout(dd)
    cfg = load_config(Path(config_path).expanduser() if config_path else None, dd)
    # Honour configured data dir when no explicit override.
    if data_dir is None:
        configured = Path(cfg.registry.data_dir).expanduser()
        if configured != dd:
            dd = configured
            paths = ensure_layout(dd)
            cfg = load_config(Path(config_path).expanduser() if config_path else None, dd)
    reg = Registry(paths["root"])
    return paths["root"], cfg, reg


def _is_builtin_path(src: str) -> bool:
    try:
        resolved = Path(src).expanduser().resolve()
    except OSError:
        return False
    root = builtin_dir().resolve()
    return resolved == root or root in resolved.parents


def _emit(obj: Any, as_json: bool) -> None:
    if as_json:
        typer.echo(json.dumps(obj, indent=2, sort_keys=True))
    else:
        typer.echo(obj)


def _table(rows: list[dict[str, Any]], columns: list[str]) -> None:
    table = Table()
    for col in columns:
        table.add_column(col)
    for row in rows:
        table.add_row(*[str(row.get(c, "")) for c in columns])
    console.print(table)


@app.command()
def version() -> None:
    """Print version (also available via --version)."""
    typer.echo(f"sklab-skills {__version__}")


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    version_flag: bool = typer.Option(False, "--version", help="Show version and exit."),
) -> None:
    if version_flag:
        typer.echo(f"sklab-skills {__version__}")
        raise typer.Exit(0)
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


@app.command("list")
def list_cmd(
    category: Optional[str] = typer.Option(None, "--category"),
    trust: Optional[str] = typer.Option(None, "--trust"),
    enabled: Optional[str] = typer.Option(None, "--enabled"),
    type: Optional[str] = typer.Option(None, "--type"),
    risk: Optional[str] = typer.Option(None, "--risk"),
    json_out: bool = typer.Option(False, "--json"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """List installed skills (stable ordering)."""
    root, _cfg, reg = _ctx(data_dir, config)
    recs = reg.list_all()
    if category:
        recs = [r for r in recs if str(r.get("category")) == category]
    if trust:
        recs = [r for r in recs if str(r.get("trust")).upper() == trust.upper()]
    if enabled:
        recs = [r for r in recs if str(r.get("enabled_state")).upper() == enabled.upper()]
    if type:
        recs = [r for r in recs if str(r.get("skill_type")).upper() == type.upper()]
    if risk:
        recs = [r for r in recs if str(r.get("risk")).upper() == risk.upper()]
    if json_out:
        typer.echo(json.dumps(recs, indent=2, sort_keys=True))
        return
    _table(
        [{"id": r.get("skill_id"), "version": r.get("version"), "name": r.get("name"),
          "category": r.get("category"), "trust": r.get("trust"),
          "enabled": r.get("enabled_state"), "risk": r.get("risk"),
          "source": r.get("source_type")} for r in recs],
        ["id", "version", "name", "category", "trust", "enabled", "risk", "source"],
    )


@app.command("show")
def show_cmd(
    skill: str,
    agents: bool = typer.Option(False, "--agents", help="Show compatible agents."),
    json_out: bool = typer.Option(False, "--json"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Show skill metadata (never dumps large executable content)."""
    _root_dir, _cfg, reg = _ctx(data_dir, config)
    rec = reg.get(skill)
    if rec is None:
        # Fall back to builtin inspection for a friendly message.
        bid = builtin_dir() / skill
        if (bid / "skill.yaml").is_file():
            inspected = inspect_skill_dir(bid, __import__("sklab_skill_hub.models", fromlist=["SourceType"]).SourceType.BUILTIN,
                                          "builtin", "v0.1.0", "BUILTIN")
            rec = {"skill_id": inspected.skill_id, "version": inspected.version, "name": inspected.manifest.name,
                   "category": inspected.manifest.category, "skill_type": inspected.manifest.type.value,
                   "trust": "BUILTIN", "risk": inspected.risk, "enabled_state": "INSTALLED",
                   "source_type": "BUILTIN", "source_url": "builtin", "source_ref": "v0.1.0",
                   "license": inspected.manifest.provenance.license,
                   "permissions": inspected.manifest.permissions.to_flat(),
                   "required_capabilities": inspected.manifest.required_capabilities(),
                   "manifest_fingerprint": inspected.manifest_fingerprint,
                   "skill_fingerprint": inspected.content_fingerprint,
                   "manifest": inspected.manifest_dict, "requires_tools": list(inspected.manifest.requires_tools),
                   "depends_on": list(inspected.manifest.depends_on),
                   "findings": [f.to_dict() for f in inspected.findings]}
        else:
            err_console.print(f"[red]unknown skill: {skill}[/red]")
            raise typer.Exit(1)
    out: dict[str, Any] = dict(rec)
    if agents:
        matrix = load_agent_capabilities()
        out["compatible_agents"] = compatible_agents(list(rec.get("required_capabilities") or []), matrix)
        out["execution_plan"] = reprobox_execution_plan(rec)
    if json_out:
        typer.echo(json.dumps(out, indent=2, sort_keys=True))
        return
    typer.echo(f"{rec.get('skill_id')} {rec.get('version')} — {rec.get('name')}")
    typer.echo(f"category={rec.get('category')} trust={rec.get('trust')} risk={rec.get('risk')} enabled={rec.get('enabled_state')}")
    typer.echo(f"source={rec.get('source_type')} {rec.get('source_url')} ref={rec.get('source_ref')}")
    typer.echo(f"fingerprint={rec.get('skill_fingerprint')}")
    typer.echo(f"permissions={json.dumps(rec.get('permissions'))}")
    typer.echo(f"capabilities={rec.get('required_capabilities')}")
    if agents:
        typer.echo(f"compatible_agents={out.get('compatible_agents')}")
    findings = rec.get("findings") or []
    if findings:
        typer.echo(f"findings={len(findings)} (see --json for detail)")


@app.command("search")
def search_cmd(
    query: str,
    json_out: bool = typer.Option(False, "--json"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Search installed + builtin registry (no untrusted web scrape)."""
    _root_dir, _cfg, reg = _ctx(data_dir, config)
    q = query.lower()
    hits: list[dict[str, Any]] = []
    for rec in reg.list_all():
        hay = " ".join([str(rec.get("skill_id")), str(rec.get("name")),
                        str((rec.get("manifest") or {}).get("description", "")),
                        str(rec.get("category"))]).lower()
        if q in hay:
            hits.append(rec)
    # Builtins not yet installed are also searchable.
    installed_ids = {str(r.get("skill_id")) for r in reg.list_all()}
    for bid in list_builtin_ids():
        if bid in installed_ids or q not in bid.lower():
            continue
        bdir = builtin_dir() / bid
        try:
            inspected = inspect_skill_dir(bdir, __import__("sklab_skill_hub.models", fromlist=["SourceType"]).SourceType.BUILTIN,
                                          "builtin", "v0.1.0", "BUILTIN")
        except (OSError, ValueError):
            continue
        if q in f"{bid} {inspected.manifest.name} {inspected.manifest.description}".lower():
            hits.append({"skill_id": bid, "version": inspected.version, "name": inspected.manifest.name,
                         "category": inspected.manifest.category, "trust": "BUILTIN (not installed)",
                         "risk": inspected.risk, "enabled_state": "-", "source_type": "BUILTIN"})
    hits.sort(key=lambda r: str(r.get("skill_id")))
    if json_out:
        typer.echo(json.dumps(hits, indent=2, sort_keys=True))
        return
    _table([{"id": r.get("skill_id"), "version": r.get("version"), "name": r.get("name"),
             "category": r.get("category"), "trust": r.get("trust")} for r in hits],
           ["id", "version", "name", "category", "trust"])


@app.command("inspect")
def inspect_cmd(
    source: str,
    json_out: bool = typer.Option(False, "--json"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Read-only inspection (never installs or executes)."""
    _ctx(data_dir, config)
    try:
        if Path(source).expanduser().exists():
            results = inspect_source(source)
        else:
            # Maybe an installed skill id.
            _root_dir2, _cfg2, reg = _ctx(data_dir, config)
            rec = reg.get(source)
            if rec is not None:
                rel = rec.get("install_path", "")
                results = []
                if rel:
                    d = _root_dir2 / str(rel)
                    if d.is_dir():
                        results = [inspect_skill_dir(d)]
                if not results:
                    if json_out:
                        typer.echo(json.dumps({"skill_id": source, "verdict": "VALID",
                                               "note": "registry record only"}, indent=2))
                        return
                    typer.echo(f"{source}: VALID (registry record)")
                    return
            else:
                results = inspect_source(source)
    except (OSError, RuntimeError, ValueError, FileNotFoundError) as exc:
        if json_out:
            typer.echo(json.dumps({"verdict": "INVALID", "error": str(exc)}, indent=2))
        else:
            typer.echo(f"INVALID: {exc}")
        raise typer.Exit(1)
    payload = [r.to_dict() for r in results]
    if json_out:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    for r in results:
        typer.echo(f"{r.skill_id}@{r.version}: {r.verdict.value} risk={r.risk} exec={r.has_executable}")


@app.command("import")
def import_cmd(
    source: str,
    trust: Optional[str] = typer.Option(None, "--trust"),
    json_out: bool = typer.Option(False, "--json"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Import (validate + install into registry). Never executes skill code."""
    root, cfg, reg = _ctx(data_dir, config)
    if trust:
        try:
            requested = TrustLevel[trust.strip().upper()]
        except KeyError:
            err_console.print(f"[red]unknown trust: {trust}[/red]")
            raise typer.Exit(1)
    else:
        requested = None
    try:
        results = _installer.install_from_source(
            source, reg, root, cfg, explicit=True, requested_trust=requested)
    except (OSError, RuntimeError, ValueError, FileNotFoundError) as exc:
        err_console.print(f"[red]import failed: {exc}[/red]")
        raise typer.Exit(1)
    if json_out:
        typer.echo(json.dumps(results, indent=2, sort_keys=True))
        return
    for res in results:
        typer.echo(f"{res.get('skill_id')}: installed={res.get('installed')} quarantined={res.get('quarantined')} ({res.get('reason')})")


@app.command("install")
def install_cmd(
    skill: str,
    source: Optional[str] = typer.Option(None, "--source", help="Explicit source dir/URL (default: builtin)."),
    trust: Optional[str] = typer.Option(None, "--trust"),
    json_out: bool = typer.Option(False, "--json"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Install a skill by id (builtin default) or explicit source."""
    root, cfg, reg = _ctx(data_dir, config)
    src = source
    if src is None:
        cand = builtin_dir() / skill
        if (cand / "skill.yaml").is_file():
            src = str(cand)
        else:
            # Maybe a local path == skill id already installed? fail clearly.
            err_console.print(f"[red]no builtin '{skill}'; pass --source <dir-or-url>[/red]")
            raise typer.Exit(1)
    requested = None
    if trust:
        try:
            requested = TrustLevel[trust.strip().upper()]
        except KeyError:
            err_console.print(f"[red]unknown trust: {trust}[/red]")
            raise typer.Exit(1)
    try:
        hint = "BUILTIN" if _is_builtin_path(src) else "LOCAL"
        with staged_source(src, trust_hint=hint) as inspected_list:
            # Prefer matching id when a repo yields several skills.
            target = next((i for i in inspected_list if i.skill_id == skill), inspected_list[0])
            res = _installer.install_inspected(target, reg, root, cfg, explicit=True, requested_trust=requested)
    except (OSError, RuntimeError, ValueError, FileNotFoundError) as exc:
        err_console.print(f"[red]install failed: {exc}[/red]")
        raise typer.Exit(1)
    if json_out:
        typer.echo(json.dumps(res, indent=2, sort_keys=True))
        return
    typer.echo(f"{skill}: installed={res.get('installed')} quarantined={res.get('quarantined')} ({res.get('reason')})")


@app.command("uninstall")
def uninstall_cmd(
    skill: str,
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes"),
    json_out: bool = typer.Option(False, "--json"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Uninstall an installed skill/version (never deletes source repos)."""
    root, _cfg, reg = _ctx(data_dir, config)
    rec = reg.get(skill)
    if rec is None:
        err_console.print(f"[red]not installed: {skill}[/red]")
        raise typer.Exit(1)
    plan = {"skill_id": skill, "version": rec.get("version"), "path": rec.get("install_path")}
    if dry_run:
        if json_out:
            typer.echo(json.dumps({**plan, "dry_run": True}, indent=2))
        else:
            typer.echo(f"would remove {plan['path']}")
        return
    if not yes and not json_out:
        typer.confirm(f"Remove {skill}@{rec.get('version')}?", abort=True)
    try:
        res = _installer.uninstall_skill(reg, root, skill)
    except PermissionError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    if json_out:
        typer.echo(json.dumps(res, indent=2, sort_keys=True))
    else:
        typer.echo(f"uninstalled {skill}")


@app.command("enable")
def enable_cmd(
    skill: str,
    task: bool = typer.Option(False, "--task", help="Enable for current task only."),
    force: bool = typer.Option(False, "--force", help="Confirm elevated permissions."),
    json_out: bool = typer.Option(False, "--json"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Enable an installed skill (global or task-scoped)."""
    _root_dir, _cfg, reg = _ctx(data_dir, config)
    try:
        res = _installer.enable_skill(reg, skill, None, task_scoped=task, force=force)
    except (KeyError, PermissionError) as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    if json_out:
        typer.echo(json.dumps(res, indent=2, sort_keys=True))
    else:
        typer.echo(f"enabled {skill} ({res['enabled']})")


@app.command("disable")
def disable_cmd(
    skill: str,
    json_out: bool = typer.Option(False, "--json"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Disable an enabled skill."""
    _root_dir, _cfg, reg = _ctx(data_dir, config)
    try:
        res = _installer.disable_skill(reg, skill)
    except KeyError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    if json_out:
        typer.echo(json.dumps(res, indent=2, sort_keys=True))
    else:
        typer.echo(f"disabled {skill}")


@app.command("update")
def update_cmd(
    skill: str,
    source: Optional[str] = typer.Option(None, "--source"),
    json_out: bool = typer.Option(False, "--json"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Update a skill from its source (permission diff + review gate)."""
    root, cfg, reg = _ctx(data_dir, config)
    rec = reg.get(skill)
    if rec is None:
        err_console.print(f"[red]not installed: {skill}[/red]")
        raise typer.Exit(1)
    src = source or rec.get("source_url") or str(builtin_dir() / skill)
    try:
        with staged_source(src) as inspected_list:
            target = next((i for i in inspected_list if i.skill_id == skill), inspected_list[0])
            plan = _installer.plan_update(rec, target)
            if plan["status"] == "SECURITY_REVIEW_REQUIRED":
                if json_out:
                    typer.echo(json.dumps({**plan, "applied": False}, indent=2, sort_keys=True))
                else:
                    typer.echo(f"SECURITY_REVIEW_REQUIRED: {plan['reason']}")
                raise typer.Exit(2)
            res = _installer.install_inspected(target, reg, root, cfg, explicit=True)
    except (OSError, RuntimeError, ValueError, FileNotFoundError) as exc:
        err_console.print(f"[red]update failed: {exc}[/red]")
        raise typer.Exit(1)
    payload = {**plan, "applied": bool(res.get("installed")), "install": res}
    if json_out:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        typer.echo(f"updated {skill}: {plan['from_version']} -> {plan['to_version']}")


@app.command("audit")
def audit_cmd(
    skill: str,
    json_out: bool = typer.Option(False, "--json"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Audit a skill: manifest, provenance, risk, findings. No execution."""
    _root_dir, _cfg, reg = _ctx(data_dir, config)
    rec = reg.get(skill)
    if rec is None:
        # Allow auditing a source path directly.
        if Path(skill).expanduser().exists():
            try:
                results = inspect_source(skill)
            except (OSError, RuntimeError, ValueError, FileNotFoundError) as exc:
                err_console.print(f"[red]audit failed: {exc}[/red]")
                raise typer.Exit(1)
            items = [r.to_dict() for r in results]
            if json_out:
                typer.echo(json.dumps(items, indent=2, sort_keys=True))
            else:
                for r in results:
                    typer.echo(f"{r.skill_id}: {r.verdict.value} risk={r.risk}")
            return
        err_console.print(f"[red]unknown skill: {skill}[/red]")
        raise typer.Exit(1)
    audit_findings = rec.get("findings", [])
    payload = {
        "skill_id": skill, "version": rec.get("version"),
        "trust": rec.get("trust"), "risk": rec.get("risk"),
        "license": rec.get("license"),
        "provenance": {"source_type": rec.get("source_type"), "source_url": rec.get("source_url"),
                       "source_ref": rec.get("source_ref")},
        "fingerprints": {"manifest": rec.get("manifest_fingerprint"), "skill": rec.get("skill_fingerprint")},
        "permissions": rec.get("permissions"), "findings": audit_findings,
        "dependencies": rec.get("depends_on"), "requires_tools": rec.get("requires_tools"),
        "recommended_action": "REVIEW_REQUIRED" if any(
            f.get("severity") in ("HIGH", "CRITICAL") for f in audit_findings) else "OK",
    }
    if json_out:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    typer.echo(f"{skill}@{rec.get('version')}: trust={rec.get('trust')} risk={rec.get('risk')}")
    typer.echo(f"license={rec.get('license')} findings={len(audit_findings)} -> {payload['recommended_action']}")


@app.command("doctor")
def doctor_cmd(
    json_out: bool = typer.Option(False, "--json"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Check registry integrity, deps, quarantine, integrations. No remote execution."""
    root, cfg, reg = _ctx(data_dir, config)
    problems = reg.check_integrity(root)
    # Broken dependencies.
    by_id = {str(r.get("skill_id")): r for r in reg.list_all()}
    for rec in reg.list_all():
        for dep in (rec.get("depends_on") or []):
            dep_id = str(dep).split(">")[0].split("=")[0].split("<")[0].strip()
            if dep_id not in by_id and dep_id not in set(list_builtin_ids()):
                problems.append(f"missing dependency: {rec.get('skill_id')} -> {dep}")
    quarantined = [r.get("skill_id") for r in reg.list_all() if r.get("trust") == "QUARANTINED"]
    payload: dict[str, Any] = {
        "ok": not problems,
        "problems": problems,
        "installed": len(reg.list_all()),
        "quarantined": quarantined,
        "builtin_available": len(list_builtin_ids()),
        "coding_lab_refs": len(coding_lab_skills()),
        "agent_matrix": sorted(load_agent_capabilities().keys()),
        "data_dir": str(root),
        "auto_mode": cfg.auto_install.mode.value,
    }
    if json_out:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        if problems:
            raise typer.Exit(1)
        return
    if problems:
        err_console.print("[red]doctor found problems:[/red]")
        for p in problems:
            typer.echo(f" - {p}")
        raise typer.Exit(1)
    typer.echo(f"OK: {payload['installed']} installed, {payload['builtin_available']} builtin, "
               f"{len(quarantined)} quarantined")


auto_app = typer.Typer(help="Auto-install policy.")
app.add_typer(auto_app, name="auto")


@auto_app.command("status")
def auto_status(
    json_out: bool = typer.Option(False, "--json"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Show auto-install policy."""
    _root_dir, cfg, _reg = _ctx(data_dir, config)
    payload = {"mode": cfg.auto_install.mode.value,
               "allow_trust": list(cfg.auto_install.allow_trust),
               "max_risk": cfg.auto_install.max_risk,
               "permanent_enable": cfg.auto_install.permanent_enable,
               "task_scoped_enable": cfg.auto_install.task_scoped_enable}
    if json_out:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        typer.echo(f"mode={payload['mode']} allow={payload['allow_trust']} max_risk={payload['max_risk']}")


@auto_app.command("set")
def auto_set(
    mode: str,
    json_out: bool = typer.Option(False, "--json"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
    config_file: Optional[str] = typer.Option(None, "--config-file"),
) -> None:
    """Set auto-install mode (OFF/SAFE/SMART/FULL)."""
    root, cfg, _reg = _ctx(data_dir, config)
    try:
        cfg.auto_install.mode = AutoMode[mode.strip().upper()]
    except KeyError:
        err_console.print(f"[red]unknown mode: {mode}[/red]")
        raise typer.Exit(1)
    if cfg.auto_install.mode in (AutoMode.SMART, AutoMode.FULL) and not json_out:
        typer.echo("warning: SMART/FULL broadens discovery; hard security gates always remain enforced. "
                   "BLOCKED/QUARANTINED skills never auto-execute.")
    dest = Path(config_file).expanduser() if config_file else (root / "sklab-skills.yaml")
    save_config(cfg, dest)
    payload = {"mode": cfg.auto_install.mode.value}
    if json_out:
        typer.echo(json.dumps(payload, indent=2))
    else:
        typer.echo(f"auto mode -> {payload['mode']}")


packs_app = typer.Typer(help="Skill packs.")
app.add_typer(packs_app, name="packs")


@packs_app.callback(invoke_without_command=True)
def packs_default(
    ctx: typer.Context,
    json_out: bool = typer.Option(False, "--json"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    if ctx.invoked_subcommand is None:
        _root_dir, _cfg, _reg = _ctx(data_dir, config)
        packs = list_packs()
        if json_out:
            typer.echo(json.dumps(packs, indent=2, sort_keys=True))
            return
        _table([{"id": p["id"], "members": len(p["members"]),  # type: ignore[arg-type]
                 "description": p["description"]} for p in packs], ["id", "members", "description"])


@packs_app.command("show")
def packs_show(
    pack: str,
    json_out: bool = typer.Option(False, "--json"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Show pack members."""
    _ctx(data_dir, config)
    try:
        spec = get_pack(pack)
    except KeyError:
        err_console.print(f"[red]unknown pack: {pack}[/red]")
        raise typer.Exit(1)
    if json_out:
        typer.echo(json.dumps(spec, indent=2, sort_keys=True))
    else:
        typer.echo(f"{pack}: {spec.get('description')}")
        for m in cast("list[str]", spec.get("members", [])):
            typer.echo(f" - {m}")


@packs_app.command("enable")
def packs_enable(
    pack: str,
    force: bool = typer.Option(False, "--force"),
    json_out: bool = typer.Option(False, "--json"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Install+enable pack members subject to policy."""
    root, cfg, reg = _ctx(data_dir, config)
    try:
        spec = get_pack(pack)
    except KeyError:
        err_console.print(f"[red]unknown pack: {pack}[/red]")
        raise typer.Exit(1)
    results: list[dict[str, Any]] = []
    for member in cast("list[str]", spec.get("members", [])):
        cand = builtin_dir() / str(member)
        if not (cand / "skill.yaml").is_file():
            results.append({"skill_id": member, "installed": False, "reason": "builtin missing"})
            continue
        try:
            inspected = inspect_skill_dir(cand, __import__("sklab_skill_hub.models", fromlist=["SourceType"]).SourceType.BUILTIN,
                                          "builtin", "v0.1.0", "BUILTIN")
        except (OSError, ValueError) as exc:
            results.append({"skill_id": member, "installed": False, "reason": str(exc)})
            continue
        res = _installer.install_inspected(inspected, reg, root, cfg, explicit=True)
        if res.get("installed"):
            try:
                _installer.enable_skill(reg, str(member), None, task_scoped=False, force=force)
                res["enabled"] = True
            except PermissionError as exc:
                res["enabled"] = False
                res["enable_note"] = str(exc)
        results.append(res)
    if json_out:
        typer.echo(json.dumps(results, indent=2, sort_keys=True))
    else:
        for r in results:
            typer.echo(f"{r.get('skill_id')}: installed={r.get('installed')} enabled={r.get('enabled', False)}")


@app.command("clean")
def clean_cmd(
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes"),
    json_out: bool = typer.Option(False, "--json"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Delete only project-owned temp/cache artifacts (never installed skills or user repos)."""
    root, _cfg, _reg = _ctx(data_dir, config)
    targets = []
    for sub in ("cache",):
        d = root / sub
        if d.is_dir():
            for child in d.iterdir():
                # Never touch installed/, quarantine/ or registry files.
                targets.append(child)
    plan = {"would_remove": [str(t) for t in targets], "protect": ["installed/", "quarantine/", "registry.json"]}
    if dry_run:
        if json_out:
            typer.echo(json.dumps({**plan, "dry_run": True}, indent=2))
        else:
            typer.echo(f"would remove {len(targets)} cache entries (installed skills protected)")
        return
    if not yes and not json_out:
        typer.confirm(f"Remove {len(targets)} cache entries?", abort=True)
    removed = 0
    for t in targets:
        try:
            if t.is_dir() and not t.is_symlink():
                shutil.rmtree(t, ignore_errors=True)
            else:
                t.unlink(missing_ok=True)
            removed += 1
        except OSError:
            continue
    # Recreate cache layout.
    (root / "cache" / "tmp").mkdir(parents=True, exist_ok=True)
    if json_out:
        typer.echo(json.dumps({"removed": removed, **plan}, indent=2))
    else:
        typer.echo(f"cleaned {removed} cache entries")


@app.command("resolve")
def resolve_cmd(
    task: str = typer.Option(..., "--task"),
    category: str = typer.Option("", "--category"),
    capabilities: str = typer.Option("", "--required-capabilities"),
    agent: str = typer.Option("", "--agent"),
    limit: int = typer.Option(5, "--limit"),
    json_out: bool = typer.Option(False, "--json"),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Task-aware skill resolution (deterministic, no embeddings)."""
    _root_dir, _cfg, reg = _ctx(data_dir, config)
    req_caps = [c.strip().upper() for c in capabilities.split(",") if c.strip()]
    agent_caps: list[str] | None = None
    if agent:
        matrix = load_agent_capabilities()
        agent_caps = sorted(matrix.get(agent, set()))
        if not agent_caps:
            err_console.print(f"[red]unknown agent: {agent}[/red]")
            raise typer.Exit(1)
    hits = _resolver.resolve_skills(task, reg.list_all(), category, req_caps or None, agent_caps, limit)
    payload = [orchestrator_skill_payload(h) for h in hits]
    if json_out:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    _table([{"skill": h["skill_id"], "version": h["version"], "score": h["task_score"],
             "trust": h["trust"], "risk": h["risk"]} for h in hits],
           ["skill", "version", "score", "trust", "risk"])


@app.command("export")
def export_cmd(
    output: Optional[str] = typer.Option(None, "--output", help="Output JSON file (default: stdout)."),
    data_dir: Optional[str] = typer.Option(None, "--data-dir"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Export registry metadata + trust decisions (no secrets, assets by reference)."""
    _root_dir, cfg, reg = _ctx(data_dir, config)
    payload: dict[str, Any] = {
        "schema_version": 1,
        "skills": [
            {k: v for k, v in r.items() if k not in ("manifest",)}
            | {"manifest_ref": f"installed/{r.get('skill_id')}/{r.get('version')}/skill.yaml"}
            for r in reg.list_all()
        ],
        "trust_decisions": reg.trust_decisions(),
        "auto_policy": {"mode": cfg.auto_install.mode.value},
    }
    text = json.dumps(payload, indent=2, sort_keys=True)
    if output:
        Path(output).expanduser().write_text(text, encoding="utf-8")
        typer.echo(f"exported {len(payload['skills'])} skills -> {output}")
    else:
        typer.echo(text)
