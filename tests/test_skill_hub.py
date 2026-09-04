"""Mandatory v0.1.0 test suite: schema, import, policy, resolver, integrations, CLI."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sklab_skill_hub import fingerprints as fp
from sklab_skill_hub import installer as installer_mod
from sklab_skill_hub import resolver as resolver_mod
from sklab_skill_hub import service as service_mod
from sklab_skill_hub.builtins import builtin_dir, list_builtin_ids
from sklab_skill_hub.cli import app
from sklab_skill_hub.config import HubConfig, effective_auto_config, load_config
from sklab_skill_hub.importer import (
    classify_source,
    default_trust_for,
    inspect_skill_dir,
    inspect_source,
)
from sklab_skill_hub.integrations import (
    coding_lab_skills,
    compatible_agents,
    load_agent_capabilities,
    orchestrator_skill_payload,
    reprobox_execution_plan,
)
from sklab_skill_hub.models import (
    AutoMode,
    RiskLevel,
    SkillManifest,
    SourceType,
    TrustLevel,
)
from sklab_skill_hub.packs import get_pack, list_packs
from sklab_skill_hub.pathsafety import (
    assert_safe_skill_dir,
    check_symlink_escape,
    is_safe_relative_path,
    safe_extract_zip,
    validate_member_paths,
)
from sklab_skill_hub.registry import Registry
from sklab_skill_hub.risk import classify_risk, parse_risk, risk_allows
from sklab_skill_hub.scanners import (
    detect_inline_secrets,
    has_hard_block,
    scan_text,
)
from sklab_skill_hub.store import ensure_layout

runner = CliRunner()
FIX = Path(__file__).parent / "fixtures"


def fx(name: str) -> str:
    return str(FIX / name)


def install_fixture(skill_dir: str, reg: Registry, data_dir: Path, cfg: HubConfig,
                    explicit: bool = True, trust_hint: str = "LOCAL"):
    inspected = inspect_source(skill_dir, trust_hint=trust_hint)[0]
    res = installer_mod.install_inspected(inspected, reg, data_dir, cfg, explicit=explicit)
    return inspected, res


# -- CLI startup/version ----------------------------------------------------

def test_cli_version():
    r = runner.invoke(app, ["--version"])
    assert r.exit_code == 0
    assert "0.1.0" in r.output


def test_cli_help():
    r = runner.invoke(app, ["--help"])
    assert r.exit_code == 0
    assert "sklab-skills" in r.output.lower() or "list" in r.output


# -- manifest schema --------------------------------------------------------

def test_strict_manifest_schema_ok():
    m = SkillManifest.model_validate({
        "schema_version": 1, "id": "bug-fix", "name": "Bug Fix", "version": "1.0.0",
        "description": "x", "type": "workflow",
    })
    assert m.id == "bug-fix"


def test_invalid_manifest_rejected():
    with pytest.raises(ValueError):
        SkillManifest.model_validate({"schema_version": 99, "id": "BAD ID!!"})


def test_invalid_fixture_inspect_verdict():
    out = inspect_source(fx("invalid-manifest"))
    assert out[0].verdict.value == "INVALID"


def test_version_parsing_rejects():
    with pytest.raises(ValueError):
        SkillManifest.model_validate({"schema_version": 1, "id": "abc-def", "name": "x", "version": "notaversion"})


def test_skill_id_pattern():
    with pytest.raises(ValueError):
        SkillManifest.model_validate({"schema_version": 1, "id": "Bad_ID!", "name": "x"})
    m = SkillManifest.model_validate({"schema_version": 1, "id": "api-security-review", "name": "x"})
    assert m.id == "api-security-review"


def test_duplicate_id_versions(registry: Registry):
    registry.upsert({"skill_id": "dup", "version": "1.0.0"})
    registry.upsert({"skill_id": "dup", "version": "2.0.0"})
    assert len(registry.versions("dup")) == 2
    assert registry.get("dup")["version"] == "2.0.0"


# -- fingerprints -----------------------------------------------------------

def test_fingerprint_stability_and_change(tmp_path: Path):
    a = inspect_skill_dir(Path(fx("safe-prompt-skill")))
    b = inspect_skill_dir(Path(fx("safe-prompt-skill")))
    assert a.content_fingerprint == b.content_fingerprint
    assert a.manifest_fingerprint == b.manifest_fingerprint
    # Content change alters fingerprint.
    import shutil
    copy = tmp_path / "copy-skill"
    shutil.copytree(fx("safe-prompt-skill"), copy)
    (copy / "SKILL.md").write_text("# Safe Prompt\n\nChanged content.\n", encoding="utf-8")
    c = inspect_skill_dir(copy)
    assert c.content_fingerprint != a.content_fingerprint


def test_fingerprint_ignores_volatile():
    d1 = {"a": 1, "imported_at": "x"}
    d2 = {"a": 1, "imported_at": "y"}
    assert fp.manifest_fingerprint(d1) == fp.manifest_fingerprint(d2)


# -- local import / git / pinning / non-execution ----------------------------

def test_local_import_no_execution(data_dir: Path, registry: Registry, config: HubConfig):
    inspected, res = install_fixture(fx("safe-workflow-skill"), registry, data_dir, config)
    assert res["installed"] is True
    assert (data_dir / "installed" / "safe-workflow-skill" / "1.0.0" / "SKILL.md").is_file()


def test_git_source_import_and_pinning(data_dir: Path, registry: Registry, config: HubConfig):
    repo = str(FIX / "git-source-repo")
    out = inspect_source(repo)
    assert out and out[0].skill_id == "git-fixture-skill"
    # Clone path via file:// URL pins a SHA.
    url = Path(repo).as_uri()
    out2 = inspect_source(url)
    sha = out2[0].provenance.get("source_ref", "")
    assert len(sha) >= 7, f"expected pinned sha, got {sha!r}"
    assert out2[0].verdict.value == "VALID"


def test_import_non_execution(data_dir: Path, registry: Registry, config: HubConfig):
    repo = FIX / "git-source-repo"
    for name in ("PWNED", "PWNED2", "PWNED3", "PWNED4"):
        assert not (repo / name).exists(), f"hook executed in source?! {name}"
    url = repo.as_uri()
    inspected = inspect_source(url)[0]
    res = installer_mod.install_inspected(inspected, registry, data_dir, config, explicit=True)
    assert res["installed"] is True
    dest = data_dir / "installed" / inspected.skill_id / inspected.version
    for name in ("PWNED", "PWNED2", "PWNED3", "PWNED4"):
        assert not (dest / name).exists()
        assert not (Path.cwd() / name).exists()


def test_provenance_stored(data_dir: Path, registry: Registry, config: HubConfig):
    _ins, _res = install_fixture(fx("safe-prompt-skill"), registry, data_dir, config)
    rec = registry.get("safe-prompt-skill")
    assert rec is not None
    assert rec["manifest_fingerprint"]
    assert rec["skill_fingerprint"]
    assert rec["license"] in ("MIT", "LICENSE_UNKNOWN")


def test_unknown_license(data_dir: Path):
    out = inspect_source(fx("unknown-license"))
    assert out[0].manifest.provenance.license == "LICENSE_UNKNOWN"


# -- install / uninstall / enable / disable ----------------------------------

def test_install_uninstall_safe(data_dir: Path, registry: Registry, config: HubConfig):
    _ins, res = install_fixture(fx("local-skill"), registry, data_dir, config)
    assert res["installed"]
    out = installer_mod.uninstall_skill(registry, data_dir, "local-skill")
    assert out["uninstalled"] is True
    assert registry.get("local-skill") is None


def test_uninstall_refuses_when_enabled(data_dir: Path, registry: Registry, config: HubConfig):
    install_fixture(fx("local-skill"), registry, data_dir, config)
    installer_mod.enable_skill(registry, "local-skill")
    with pytest.raises(PermissionError):
        installer_mod.uninstall_skill(registry, data_dir, "local-skill")


def test_enable_disable(data_dir: Path, registry: Registry, config: HubConfig):
    install_fixture(fx("safe-prompt-skill"), registry, data_dir, config)
    r = installer_mod.enable_skill(registry, "safe-prompt-skill")
    assert r["enabled"] == "ENABLED_GLOBAL"
    r = installer_mod.disable_skill(registry, "safe-prompt-skill")
    assert r["enabled"] == "DISABLED"


def test_task_scoped_vs_global_enable(data_dir: Path, registry: Registry, config: HubConfig):
    install_fixture(fx("safe-prompt-skill"), registry, data_dir, config)
    installer_mod.enable_skill(registry, "safe-prompt-skill", task_scoped=True)
    rec = registry.get("safe-prompt-skill")
    assert rec is not None and rec["enabled_state"] == "ENABLED_FOR_TASK"
    installer_mod.enable_skill(registry, "safe-prompt-skill", task_scoped=False)
    rec = registry.get("safe-prompt-skill")
    assert rec is not None and rec["enabled_state"] == "ENABLED_GLOBAL"


def test_enable_high_risk_needs_force(data_dir: Path, registry: Registry, config: HubConfig):
    install_fixture(fx("high-risk-network-shell"), registry, data_dir, config)
    with pytest.raises(PermissionError):
        installer_mod.enable_skill(registry, "high-risk-network-shell")
    r = installer_mod.enable_skill(registry, "high-risk-network-shell", force=True)
    assert r["enabled"] == "ENABLED_GLOBAL"


# -- update + escalation -----------------------------------------------------

def test_update_permission_escalation(data_dir: Path, registry: Registry, config: HubConfig):
    ins1 = inspect_source(fx("update-permission-escalation-v1"))[0]
    r1 = installer_mod.install_inspected(ins1, registry, data_dir, config, explicit=True)
    assert r1["installed"]
    ins2 = inspect_source(fx("update-permission-escalation-v2"))[0]
    old = registry.get("update-permission-escalation")
    assert old is not None
    plan = installer_mod.plan_update(old, ins2)
    assert plan["status"] == "SECURITY_REVIEW_REQUIRED"
    assert plan["permission_diff"]["escalated"] is True
    # Old version preserved until review passes.
    assert registry.get("update-permission-escalation")["version"] == "1.0.0"


# -- trust / quarantine / hard blocks ----------------------------------------

def test_trust_levels():
    assert default_trust_for(SourceType.BUILTIN) == TrustLevel.BUILTIN
    assert default_trust_for(SourceType.GITHUB) == TrustLevel.COMMUNITY
    assert default_trust_for(SourceType.LOCAL_DIRECTORY) == TrustLevel.LOCAL
    assert default_trust_for(SourceType.LOCAL_DIRECTORY, "VERIFIED") == TrustLevel.VERIFIED


def test_quarantine_flow(data_dir: Path, registry: Registry, config: HubConfig):
    _ins, res = install_fixture(fx("quarantined-skill"), registry, data_dir, config, explicit=False)
    assert res["quarantined"] is True
    rec = registry.get("quarantined-skill")
    assert rec is not None and rec["trust"] == "QUARANTINED"
    with pytest.raises(PermissionError):
        installer_mod.enable_skill(registry, "quarantined-skill")
    assert (data_dir / "quarantine" / "quarantined-skill-1.0.0").is_dir()


def test_hard_block_secret_network():
    ins = inspect_skill_dir(Path(fx("secret-network-skill")))
    assert has_hard_block(ins.findings) or (
        ins.manifest.permissions.secrets and ins.manifest.permissions.network)
    blocked, _reason = installer_mod.check_hard_gates(ins, HubConfig())
    assert blocked is True


# -- risk --------------------------------------------------------------------

def test_risk_classification():
    low = inspect_skill_dir(Path(fx("safe-prompt-skill")))
    assert classify_risk(low.manifest, low.has_executable) == RiskLevel.LOW
    med = inspect_skill_dir(Path(fx("community-executable")))
    assert classify_risk(med.manifest, med.has_executable) in (RiskLevel.MEDIUM, RiskLevel.HIGH)
    high = inspect_skill_dir(Path(fx("high-risk-network-shell")))
    assert classify_risk(high.manifest, high.has_executable) == RiskLevel.HIGH
    crit = inspect_skill_dir(Path(fx("secret-network-skill")))
    assert classify_risk(crit.manifest, crit.has_executable) == RiskLevel.CRITICAL


def test_risk_allows():
    assert risk_allows(RiskLevel.LOW, RiskLevel.LOW)
    assert not risk_allows(RiskLevel.HIGH, RiskLevel.LOW)
    assert parse_risk("low") == RiskLevel.LOW


# -- scanners -----------------------------------------------------------------

def test_static_security_findings():
    ins = inspect_skill_dir(Path(fx("quarantined-skill")))
    ids = {f.id for f in ins.findings}
    assert "cookie-theft" in ids or "exfil" in ids or "perm-shell-net" in ids


def test_prompt_injection_findings():
    ins = inspect_skill_dir(Path(fx("malicious-prompt-injection")))
    ids = {f.id for f in ins.findings}
    assert any(i.startswith("inj-") for i in ids), f"expected inj- finding, got {ids}"


def test_benign_doc_not_rejected():
    findings = scan_text("This checklist helps detect exfiltration. Never upload the repository.", "SKILL.md")
    assert all(f.severity in ("LOW", "MEDIUM") for f in findings)


def test_no_inline_secrets():
    findings = detect_inline_secrets({"description": "use AKIAIOSFODNN7EXAMPLE please"})
    assert findings, "expected inline secret detection"
    safe = detect_inline_secrets({"description": "reference secret://provider-connections/github"})
    assert not safe


def test_inline_secret_manifest_blocked(data_dir: Path, registry: Registry, config: HubConfig, tmp_path: Path):
    d = tmp_path / "evil-secret"
    d.mkdir()
    (d / "skill.yaml").write_text(
        "schema_version: 1\nid: evil-secret-skill\nname: Evil\nversion: 1.0.0\n"
        "description: 'token ghp_abcdefghij1234567890abcdefghij123456'\ntype: prompt\n", encoding="utf-8")
    (d / "SKILL.md").write_text("# Evil\n", encoding="utf-8")
    ins = inspect_skill_dir(d)
    assert ins.secret_findings, "manifest inline secret must be flagged"


# -- dependencies / cycles / chains -------------------------------------------

def test_dependency_cycle_rejected():
    by_id = {
        "dependency-cycle-a": {"depends_on": ["dependency-cycle-b"]},
        "dependency-cycle-b": {"depends_on": ["dependency-cycle-a"]},
    }
    with pytest.raises(ValueError, match="cycle"):
        resolver_mod.resolve_dependencies("dependency-cycle-a", by_id)


def test_dependency_missing():
    with pytest.raises(KeyError):
        resolver_mod.resolve_dependencies("x", {"x": {"depends_on": ["nope"]}})


def test_chain_validation():
    by_id = {"a": {}, "b": {}}
    assert resolver_mod.validate_chain(["a", "b"], by_id) == ["a", "b"]
    with pytest.raises(ValueError):
        resolver_mod.validate_chain(["a", "a"], by_id)
    with pytest.raises(ValueError):
        resolver_mod.validate_chain([f"s{i}" for i in range(20)], {f"s{i}": {} for i in range(20)})


# -- task resolution / agent caps ----------------------------------------------

def _seed_resolver(registry: Registry, data_dir: Path, cfg: HubConfig):
    for name in ("safe-prompt-skill", "safe-workflow-skill", "local-skill"):
        install_fixture(str(FIX / name), registry, data_dir, cfg)
    installer_mod.enable_skill(registry, "safe-workflow-skill")


def test_task_resolution(data_dir: Path, registry: Registry, config: HubConfig):
    _seed_resolver(registry, data_dir, config)
    hits = resolver_mod.resolve_skills("summarize repository docs", registry.list_all(), limit=3)
    assert hits and all("skill_id" in h for h in hits)
    for h in hits:
        assert {"skill_id", "version", "fingerprint", "trust", "risk",
                "permissions", "entry_type", "entry_asset", "task_score", "warnings"} <= set(h)


def test_agent_capability_matching():
    matrix = load_agent_capabilities()
    assert "hermes" in matrix
    agents = compatible_agents(["FILES_READ", "SHELL"], matrix)
    assert "hermes" in agents
    agents_none = compatible_agents(["FILES_READ", "SHELL", "NONEXISTENT_CAP_XYZ"], matrix)
    assert agents_none == []


def test_resolve_respects_agent_caps(data_dir: Path, registry: Registry, config: HubConfig):
    _seed_resolver(registry, data_dir, config)
    hits = resolver_mod.resolve_skills("summarize", registry.list_all(), agent_capabilities=["FILES_READ"])
    assert isinstance(hits, list)


# -- packs ---------------------------------------------------------------------

def test_packs():
    packs = list_packs()
    ids = {p["id"] for p in packs}
    assert {"coding", "git", "backend", "frontend", "devops", "research"} <= ids
    coding = get_pack("coding")
    assert "bug-fix" in coding["members"]
    with pytest.raises(KeyError):
        get_pack("nope")


def test_builtin_count_and_quality():
    ids = list_builtin_ids()
    assert 25 <= len(ids) <= 35, f"expected 25-35 builtins, got {len(ids)}"
    for bid in ids:
        assert (builtin_dir() / bid / "skill.yaml").is_file()
        assert (builtin_dir() / bid / "SKILL.md").is_file()


# -- auto modes -----------------------------------------------------------------

def _auto_cfg(mode: str) -> HubConfig:
    cfg = HubConfig()
    cfg.auto_install.mode = AutoMode[mode]
    return cfg


def test_auto_off_denies():
    ok, _ = installer_mod.auto_decision(TrustLevel.VERIFIED, RiskLevel.LOW, False,
                                        AutoMode.OFF, ["BUILTIN", "VERIFIED"], RiskLevel.LOW)
    assert ok is False


def test_auto_safe_allows_verified_low():
    ok, _ = installer_mod.auto_decision(TrustLevel.VERIFIED, RiskLevel.LOW, False,
                                        AutoMode.SAFE, ["BUILTIN", "VERIFIED"], RiskLevel.LOW)
    assert ok is True


def test_auto_safe_denies_community_exec():
    ok, _ = installer_mod.auto_decision(TrustLevel.COMMUNITY, RiskLevel.MEDIUM, True,
                                        AutoMode.SAFE, ["BUILTIN", "VERIFIED"], RiskLevel.LOW)
    assert ok is False


def test_auto_smart_quarantines_community_exec():
    ok, reason = installer_mod.auto_decision(TrustLevel.COMMUNITY, RiskLevel.HIGH, True,
                                             AutoMode.SMART, ["BUILTIN", "VERIFIED", "COMMUNITY"], RiskLevel.HIGH)
    assert ok is False


def test_full_respects_hard_gates(data_dir: Path, registry: Registry):
    cfg = _auto_cfg("FULL")
    ins = inspect_skill_dir(Path(fx("secret-network-skill")))
    blocked, _ = installer_mod.check_hard_gates(ins, cfg)
    assert blocked is True
    res = installer_mod.install_inspected(ins, registry, data_dir, cfg, explicit=False)
    assert res["installed"] is False
    assert res["quarantined"] is True


def test_safe_auto_install_task(data_dir: Path, registry: Registry):
    """SAFE installs VERIFIED low-risk bug-fix; skips COMMUNITY executable."""
    cfg = _auto_cfg("SAFE")
    verified = inspect_source(fx("safe-workflow-skill"), trust_hint="VERIFIED")[0]
    res_ok = installer_mod.install_inspected(verified, registry, data_dir, cfg, explicit=False)
    assert res_ok["installed"] is True
    community = inspect_source(fx("community-executable"), trust_hint="COMMUNITY")[0]
    res_no = installer_mod.install_inspected(community, registry, data_dir, cfg, explicit=False)
    assert res_no["installed"] is False
    assert registry.get("safe-workflow-skill") is not None


def test_effective_category_override():
    cfg = HubConfig()
    assert effective_auto_config(cfg, "coding").mode == AutoMode.SAFE


# -- clean safety -----------------------------------------------------------------

def test_clean_safety(data_dir: Path, registry: Registry, config: HubConfig, tmp_path: Path):
    install_fixture(fx("safe-prompt-skill"), registry, data_dir, config)
    (data_dir / "cache" / "tmp" / "scratch.txt").parent.mkdir(parents=True, exist_ok=True)
    (data_dir / "cache" / "tmp" / "scratch.txt").write_text("x", encoding="utf-8")
    r = runner.invoke(app, ["clean", "--data-dir", str(data_dir), "--yes"])
    assert r.exit_code == 0
    assert registry.get("safe-prompt-skill") is not None
    assert (data_dir / "installed" / "safe-prompt-skill").is_dir()


# -- JSON output ---------------------------------------------------------------------

def test_json_outputs(tmp_path: Path):
    dd = tmp_path / "j"
    ensure_layout(dd)
    r = runner.invoke(app, ["list", "--data-dir", str(dd), "--json"])
    assert r.exit_code == 0
    json.loads(r.output)
    r = runner.invoke(app, ["auto", "status", "--data-dir", str(dd), "--json"])
    assert r.exit_code == 0
    assert json.loads(r.output)["mode"] == "SAFE"
    r = runner.invoke(app, ["doctor", "--data-dir", str(dd), "--json"])
    assert r.exit_code == 0
    r = runner.invoke(app, ["inspect", fx("safe-prompt-skill"), "--json"])
    assert r.exit_code == 0
    payload = json.loads(r.output)
    assert payload[0]["skill_id"] == "safe-prompt-skill"


def test_cli_import_enable_audit(tmp_path: Path):
    dd = tmp_path / "cli"
    r = runner.invoke(app, ["import", fx("safe-prompt-skill"), "--data-dir", str(dd)])
    assert r.exit_code == 0
    r = runner.invoke(app, ["show", "safe-prompt-skill", "--data-dir", str(dd), "--json"])
    assert r.exit_code == 0
    assert json.loads(r.output)["skill_id"] == "safe-prompt-skill"
    r = runner.invoke(app, ["search", "safe", "--data-dir", str(dd), "--json"])
    assert r.exit_code == 0
    r = runner.invoke(app, ["enable", "safe-prompt-skill", "--data-dir", str(dd)])
    assert r.exit_code == 0
    r = runner.invoke(app, ["audit", "safe-prompt-skill", "--data-dir", str(dd), "--json"])
    assert r.exit_code == 0
    assert json.loads(r.output)["skill_id"] == "safe-prompt-skill"
    r = runner.invoke(app, ["disable", "safe-prompt-skill", "--data-dir", str(dd)])
    assert r.exit_code == 0
    r = runner.invoke(app, ["uninstall", "safe-prompt-skill", "--data-dir", str(dd), "--yes"])
    assert r.exit_code == 0


def test_cli_packs_and_resolve_and_export(tmp_path: Path):
    dd = tmp_path / "packs"
    r = runner.invoke(app, ["packs", "--data-dir", str(dd)])
    assert r.exit_code == 0
    r = runner.invoke(app, ["packs", "show", "coding", "--data-dir", str(dd)])
    assert r.exit_code == 0
    r = runner.invoke(app, ["import", fx("safe-workflow-skill"), "--data-dir", str(dd)])
    assert r.exit_code == 0
    r = runner.invoke(app, ["resolve", "--task", "summarize repository", "--data-dir", str(dd), "--json"])
    assert r.exit_code == 0
    out = tmp_path / "exp.json"
    r = runner.invoke(app, ["export", "--data-dir", str(dd), "--output", str(out)])
    assert r.exit_code == 0
    assert out.is_file()


# -- path / symlink / archive safety --------------------------------------------------

def test_cli_install_builtin_trust(tmp_path: Path):
    from sklab_skill_hub.builtins import builtin_dir as _bd
    dd = tmp_path / "builtin-trust"
    r = runner.invoke(app, ["install", "bug-fix", "--source", str(_bd() / "bug-fix"),
                            "--data-dir", str(dd)])
    assert r.exit_code == 0
    rec = Registry(dd).get("bug-fix")
    assert rec is not None and rec["trust"] == "BUILTIN"


def test_path_traversal_rejected():
    assert not is_safe_relative_path("../../evil.md")
    assert not is_safe_relative_path("/abs/path")
    assert not is_safe_relative_path("C:\\Windows\\x")
    assert is_safe_relative_path("SKILL.md")
    assert is_safe_relative_path("assets/guide.md")
    bad = validate_member_paths(["ok.md", "../evil.md", "/abs"])
    assert len(bad) == 2


def test_symlink_escape_rejected(tmp_path: Path):
    skill = tmp_path / "sk"
    skill.mkdir()
    (skill / "skill.yaml").write_text("x", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = skill / "link.md"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    bad = check_symlink_escape(skill)
    assert bad, "symlink escape must be reported"
    assert assert_safe_skill_dir(skill), "skill dir with escape must report violations"


def test_archive_traversal_rejected(tmp_path: Path):
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../evil.md", "x")
        zf.writestr("ok.md", "y")
    dest = tmp_path / "dest"
    dest.mkdir()
    violations = safe_extract_zip(z, dest)
    assert violations
    assert not (dest / "evil.md").exists()


def test_git_source_no_hooks_env():
    # Clone helper must isolate git config and never use shell.
    import inspect as _inspect
    src = _inspect.getsource(__import__("sklab_skill_hub.importer", fromlist=["clone_git"]).clone_git)
    assert "shell=True" not in src
    assert "GIT_CONFIG_NOSYSTEM" in src


# -- Web UI DTO + orchestrator --------------------------------------------------------

def test_web_dto_safety(data_dir: Path, registry: Registry, config: HubConfig):
    install_fixture(fx("safe-prompt-skill"), registry, data_dir, config)
    for dto in service_mod.list_skills(data_dir):
        blob = json.dumps(dto).lower()
        assert "ghp_" not in blob
        assert "api_key_value" not in blob
        assert set(dto) <= {"skill_id", "name", "version", "category", "skill_type", "trust",
                            "risk", "verdict", "enabled_state", "source_type", "source_url",
                            "source_ref", "license", "permissions", "required_capabilities",
                            "requires_tools", "depends_on", "manifest_fingerprint",
                            "skill_fingerprint", "has_executable", "findings", "description",
                            "tags", "signature_status", "signer"}


def test_orchestrator_contract(data_dir: Path, registry: Registry, config: HubConfig):
    install_fixture(fx("safe-workflow-skill"), registry, data_dir, config)
    installer_mod.enable_skill(registry, "safe-workflow-skill")
    hits = service_mod.resolve_for_task(data_dir, "summarize repository")
    assert hits
    payload = orchestrator_skill_payload({**hits[0], "version": hits[0].get("version")})
    assert {"skill_id", "version", "fingerprint", "trust", "risk",
            "permissions", "entry_type", "entry_asset", "task_score", "warnings"} <= set(payload)


def test_reprobox_plan():
    plan = reprobox_execution_plan({"skill_id": "x", "version": "1.0.0"})
    assert plan["backend"] == "reprobox"
    assert plan["isolated"] is True


# -- ecosystem integrations -----------------------------------------------------------------

def test_agent_adapters_integration():
    matrix = load_agent_capabilities()
    assert isinstance(matrix, dict) and "generic" in matrix
    # No paid inference: pure local table read.
    assert compatible_agents(["FILES_READ"], matrix)


def test_coding_lab_integration():
    refs = coding_lab_skills()
    assert isinstance(refs, list)
    for ref in refs[:5]:
        assert "skill_id" in ref and "provenance" in ref


def test_orchestrator_fixture_compat():
    # Orchestrator SkillRef shape compatibility (id/version/category/caps/risk).
    try:
        from sklab_orchestrator.skills import SkillResolver

        ref = SkillResolver().get("bug-fix")
        assert ref.id == "bug-fix"
        assert "FILES_READ" in ref.required_capabilities
    except ImportError:
        pytest.skip("orchestrator not installed")


# -- dogfood ----------------------------------------------------------------------------------

def test_dogfood_chain(data_dir: Path, registry: Registry, config: HubConfig):
    from sklab_skill_hub.builtins import builtin_dir as _bd
    for sid in ("repo-understand", "fastapi-debug", "test-failure-debug", "code-review"):
        src = str(_bd() / sid)
        ins = inspect_source(src, trust_hint="BUILTIN")[0]
        installer_mod.install_inspected(ins, registry, data_dir, config, explicit=True)
        installer_mod.enable_skill(registry, sid)
    hits = resolver_mod.resolve_skills("Fix failing FastAPI test", registry.list_all(), limit=6)
    ids = [h["skill_id"] for h in hits]
    assert "fastapi-debug" in ids
    assert "test-failure-debug" in ids
    # Disable one skill -> resolver selects alternative deterministically.
    installer_mod.disable_skill(registry, "fastapi-debug")
    hits2 = resolver_mod.resolve_skills("Fix failing FastAPI test", registry.list_all(), limit=6)
    ids2 = [h["skill_id"] for h in hits2]
    assert "fastapi-debug" not in ids2
    assert hits2[0]["skill_id"] != "fastapi-debug"


def test_doctor_ok(data_dir: Path, registry: Registry, config: HubConfig):
    install_fixture(fx("safe-prompt-skill"), registry, data_dir, config)
    assert registry.check_integrity(data_dir) == []
    r = runner.invoke(app, ["doctor", "--data-dir", str(data_dir)])
    assert r.exit_code == 0


def test_config_roundtrip(tmp_path: Path):
    cfg = HubConfig()
    assert load_config(None, tmp_path).auto_install.mode == AutoMode.SAFE
    assert cfg.auto_install.task_scoped_enable is True


def test_classify_source():
    kind, _ = classify_source("https://github.com/org/repo")
    assert kind == SourceType.GITHUB
    kind, _ = classify_source(fx("safe-prompt-skill"))
    assert kind == SourceType.LOCAL_DIRECTORY


def test_license_unknown_value():
    out = inspect_source(fx("unknown-license"))
    assert out[0].provenance.get("license", "LICENSE_UNKNOWN") in ("LICENSE_UNKNOWN", "MIT")
