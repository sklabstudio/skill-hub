"""Source resolution + static import. IMPORT MUST NOT EXECUTE SKILL CODE."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sklab_skill_hub import fingerprints as fp
from sklab_skill_hub.models import (
    InspectVerdict,
    SkillManifest,
    SourceType,
    TrustLevel,
)
from sklab_skill_hub.pathsafety import assert_safe_skill_dir
from sklab_skill_hub.risk import classify_risk
from sklab_skill_hub.scanners import (
    Finding,
    detect_inline_secrets,
    has_hard_block,
    scan_skill_dir,
)

GITHUB_RE = re.compile(r"^https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/#?]+?)(?:\.git)?(?:/(?:tree|commit|blob)/(?P<ref>[^#?]+))?(?:#.*)?$", re.I)
MANIFEST_NAMES = ("skill.yaml", "skill.yml", "SKILL.yaml")


@dataclass
class InspectedSkill:
    skill_id: str
    version: str
    manifest: SkillManifest
    manifest_dict: dict[str, Any]
    manifest_fingerprint: str
    content_fingerprint: str
    findings: list[Finding] = field(default_factory=list)
    secret_findings: list[Finding] = field(default_factory=list)
    path_violations: list[str] = field(default_factory=list)
    has_executable: bool = False
    risk: str = "LOW"
    verdict: InspectVerdict = InspectVerdict.VALID
    provenance: dict[str, Any] = field(default_factory=dict)
    skill_dir: Path | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "skill_id": self.skill_id,
            "version": self.version,
            "verdict": self.verdict.value,
            "risk": self.risk,
            "trust_hint": self.provenance.get("trust_hint", "LOCAL"),
            "manifest_fingerprint": self.manifest_fingerprint,
            "content_fingerprint": self.content_fingerprint,
            "findings": [f.to_dict() for f in self.findings],
            "secret_findings": [f.to_dict() for f in self.secret_findings],
            "path_violations": self.path_violations,
            "has_executable": self.has_executable,
            "provenance": self.provenance,
        }


def classify_source(raw: str) -> tuple[SourceType, str]:
    s = raw.strip()
    if GITHUB_RE.match(s):
        return SourceType.GITHUB, s
    if s.startswith(("http://", "https://")) and s.endswith((".zip", ".tar.gz", ".tgz", ".tar")):
        return SourceType.HTTP_ARCHIVE, s
    if s.startswith(("http://", "https://", "git@", "ssh://")) and (".git" in s or "github.com" in s or "gitlab" in s):
        return SourceType.GIT_REPOSITORY, s
    p = Path(s).expanduser()
    if p.exists():
        return SourceType.LOCAL_DIRECTORY, str(p)
    # Unknown remote-ish string -> treat as git repository URL (will fail cleanly later).
    if "://" in s or s.endswith(".git") or s.count("/") >= 1 and " " not in s and Path(s).suffix == "":
        return SourceType.GIT_REPOSITORY, s
    return SourceType.LOCAL_DIRECTORY, s


def _safe_env() -> dict[str, str]:
    env = dict(os.environ)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "echo"
    return env


def clone_git(url: str, dest: Path, ref: str | None = None) -> tuple[str, str]:
    """Clone without running hooks or repo scripts. Returns (resolved_sha, source_url).

    Never uses shell. Never executes repo content. GIT_CONFIG_NOSYSTEM set.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "--no-checkout", "--depth", "1"]
    if ref:
        cmd += ["--branch", ref]
    cmd += [url, str(dest)]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, env=_safe_env(), timeout=120)
    except FileNotFoundError as exc:
        raise RuntimeError("git executable not found") from exc
    except subprocess.CalledProcessError as exc:
        # Retry without --branch for commit SHAs.
        if ref:
            shutil.rmtree(dest, ignore_errors=True)
            cmd2 = ["git", "clone", "--no-checkout", url, str(dest)]
            try:
                subprocess.run(cmd2, check=True, capture_output=True, text=True, env=_safe_env(), timeout=120)
            except subprocess.CalledProcessError as exc2:
                raise RuntimeError(f"git clone failed: {(exc2.stderr or exc2.stdout or '')[:500]}") from exc2
        else:
            raise RuntimeError(f"git clone failed: {(exc.stderr or exc.stdout or '')[:500]}") from exc
    # Resolve SHA without checking out hooks: use ls-remote style rev-parse on origin.
    sha = ""
    try:
        proc = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            capture_output=True, text=True, env=_safe_env(), timeout=30,
        )
        sha = (proc.stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        sha = ""
    # Checkout files only (no hooks run by checkout of tracked files; hooks run on
    # commit/checkout hooks only if configured — core.hooksPath disabled).
    try:
        subprocess.run(
            ["git", "-C", str(dest), "-c", "core.hooksPath=/dev/null",
             "checkout", "--force", ref or "HEAD"],
            capture_output=True, text=True, env=_safe_env(), timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        pass
    return sha, url


def find_skill_dirs(root: Path) -> list[Path]:
    found: list[Path] = []
    if (root / "skill.yaml").is_file() or (root / "skill.yml").is_file():
        return [root]
    for manifest_name in MANIFEST_NAMES:
        for path in root.rglob(manifest_name):
            if ".git" in path.parts:
                continue
            found.append(path.parent)
    # Agent-native single-file fallback: SKILL.md at root with front-matter?
    if not found and (root / "SKILL.md").is_file():
        found.append(root)
    seen: list[Path] = []
    for d in found:
        if d not in seen:
            seen.append(d)
    return sorted(seen)


def load_manifest_dict(skill_dir: Path) -> tuple[dict[str, Any], Path]:
    for name in MANIFEST_NAMES:
        cand = skill_dir / name
        if cand.is_file():
            raw = yaml.safe_load(cand.read_text(encoding="utf-8")) or {}
            if not isinstance(raw, dict):
                raise ValueError(f"{name} must be a mapping")
            return raw, cand
    # Agent-native fallback: synthesize from SKILL.md front-matter.
    skill_md = skill_dir / "SKILL.md"
    if skill_md.is_file():
        return manifest_from_agent_native(skill_dir), skill_md
    raise FileNotFoundError(f"no skill manifest (skill.yaml) in {skill_dir}")


def manifest_from_agent_native(skill_dir: Path) -> dict[str, Any]:
    text = (skill_dir / "SKILL.md").read_text(encoding="utf-8", errors="replace")
    front: dict[str, Any] = {}
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            try:
                front = yaml.safe_load(text[3:end]) or {}
            except yaml.YAMLError:
                front = {}
    stem = skill_dir.name.lower().replace("_", "-").replace(" ", "-")
    stem = re.sub(r"[^a-z0-9-]", "", stem) or "imported-skill"
    if len(stem) < 3:
        stem = f"sk-{stem}-skill"
    return {
        "schema_version": 1,
        "id": str(front.get("id", stem))[:64],
        "name": str(front.get("name", skill_dir.name)),
        "version": str(front.get("version", "1.0.0")),
        "description": str(front.get("description", "Imported agent-native skill."))[:500],
        "type": str(front.get("type", "prompt")),
        "category": str(front.get("category", "general")),
        "permissions": {"filesystem": {"read": True, "write": False}},
        "entry": {"file": "SKILL.md"},
        "provenance": {"source_type": "AGENT_NATIVE"},
    }


def _has_executable(skill_dir: Path) -> bool:
    for path in skill_dir.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        if path.suffix.lower() in {".sh", ".ps1", ".bat", ".cmd", ".exe", ".py", ".js", ".ts"}:
            return True
        if path.name in ("package.json", "setup.py", "Makefile", "postinstall.sh"):
            return True
    return False


def inspect_skill_dir(
    skill_dir: Path,
    source_type: SourceType = SourceType.LOCAL_DIRECTORY,
    source_url: str = "",
    source_ref: str = "",
    trust_hint: str = "LOCAL",
) -> InspectedSkill:
    manifest_dict, _manifest_path = load_manifest_dict(skill_dir)
    secret_findings = detect_inline_secrets(manifest_dict)
    try:
        manifest = SkillManifest.model_validate(manifest_dict)
    except Exception as exc:
        # Build a minimal invalid inspection record.
        sid = str(manifest_dict.get("id", skill_dir.name))
        ver = str(manifest_dict.get("version", "0.0.0"))
        return InspectedSkill(
            skill_id=sid, version=ver,
            manifest=SkillManifest.model_construct(
                id="invalid-skill-id-fallback" if not re.match(
                    r"^[a-z0-9][a-z0-9-]{2,63}$", sid) else sid,
                name=str(manifest_dict.get("name", sid)),
            ),
            manifest_dict=manifest_dict if isinstance(manifest_dict, dict) else {},
            manifest_fingerprint="",
            content_fingerprint="",
            findings=[Finding(id="manifest-invalid", severity="HIGH",
                              message=f"Manifest validation failed: {exc}",
                              path="skill.yaml")],
            secret_findings=secret_findings,
            verdict=InspectVerdict.INVALID,
            provenance={"source_type": source_type.value, "source_url": source_url,
                        "source_ref": source_ref, "trust_hint": trust_hint},
            skill_dir=skill_dir,
        )
    path_violations = assert_safe_skill_dir(skill_dir)
    findings = scan_skill_dir(skill_dir, manifest)
    findings.extend(secret_findings)
    has_exec = _has_executable(skill_dir)
    manifest_fp = fp.manifest_fingerprint(manifest.to_normalized_dict())
    assets = fp.collect_asset_texts(skill_dir, manifest.entry.file)
    content_fp = fp.skill_fingerprint(manifest.to_normalized_dict(), assets)
    risk = classify_risk(manifest, has_exec).value
    verdict = InspectVerdict.VALID
    if path_violations:
        verdict = InspectVerdict.QUARANTINE_RECOMMENDED
    elif has_hard_block(findings):
        verdict = InspectVerdict.QUARANTINE_RECOMMENDED
    elif any(f.severity in ("HIGH", "CRITICAL") for f in findings):
        verdict = InspectVerdict.SUSPICIOUS
    provenance = {
        "source_type": source_type.value,
        "source_url": source_url,
        "source_ref": source_ref,
        "license": manifest.provenance.license or "LICENSE_UNKNOWN",
        "trust_hint": trust_hint,
    }
    return InspectedSkill(
        skill_id=manifest.id, version=manifest.version, manifest=manifest,
        manifest_dict=manifest_dict, manifest_fingerprint=manifest_fp,
        content_fingerprint=content_fp, findings=findings,
        secret_findings=secret_findings, path_violations=path_violations,
        has_executable=has_exec, risk=risk, verdict=verdict,
        provenance=provenance, skill_dir=skill_dir,
    )


def inspect_source(
    source: str,
    work_root: Path | None = None,
    trust_hint: str = "LOCAL",
) -> list[InspectedSkill]:
    """Read-only inspection of a local dir or git/github source. No install, no exec."""
    kind, loc = classify_source(source)
    tmpdir: Path | None = None
    try:
        if kind in (SourceType.GITHUB, SourceType.GIT_REPOSITORY):
            tmpdir = Path(tempfile.mkdtemp(prefix="sklab-skills-import-"))
            dest = tmpdir / "repo"
            m = GITHUB_RE.match(source.strip()) if kind == SourceType.GITHUB else None
            ref = (m.group("ref") if m and m.group("ref") else None)
            sha, _url = clone_git(loc, dest, ref)
            dirs = find_skill_dirs(dest)
            if not dirs:
                raise FileNotFoundError(f"no skill manifests found in {source}")
            out = []
            for d in dirs:
                out.append(inspect_skill_dir(
                    d, source_type=kind, source_url=source,
                    source_ref=sha, trust_hint=trust_hint))
            return out
        if kind == SourceType.HTTP_ARCHIVE:
            raise RuntimeError("HTTP archive import is not enabled in v0.1.0 (use git or local directory)")
        root = Path(loc).expanduser()
        if not root.exists():
            raise FileNotFoundError(f"source not found: {source}")
        if root.is_file() and root.name == "skill.yaml":
            root = root.parent
        dirs = find_skill_dirs(root)
        if not dirs:
            raise FileNotFoundError(f"no skill manifests found in {source}")
        return [inspect_skill_dir(d, source_type=kind, source_url=str(root),
                                  source_ref="", trust_hint=trust_hint) for d in dirs]
    finally:
        if tmpdir is not None:
            shutil.rmtree(tmpdir, ignore_errors=True)


def default_trust_for(source_type: SourceType, trust_hint: str = "") -> TrustLevel:
    hint = (trust_hint or "").strip().upper()
    if hint in TrustLevel.__members__:
        return TrustLevel[hint]
    if source_type == SourceType.BUILTIN:
        return TrustLevel.BUILTIN
    if source_type in (SourceType.GITHUB, SourceType.GIT_REPOSITORY):
        return TrustLevel.COMMUNITY
    if source_type == SourceType.AGENT_NATIVE:
        return TrustLevel.LOCAL
    return TrustLevel.LOCAL
