"""Builtin skill loader: ships declarative starter skills with the package."""

from __future__ import annotations

from importlib import resources
from pathlib import Path


def builtin_dir() -> Path:
    # Builtins live in <repo>/builtin_skills; installed package may ship a copy.
    here = Path(__file__).resolve()
    repo_root = here.parents[2]  # src/sklab_skill_hub/*.py -> skill-hub/
    candidate = repo_root / "builtin_skills"
    if candidate.is_dir():
        return candidate
    # Fallback: package data dir next to this file.
    pkg_data = here.parent / "builtin_skills"
    if pkg_data.is_dir():
        return pkg_data
    try:
        with resources.as_file(resources.files("sklab_skill_hub") / "builtin_skills") as p:
            if Path(p).is_dir():
                return Path(p)
    except (ModuleNotFoundError, FileNotFoundError, TypeError, OSError):
        pass
    return candidate


def list_builtin_ids() -> list[str]:
    root = builtin_dir()
    if not root.is_dir():
        return []
    ids = [p.name for p in root.iterdir() if p.is_dir() and (p / "skill.yaml").is_file()]
    return sorted(ids)
