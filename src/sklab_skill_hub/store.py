"""Data-dir resolution and on-disk layout (~/.sklab/skills)."""

from __future__ import annotations

import os
from pathlib import Path


def resolve_data_dir(explicit: str | Path | None = None) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    env = os.environ.get("SKLAB_SKILLS_DIR", "").strip()
    if env:
        return Path(env).expanduser()
    return Path.home() / ".sklab" / "skills"


def ensure_layout(data_dir: Path) -> dict[str, Path]:
    paths = {
        "root": data_dir,
        "installed": data_dir / "installed",
        "cache": data_dir / "cache",
        "quarantine": data_dir / "quarantine",
        "tmp": data_dir / "cache" / "tmp",
        "registry": data_dir / "registry.json",
        "trust": data_dir / "trust.json",
        "config": data_dir / "sklab-skills.yaml",
    }
    for key in ("root", "installed", "cache", "quarantine", "tmp"):
        paths[key].mkdir(parents=True, exist_ok=True)
    return paths
