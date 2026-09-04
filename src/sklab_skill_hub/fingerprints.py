"""Stable SHA-256 fingerprints over normalized manifest + declarative assets."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

VOLATILE_KEYS = {"imported_at", "imported_by", "original_fingerprint"}


def _strip_volatile(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _strip_volatile(v) for k, v in sorted(obj.items()) if k not in VOLATILE_KEYS}
    if isinstance(obj, list):
        return [_strip_volatile(v) for v in obj]
    return obj


def canonical_json(obj: Any) -> str:
    return json.dumps(_strip_volatile(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def manifest_fingerprint(manifest_dict: dict[str, Any]) -> str:
    return sha256_text(canonical_json(manifest_dict))


DECLARATIVE_EXTS = {".md", ".yaml", ".yml", ".json", ".txt", ".toml"}
EXECUTABLE_EXTS = {".sh", ".ps1", ".bat", ".cmd", ".exe", ".py", ".js", ".ts"}


def skill_fingerprint(manifest_dict: dict[str, Any], asset_texts: dict[str, str]) -> str:
    """Hash normalized manifest + sorted asset (path -> content) pairs."""
    manifest_part = canonical_json(manifest_dict)
    parts = [f"manifest:{sha256_text(manifest_part)}"]
    for rel in sorted(asset_texts):
        try:
            content = asset_texts[rel]
        except KeyError:
            continue
        parts.append(f"asset:{rel}:{sha256_text(content)}")
    return sha256_text("\n".join(parts))


def collect_asset_texts(skill_dir: Path, manifest_entry: str = "SKILL.md") -> dict[str, str]:
    texts: dict[str, str] = {}
    if not skill_dir.is_dir():
        return texts
    for path in sorted(skill_dir.rglob("*")):
        if not path.is_file():
            continue
        if ".git" in path.parts:
            continue
        rel = path.relative_to(skill_dir).as_posix()
        suffix = path.suffix.lower()
        if suffix in DECLARATIVE_EXTS or path.name == manifest_entry or rel == "skill.yaml":
            try:
                texts[rel] = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
        elif suffix in EXECUTABLE_EXTS:
            # Hash executable metadata (name + size + sha) — not full trust.
            try:
                data = path.read_bytes()
            except OSError:
                continue
            texts[rel] = f"<executable sha256={hashlib.sha256(data).hexdigest()} size={len(data)}>"
    return texts
