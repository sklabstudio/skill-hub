"""Path / archive / symlink safety. Aggressive rejection of traversal escapes."""

from __future__ import annotations

import os
import tarfile
import zipfile
from pathlib import Path


def is_safe_relative_path(rel: str) -> bool:
    if not rel or rel.strip() == "":
        return False
    # Reject absolute paths (posix + windows drive + UNC).
    if rel.startswith("/") or rel.startswith("\\"):
        return False
    if len(rel) >= 2 and rel[1] == ":":
        return False
    if rel.startswith("\\\\"):
        return False
    # Reject NUL bytes and control tricks.
    if "\x00" in rel:
        return False
    # Normalize backslashes for windows tricks, then check parts.
    norm = rel.replace("\\", "/")
    parts = norm.split("/")
    for part in parts:
        if part in ("..",):
            return False
        if part in ("",) and norm.startswith("/"):
            return False
    # After normalization, no parent escape.
    if norm.startswith("../") or norm == ".." or "/../" in norm:
        return False
    # ADS / NTFS tricks.
    if ":" in norm and not norm.startswith("./"):
        # Allow drive-relative already rejected; colons elsewhere (ADS like file:stream) rejected.
        return False
    return True


def validate_member_paths(members: list[str]) -> list[str]:
    """Return list of rejected member paths."""
    return [m for m in members if not is_safe_relative_path(m)]


def check_symlink_escape(skill_dir: Path) -> list[str]:
    """Walk skill_dir; report symlinks that escape the skill root."""
    bad: list[str] = []
    root = skill_dir.resolve()
    for path in skill_dir.rglob("*"):
        try:
            if path.is_symlink():
                target = (path.parent / os.readlink(path)).resolve()
                try:
                    target.relative_to(root)
                except ValueError:
                    bad.append(path.relative_to(skill_dir).as_posix())
        except OSError:
            bad.append(path.relative_to(skill_dir).as_posix() if path else "?")
    return bad


def assert_safe_skill_dir(skill_dir: Path) -> list[str]:
    """Return list of path-safety violations (empty = safe)."""
    violations: list[str] = []
    if not skill_dir.is_dir():
        return [f"not a directory: {skill_dir}"]
    for path in skill_dir.rglob("*"):
        try:
            rel = path.relative_to(skill_dir).as_posix()
        except ValueError:
            violations.append(f"escape: {path}")
            continue
        if not is_safe_relative_path(rel):
            violations.append(f"unsafe path: {rel}")
    violations.extend(f"symlink escape: {s}" for s in check_symlink_escape(skill_dir))
    return violations


def safe_extract_zip(archive: Path, dest: Path) -> list[str]:
    """Validate (do not extract if violations). Returns violations list."""
    violations: list[str] = []
    try:
        with zipfile.ZipFile(archive) as zf:
            names = zf.namelist()
            violations.extend(f"unsafe member: {m}" for m in validate_member_paths(names))
            for info in zf.infolist():
                if info.is_dir():
                    continue
                # zip symlink/device detection: external_attr bits
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    violations.append(f"symlink member: {info.filename}")
    except zipfile.BadZipFile as exc:
        violations.append(f"bad zip: {exc}")
    if violations:
        return violations
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            target = (dest / info.filename).resolve()
            try:
                target.relative_to(dest.resolve())
            except ValueError:
                return [f"extraction escape: {info.filename}"]
        zf.extractall(dest)
    return []


def safe_extract_tar(archive: Path, dest: Path) -> list[str]:
    violations: list[str] = []
    try:
        with tarfile.open(archive, "r:*") as tf:
            members = tf.getmembers()
            names = [m.name for m in members]
            violations.extend(f"unsafe member: {m}" for m in validate_member_paths(names))
            for m in members:
                if m.issym() or m.islnk():
                    violations.append(f"symlink member: {m.name}")
                if m.isdev():
                    violations.append(f"device member: {m.name}")
                if m.name.startswith("/") or m.name.startswith("\\"):
                    violations.append(f"absolute member: {m.name}")
    except (tarfile.TarError, OSError) as exc:
        violations.append(f"bad tar: {exc}")
    if violations:
        return violations
    with tarfile.open(archive, "r:*") as tf:
        dest_resolved = dest.resolve()
        for m in tf.getmembers():
            target = (dest / m.name).resolve()
            try:
                target.relative_to(dest_resolved)
            except ValueError:
                return [f"extraction escape: {m.name}"]
        tf.extractall(dest, filter="data")
    return []
