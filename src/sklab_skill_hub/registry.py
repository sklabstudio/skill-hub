"""Local registry: atomic JSON store over installed skills + trust decisions."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sklab_skill_hub.models import EnableState, RiskLevel, TrustLevel

REGISTRY_VERSION = 1


def utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _atomic_write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".registry-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class Registry:
    """Minimal reliable store. No PostgreSQL; single atomic JSON document."""

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir).expanduser()
        self.path = self.data_dir / "registry.json"
        self.trust_path = self.data_dir / "trust.json"
        self._doc: dict[str, Any] = {"version": REGISTRY_VERSION, "skills": {}}
        self._trust: dict[str, Any] = {"decisions": []}
        self.load()

    # -- persistence -----------------------------------------------------
    def load(self) -> None:
        if self.path.is_file():
            try:
                self._doc = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self._doc = {"version": REGISTRY_VERSION, "skills": {}}
        if not isinstance(self._doc.get("skills"), dict):
            self._doc["skills"] = {}
        if self.trust_path.is_file():
            try:
                self._trust = json.loads(self.trust_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self._trust = {"decisions": []}

    def save(self) -> None:
        _atomic_write_json(self.path, self._doc)
        _atomic_write_json(self.trust_path, self._trust)

    # -- skills ----------------------------------------------------------
    def key(self, skill_id: str, version: str) -> str:
        return f"{skill_id}@{version}"

    def upsert(self, record: dict[str, Any]) -> None:
        self._doc["skills"][self.key(record["skill_id"], record["version"])] = record
        self.save()

    def get(self, skill_id: str, version: str | None = None) -> dict[str, Any] | None:
        skills: dict[str, Any] = self._doc["skills"]
        if version is not None:
            return skills.get(self.key(skill_id, version))
        # Latest by version string sort (semantic-ish).
        candidates = [r for r in skills.values() if r.get("skill_id") == skill_id]
        if not candidates:
            return None
        candidates.sort(key=lambda r: str(r.get("version", "")), reverse=True)
        return candidates[0]

    def list_all(self) -> list[dict[str, Any]]:
        return sorted(self._doc["skills"].values(), key=lambda r: (str(r.get("skill_id")), str(r.get("version"))))

    def versions(self, skill_id: str) -> list[dict[str, Any]]:
        return sorted(
            [r for r in self._doc["skills"].values() if r.get("skill_id") == skill_id],
            key=lambda r: str(r.get("version", "")),
        )

    def remove(self, skill_id: str, version: str) -> bool:
        k = self.key(skill_id, version)
        if k in self._doc["skills"]:
            del self._doc["skills"][k]
            self.save()
            return True
        return False

    def ids(self) -> list[str]:
        return sorted({str(r.get("skill_id")) for r in self._doc["skills"].values()})

    # -- enable state ----------------------------------------------------
    def set_enabled(self, skill_id: str, version: str, state: EnableState) -> bool:
        rec = self.get(skill_id, version)
        if rec is None:
            return False
        rec["enabled_state"] = state.value
        rec["updated_at"] = utcnow_iso()
        self.save()
        return True

    # -- trust decisions -------------------------------------------------
    def record_trust_decision(
        self,
        skill_id: str,
        skill_fingerprint: str,
        decision: str,
        scope: str = "local",
        actor: str = "user",
    ) -> None:
        self._trust.setdefault("decisions", []).append({
            "skill_id": skill_id,
            "skill_fingerprint": skill_fingerprint,
            "decision": decision,
            "scope": scope,
            "actor": actor,
            "timestamp": utcnow_iso(),
        })
        self.save()

    def trust_decisions(self, skill_id: str = "") -> list[dict[str, Any]]:
        decisions = list(self._trust.get("decisions", []))
        if skill_id:
            decisions = [d for d in decisions if d.get("skill_id") == skill_id]
        return decisions

    def is_trust_valid_for_fingerprint(self, skill_id: str, fingerprint: str) -> bool:
        for d in reversed(self.trust_decisions(skill_id)):
            if d.get("skill_fingerprint") == fingerprint and d.get("decision") in ("trust", "approve", "verified"):
                return True
        return False

    # -- integrity -------------------------------------------------------
    def check_integrity(self, data_dir: Path | None = None) -> list[str]:
        problems: list[str] = []
        root = data_dir or self.data_dir
        seen_ids: dict[str, int] = {}
        for rec in self.list_all():
            sid = str(rec.get("skill_id"))
            seen_ids[sid] = seen_ids.get(sid, 0) + 1
            rel = rec.get("install_path", "")
            if rel:
                full = root / str(rel)
                if not full.is_dir():
                    problems.append(f"missing assets: {sid}@{rec.get('version')} ({rel})")
                elif not (full / "skill.yaml").is_file():
                    problems.append(f"missing manifest: {sid}@{rec.get('version')}")
            try:
                TrustLevel[str(rec.get("trust", "LOCAL")).upper()]
            except KeyError:
                problems.append(f"bad trust: {sid}")
            try:
                RiskLevel[str(rec.get("risk", "LOW")).upper()]
            except KeyError:
                problems.append(f"bad risk: {sid}")
        return problems
