"""Deterministic task-aware resolution, chains, and dependency handling."""

from __future__ import annotations

import re
from typing import Any

from sklab_skill_hub.models import EnableState

MAX_CHAIN_LENGTH = 8

_STOPWORDS = frozenset({
    "the", "a", "an", "and", "or", "to", "of", "in", "on", "for", "with",
    "fix", "please", "help", "my", "our", "is", "are", "it", "this", "that",
})

CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "coding": ["bug", "fix", "feature", "refactor", "implement", "code"],
    "testing": ["test", "failing", "pytest", "coverage", "regression", "flaky"],
    "git": ["merge", "conflict", "history", "commit", "branch", "changelog", "release"],
    "backend": ["fastapi", "api", "backend", "database", "migration", "endpoint"],
    "frontend": ["frontend", "react", "nextjs", "css", "accessibility", "typecheck"],
    "devops": ["ci", "docker", "compose", "github-actions", "deploy", "pipeline"],
    "research": ["docs", "architecture", "plan", "summary", "research"],
    "security": ["security", "audit", "vulnerability", "secret", "auth", "tls"],
    "contracts": ["solidity", "contract", "foundry", "slither", "reentrancy", "gas"],
}


def tokenize(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9][a-z0-9\-]+", text.lower()) if t not in _STOPWORDS}


def score_skill(record: dict[str, Any], task: str, category: str = "",
                required_capabilities: list[str] | None = None) -> float:
    manifest = record.get("manifest") or {}
    tags = {str(t).lower() for t in (manifest.get("tags") or [])}
    rec_category = str(record.get("category", "")).lower()
    name = str(record.get("name", "")).lower()
    desc = str(manifest.get("description", "")).lower()
    tokens = tokenize(task + " " + category)
    hay = tokenize(" ".join([name, desc, rec_category, " ".join(tags), str(record.get("skill_id"))]))
    overlap = len(tokens & hay)
    score = float(overlap)
    if category and rec_category == category.lower():
        score += 3.0
    for kw in CATEGORY_KEYWORDS.get((category or "").lower(), []):
        if kw in hay:
            score += 0.5
    if required_capabilities:
        have = {c.upper() for c in (record.get("required_capabilities") or [])}
        need = {c.upper() for c in required_capabilities}
        if need and not need.issubset(have):
            score -= 5.0
    # Prefer lower risk and higher trust.
    risk = str(record.get("risk", "LOW")).upper()
    score -= {"LOW": 0.0, "MEDIUM": 0.5, "HIGH": 2.0, "CRITICAL": 5.0}.get(risk, 1.0)
    trust = str(record.get("trust", "LOCAL")).upper()
    score += {"BUILTIN": 1.0, "VERIFIED": 0.8, "LOCAL": 0.3, "COMMUNITY": 0.0,
              "QUARANTINED": -10.0, "BLOCKED": -10.0}.get(trust, 0.0)
    return score


def resolve_skills(
    task: str,
    records: list[dict[str, Any]],
    category: str = "",
    required_capabilities: list[str] | None = None,
    agent_capabilities: list[str] | None = None,
    limit: int = 5,
    include_disabled: bool = False,
) -> list[dict[str, Any]]:
    pool = []
    for rec in records:
        if rec.get("trust") in ("QUARANTINED", "BLOCKED"):
            continue
        if rec.get("enabled_state") == EnableState.QUARANTINED.value:
            continue
        if not include_disabled and rec.get("enabled_state") == EnableState.DISABLED.value:
            continue
        if agent_capabilities:
            have = {c.upper() for c in agent_capabilities}
            need = {c.upper() for c in (rec.get("required_capabilities") or [])}
            # Agent must cover skill needs; unknown agent caps (empty) means no filter.
            if need and not need.issubset(have):
                continue
        pool.append(rec)
    scored = [(score_skill(r, task, category, required_capabilities), r) for r in pool]
    scored.sort(key=lambda t: (-t[0], str(t[1].get("skill_id"))))
    out: list[dict[str, Any]] = []
    for score, rec in scored[:limit]:
        out.append({
            "skill_id": rec.get("skill_id"),
            "version": rec.get("version"),
            "fingerprint": rec.get("skill_fingerprint"),
            "trust": rec.get("trust"),
            "risk": rec.get("risk"),
            "permissions": rec.get("permissions"),
            "entry_type": (rec.get("manifest") or {}).get("type", "WORKFLOW"),
            "entry_asset": ((rec.get("manifest") or {}).get("entry") or {}).get("file", "SKILL.md"),
            "task_score": round(score, 2),
            "warnings": _warnings(rec),
            "category": rec.get("category"),
        })
    return out


def _warnings(rec: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    if rec.get("has_executable"):
        warnings.append("contains executable assets; run only in isolated runtime")
    if str(rec.get("risk", "")).upper() in ("HIGH", "CRITICAL"):
        warnings.append(f"elevated risk: {rec.get('risk')}")
    missing = [t for t in (rec.get("requires_tools") or [])]
    if missing:
        warnings.append(f"requires tools: {', '.join(missing)}")
    return warnings


def parse_dep(spec: str) -> tuple[str, str]:
    m = re.match(r"^([a-z0-9][a-z0-9-]*)(.*)$", spec.strip())
    if not m:
        raise ValueError(f"invalid dependency spec: {spec!r}")
    return m.group(1), (m.group(2) or "").strip()


def resolve_dependencies(skill_id: str, by_id: dict[str, dict[str, Any]]) -> list[str]:
    """Topological order of dependencies ending with skill_id. Raises on missing/cycle."""
    order: list[str] = []
    visiting: list[str] = []
    visited: set[str] = set()

    def visit(sid: str) -> None:
        if sid in visited:
            return
        if sid in visiting:
            cycle = " -> ".join([*visiting, sid])
            raise ValueError(f"dependency cycle: {cycle}")
        rec = by_id.get(sid)
        if rec is None:
            raise KeyError(f"missing dependency: {sid}")
        visiting.append(sid)
        for dep in (rec.get("depends_on") or []):
            dep_id, _constraint = parse_dep(str(dep))
            visit(dep_id)
        visiting.pop()
        visited.add(sid)
        order.append(sid)

    visit(skill_id)
    return order


def validate_chain(chain: list[str], by_id: dict[str, dict[str, Any]]) -> list[str]:
    if len(chain) > MAX_CHAIN_LENGTH:
        raise ValueError(f"chain exceeds max length {MAX_CHAIN_LENGTH}")
    if len(set(chain)) != len(chain):
        raise ValueError("chain contains duplicate skills (possible loop)")
    for sid in chain:
        if sid not in by_id:
            raise KeyError(f"unknown skill in chain: {sid}")
    return list(chain)


def agent_compatible(record: dict[str, Any], agent_caps: set[str]) -> bool:
    need = {c.upper() for c in (record.get("required_capabilities") or [])}
    return need.issubset({c.upper() for c in agent_caps})


def trust_allows(trust: str, allowed: list[str]) -> bool:
    return trust.upper() in {a.upper() for a in allowed}


def risk_within(risk: str, max_risk: str) -> bool:
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    return order[risk.upper()] <= order[max_risk.upper()]
