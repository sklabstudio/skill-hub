"""Skill packs: curated groups of builtin skills."""

from __future__ import annotations

from typing import cast

PACKS: dict[str, dict[str, object]] = {
    "coding": {
        "description": "Core coding workflows: understand, fix, build, review, test.",
        "members": ["repo-understand", "bug-fix", "feature-build", "refactor-safe",
                    "code-review", "test-first", "test-generator", "test-failure-debug",
                    "dependency-upgrade", "performance-review"],
    },
    "git": {
        "description": "Git history, conflicts, releases and changelogs.",
        "members": ["git-history-analysis", "merge-conflict-review", "release-check",
                    "changelog-review", "version-bump-review"],
    },
    "backend": {
        "description": "API design, backend debugging and data reviews.",
        "members": ["api-design", "fastapi-debug", "backend-debug", "database-review", "migration-review"],
    },
    "frontend": {
        "description": "Frontend debugging, typecheck and accessibility.",
        "members": ["frontend-debug", "nextjs-debug", "typecheck-fix", "accessibility-review"],
    },
    "devops": {
        "description": "CI, Docker, compose and GitHub Actions.",
        "members": ["ci-fix", "docker-debug", "compose-review", "github-actions-review"],
    },
    "research": {
        "description": "Docs, architecture summaries and implementation plans.",
        "members": ["docs-review", "architecture-summary", "implementation-plan"],
    },
    # Future packs: stubs only (no members shipped in v0.1.0).
    "cyber": {
        "description": "Future defensive-security pack (integration point only).",
        "members": [],
        "future": ["repo-security-audit", "secret-scan", "dependency-vulnerability-review",
                   "docker-security", "github-actions-security", "api-security-review",
                   "auth-review", "tls-header-review", "security-remediation", "incident-log-analysis"],
    },
    "contracts": {
        "description": "Future smart-contract pack (integration point only).",
        "members": [],
        "future": ["solidity-build", "contract-review", "access-control-audit", "reentrancy-review",
                   "slither-audit", "foundry-tests", "fuzz-tests", "invariant-tests",
                   "gas-review", "upgradeability-review", "token-contract-review"],
    },
}


def list_packs() -> list[dict[str, object]]:
    return [{"id": pid, "description": spec.get("description"),
             "members": cast("list[str]", spec.get("members", [])),
             "future": cast("list[str]", spec.get("future", []))}
            for pid, spec in sorted(PACKS.items())]


def get_pack(pack_id: str) -> dict[str, object]:
    spec = PACKS.get(pack_id)
    if spec is None:
        raise KeyError(f"unknown pack: {pack_id}")
    return {"id": pack_id, "description": spec.get("description"),
            "members": cast("list[str]", spec.get("members", [])),
            "future": cast("list[str]", spec.get("future", []))}
