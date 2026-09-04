# Changelog

## 0.1.0

- Strict `skill.yaml` schema (Pydantic, schema_version 1) with stable skill IDs and semver.
- SHA-256 manifest + content fingerprints with stable ordering.
- Local registry (atomic JSON) with installed/enabled state, provenance, trust decisions.
- Trust levels BUILTIN/VERIFIED/COMMUNITY/LOCAL/QUARANTINED/BLOCKED; auto-install OFF/SAFE/SMART/FULL (default SAFE); installed != enabled incl. task-scoped enable.
- Permission matrix (deny by default) + deterministic LOW/MEDIUM/HIGH/CRITICAL risk + hard blocks.
- Static security + prompt-injection scanners with evidence; quarantine flow; path/archive/symlink safety; git import without hooks or execution; pinned revisions.
- CLI: list/show/search/inspect/import/install/uninstall/enable/disable/update/audit/doctor/auto/packs/clean/resolve/export with `--json`.
- 31 high-quality declarative builtin skills across coding/git/backend/frontend/devops/research packs.
- Task-aware deterministic resolver, dependency + cycle handling, chain validation, capability matching.
- Web UI service DTOs + Orchestrator contract payloads; Agent Adapters / Coding Lab / ReproBox integration points.
