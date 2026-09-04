# SKLab Skill Hub

**A safe, agent-agnostic registry for reusable AI engineering skills.**

Quick start:

```bash
sklab-skills list
sklab-skills show bug-fix
sklab-skills packs
sklab-skills auto status
sklab-skills import ./my-skill
sklab-skills audit my-skill
```

> A skill is useful only when its provenance, permissions, compatibility, and trust are explicit.

## Why

Different agents keep reusable capabilities in different formats — prompts,
workflows, checklists, MCP references, scripts. Skill Hub is one safe layer that
discovers, normalizes, fingerprints, classifies, installs, permissions, and
resolves skills across agents and workflows — without blindly executing random
internet code.

## Skill Format

Each skill is a directory with `skill.yaml` (schema_version 1, strict Pydantic)
plus a `SKILL.md` entry asset. See `docs/skill-format.md` and `docs/authoring.md`.

## Built-in Skills

31 declarative starter skills across `coding`, `git`, `backend`, `frontend`,
`devops`, `research` packs. See `builtin_skills/` and `docs/packs.md`.

## Trust Levels

`BUILTIN` / `VERIFIED` / `COMMUNITY` / `LOCAL` / `QUARANTINED` / `BLOCKED`.
Popularity is never trust. See `docs/trust.md`.

## Permissions

Explicit deny-by-default matrix (`filesystem_read/write`, `shell`, `network`,
`git_read/write`, `docker`, `mcp`, `secrets`, `provider_access`, `web_access`)
with optional scopes. See `docs/permissions.md`.

## Risk Model

Deterministic `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`. Risk is a policy signal,
not a malware verdict. See `docs/security.md`.

## Auto Install

Modes `OFF` / `SAFE` (default) / `SMART` / `FULL`. Installed != enabled
(`INSTALLED` / `ENABLED_GLOBAL` / `ENABLED_FOR_TASK` / `DISABLED` /
`QUARANTINED`). `FULL` never disables hard gates. See `docs/auto-install.md`.

## Packs

```bash
sklab-skills packs
sklab-skills packs show coding
sklab-skills packs enable coding
```

## Importing Skills

```bash
sklab-skills inspect ./my-skill      # read-only, no install, no exec
sklab-skills import ./my-skill       # validate + install
sklab-skills install bug-fix         # builtin by id
```

Import never executes skill code: no hooks, no postinstall, no package-manager
scripts, pinned Git revisions. See `docs/imports.md`.

## GitHub Sources

GitHub URLs pin the exact commit SHA at import; updates go through explicit
`sklab-skills update`. No credential scraping, no private-repo fetching unless
the user configured legitimate access.

## Agent Compatibility

Skills declare required capabilities (`FILES_READ`, `SHELL`, …) from the Agent
Adapters model. `sklab-skills show <skill> --agents` lists compatible agents.

## Orchestrator Integration

Python API `resolve_skills(task, category, required_capabilities,
agent_capabilities, policy)` returns skill metadata for the Orchestrator, which
owns execution. Skill Hub never executes skills itself. See `docs/integrations.md`.

## Security Model

- Imported skills are untrusted until validated.
- Static analysis cannot prove safety.
- Nothing executes during import/install.
- Executable skills need runtime isolation (ReproBox) + explicit policy.
- No secrets stored; manifests must use references, never values.
- `FULL` mode keeps all hard gates.
- Updates can change risk → `SECURITY_REVIEW_REQUIRED`.

## Updating Skills

`sklab-skills update <skill>` diffs permissions/fingerprints and refuses silent
escalation (`PERMISSION_ESCALATION` → review gate).

## Quarantine

Suspicious skills go to `~/.sklab/skills/quarantine/` — inspectable and
deletable, never enabled or resolved.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
mypy src
python -m build
```

## Limitations

- No remote marketplace, billing, embeddings, or signed-registry server in v0.1.0.
- HTTP archives disabled by default; prefer git/local imports.
- Static scanners are heuristics, not guarantees.

## Roadmap

Remote registry, signed skills/packs, Cyber + Contract packs, SkillMiner
distillation, semantic search, org policies, Web UI flows. See `docs/progress.md`.

## License

MIT — Copyright (c) 2026 SKLab Studio. Third-party skills keep their own licenses.
