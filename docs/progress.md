# Skill Hub — progress log

## v0.1.0 build

- [x] Schema / models / fingerprints
- [x] Registry / store / config
- [x] Trust / permission / risk model
- [x] Builtin loader + 31 builtin skills
- [x] Local / git import without execution
- [x] Security + injection scanners, quarantine
- [x] Install / enable / update flows, escalation gate
- [x] Auto-install policies (OFF/SAFE/SMART/FULL)
- [x] Packs (coding/git/backend/frontend/devops/research + cyber/contracts stubs)
- [x] Task-aware resolver, chains, dependencies
- [x] Agent Adapters / Orchestrator / Coding Lab / ReproBox integration points
- [x] CLI with --json across major commands
- [x] Docs, fixtures, tests
- [x] Final gate: pytest + ruff + mypy + build + smoke
- [x] GitHub publish + Actions green (https://github.com/sklabstudio/skill-hub)

CI note (fixed 2026-09-04): first CI run caught a real bug — remote-clone
temp dirs were cleaned up before install, breaking git-source installs on
Linux (masked on Windows where rmtree silently fails on locked files).
Fixed via `staged_source` clone-lifetime context + `install_from_source`;
all import/install/update flows use it. Regression tests added.

No external AI, no paid providers, no arbitrary remote execution used.
