# Release Check

Pre-release checklist: version, changelog, build, smoke.

## Inputs

- `release`

## Workflow

1. Version and changelog
2. Build artifact
3. Smoke checks

## Outputs

- `verdict`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
