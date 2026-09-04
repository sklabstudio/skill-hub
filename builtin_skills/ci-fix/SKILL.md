# CI Fix

Fix a failing CI workflow using exact logs.

## Inputs

- `ci-log`

## Workflow

1. Read exact failing step
2. Reproduce locally with same command
3. Patch workflow minimally

## Outputs

- `fix`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
