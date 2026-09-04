# FastAPI Debug

Diagnose FastAPI failures: routing, validation, dependency injection.

## Inputs

- `traceback`

## Workflow

1. Reproduce request
2. Check route and schema
3. Fix with regression test

## Outputs

- `diagnosis`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
