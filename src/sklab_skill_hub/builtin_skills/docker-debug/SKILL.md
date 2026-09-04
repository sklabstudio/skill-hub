# Docker Debug

Diagnose container build and runtime failures.

## Inputs

- `dockerfile`

## Workflow

1. Inspect build stage failure
2. Check layer caching and context
3. Verify minimal image run

## Outputs

- `diagnosis`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
