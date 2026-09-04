# Feature Build

Implement a scoped feature with tests and docs, minimal diff.

## Inputs

- `spec`

## Workflow

1. Clarify acceptance criteria
2. Implement with tests
3. Verify full relevant suite

## Outputs

- `feature`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
