# Test First

Write failing tests first, then implement until green.

## Inputs

- `requirement`

## Workflow

1. Write failing test
2. Implement minimally
3. Refactor on green

## Outputs

- `tests`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
