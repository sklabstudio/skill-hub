# Test Generator

Generate focused unit and integration tests for uncovered behavior.

## Inputs

- `module`

## Workflow

1. Identify uncovered paths
2. Add deterministic tests
3. Run and report coverage delta

## Outputs

- `tests`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
