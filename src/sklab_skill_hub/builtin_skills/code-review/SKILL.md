# Code Review

Review a diff for correctness, regressions, scope and security.

## Inputs

- `diff`

## Workflow

1. Check correctness and edge cases
2. Flag scope creep and security issues
3. Give actionable findings

## Outputs

- `review`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
