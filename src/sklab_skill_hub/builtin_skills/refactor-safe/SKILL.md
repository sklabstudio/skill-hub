# Safe Refactor

Behavior-preserving refactor with before/after test evidence.

## Inputs

- `target`

## Workflow

1. Baseline tests first
2. Small reversible steps
3. Re-run suite and diff review

## Outputs

- `refactor`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
