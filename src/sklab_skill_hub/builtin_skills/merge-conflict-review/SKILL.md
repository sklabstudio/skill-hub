# Merge Conflict Review

Resolve merge conflicts preserving intent of both sides.

## Inputs

- `branches`

## Workflow

1. Understand both sides
2. Resolve per-hunk with tests
3. Verify build after merge

## Outputs

- `resolved-tree`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
