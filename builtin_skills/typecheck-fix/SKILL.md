# Typecheck Fix

Fix static type errors without loosening safety.

## Inputs

- `type-errors`

## Workflow

1. Read full type error
2. Narrow types at cause
3. Re-run typecheck

## Outputs

- `fix`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
