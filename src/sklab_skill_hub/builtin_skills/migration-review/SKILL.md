# Migration Review

Review a data migration for safety and rollback.

## Inputs

- `migration`

## Workflow

1. Check idempotency
2. Verify rollback plan
3. Require backup note

## Outputs

- `verdict`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
