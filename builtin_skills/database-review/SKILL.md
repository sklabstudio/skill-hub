# Database Review

Review schema, migration and query safety.

## Inputs

- `schema`

## Workflow

1. Check constraints and indexes
2. Review migration reversibility
3. Flag N+1 and locking risks

## Outputs

- `review`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
