# Docs Review

Review documentation accuracy and examples.

## Inputs

- `docs`

## Workflow

1. Verify examples run
2. Check links and versions
3. Flag stale sections

## Outputs

- `review`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
