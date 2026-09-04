# Changelog Review

Review changelog accuracy against commits.

## Inputs

- `changelog`

## Workflow

1. Compare entries to commits
2. Check versions and dates
3. Flag missing breaking notes

## Outputs

- `review`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
