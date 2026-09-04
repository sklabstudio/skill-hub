# GitHub Actions Review

Review a workflow for triggers, pins and secret handling.

## Inputs

- `workflow`

## Workflow

1. Check trigger scope
2. Verify action pins
3. Review secret use

## Outputs

- `review`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
