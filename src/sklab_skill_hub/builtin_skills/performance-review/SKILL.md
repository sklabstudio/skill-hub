# Performance Review

Checklist for hotspot, complexity and regression review.

## Inputs

- `diff`

## Workflow

1. Check algorithmic complexity
2. Look for N+1 and hot loops
3. Suggest measured follow-ups

## Outputs

- `checklist`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
