# Backend Debug

General backend diagnosis across logs, config and data.

## Inputs

- `symptom`

## Workflow

1. Gather logs and config
2. Bisect recent changes
3. Verify fix in staging order

## Outputs

- `diagnosis`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
