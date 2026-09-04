# Test Failure Debug

Diagnose a failing test from trusted output without unrelated changes.

## Inputs

- `failure-output`

## Workflow

1. Read exact failure output
2. Isolate failing unit
3. Propose minimal fix

## Outputs

- `diagnosis`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
