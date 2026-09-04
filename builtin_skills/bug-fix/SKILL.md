# Bug Fix

Reproduce a reported bug, apply a minimal fix, and add regression coverage.

## Inputs

- `report`

## Workflow

1. Reproduce with minimal steps
2. Diagnose causal chain from evidence
3. Minimal patch plus regression test

## Outputs

- `fix`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
