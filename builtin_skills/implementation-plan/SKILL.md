# Implementation Plan

Produce a staged implementation plan with verification.

## Inputs

- `task`

## Workflow

1. Break into stages
2. Define verification per stage
3. List risks and rollbacks

## Outputs

- `plan`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
