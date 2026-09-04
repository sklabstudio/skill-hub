# Frontend Debug

Diagnose UI bugs across state, rendering and network.

## Inputs

- `repro`

## Workflow

1. Reproduce in clean state
2. Inspect state and network
3. Fix with visual check

## Outputs

- `diagnosis`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
