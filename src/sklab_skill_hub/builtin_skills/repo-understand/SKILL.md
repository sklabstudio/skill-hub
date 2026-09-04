# Repository Understand

Survey repository layout, entry points, dependencies and tests before changing code.

## Inputs

- `repository`

## Workflow

1. Map top-level layout and README
2. Identify entry points, configs, test commands
3. Summarize risks and unknowns

## Outputs

- `map`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
