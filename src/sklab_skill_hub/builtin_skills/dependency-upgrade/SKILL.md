# Dependency Upgrade

Upgrade one dependency safely with changelog and test evidence.

## Inputs

- `package`

## Workflow

1. Check changelog and breaking changes
2. Upgrade in isolation
3. Run suite and record results

## Outputs

- `upgrade-report`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
