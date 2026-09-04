# Version Bump Review

Review a version bump for semver correctness.

## Inputs

- `diff`

## Workflow

1. Classify change type
2. Verify semver increment
3. Check dependent updates

## Outputs

- `verdict`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
