# Next.js Debug

Diagnose Next.js App Router, data-fetching and build issues.

## Inputs

- `traceback`

## Workflow

1. Identify server vs client fault
2. Check fetch and cache semantics
3. Verify build output

## Outputs

- `diagnosis`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
