# Accessibility Review

WCAG-oriented accessibility checklist for UI changes.

## Inputs

- `ui-diff`

## Workflow

1. Keyboard and focus order
2. Contrast and labels
3. Reduced-motion and semantics

## Outputs

- `checklist`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
