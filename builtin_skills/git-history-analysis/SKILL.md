# Git History Analysis

Analyze git history for risk, churn and ownership signals.

## Inputs

- `repository`

## Workflow

1. Summarize recent commits
2. Flag churn and revert clusters
3. Note ownership gaps

## Outputs

- `history-report`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
