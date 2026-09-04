# Compose Review

Review docker-compose for correctness and safety.

## Inputs

- `compose-file`

## Workflow

1. Check services and networks
2. Review volumes and secrets refs
3. Flag privileged flags

## Outputs

- `review`

## Guardrails

- Minimal diff; no unrelated refactors.
- Never access secrets; declare permission needs explicitly.
- Record evidence (commands, outputs) for verification.
