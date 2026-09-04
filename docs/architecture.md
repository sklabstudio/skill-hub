# Architecture

```
sources (builtin / local / git / github / agent-native / mcp-metadata)
  -> importer (resolve, clone w/o hooks, inspect, NO EXEC)
  -> scanners (static + injection + secrets) + pathsafety
  -> risk + trust classification
  -> installer (policy-gated install / quarantine)
  -> registry (atomic JSON: records, enable state, trust decisions)
  -> resolver (task-aware, deterministic)
  -> service API (Web UI DTOs) / Orchestrator contract / CLI
```

- Agent-agnostic, model-agnostic, provider-agnostic, local-first.
- Skill Hub never executes skills. Orchestrator owns execution.
- Deterministic where practical: stable ordering, sorted fingerprints, scored resolution.
- Web-UI ready (service.py), Orchestrator ready (contract payloads), ReproBox ready (execution plans).
