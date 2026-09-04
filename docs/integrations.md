# Integrations

- Agent Adapters: capability matrix read (never modified); `show --agents` and resolver filter by agent caps; no inference calls.
- Orchestrator: `resolve_skills()` returns skill_id/version/fingerprint/trust/risk/permissions/entry/task_score/warnings; execution stays in Orchestrator.
- Coding Lab: prompts/workflows/playbooks/checklists referenced read-only with `source: coding-lab` provenance.
- RepoContext: consumes repo metadata passed by Orchestrator; never calls it directly.
- ReproBox: high-risk/executable skills expose execution-plan metadata; no community code executed to prove it.
- SkillMiner (future): registry carries generated_by/evidence_refs/validation_status.
