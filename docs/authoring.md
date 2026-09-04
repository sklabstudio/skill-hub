# Authoring

1. Pick stable id `[a-z0-9][a-z0-9-]{2,63}` (no provider/model names).
2. Define one purpose, explicit inputs/outputs.
3. Prefer declarative (prompt/workflow/checklist/knowledge) over executable.
4. Declare permissions honestly (deny by default); no secret values.
5. Declare `requires.tools` and `depends_on` (no cycles).
6. Add compatibility (sklab range + agent capabilities).
7. Document provenance/license; never relicense third-party content.
8. Add deterministic examples; run `sklab-skills audit <dir>`; record fingerprint.
