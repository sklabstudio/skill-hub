# Demo

```bash
pip install -e ".[dev]"
sklab-skills list
sklab-skills show bug-fix
sklab-skills search test
sklab-skills inspect ./builtin_skills/bug-fix
sklab-skills import ./builtin_skills/bug-fix
sklab-skills enable bug-fix
sklab-skills resolve --task "Fix failing FastAPI test" --category testing --json
sklab-skills audit bug-fix
sklab-skills doctor
sklab-skills auto status
```

Dogfood: "Fix failing FastAPI test" resolves repo-understand,
fastapi-debug, test-failure-debug, code-review deterministically.
