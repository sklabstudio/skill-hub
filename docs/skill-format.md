# Skill format

Directory with `skill.yaml` + entry asset (default `SKILL.md`).

```yaml
schema_version: 1
id: repo-security-audit
name: Repository Security Audit
version: 1.0.0
description: Defensive security review workflow.
type: workflow
category: cyber
tags: [security, review]
trust: {source: community}
compatibility:
  sklab: ">=0.1"
  agents: [{capability: files_read}]
permissions:
  filesystem: {read: true, write: false}
  shell: false
  network: false
  git: {read: true, write: false}
  docker: false
  secrets: false
inputs: [repository]
outputs: [report]
entry: {file: SKILL.md}
provenance:
  source_type: github
  source_url: https://github.com/example/repo
  source_ref: "<sha>"
  license: MIT
requires: {tools: [git]}
depends_on: []
```

Rules: id `[a-z0-9][a-z0-9-]{2,63}` immutable; semver version;
strict Pydantic (unknown critical fields fail); nested
`filesystem:`/`git:` shorthand accepted; `requires.tools` or
`requires: [..]` shorthand accepted; `compatibility.agents` accepts
strings or `{capability:}` maps; entry may be a filename string.
