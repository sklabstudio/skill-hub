# Security

- Imported skills are untrusted until validated.
- Static analysis is heuristic evidence, never proof of safety.
- No code executes during import/install (no hooks, postinstall, install scripts, `curl|bash`).
- Executable skills are high-risk by default; future runtime = ReproBox + explicit policy.
- No secrets stored; inline secret values rejected.
- FULL mode keeps all hard gates: cookie theft, credential harvesting, MFA/quota bypass, destructive fs, force-push defaults, root destruction, persistence, exfiltration, gate-disabling.
- Updates can change risk: permission diff -> SECURITY_REVIEW_REQUIRED.
- Path safety: reject `..`, absolute writes, symlink escapes, archive traversal, ADS tricks.
- Git: clone into temp, `GIT_CONFIG_NOSYSTEM=1`, no hooks, inspect-only, pin SHA.
