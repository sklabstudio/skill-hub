# Auto-install

Modes: OFF, SAFE (default), SMART, FULL. FULL is not "disable safety".

- OFF: never auto-install.
- SAFE: only BUILTIN/VERIFIED declarative low-risk; no community executables, dangerous perms, secrets, post-install network.
- SMART: task-aware; suggests COMMUNITY but quarantines elevated/executable before enable; may task-enable safe declarative skills.
- FULL: broader discovery; BLOCKED/QUARANTINED never execute; dangerous perms still need explicit approval.

Installed != enabled: INSTALLED / ENABLED_GLOBAL / ENABLED_FOR_TASK /
DISABLED / QUARANTINED. Auto-install never implies permanent global enable.

```yaml
auto_install: {mode: safe, allow_trust: [builtin, verified], max_risk: low,
  permanent_enable: false, task_scoped_enable: true}
```
