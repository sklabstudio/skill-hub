# Trust

Levels: BUILTIN, VERIFIED, COMMUNITY, LOCAL, QUARANTINED, BLOCKED.

- BUILTIN: shipped by SKLab, versioned in repo.
- VERIFIED: passed explicit review; provenance recorded; NOT absolute safety.
- COMMUNITY: external, restricted by default.
- LOCAL: user-created; policy-dependent.
- QUARANTINED: suspicious/incompatible/pending; cannot enable or resolve.
- BLOCKED: known unsafe; never auto-installs.

Stars/popularity are never trust. Trust decisions persist per
(source, skill fingerprint); a fingerprint change re-opens review.
