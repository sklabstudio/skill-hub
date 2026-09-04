# Imports

`sklab-skills inspect <source>` is read-only. `import` resolves, copies to
project-owned temp, rejects traversal/symlinks, finds manifests, normalizes,
records license/provenance, scans, classifies trust, installs if policy allows.

- GitHub: pin exact commit SHA; updates explicit.
- No private-repo fetching without configured access; no credential scraping.
- HTTP archives disabled in v0.1.0; agent-native dirs read, never mutated.
- MCP sources register MCP_REFERENCE metadata (server/tools/perms) without secrets or autostart.
