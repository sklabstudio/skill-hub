# Permissions

Flat matrix (deny by default): filesystem_read, filesystem_write, shell,
network, git_read, git_write, docker, mcp, secrets, provider_access,
web_access. Optional scopes: allowed_paths, allowed_hosts,
allowed_commands, allowed_mcp_servers, allowed_secret_refs.

Manifest shorthand (`filesystem: {read, write}`, `git: {read, write}`,
`secrets: {references: [...]}`) normalizes to flat fields.
`secrets` means "requires access", resolved only by Provider Connections
at execution — Skill Hub never stores values and rejects inline secrets.
