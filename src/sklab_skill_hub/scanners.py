"""Conservative static security + prompt-injection scanners. Heuristics with evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from sklab_skill_hub.models import SkillManifest


@dataclass
class Finding:
    id: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    message: str
    evidence: str = ""
    path: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "severity": self.severity,
            "message": self.message,
            "evidence": self.evidence[:500],
            "path": self.path,
        }


# (id, regex, severity, message)
STATIC_RULES: list[tuple[str, str, str, str]] = [
    ("cred-ssh", r"\.ssh[\\/](id_rsa|id_ed25519|known_hosts)", "HIGH", "References SSH private key material"),
    ("cred-aws", r"\.aws[\\/]credentials|AKIA[0-9A-Z]{16}", "HIGH", "Possible AWS credential reference"),
    ("cred-cloud", r"gcp|application_default_credentials|azure[._-]?profile", "MEDIUM", "Possible cloud credential path"),
    ("cookie-theft", r"Cookies|Cookie\s*DB|Login\s*Data|Local\s*Storage|browser.*(cookie|password|Login)", "CRITICAL", "Possible browser cookie/credential store access"),
    ("token-collect", r"(ghp_[A-Za-z0-9]{20,}|github_pat_|xox[bpas]-|sk-ant-|sk-proj-)", "CRITICAL", "Embedded token-like secret pattern"),
    ("destructive-rm", r"rm\s+-rf\s+(/|~|\$HOME|\*)", "CRITICAL", "Destructive recursive delete pattern"),
    ("destructive-ps", r"Remove-Item.*-Recurse.*-Force", "HIGH", "Destructive PowerShell recursion"),
    ("format-drive", r"(mkfs|:?\(\)\s*\{\s*:|Format-Volume|diskpart)", "CRITICAL", "Disk destructive operation pattern"),
    ("curl-pipe-shell", r"(curl|wget)[^\n|]*\|\s*(bash|sh|powershell|pwsh)", "HIGH", "Network fetch piped directly to shell"),
    ("b64-exec", r"(base64\s+(-d|--decode)|FromBase64String)[^\n]*(bash|sh|powershell|Invoke-Expression|iex)", "HIGH", "Base64-obfuscated execution"),
    ("exfil", r"(exfil|send.*(secret|token|key).*(http|POST|PUT)|POST.*\$\{?(SECRET|TOKEN|KEY))", "CRITICAL", "Possible secret exfiltration pattern"),
    ("docker-sock", r"(/var/run/docker\.sock|docker\.sock)", "HIGH", "Docker socket access"),
    ("docker-priv", r"--privileged|--pid\s*=\s*host|--network\s+host", "HIGH", "Privileged container flags"),
    ("history-collect", r"\.(bash_history|zsh_history)|Get-History|history\.db", "MEDIUM", "Shell history collection"),
    ("mfa-bypass", r"(mfa[\s_-]?bypass|bypass[\s_-]?(mfa|2fa|otp))", "CRITICAL", "MFA bypass request"),
    ("quota-bypass", r"(quota[\s_-]?bypass|bypass.*quota|rate[\s_-]?limit[\s_-]?bypass)", "HIGH", "Provider quota bypass attempt"),
    ("persistence", r"(HKLM.*Run|LaunchAgents|systemd.*\[Install\]|cron\.d|ScheduledTasks.*Register)", "HIGH", "Persistence outside declared scope"),
    ("force-push", r"git\s+push\s+(-f|--force)(?!\s+--dry-run)", "MEDIUM", "Force-push by default"),
    ("disable-safety", r"(disable\s+(safety|guardrail|sandbox|policy)|--no-verify\s*$|SKIP_SAFETY)", "HIGH", "Attempts to disable safety gates"),
    ("chmod-777", r"chmod\s+(-R\s+)?777", "MEDIUM", "Overly broad permission grant"),
    ("secret-path-env", r"(\.env|secrets?\.ya?ml|\.npmrc|\.pypirc)", "MEDIUM", "References secret-bearing files"),
]

INJECTION_RULES: list[tuple[str, str, str, str]] = [
    ("inj-ignore", r"ignore\s+(all\s+)?(previous|prior|system|above)\s+instructions", "HIGH", "Attempts to override system instructions"),
    ("inj-reveal", r"(reveal|disclose|print|dump).{0,40}(secret|api[\s_-]?key|password|token|credential)", "CRITICAL", "Requests secret disclosure"),
    ("inj-disable", r"(disable|turn\s+off|bypass).{0,40}(safety|policy|guardrail|content\s+filter)", "HIGH", "Requests safety disablement"),
    ("inj-upload", r"(upload|send|exfiltrate|transmit).{0,40}(repositor|entire\s+code|all\s+files|\.git)", "HIGH", "Requests bulk repository upload"),
    ("inj-bypass-pol", r"bypass.{0,30}polic", "HIGH", "Requests policy bypass"),
    ("inj-jailbreak", r"(jailbreak|DAN\s+mode|do\s+anything\s+now)", "MEDIUM", "Jailbreak phrasing"),
]

# Benign-doc guard: if the match sits in a sentence about defense/review, downgrade.
BENIGN_CONTEXT_RE = re.compile(r"(defen[cs]e|review|detect|prevent|checklist|audit|do not|never|avoid|ensure no)", re.I)

INLINE_SECRET_RES = [
    ("aws-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github-token", re.compile(r"(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("private-key-block", re.compile(r"-----BEGIN (RSA )?PRIVATE KEY-----")),
    ("generic-secret-assign", re.compile(r"(?i)(api[_-]?key|secret|passwd|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}")),
]

HARD_BLOCK_IDS = {
    "cookie-theft", "token-collect", "destructive-rm", "format-drive",
    "mfa-bypass", "inj-reveal", "exfil",
}


def _context_is_benign(text: str, start: int, end: int, window: int = 120) -> bool:
    snippet = text[max(0, start - window): end + window]
    return bool(BENIGN_CONTEXT_RE.search(snippet))


def scan_text(content: str, rel_path: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for fid, pattern, sev, msg in STATIC_RULES:
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error:
            continue
        for m in rx.finditer(content):
            sev_eff = sev
            if fid in ("disable-safety", "force-push", "exfil") and _context_is_benign(content, m.start(), m.end()):
                sev_eff = "LOW" if sev != "CRITICAL" else "MEDIUM"
            findings.append(Finding(
                id=fid, severity=sev_eff,
                message=msg, evidence=m.group(0).strip()[:300], path=rel_path,
            ))
    for fid, pattern, sev, msg in INJECTION_RULES:
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error:
            continue
        for m in rx.finditer(content):
            sev_eff = sev
            if _context_is_benign(content, m.start(), m.end()):
                sev_eff = "LOW"
            findings.append(Finding(
                id=fid, severity=sev_eff,
                message=f"Prompt-injection heuristic: {msg}",
                evidence=m.group(0).strip()[:300], path=rel_path,
            ))
    return findings


def scan_skill_dir(skill_dir: Path, manifest: SkillManifest | None = None) -> list[Finding]:
    findings: list[Finding] = []
    if not skill_dir.is_dir():
        return findings
    for path in sorted(skill_dir.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        if path.suffix.lower() not in {".md", ".yaml", ".yml", ".txt", ".json", ".toml", ".sh", ".ps1", ".py", ".js", ".ts"}:
            continue
        if path.stat().st_size > 512_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(skill_dir).as_posix()
        findings.extend(scan_text(text, rel))
    if manifest is not None:
        p = manifest.permissions
        if p.docker:
            findings.append(Finding(id="perm-docker", severity="MEDIUM", message="Skill requests Docker access", path="skill.yaml"))
        if p.secrets and (p.network or p.shell):
            findings.append(Finding(id="perm-secret-net", severity="CRITICAL", message="Skill requests secrets + network/shell", path="skill.yaml"))
        if p.network and p.shell:
            findings.append(Finding(id="perm-shell-net", severity="HIGH", message="Skill requests shell + network", path="skill.yaml"))
    return findings


def has_hard_block(findings: list[Finding]) -> bool:
    for f in findings:
        if f.id in HARD_BLOCK_IDS and f.severity in ("HIGH", "CRITICAL"):
            return True
    return False


def detect_inline_secrets(obj: object, path: str = "manifest") -> list[Finding]:
    findings: list[Finding] = []
    if isinstance(obj, dict):
        for k, v in obj.items():  # type: ignore[union-attr]
            findings.extend(detect_inline_secrets(v, f"{path}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):  # type: ignore[union-attr]
            findings.extend(detect_inline_secrets(v, f"{path}[{i}]"))
    elif isinstance(obj, str):
        for fid, rx in INLINE_SECRET_RES:
            if rx.search(obj):
                findings.append(Finding(id=f"secret-{fid}", severity="CRITICAL",
                                        message="Possible inline secret value — secrets must be references, never values",
                                        evidence=obj[:120], path=path))
    return findings


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts
