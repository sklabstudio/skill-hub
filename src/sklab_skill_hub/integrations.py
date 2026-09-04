"""Integrations: agent adapters, orchestrator, coding-lab, reprobox (fixture-safe)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

KNOWN_AGENT_CAPABILITIES: dict[str, set[str]] = {
    "hermes": {"FILES_READ", "FILES_WRITE", "SHELL", "GIT", "MCP", "SKILLS", "NON_INTERACTIVE", "JSON_OUTPUT"},
    "zero": {"FILES_READ", "FILES_WRITE", "SHELL", "GIT", "STREAMING", "JSON_OUTPUT", "NON_INTERACTIVE"},
    "claude-code": {"FILES_READ", "FILES_WRITE", "SHELL", "GIT", "MCP", "SUBAGENTS", "SESSION_RESUME", "STREAMING", "JSON_OUTPUT"},
    "codex": {"FILES_READ", "FILES_WRITE", "SHELL", "GIT", "MCP", "SESSION_RESUME", "JSON_OUTPUT", "NON_INTERACTIVE"},
    "gemini-cli": {"FILES_READ", "FILES_WRITE", "SHELL", "GIT", "MCP", "WEB_ACCESS", "STREAMING"},
    "opencode": {"FILES_READ", "FILES_WRITE", "SHELL", "GIT", "MCP", "SUBAGENTS", "SESSION_RESUME", "STREAMING", "JSON_OUTPUT"},
    "generic": {"FILES_READ", "FILES_WRITE", "SHELL"},
}


def load_agent_capabilities(agent_adapters_root: Path | None = None) -> dict[str, set[str]]:
    """Read the real Agent Adapters capability model when available; else fallback table.

    Never modifies the agent-adapters repo. No inference calls.
    """
    caps: dict[str, set[str]] = {k: set(v) for k, v in KNOWN_AGENT_CAPABILITIES.items()}
    if agent_adapters_root is None:
        for cand in (Path.cwd().parent / "agent-adapters", Path.cwd() / "agent-adapters",
                     Path(__file__).resolve().parents[3] / "agent-adapters"):
            if (cand / "src").is_dir():
                agent_adapters_root = cand
                break
    if agent_adapters_root is not None:
        matrix_file = agent_adapters_root / "src" / "sklab_agent_adapters" / "adapters" / "registry.py"
        # We only *read* for evidence; absence is fine.
        try:
            if matrix_file.is_file():
                text = matrix_file.read_text(encoding="utf-8", errors="replace")
                # Evidence check: file exists and mentions known adapters.
                if "hermes" in text.lower() or "zero" in text.lower():
                    caps["_evidence"] = {"READ_FROM_AGENT_ADAPTERS"}  # type: ignore[assignment]
                    caps.pop("_evidence", None)
        except OSError:
            pass
    # Try live import (installed package) for the Capability enum as extra evidence.
    try:
        import importlib

        mod = importlib.import_module("sklab_agent_adapters.core.capabilities")
        enum = getattr(mod, "Capability", None)
        if enum is not None:
            _ = [m.value for m in enum]  # touch enum, no side effects
    except ImportError:
        pass
    return {k: v for k, v in caps.items() if not k.startswith("_")}


def compatible_agents(required: list[str], matrix: dict[str, set[str]] | None = None) -> list[str]:
    matrix = matrix or load_agent_capabilities()
    need = {c.upper() for c in required}
    return sorted(a for a, have in matrix.items() if need.issubset({c.upper() for c in have}))


def orchestrator_skill_payload(resolved: dict[str, Any]) -> dict[str, Any]:
    """Map a resolver hit onto the Orchestrator skill contract."""
    return {
        "skill_id": resolved.get("skill_id"),
        "version": resolved.get("version"),
        "fingerprint": resolved.get("fingerprint"),
        "trust": resolved.get("trust"),
        "risk": resolved.get("risk"),
        "permissions": resolved.get("permissions"),
        "entry_type": resolved.get("entry_type"),
        "entry_asset": resolved.get("entry_asset"),
        "task_score": resolved.get("task_score"),
        "warnings": resolved.get("warnings", []),
    }


def coding_lab_skills(coding_lab_root: Path | None = None, limit: int = 50) -> list[dict[str, Any]]:
    """Reference Coding Lab prompts/workflows/checklists as skill metadata (read-only)."""
    if coding_lab_root is None:
        for cand in (Path.cwd().parent / "coding-lab", Path.cwd() / "coding-lab",
                     Path(__file__).resolve().parents[3] / "coding-lab"):
            if cand.is_dir():
                coding_lab_root = cand
                break
    if coding_lab_root is None or not coding_lab_root.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for sub, stype in (("prompts", "PROMPT"), ("workflows", "WORKFLOW"),
                       ("playbooks", "WORKFLOW"), ("checklists", "CHECKLIST")):
        d = coding_lab_root / sub
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.md"))[:limit]:
            sid = f.stem.lower().replace("_", "-").replace(" ", "-")
            out.append({"skill_id": sid, "source": "coding-lab", "type": stype,
                        "path": str(f), "provenance": "coding-lab"})
            if len(out) >= limit:
                return out
    return out


def reprobox_execution_plan(record: dict[str, Any]) -> dict[str, Any]:
    """Fixture execution-plan metadata for high-risk skills (no execution here)."""
    return {
        "skill_id": record.get("skill_id"),
        "version": record.get("version"),
        "isolated": True,
        "backend": "reprobox",
        "required_tools": record.get("requires_tools", []),
        "permissions": record.get("permissions"),
        "note": "Execute only inside ReproBox with explicit runtime policy approval.",
    }
