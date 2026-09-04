"""Shared fixtures: isolated data dir + registry + config."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from sklab_skill_hub.config import HubConfig
from sklab_skill_hub.registry import Registry
from sklab_skill_hub.store import ensure_layout


@pytest.fixture(scope="session", autouse=True)
def _ensure_git_fixture() -> None:
    """Rebuild the git-source fixture repo on demand (its .git is git-ignored)."""
    repo = Path(__file__).parent / "fixtures" / "git-source-repo"
    if (repo / ".git").is_dir() or not (repo / "skill.yaml").is_file():
        return
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1")
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True, env=env)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True, env=env)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "init"],
                   cwd=repo, check=True, capture_output=True, env=env)


@pytest.fixture()
def data_dir(tmp_path: Path) -> Path:
    dd = tmp_path / "skills"
    ensure_layout(dd)
    return dd


@pytest.fixture()
def registry(data_dir: Path) -> Registry:
    return Registry(data_dir)


@pytest.fixture()
def config() -> HubConfig:
    return HubConfig()


@pytest.fixture()
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"
