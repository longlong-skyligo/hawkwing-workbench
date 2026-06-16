from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


CONFIG_DIR = Path("/app/config")
if not CONFIG_DIR.exists():
    CONFIG_DIR = Path("config")


def _load_yaml(name: str) -> dict[str, Any]:
    path = CONFIG_DIR / name
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


@lru_cache
def get_tool_catalog() -> dict[str, Any]:
    return _load_yaml("tool-catalog.yaml")


@lru_cache
def get_runner_profiles() -> dict[str, Any]:
    return _load_yaml("runner-profiles.yaml")


@lru_cache
def get_skill_registry() -> dict[str, Any]:
    return _load_yaml("skill-registry.yaml")


@lru_cache
def get_dynamic_runner_policy() -> dict[str, Any]:
    return _load_yaml("dynamic-runner-policy.yaml")


def find_runner_profile(profile_name: str) -> dict[str, Any]:
    return get_runner_profiles().get("runner_profiles", {}).get(profile_name, {})


def find_tool(tool_name: str) -> dict[str, Any]:
    return get_tool_catalog().get("tools", {}).get(tool_name, {})

