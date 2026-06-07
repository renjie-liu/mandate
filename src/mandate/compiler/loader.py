"""YAML loading + kind dispatch for the three manifest files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..model import AgentDeployment, AgentImage, OrgPolicy

SUPPORTED_API_VERSIONS = {"mandate/v1"}


def load_manifest(path: str | Path) -> dict[str, Any]:
    """Read a YAML manifest and sanity-check its ``apiVersion``."""
    raw = yaml.safe_load(Path(path).read_text())
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: manifest must be a YAML mapping")
    api = raw.get("apiVersion")
    if api not in SUPPORTED_API_VERSIONS:
        raise ValueError(
            f"{path}: unsupported apiVersion {api!r}; "
            f"expected one of {', '.join(sorted(SUPPORTED_API_VERSIONS))}"
        )
    return raw


def load_image(path: str | Path) -> AgentImage:
    return AgentImage.from_dict(load_manifest(path))


def load_deployment(path: str | Path, agent: str | None = None) -> AgentDeployment:
    return AgentDeployment.from_dict(load_manifest(path), agent=agent)


def load_org_policy(path: str | Path | None) -> OrgPolicy:
    """Load an org policy, or return an empty one when ``path`` is ``None``.

    P0 treats org policy as optional but first-class: passing ``None`` yields an empty
    policy that still participates in the meet.
    """
    if path is None:
        return OrgPolicy.empty()
    return OrgPolicy.from_dict(load_manifest(path))
