"""Canonical distribution and Skill contract for agentctl consumers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from . import __version__


CANONICAL_REPOSITORY = "https://github.com/Pvxlabs/agentctl"
CANONICAL_BRANCH = "main"
CANONICAL_RELEASE = f"v{__version__}"
TRUSTED_ACCESS_ONBOARDING_VERSION = "1.1"
SKILL_VERSION = "1.1.0"
SKILL_MIN_AGENTCTL_VERSION = __version__
SKILL_PATH = "skills/agentctl/SKILL.md"
SKILL_URL = f"{CANONICAL_REPOSITORY}/raw/{CANONICAL_RELEASE}/{SKILL_PATH}"

_VERSION_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:[-+].*)?$")


def parse_version(value: str) -> tuple[int, int, int]:
    match = _VERSION_RE.fullmatch(value.strip().lstrip("v"))
    if not match:
        raise ValueError(f"invalid agentctl version: {value!r}")
    return tuple(int(part or 0) for part in match.groups())  # type: ignore[return-value]


def is_compatible(installed: str, required: str = SKILL_MIN_AGENTCTL_VERSION) -> bool:
    return parse_version(installed) >= parse_version(required)


def version_contract() -> dict[str, str]:
    return {
        "installed_version": __version__,
        "canonical_repository": CANONICAL_REPOSITORY,
        "canonical_branch": CANONICAL_BRANCH,
        "canonical_release": CANONICAL_RELEASE,
        "package_version": __version__,
        "agentctl_min_version": SKILL_MIN_AGENTCTL_VERSION,
        "skill_version": SKILL_VERSION,
        "trusted_access_onboarding_version": TRUSTED_ACCESS_ONBOARDING_VERSION,
    }


def _codex_home() -> Path:
    return Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")).expanduser().resolve()


def skill_install_dir() -> Path:
    return _codex_home() / "skills" / "agentctl"


def _safe_skill_dir(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing to install into symlinked Skill path: {path}")
    if path.exists() and not path.is_dir():
        raise ValueError(f"Skill path is not a directory: {path}")


def _fetch_skill() -> bytes:
    request = Request(SKILL_URL, headers={"User-Agent": f"agentctl/{__version__}"})
    try:
        with urlopen(request, timeout=15) as response:
            content = response.read()
    except (HTTPError, URLError, OSError) as exc:
        raise RuntimeError(f"could not download canonical Skill from {SKILL_URL}: {exc}") from exc
    if not content.startswith(b"---\n") or b"name: agentctl\n" not in content:
        raise RuntimeError("downloaded Skill does not match the agentctl Skill contract")
    return content


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(content)
        handle.flush()
        os.fchmod(handle.fileno(), mode & 0o777)
    temporary.replace(path)


def install_skill(*, update: bool = False) -> dict[str, Any]:
    destination = skill_install_dir()
    _safe_skill_dir(destination)
    skill_path = destination / "SKILL.md"
    metadata_path = destination / "agentctl-skill.json"
    existing = read_skill_status()
    if existing.get("installed") and not update:
        raise RuntimeError("agentctl Skill is already installed; use --update to refresh it")
    content = _fetch_skill()
    digest = hashlib.sha256(content).hexdigest()
    if existing.get("installed") and existing.get("sha256") == digest:
        return {**existing, "updated": False, "source": SKILL_URL}
    metadata = {
        **version_contract(),
        "source": SKILL_URL,
        "sha256": digest,
    }
    _atomic_write(skill_path, content)
    _atomic_write(metadata_path, (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return {"installed": True, "updated": bool(existing.get("installed")), "path": str(destination), **metadata}


def read_skill_status() -> dict[str, Any]:
    destination = skill_install_dir()
    skill_path = destination / "SKILL.md"
    metadata_path = destination / "agentctl-skill.json"
    if not skill_path.is_file() or not metadata_path.is_file():
        return {"installed": False, "path": str(destination), **version_contract()}
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        digest = hashlib.sha256(skill_path.read_bytes()).hexdigest()
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {"installed": False, "path": str(destination), "status": "INVALID", **version_contract()}
    compatible = is_compatible(__version__, str(metadata.get("agentctl_min_version", "0.0.0")))
    return {
        "installed": True,
        "path": str(destination),
        "sha256": digest,
        "content_matches_metadata": digest == metadata.get("sha256"),
        "compatible": compatible,
        **{key: metadata.get(key) for key in version_contract()},
        "source": metadata.get("source", SKILL_URL),
    }
