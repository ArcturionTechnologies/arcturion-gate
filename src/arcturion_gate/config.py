"""Local configuration: data paths, Keychain service, browser bridge identity.

Everything is resolved at call time so tests and alternate installs can point
the whole system somewhere else with environment variables:

- ``ARCTURION_GATE_HOME``      data directory (default: ``~/Library/Application Support/arcturion-gate``)
- ``ARCTURION_GATE_KEYCHAIN_SERVICE``  Keychain service name for the root key
- ``ARCTURION_GATE_EXTENSION_ID``      Chrome extension ID allowed to call the native host
- ``ARCTURION_GATE_NATIVE_HOST``       native messaging host name

Values not set in the environment are read from ``<home>/config.json`` when it
exists. Nothing here is secret.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

DEFAULT_KEYCHAIN_SERVICE = "com.arcturiontech.gate.root"
DEFAULT_NATIVE_HOST = "com.arcturiontech.gate"
EXTENSION_ID_PATTERN = re.compile(r"^[a-p]{32}$")
NATIVE_HOST_PATTERN = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)*$")


def home() -> Path:
    override = os.environ.get("ARCTURION_GATE_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / "Library" / "Application Support" / "arcturion-gate"


def vault_root() -> Path:
    return home() / "vault"


def bridge_root() -> Path:
    return home() / "bridge"


def _file_settings() -> dict:
    path = home() / "config.json"
    if path.is_symlink() or not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def setting(name: str, env: str, default: str | None = None) -> str | None:
    value = os.environ.get(env)
    if value:
        return value
    value = _file_settings().get(name)
    return value if isinstance(value, str) and value else default


def keychain_service() -> str:
    return setting("keychain_service", "ARCTURION_GATE_KEYCHAIN_SERVICE", DEFAULT_KEYCHAIN_SERVICE)


def catalog_dir() -> Path | None:
    value = setting("catalog_dir", "ARCTURION_GATE_CATALOG")
    return Path(value).expanduser() if value else None


def native_host() -> str:
    value = setting("native_host", "ARCTURION_GATE_NATIVE_HOST", DEFAULT_NATIVE_HOST)
    if not NATIVE_HOST_PATTERN.match(value or ""):
        raise ValueError("native host name must be lowercase dotted identifiers")
    return value


def extension_id() -> str | None:
    value = setting("extension_id", "ARCTURION_GATE_EXTENSION_ID")
    if value is None:
        return None
    if not EXTENSION_ID_PATTERN.match(value):
        raise ValueError("extension ID must be 32 characters a-p")
    return value


def chrome_profile_directory() -> str | None:
    value = setting("chrome_profile_directory", "ARCTURION_GATE_CHROME_PROFILE")
    if value is not None and ("/" in value or value.startswith(".")):
        raise ValueError("invalid Chrome profile directory")
    return value


def write_settings(updates: dict) -> Path:
    """Merge non-secret settings into ``config.json`` (0600, owner-only directory)."""
    root = home()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = root / "config.json"
    if path.is_symlink():
        raise ValueError("config.json must not be a symlink")
    current = _file_settings()
    current.update({k: v for k, v in updates.items() if v is not None})
    staging = path.with_suffix(".staging")
    staging.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
    os.chmod(staging, 0o600)
    os.replace(staging, path)
    return path
