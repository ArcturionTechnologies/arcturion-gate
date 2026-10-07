"""Noninteractive macOS login Keychain wrapper for the root key.

The root key never appears in argv: ``security add-generic-password -w`` with
no value reads the password from stdin.
"""

from __future__ import annotations

import base64
import getpass
import subprocess

from . import config
from .errors import GateError

SECURITY = "/usr/bin/security"


def _run(args: list[str], *, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise GateError("KEYCHAIN_UNAVAILABLE", f"Login Keychain unavailable: {type(exc).__name__}", retryable=True) from exc


def get_root_key() -> bytes:
    result = _run([SECURITY, "find-generic-password", "-a", getpass.getuser(), "-s", config.keychain_service(), "-w"])
    if result.returncode != 0 or not result.stdout.strip():
        raise GateError("SEALED", "ArcturionGate is sealed")
    try:
        return base64.urlsafe_b64decode(result.stdout.strip().encode("ascii"))
    except Exception as exc:
        raise GateError("INTEGRITY_FAILURE", "Keychain root key is malformed") from exc


def put_root_key(root_key: bytes) -> None:
    encoded = base64.urlsafe_b64encode(root_key).decode("ascii")
    result = _run(
        [SECURITY, "add-generic-password", "-U", "-a", getpass.getuser(), "-s", config.keychain_service(), "-w"],
        stdin=encoded + "\n" + encoded + "\n",
    )
    if result.returncode != 0:
        raise GateError("KEYCHAIN_UNAVAILABLE", "Could not store the root key", retryable=True)


def delete_root_key() -> None:
    result = _run([SECURITY, "delete-generic-password", "-a", getpass.getuser(), "-s", config.keychain_service()])
    if result.returncode not in (0, 44):
        raise GateError("KEYCHAIN_UNAVAILABLE", "Could not remove the root key", retryable=True)
