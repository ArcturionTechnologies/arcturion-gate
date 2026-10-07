"""``gate-bridge``: set up the Chrome bridge on this machine.

Subcommands
-----------
extension-key  Create (or reuse) an RSA key for the extension and print the
               manifest ``key`` and the extension ID it produces. The private
               key stays wherever you put it; never commit it.
install-native Write config, the native host launcher, and Chrome's native
               messaging manifest that allows exactly one extension ID.
enroll         Create a one-time enrollment nonce and open the extension's
               enrollment page in Chrome (or print the URL).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

from .. import config
from .state import State

CHROME_HOSTS_DIR = Path.home() / "Library" / "Application Support" / "Google" / "Chrome" / "NativeMessagingHosts"


def extension_id_from_public_der(der: bytes) -> str:
    """Chrome's ID: first 16 bytes of SHA-256(SubjectPublicKeyInfo DER), hex digits 0-f mapped to a-p."""
    return "".join(chr(ord("a") + int(c, 16)) for c in hashlib.sha256(der).hexdigest()[:32])


def extension_key(private_key_path: Path) -> dict:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    path = private_key_path.expanduser()
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"manifest_key": base64.b64encode(der).decode("ascii"), "extension_id": extension_id_from_public_der(der),
            "private_key": str(path)}


def native_manifest(host_name: str, launcher: Path, extension_id: str) -> dict:
    return {"name": host_name, "description": "ArcturionGate one-shot credential bridge",
            "path": str(launcher), "type": "stdio",
            "allowed_origins": ["chrome-extension://" + extension_id + "/"]}


def install_native(extension_id: str, host_name: str, manifest_dir: Path, chrome_profile: str | None) -> dict:
    if not config.EXTENSION_ID_PATTERN.match(extension_id):
        raise SystemExit("extension ID must be 32 characters a-p")
    if not config.NATIVE_HOST_PATTERN.match(host_name):
        raise SystemExit("host name must be lowercase dotted identifiers")
    os.umask(0o077)
    settings = config.write_settings({"extension_id": extension_id, "native_host": host_name,
                                      "chrome_profile_directory": chrome_profile})
    bin_dir = config.home() / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    launcher = bin_dir / "gate-native"
    script = ("#!/bin/sh\numask 077\n"
              "export ARCTURION_GATE_HOME=" + shlex.quote(str(config.home())) + "\n"
              "export ARCTURION_GATE_ACTOR=browser-host\n"
              "exec " + shlex.quote(sys.executable) + " -I -m arcturion_gate.mcp_server.native \"$@\"\n")
    launcher.write_text(script)
    os.chmod(launcher, 0o700)
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / (host_name + ".json")
    manifest_path.write_text(json.dumps(native_manifest(host_name, launcher, extension_id), indent=2) + "\n")
    os.chmod(manifest_path, 0o644)
    return {"config": str(settings), "launcher": str(launcher), "native_manifest": str(manifest_path),
            "extension_id": extension_id, "native_host": host_name,
            "reminder": "extension/config.js NATIVE_HOST must equal native_host"}


def enroll(print_only: bool) -> dict:
    extension_id = config.extension_id()
    if not extension_id:
        raise SystemExit("run gate-bridge install-native first")
    nonce = State().create_enrollment()
    url = "chrome-extension://" + extension_id + "/operation.html#enroll=" + nonce
    if print_only:
        return {"status": "enrollment_created", "expires_in_seconds": 120, "url": url}
    args = ["/usr/bin/open", "-a", "Google Chrome"]
    profile = config.chrome_profile_directory()
    if profile:
        args += ["--args", "--profile-directory=" + profile]
    subprocess.run(args + [url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    return {"status": "enrollment_launched", "expires_in_seconds": 120}


def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="gate-bridge", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    key = sub.add_parser("extension-key")
    key.add_argument("--private-key", required=True, type=Path, help="PEM path outside the repository")
    inst = sub.add_parser("install-native")
    inst.add_argument("--extension-id", required=True)
    inst.add_argument("--host-name", default=config.DEFAULT_NATIVE_HOST)
    inst.add_argument("--manifest-dir", type=Path, default=CHROME_HOSTS_DIR)
    inst.add_argument("--chrome-profile", help="Chrome profile directory name, e.g. 'Default' or 'Profile 1'")
    en = sub.add_parser("enroll")
    en.add_argument("--print-url", action="store_true")
    args = p.parse_args(argv)
    if args.command == "extension-key":
        result = extension_key(args.private_key)
    elif args.command == "install-native":
        result = install_native(args.extension_id, args.host_name, args.manifest_dir, args.chrome_profile)
    else:
        result = enroll(args.print_url)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
