"""Key derivation and authenticated encryption primitives."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SCHEMA_VERSION = 1
KEY_VERSION = 1


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def new_root_key() -> bytes:
    return os.urandom(32)


def new_recovery_code() -> str:
    return b64e(os.urandom(32)).rstrip("=")


@dataclass(frozen=True)
class Keys:
    encryption: bytes
    lookup: bytes
    audit: bytes
    key_id: str = f"v{KEY_VERSION}"


def derive_keys(root_key: bytes) -> Keys:
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=96,
        salt=b"arcturion-gate-v2",
        info=b"root-key-split-v1",
    ).derive(root_key)
    return Keys(material[:32], material[32:64], material[64:96])


def aad(record_id: str, version: int, payload_type: str) -> bytes:
    return f"agate:{SCHEMA_VERSION}:{record_id}:{version}:{payload_type}".encode("utf-8")


def encrypt_payload(keys: Keys, record_id: str, version: int, payload_type: str, payload: dict) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return nonce, AESGCM(keys.encryption).encrypt(nonce, raw, aad(record_id, version, payload_type))


def decrypt_payload(keys: Keys, record_id: str, version: int, payload_type: str, nonce: bytes, ciphertext: bytes) -> dict:
    raw = AESGCM(keys.encryption).decrypt(nonce, ciphertext, aad(record_id, version, payload_type))
    return json.loads(raw.decode("utf-8"))


# The recovery code is 256 random bits, so the KDF is not what protects it;
# these bounds stop a modified envelope from downgrading the work factor or
# asking unseal to run an unbounded number of iterations.
RECOVERY_ITERATIONS = 600_000
MAX_RECOVERY_ITERATIONS = 10_000_000


def wrap_for_recovery(root_key: bytes, recovery_code: str) -> dict:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    wrap_key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=RECOVERY_ITERATIONS).derive(
        recovery_code.encode("utf-8")
    )
    ciphertext = AESGCM(wrap_key).encrypt(nonce, root_key, b"arcturion-gate-recovery-v1")
    return {"version": 1, "kdf": "pbkdf2-sha256", "iterations": RECOVERY_ITERATIONS, "salt": b64e(salt), "nonce": b64e(nonce), "ciphertext": b64e(ciphertext)}


def unwrap_recovery(envelope: dict, recovery_code: str) -> bytes:
    if not isinstance(envelope, dict) or envelope.get("version") != 1 or envelope.get("kdf") != "pbkdf2-sha256":
        raise ValueError("unsupported recovery envelope")
    iterations = envelope.get("iterations")
    if type(iterations) is not int or not RECOVERY_ITERATIONS <= iterations <= MAX_RECOVERY_ITERATIONS:
        raise ValueError("recovery envelope work factor out of range")
    salt, nonce = b64d(envelope["salt"]), b64d(envelope["nonce"])
    if len(salt) < 16 or len(nonce) != 12:
        raise ValueError("malformed recovery envelope")
    wrap_key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    ).derive(recovery_code.encode("utf-8"))
    return AESGCM(wrap_key).decrypt(nonce, b64d(envelope["ciphertext"]), b"arcturion-gate-recovery-v1")

