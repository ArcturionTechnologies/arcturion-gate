"""Owner-only, secret-free operation descriptors, targets and receipts.

This database never holds a credential value. It holds:

- enrolled browser profiles (ID + SHA-256 of a profile auth value),
- published destination targets (tab/frame/document/origin/field bindings),
- single-use operation handles with a 120-second lifetime, and their receipts.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time
from urllib.parse import urlsplit

from .. import config

HANDLE_LIFETIME = 120
TARGET_LIFETIME = 120
ABSENT_ACCOUNT = hashlib.sha256(b"absent").hexdigest()
FIELD_KINDS = {"password", "totp", "token", "seed", "recovery", "note"}


class PrivateError(Exception):
    """An error that carries only a stable code, never a value."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def secure_directory(path):
    path = Path(path)
    if path.is_symlink():
        raise PrivateError("UNSAFE_PATH")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if info.st_uid != os.getuid() or not stat.S_ISDIR(info.st_mode):
        raise PrivateError("UNSAFE_PATH")
    os.chmod(path, 0o700)
    return path


def extension_origin_for(extension_id):
    if not extension_id or not config.EXTENSION_ID_PATTERN.match(extension_id):
        raise PrivateError("EXTENSION_NOT_CONFIGURED")
    return "chrome-extension://" + extension_id


def origin(value, synthetic=False, extension_origin=None):
    """Return the canonical HTTPS origin, or the extension origin for the fixture."""
    if synthetic:
        if not extension_origin or value != extension_origin:
            raise PrivateError("WRONG_ORIGIN")
        return value
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise PrivateError("WRONG_ORIGIN")
    try:
        port = parsed.port
    except ValueError:
        raise PrivateError("WRONG_ORIGIN") from None
    host = parsed.hostname.lower()
    if ":" in host:
        host = "[" + host + "]"
    canonical = "https://" + host + ((":" + str(port)) if port and port != 443 else "")
    supplied = value.rstrip("/")
    if supplied not in {canonical, canonical + ":443" if port == 443 else canonical}:
        raise PrivateError("WRONG_ORIGIN")
    return canonical


def target_binding(target, extension_origin):
    """Validate a destination and return its canonical serialized binding."""
    expected = {"tab_id", "frame_id", "document_id", "origin", "field", "account_hash", "synthetic", "document_path"}
    if not isinstance(target, dict) or set(target) != expected:
        raise PrivateError("INVALID_TARGET")
    if type(target["tab_id"]) is not int or type(target["frame_id"]) is not int:
        raise PrivateError("INVALID_TARGET")
    if not isinstance(target["document_id"], str) or not target["document_id"]:
        raise PrivateError("INVALID_TARGET")
    if type(target["synthetic"]) is not bool:
        raise PrivateError("INVALID_TARGET")
    origin(target["origin"], target["synthetic"], extension_origin)
    if not isinstance(target["document_path"], str):
        raise PrivateError("WRONG_DOCUMENT")
    if target["synthetic"] and target["document_path"] != "/fixture.html":
        raise PrivateError("WRONG_DOCUMENT")
    if not target["document_path"].startswith("/") or "?" in target["document_path"] or "#" in target["document_path"]:
        raise PrivateError("WRONG_DOCUMENT")
    field = target["field"]
    if not isinstance(field, dict) or set(field) != {"selector", "fingerprint", "kind"} or field["kind"] not in FIELD_KINDS:
        raise PrivateError("WRONG_FIELD")
    if not all(isinstance(field[n], str) and 0 < len(field[n]) <= 512 for n in field):
        raise PrivateError("WRONG_FIELD")
    if not isinstance(target["account_hash"], str) or len(target["account_hash"]) != 64 or any(c not in "0123456789abcdef" for c in target["account_hash"]):
        raise PrivateError("WRONG_ACCOUNT")
    return json.dumps(target, sort_keys=True, separators=(",", ":"))


class State:
    def __init__(self, root=None, clock=time.time, extension_id=None):
        self.root = secure_directory(root if root is not None else config.bridge_root())
        self.clock = clock
        self.extension_id = extension_id if extension_id is not None else config.extension_id()
        self.db = self.root / "operations.db"
        if self.db.is_symlink():
            raise PrivateError("UNSAFE_PATH")
        with self.connect() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS profiles(id TEXT PRIMARY KEY, auth_hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS targets(id TEXT PRIMARY KEY, profile TEXT NOT NULL, binding TEXT NOT NULL, expires REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS operations(handle TEXT PRIMARY KEY, profile TEXT NOT NULL, destination TEXT NOT NULL,
            descriptor TEXT NOT NULL, expires REAL NOT NULL, state TEXT NOT NULL, receipt TEXT);
            CREATE UNIQUE INDEX IF NOT EXISTS active_destination ON operations(destination)
            WHERE state IN ('issued','claimed');
            """)
        os.chmod(self.db, 0o600)

    @property
    def extension_origin(self):
        return extension_origin_for(self.extension_id)

    def binding(self, target):
        return target_binding(target, self.extension_origin if self.extension_id else None)

    @contextlib.contextmanager
    def connect(self):
        conn = sqlite3.connect(self.db, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def create_enrollment(self, lifetime=HANDLE_LIFETIME):
        """Write a one-time nonce; the extension must present it within ``lifetime`` seconds."""
        nonce = secrets.token_urlsafe(32)
        path = self.root / "enrollment.json"
        if path.is_symlink():
            raise PrivateError("UNSAFE_PATH")
        staging = path.with_suffix(".staging")
        if staging.is_symlink() or staging.exists():
            staging.unlink()
        # Created owner-only from the first byte, never through a symlink.
        fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(json.dumps({"nonce": nonce, "expires": self.clock() + lifetime}))
        os.replace(staging, path)
        return nonce

    def enroll(self, profile_id, profile_auth, install_nonce):
        path = self.root / "enrollment.json"
        if path.is_symlink() or not path.exists():
            raise PrivateError("ENROLLMENT_REQUIRED")
        if not all(isinstance(v, str) for v in (profile_id, profile_auth, install_nonce)):
            raise PrivateError("INVALID_ENROLLMENT")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            pending = json.loads(path.read_text())
            if self.clock() >= pending["expires"] or not secrets.compare_digest(install_nonce, pending["nonce"]):
                raise PrivateError("INVALID_ENROLLMENT")
            if len(profile_id) != 36 or len(profile_auth) < 64:
                raise PrivateError("INVALID_PROFILE")
            digest = hashlib.sha256(profile_auth.encode()).hexdigest()
            prior = conn.execute("SELECT auth_hash FROM profiles WHERE id=?", (profile_id,)).fetchone()
            if prior and not secrets.compare_digest(prior[0], digest):
                raise PrivateError("PROFILE_ALREADY_ENROLLED")
            conn.execute("INSERT OR IGNORE INTO profiles VALUES(?,?)", (profile_id, digest))
            path.unlink()
            conn.execute("COMMIT")
        return {"status": "enrolled", "profile_id": profile_id}

    def authenticate(self, profile_id, profile_auth):
        if not isinstance(profile_id, str) or not isinstance(profile_auth, str):
            raise PrivateError("WRONG_PROFILE")
        with self.connect() as conn:
            row = conn.execute("SELECT auth_hash FROM profiles WHERE id=?", (profile_id,)).fetchone()
        digest = hashlib.sha256(profile_auth.encode()).hexdigest()
        if not row or not secrets.compare_digest(row[0], digest):
            raise PrivateError("WRONG_PROFILE")

    def publish(self, profile_id, targets):
        result = []
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM targets WHERE profile=?", (profile_id,))
            for target in targets[:100]:
                binding = self.binding(target)
                ref = secrets.token_urlsafe(24)
                conn.execute("INSERT INTO targets VALUES(?,?,?,?)", (ref, profile_id, binding, self.clock() + TARGET_LIFETIME))
                result.append({"target_id": ref, "profile_id": profile_id, **target})
            conn.execute("COMMIT")
        return {"targets": result}

    def targets(self):
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM targets WHERE expires>?", (self.clock(),)).fetchall()
        return [{"target_id": r["id"], "profile_id": r["profile"], **json.loads(r["binding"])} for r in rows]

    def issue(self, target_id, descriptor):
        now = self.clock()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE operations SET state='expired' WHERE expires<=? AND state IN ('issued','claimed')", (now,))
            row = conn.execute("SELECT * FROM targets WHERE id=? AND expires>?", (target_id, now)).fetchone()
            if not row:
                raise PrivateError("TARGET_STALE")
            binding = json.loads(row["binding"])
            descriptor = {**descriptor, "target": binding, "profile_id": row["profile"]}
            # One active operation per profile/tab/frame: same-destination work serializes.
            destination = hashlib.sha256((row["profile"] + str(binding["tab_id"]) + str(binding["frame_id"])).encode()).hexdigest()
            handle = secrets.token_urlsafe(32)
            try:
                conn.execute("INSERT INTO operations VALUES(?,?,?,?,?,'issued',NULL)",
                             (handle, row["profile"], destination, json.dumps(descriptor, sort_keys=True), now + HANDLE_LIFETIME))
            except sqlite3.IntegrityError:
                raise PrivateError("DESTINATION_BUSY") from None
            conn.execute("COMMIT")
        return {"status": "prepared", "operation_handle": handle, "expires_at": now + HANDLE_LIFETIME}

    def describe(self, handle, profile_id):
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM operations WHERE handle=?", (handle,)).fetchone()
        if not row or row["profile"] != profile_id:
            raise PrivateError("WRONG_PROFILE")
        if self.clock() >= row["expires"]:
            raise PrivateError("EXPIRED_HANDLE")
        if row["state"] != "issued":
            raise PrivateError("REPLAY")
        return json.loads(row["descriptor"])

    def claim(self, handle, profile_id, target):
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM operations WHERE handle=?", (handle,)).fetchone()
            if not row or row["profile"] != profile_id:
                raise PrivateError("WRONG_PROFILE")
            if self.clock() >= row["expires"]:
                raise PrivateError("EXPIRED_HANDLE")
            if row["state"] != "issued":
                raise PrivateError("REPLAY")
            descriptor = json.loads(row["descriptor"])
            if self.binding(target) != self.binding(descriptor["target"]):
                raise PrivateError("DESTINATION_MISMATCH")
            conn.execute("UPDATE operations SET state='claimed' WHERE handle=?", (handle,))
            conn.execute("COMMIT")
        return descriptor

    def complete(self, handle, profile_id, receipt):
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM operations WHERE handle=?", (handle,)).fetchone()
            if not row or row["profile"] != profile_id or row["state"] != "claimed":
                raise PrivateError("REPLAY")
            receipt = {**receipt, "receipt_id": secrets.token_urlsafe(24), "operation_handle": handle, "completed_at": self.clock()}
            conn.execute("UPDATE operations SET state='complete',receipt=? WHERE handle=?", (json.dumps(receipt), handle))
            conn.execute("COMMIT")
        return receipt

    def operation(self, handle):
        with self.connect() as conn:
            row = conn.execute("SELECT descriptor FROM operations WHERE handle=?", (handle,)).fetchone()
        if not row:
            raise PrivateError("NOT_FOUND")
        return json.loads(row[0])

    def receipt(self, handle):
        with self.connect() as conn:
            row = conn.execute("SELECT receipt,state,expires FROM operations WHERE handle=?", (handle,)).fetchone()
        if not row:
            raise PrivateError("NOT_FOUND")
        return json.loads(row["receipt"]) if row["receipt"] else {"status": "expired" if self.clock() >= row["expires"] else row["state"]}
