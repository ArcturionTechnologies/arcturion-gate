"""Encrypted, transactional credential store and public Python API.

Storage model
-------------
- One 32-byte root key lives in the macOS login Keychain. HKDF splits it into
  an encryption key, a lookup key (HMAC tokens for titles/aliases) and an audit
  key (HMAC chain over audit events).
- Every record payload is a JSON document encrypted with AES-256-GCM. The AAD
  binds ciphertext to ``record_id``, ``version`` and payload type, so a blob
  cannot be swapped between records or replayed as another version.
- Every committed version is also written to ``revisions`` (encrypted), so an
  edit never destroys the previous value.
- Writes require the caller's expected version; a stale write fails with
  ``VERSION_CONFLICT`` and changes nothing.
- Every secret release and every mutation appends an HMAC-chained audit event
  inside the same transaction. If the chain was tampered with, release fails.
- The chain head is anchored with a keyed HMAC over (event count, last HMAC),
  so deleting the newest events and re-pointing the anchor is detected.
- Before a release or write, the record row must match the newest version (and
  tombstone state) recorded in the authenticated audit chain, so restoring an
  older revision into ``records`` is detected rather than served.
- Limit: a copy of the *whole* database (records, audit and anchor together)
  restored over the current one is self-consistent and is not detected.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import sqlite3
import time
import uuid
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Iterator

from . import config, keychain
from .crypto import Keys, decrypt_payload, derive_keys, encrypt_payload, new_recovery_code, new_root_key, unwrap_recovery, wrap_for_recovery
from .errors import GateError

ALLOWED_CATEGORIES = {
    "APICredential", "ConnectionString", "Login", "Password", "Secret", "SSHKey",
    "Recovery", "Identity", "PaymentCard", "CreditCard", "BankAccount",
}

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS records(
  id TEXT PRIMARY KEY, version INTEGER NOT NULL, lookup_token BLOB NOT NULL,
  nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, key_id TEXT NOT NULL,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, deleted_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_records_lookup ON records(lookup_token);
CREATE TABLE IF NOT EXISTS aliases(token BLOB NOT NULL, record_id TEXT NOT NULL REFERENCES records(id), UNIQUE(token,record_id));
CREATE INDEX IF NOT EXISTS idx_alias_token ON aliases(token);
CREATE TABLE IF NOT EXISTS revisions(
  record_id TEXT NOT NULL REFERENCES records(id), version INTEGER NOT NULL,
  nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, key_id TEXT NOT NULL, at INTEGER NOT NULL,
  PRIMARY KEY(record_id,version)
);
CREATE TABLE IF NOT EXISTS audit(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL, at INTEGER NOT NULL,
  actor TEXT NOT NULL, session TEXT NOT NULL, purpose TEXT NOT NULL, action TEXT NOT NULL,
  record_id TEXT, field TEXT, result TEXT NOT NULL, version INTEGER,
  prev_hmac BLOB NOT NULL, event_hmac BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_record ON audit(record_id, action);
CREATE TABLE IF NOT EXISTS outbox(
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, record_id TEXT NOT NULL, version INTEGER NOT NULL,
  payload_hash TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'queued', created_at INTEGER NOT NULL,
  processed_at INTEGER
);
CREATE TABLE IF NOT EXISTS idempotency(
  id TEXT PRIMARY KEY, action TEXT NOT NULL, result_json TEXT NOT NULL, at INTEGER NOT NULL
);
"""


def _now() -> int:
    return int(time.time())


def _norm(value: str) -> str:
    return " ".join(value.casefold().strip().split())


def _create_private_file(path: Path) -> None:
    """Create ``path`` as a new owner-only (0600) file; refuse existing files and symlinks."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)


def _write_private_file(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(text)


def _context() -> tuple[str, str]:
    # Self-reported attribution. It is useful for reading your own audit log,
    # not a security boundary: any local process can set these variables.
    actor = os.environ.get("ARCTURION_GATE_ACTOR") or "LOCAL"
    session = os.environ.get("ARCTURION_GATE_SESSION") or f"{platform.node()}:{os.getpid()}"
    return actor, session


class GateStore:
    def __init__(self, root: Path | str | None = None, *, catalog: Path | str | None = None) -> None:
        self.root = Path(root).expanduser() if root is not None else config.vault_root()
        configured = catalog if catalog is not None else config.catalog_dir()
        # Optional value-free Markdown catalog (titles, IDs, versions; never values).
        self.catalog = Path(configured).expanduser() if configured is not None else None
        self.db_path = self.root / "gate.db"
        self.envelope_path = self.root / "recovery-envelope.json"
        self.sealed_path = self.root / "SEALED"

    def initialize(self) -> str:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        if self.db_path.exists():
            raise GateError("INVALID", "ArcturionGate is already initialized at this path")
        root_key = new_root_key()
        recovery_code = new_recovery_code()
        # Files are created owner-only from the first byte; there is no window in
        # which the envelope or database exists with default (umask) permissions.
        if self.envelope_path.exists() or self.envelope_path.is_symlink():
            raise GateError("INVALID", "A recovery envelope already exists at this path")
        keychain.put_root_key(root_key)
        _create_private_file(self.db_path)
        _write_private_file(self.envelope_path, json.dumps(wrap_for_recovery(root_key, recovery_code), indent=2) + "\n")
        with self._connect(raw=True) as conn:
            conn.executescript(SCHEMA)
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version','1')")
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('key_id','v1')")
        os.chmod(self.db_path, 0o600)
        return recovery_code

    def _keys(self) -> Keys:
        if self.sealed_path.exists():
            raise GateError("SEALED", "ArcturionGate is sealed")
        return derive_keys(keychain.get_root_key())

    @contextmanager
    def _connect(self, *, raw: bool = False) -> Iterator[sqlite3.Connection]:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        conn = sqlite3.connect(self.db_path, timeout=20, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=20000")
        if not raw:
            conn.executescript(SCHEMA)
        try:
            yield conn
        finally:
            conn.close()

    def _lookup_token(self, keys: Keys, value: str) -> bytes:
        return hmac.new(keys.lookup, _norm(value).encode("utf-8"), hashlib.sha256).digest()

    def _idempotency_token(self, keys: Keys, value: str) -> bytes:
        return hmac.new(keys.lookup, b"idempotency\x00" + value.encode("utf-8"), hashlib.sha256).digest()

    def _payload(self, keys: Keys, row: sqlite3.Row, payload_type: str = "record") -> dict:
        try:
            return decrypt_payload(keys, row["id"], int(row["version"]), payload_type, row["nonce"], row["ciphertext"])
        except Exception as exc:
            raise GateError("INTEGRITY_FAILURE", f"Encrypted record failed authentication: {row['id']}") from exc

    def _safe(self, payload: dict, row: sqlite3.Row | None = None) -> dict:
        return {
            "id": payload["id"], "title": payload["title"], "category": payload["category"],
            "version": payload["version"], "tags": payload.get("tags", []),
            "deleted": bool(row and row["deleted_at"]),
        }

    def _validate_payload(self, payload: dict) -> None:
        if not isinstance(payload.get("title"), str) or not payload["title"].strip():
            raise GateError("INVALID", "Record title is required")
        if payload.get("category") not in ALLOWED_CATEGORIES:
            raise GateError("INVALID", "Unsupported category")
        if not isinstance(payload.get("fields"), dict):
            raise GateError("INVALID", "fields must be an object")
        for key, value in payload["fields"].items():
            if not isinstance(key, str) or not key.strip() or not isinstance(value, str):
                raise GateError("INVALID", "field names and values must be strings")
        for name in payload.get("aliases", []):
            if not isinstance(name, str) or not name.strip():
                raise GateError("INVALID", "aliases must be non-empty strings")
        if not isinstance(payload.get("notes_markdown", ""), str):
            raise GateError("INVALID", "notes_markdown must be a string")

    @staticmethod
    def _anchor(keys: Keys, count: int, head: bytes) -> str:
        # Keyed: only the root-key holder can produce an anchor for a given
        # (count, head), so truncating the newest events cannot be re-anchored.
        return "v2:" + hmac.new(keys.audit, b"agate-audit-head:v2:" + str(count).encode("ascii") + b":" + head, hashlib.sha256).hexdigest()

    def _verify_audit_chain(self, conn: sqlite3.Connection, keys: Keys) -> int:
        prev = b"\x00" * 32
        count = 0
        for row in conn.execute("SELECT * FROM audit ORDER BY seq"):
            body = json.dumps(
                {"event_id": row["event_id"], "at": row["at"], "actor": row["actor"], "session": row["session"],
                 "purpose": row["purpose"], "action": row["action"], "record_id": row["record_id"] or "",
                 "field": row["field"], "result": row["result"], "version": row["version"]},
                sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
            expected = hmac.new(keys.audit, prev + body, hashlib.sha256).digest()
            if not hmac.compare_digest(bytes(row["prev_hmac"]), prev) or not hmac.compare_digest(bytes(row["event_hmac"]), expected):
                raise GateError("INTEGRITY_FAILURE", f"Audit chain failed at sequence {row['seq']}")
            prev = expected
            count += 1
        anchored = conn.execute("SELECT value FROM meta WHERE key='audit_head'").fetchone()
        if anchored is None:
            # Only a store with no audit events yet may lack an anchor. If the
            # events *and* the anchor were deleted, every record also loses its
            # audited version, so _assert_current refuses to release or modify it.
            if count:
                raise GateError("INTEGRITY_FAILURE", "Audit chain anchor is missing")
            return count
        if not hmac.compare_digest(str(anchored[0]), self._anchor(keys, count, prev)):
            raise GateError("INTEGRITY_FAILURE", "Audit chain head does not match its durable anchor")
        return count

    def _assert_current(self, conn: sqlite3.Connection, record_id: str, version: int, deleted_at) -> None:
        """Fail closed unless the row is the newest audited version of the record.

        Call only after the audit chain was verified in the same transaction:
        the chain is then authentic and complete up to its keyed anchor.
        """
        audited = conn.execute(
            "SELECT MAX(version) FROM audit WHERE record_id=? AND action IN ('create','patch')", (record_id,)
        ).fetchone()[0]
        tombstoned = conn.execute(
            "SELECT 1 FROM audit WHERE record_id=? AND action='tombstone' LIMIT 1", (record_id,)
        ).fetchone() is not None
        if audited is None or int(audited) != int(version) or tombstoned != bool(deleted_at):
            raise GateError("INTEGRITY_FAILURE", f"Record does not match its audited version: {record_id}")

    def _current_row(self, conn: sqlite3.Connection, record_id: str) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        if row is None or row["deleted_at"]:
            raise GateError("NOT_FOUND", "Credential not found")
        return row

    def _audit(
        self, conn: sqlite3.Connection, keys: Keys, *, action: str, record_id: str | None,
        field: str = "", result: str = "ok", version: int | None = None, purpose: str = "",
    ) -> None:
        # Secret release and every state mutation fail closed if any earlier
        # audit entry was modified or removed from the authenticated chain.
        count = self._verify_audit_chain(conn, keys)
        actor, session = _context()
        prev_row = conn.execute("SELECT event_hmac FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = bytes(prev_row[0]) if prev_row else b"\x00" * 32
        event_id = str(uuid.uuid4())
        at = _now()
        # Purposes are keyed-hashed so free text never sits in the database in the
        # clear and short purposes cannot be recovered by guessing. Older events
        # keep their stored "sha256:" form; the chain authenticates whatever is stored.
        safe_purpose = ("hmac:" + hmac.new(keys.audit, b"purpose\x00" + purpose.encode("utf-8"), hashlib.sha256).hexdigest()
                        if purpose else "")
        body = json.dumps(
            {"event_id": event_id, "at": at, "actor": actor, "session": session, "purpose": safe_purpose,
             "action": action, "record_id": record_id or "", "field": field, "result": result,
             "version": version},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        digest = hmac.new(keys.audit, prev + body, hashlib.sha256).digest()
        conn.execute(
            "INSERT INTO audit(event_id,at,actor,session,purpose,action,record_id,field,result,version,prev_hmac,event_hmac) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, at, actor, session, safe_purpose, action, record_id, field, result, version, prev, digest),
        )
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('audit_head',?)", (self._anchor(keys, count + 1, digest),))

    def _outbox(self, conn: sqlite3.Connection, keys: Keys, kind: str, record_id: str, version: int, payload: dict) -> None:
        # Keyed, so the stored digest is not an offline guessing oracle for titles or tags.
        digest = hmac.new(keys.lookup, b"outbox\x00" + json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
                          hashlib.sha256).hexdigest()
        conn.execute(
            "INSERT INTO outbox(id,kind,record_id,version,payload_hash,created_at) VALUES(?,?,?,?,?,?)",
            (str(uuid.uuid4()), kind, record_id, version, digest, _now()),
        )

    def _after_commit(self) -> None:
        if self.catalog is None:
            return
        try:
            self.process_catalog_outbox()
        except Exception:
            # The catalog is a convenience view; the commit already succeeded
            # and queued work is retried on the next write.
            pass

    def create(self, data: dict, *, purpose: str = "", idempotency_key: str | None = None) -> dict:
        keys = self._keys()
        if idempotency_key:
            with self._connect() as conn:
                row = conn.execute("SELECT result_json FROM idempotency WHERE id=?", (self._idempotency_token(keys, idempotency_key),)).fetchone()
                if row:
                    return json.loads(row[0])
        try:
            rid = str(uuid.UUID(str(data["id"]))) if data.get("id") else str(uuid.uuid4())
        except (ValueError, TypeError, AttributeError) as exc:
            raise GateError("INVALID", "Record ID must be a canonical UUID") from exc
        now = _now()
        payload = {
            "id": rid, "version": 1, "title": str(data.get("title", "")).strip(),
            "category": data.get("category", "APICredential"),
            "aliases": sorted(set(str(v).strip() for v in data.get("aliases", []) if str(v).strip())),
            "tags": sorted(set(str(v).strip() for v in data.get("tags", []) if str(v).strip())),
            "fields": dict(data.get("fields", {})), "notes_markdown": str(data.get("notes_markdown", "")),
            "created_at": now, "updated_at": now,
        }
        self._validate_payload(payload)
        nonce, ciphertext = encrypt_payload(keys, rid, 1, "record", payload)
        result = {"id": rid, "version": 1, "committed": True}
        with self._connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "INSERT INTO records(id,version,lookup_token,nonce,ciphertext,key_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                    (rid, 1, self._lookup_token(keys, payload["title"]), nonce, ciphertext, keys.key_id, now, now),
                )
                conn.execute("INSERT INTO revisions(record_id,version,nonce,ciphertext,key_id,at) VALUES(?,?,?,?,?,?)", (rid, 1, nonce, ciphertext, keys.key_id, now))
                for alias in payload["aliases"]:
                    conn.execute("INSERT INTO aliases(token,record_id) VALUES(?,?)", (self._lookup_token(keys, alias), rid))
                self._audit(conn, keys, action="create", record_id=rid, version=1, purpose=purpose)
                self._outbox(conn, keys, "catalog", rid, 1, self._safe(payload))
                if idempotency_key:
                    conn.execute("INSERT INTO idempotency(id,action,result_json,at) VALUES(?,?,?,?)", (self._idempotency_token(keys, idempotency_key), "create", json.dumps(result), now))
                conn.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                conn.execute("ROLLBACK")
                raise GateError("INVALID", "Record ID or alias already exists") from exc
            except Exception:
                conn.execute("ROLLBACK")
                raise
        self._after_commit()
        return result

    def _rows(self, *, include_deleted: bool = False) -> list[sqlite3.Row]:
        where = "" if include_deleted else " WHERE deleted_at IS NULL"
        with self._connect() as conn:
            return list(conn.execute("SELECT * FROM records" + where))

    def find(self, query: str, *, include_deleted: bool = False) -> list[dict]:
        """Value-free search over titles, aliases and tags. Exact matches win."""
        keys = self._keys()
        norm = _norm(query)
        exact: list[dict] = []
        fuzzy: list[dict] = []
        for row in self._rows(include_deleted=include_deleted):
            payload = self._payload(keys, row)
            names = [payload["title"], *payload.get("aliases", [])]
            safe = self._safe(payload, row)
            if str(row["id"]) == query or any(_norm(n) == norm for n in names):
                exact.append(safe)
            elif any(norm in _norm(n) for n in names) or norm in _norm(" ".join(payload.get("tags", []))):
                fuzzy.append(safe)
        return exact or fuzzy

    def resolve(self, reference: str) -> tuple[sqlite3.Row, dict, Keys]:
        keys = self._keys()
        rows = self._rows()
        matches: list[tuple[sqlite3.Row, dict]] = []
        for row in rows:
            payload = self._payload(keys, row)
            if row["id"] == reference:
                return row, payload, keys
            if _norm(payload["title"]) == _norm(reference) or any(_norm(a) == _norm(reference) for a in payload.get("aliases", [])):
                matches.append((row, payload))
        if not matches:
            raise GateError("NOT_FOUND", "Credential not found")
        if len(matches) > 1:
            raise GateError("AMBIGUOUS", "Credential reference is ambiguous", candidates=[self._safe(p, r) for r, p in matches])
        return matches[0][0], matches[0][1], keys

    def inspect(self, reference: str) -> dict:
        row, payload, _ = self.resolve(reference)
        return self._safe(payload, row)

    def _release(self, reference: str, *, field: str | None, purpose: str) -> dict:
        """Read the current row, audit the release and check freshness in one transaction.

        The value released is exactly the version named in its audit event.
        """
        resolved, _, keys = self.resolve(reference)
        try:
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    row = self._current_row(conn, resolved["id"])
                    payload = self._payload(keys, row)
                    if field is not None and field not in payload.get("fields", {}):
                        raise GateError("NOT_FOUND", "Field not found", record_id=row["id"], version=row["version"])
                    self._audit(conn, keys, action="read_record" if field is None else "read_field", record_id=row["id"],
                                field=field or "", version=row["version"], purpose=purpose)
                    self._assert_current(conn, row["id"], row["version"], row["deleted_at"])
                    conn.execute("COMMIT")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
        except Exception as exc:
            if isinstance(exc, GateError):
                raise
            raise GateError("AUDIT_FAILURE", "Could not record the credential read", retryable=True) from exc
        return payload

    def get_record(self, reference: str, *, purpose: str = "") -> dict:
        return self._release(reference, field=None, purpose=purpose)

    def get(self, reference: str, field: str = "credential", *, purpose: str = "") -> str:
        return str(self._release(reference, field=field, purpose=purpose)["fields"][field])

    def patch(
        self, reference: str, patch: dict, *, expected_version: int, purpose: str = "",
        idempotency_key: str | None = None,
    ) -> dict:
        row, payload, keys = self.resolve(reference)
        if idempotency_key:
            with self._connect() as conn:
                prior = conn.execute("SELECT result_json FROM idempotency WHERE id=?", (self._idempotency_token(keys, idempotency_key),)).fetchone()
                if prior:
                    return json.loads(prior[0])
        if int(row["version"]) != int(expected_version):
            raise GateError("VERSION_CONFLICT", "Record changed before this edit", record_id=row["id"], version=row["version"])
        updated = dict(payload)
        if "fields" in patch:
            fields = dict(updated.get("fields", {}))
            for name, value in patch["fields"].items():
                if value is None:
                    fields.pop(name, None)
                else:
                    fields[name] = value
            updated["fields"] = fields
        for key in ("title", "category", "aliases", "tags", "notes_markdown"):
            if key in patch:
                updated[key] = patch[key]
        updated["version"] = int(row["version"]) + 1
        updated["updated_at"] = _now()
        self._validate_payload(updated)
        nonce, ciphertext = encrypt_payload(keys, row["id"], updated["version"], "record", updated)
        result = {"id": row["id"], "version": updated["version"], "committed": True}
        with self._connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                current = self._current_row(conn, row["id"])
                self._verify_audit_chain(conn, keys)
                if int(current["version"]) == int(expected_version):
                    self._assert_current(conn, current["id"], current["version"], current["deleted_at"])
                changed = conn.execute(
                    "UPDATE records SET version=?,lookup_token=?,nonce=?,ciphertext=?,key_id=?,updated_at=? WHERE id=? AND version=?",
                    (updated["version"], self._lookup_token(keys, updated["title"]), nonce, ciphertext, keys.key_id, updated["updated_at"], row["id"], expected_version),
                ).rowcount
                if changed != 1:
                    raise GateError("VERSION_CONFLICT", "Record changed before commit", record_id=row["id"])
                conn.execute("DELETE FROM aliases WHERE record_id=?", (row["id"],))
                for alias in updated.get("aliases", []):
                    conn.execute("INSERT INTO aliases(token,record_id) VALUES(?,?)", (self._lookup_token(keys, alias), row["id"]))
                conn.execute("INSERT INTO revisions(record_id,version,nonce,ciphertext,key_id,at) VALUES(?,?,?,?,?,?)", (row["id"], updated["version"], nonce, ciphertext, keys.key_id, updated["updated_at"]))
                self._audit(conn, keys, action="patch", record_id=row["id"], version=updated["version"], purpose=purpose)
                self._outbox(conn, keys, "catalog", row["id"], updated["version"], self._safe(updated))
                if idempotency_key:
                    conn.execute("INSERT INTO idempotency(id,action,result_json,at) VALUES(?,?,?,?)", (self._idempotency_token(keys, idempotency_key), "patch", json.dumps(result), _now()))
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        self._after_commit()
        return result

    def append_note(self, reference: str, note: str, *, expected_version: int, purpose: str = "") -> dict:
        _, payload, _ = self.resolve(reference)
        current = payload.get("notes_markdown", "").rstrip()
        merged = (current + "\n\n" + note.strip()).strip()
        return self.patch(reference, {"notes_markdown": merged}, expected_version=expected_version, purpose=purpose)

    def delete(self, reference: str, *, expected_version: int, purpose: str = "") -> dict:
        """Tombstone a record. Ciphertext and revisions are retained."""
        row, _, keys = self.resolve(reference)
        if int(row["version"]) != int(expected_version):
            raise GateError("VERSION_CONFLICT", "Record changed before deletion", record_id=row["id"], version=row["version"])
        with self._connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                current = self._current_row(conn, row["id"])
                self._verify_audit_chain(conn, keys)
                if int(current["version"]) != int(expected_version):
                    raise GateError("VERSION_CONFLICT", "Record changed before deletion", record_id=row["id"], version=current["version"])
                self._assert_current(conn, current["id"], current["version"], current["deleted_at"])
                conn.execute("UPDATE records SET deleted_at=? WHERE id=? AND version=?", (_now(), row["id"], expected_version))
                self._audit(conn, keys, action="tombstone", record_id=row["id"], version=expected_version, purpose=purpose)
                self._outbox(conn, keys, "catalog", row["id"], expected_version, {"deleted": True})
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        self._after_commit()
        return {"id": row["id"], "version": expected_version, "committed": True, "deleted": True}

    def process_catalog_outbox(self) -> int:
        """Write the value-free Markdown catalog, one file per record."""
        if self.catalog is None:
            return 0
        self.catalog.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.catalog, 0o700)
        keys = self._keys()
        count = 0
        with self._connect() as conn:
            rows = list(conn.execute("SELECT * FROM outbox WHERE kind='catalog' AND state='queued' ORDER BY created_at"))
            for event in rows:
                record = conn.execute("SELECT * FROM records WHERE id=?", (event["record_id"],)).fetchone()
                try:
                    rid = str(uuid.UUID(str(event["record_id"])))
                except (ValueError, TypeError, AttributeError) as exc:
                    raise GateError("INTEGRITY_FAILURE", "Catalog outbox contains a non-UUID record ID") from exc
                catalog_root = self.catalog.resolve()
                path = (catalog_root / f"{rid}.md").resolve()
                if path.parent != catalog_root:
                    raise GateError("INTEGRITY_FAILURE", "Catalog path escaped its root")
                if not record or record["deleted_at"]:
                    if path.exists():
                        path.unlink()
                else:
                    payload = self._payload(keys, record)
                    text = (
                        f"# {payload['title']}\n\n"
                        f"- ID: `{payload['id']}`\n- Category: `{payload['category']}`\n"
                        f"- Version: `{payload['version']}`\n"
                        f"- Open: `gate view {payload['id']}`\n"
                    )
                    tmp = path.with_suffix(".tmp")
                    tmp.write_text(text)
                    os.chmod(tmp, 0o600)
                    os.replace(tmp, path)
                conn.execute("UPDATE outbox SET state='processed',processed_at=? WHERE id=?", (_now(), event["id"]))
                count += 1
        return count

    def audit_summary(self) -> dict:
        keys = self._keys()
        with self._connect() as conn:
            count = self._verify_audit_chain(conn, keys)
        return {"events": count, "chain_valid": True}

    def health(self) -> dict:
        keys = self._keys()
        with self._connect() as conn:
            # One snapshot keeps the chain and anchor consistent with each other.
            conn.execute("BEGIN")
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            records = conn.execute("SELECT COUNT(*) FROM records WHERE deleted_at IS NULL").fetchone()[0]
            revisions = conn.execute("SELECT COUNT(*) FROM revisions").fetchone()[0]
            queued = conn.execute("SELECT COUNT(*) FROM outbox WHERE state='queued'").fetchone()[0]
            if integrity != "ok":
                raise GateError("INTEGRITY_FAILURE", "SQLite integrity check failed")
            count = self._verify_audit_chain(conn, keys)
            conn.execute("COMMIT")
        return {"healthy": True, "records": records, "revisions": revisions, "outbox_queued": queued,
                "sealed": False, "audit": {"events": count, "chain_valid": True}}

    def backup(self, destination: Path | str) -> dict:
        """Copy the encrypted database. The backup is only as useful as the root key or recovery code.

        The destination must not exist (no overwrite, no writing through a
        symlink) and is created 0600 before any page is copied into it.
        """
        dest = Path(destination).expanduser()
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            _create_private_file(dest)
        except FileExistsError as exc:
            raise GateError("INVALID", "Backup destination already exists") from exc
        try:
            with self._connect() as source, closing(sqlite3.connect(dest)) as target:
                source.backup(target)
        except BaseException:
            dest.unlink(missing_ok=True)
            raise
        os.chmod(dest, 0o600)
        return {"path": str(dest), "bytes": dest.stat().st_size}

    def seal(self) -> None:
        self.sealed_path.write_text("sealed\n")
        os.chmod(self.sealed_path, 0o600)
        keychain.delete_root_key()

    def unseal(self, recovery_code: str) -> None:
        if not self.envelope_path.exists():
            raise GateError("NOT_FOUND", "Recovery envelope is missing")
        try:
            root_key = unwrap_recovery(json.loads(self.envelope_path.read_text()), recovery_code.strip())
        except Exception as exc:
            raise GateError("INVALID", "Recovery code did not open the envelope") from exc
        keychain.put_root_key(root_key)
        if self.sealed_path.exists():
            self.sealed_path.unlink()
        self.health()


class Gate:
    """Thin convenience API for consumers."""

    def __init__(self, root: Path | str | None = None, *, store: GateStore | None = None) -> None:
        self.store = store or GateStore(root)

    def get(self, record: str, field: str = "credential", *, purpose: str = "") -> str:
        return self.store.get(record, field, purpose=purpose)

    def create(self, data: dict, *, purpose: str = "", idempotency_key: str | None = None) -> dict:
        return self.store.create(data, purpose=purpose, idempotency_key=idempotency_key)

    def patch(self, record: str, patch: dict, *, expected_version: int, purpose: str = "", idempotency_key: str | None = None) -> dict:
        return self.store.patch(record, patch, expected_version=expected_version, purpose=purpose, idempotency_key=idempotency_key)
