from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from arcturion_gate import crypto
from arcturion_gate.cli import _split_env, markdown_replacement_patch, new_record_template
from arcturion_gate.errors import GateError
from arcturion_gate.markdown import parse, render
from arcturion_gate.store import GateStore

from helpers import isolate


class GateCase(unittest.TestCase):
    def setUp(self):
        base = isolate(self, root_key=b"r" * 32)
        self.store = GateStore(base / "state", catalog=base / "catalog")
        self.recovery = self.store.initialize()

    def create(self, title="Example"):
        return self.store.create({
            "title": title, "category": "Login", "aliases": ["example.test"],
            "fields": {"url": "https://example.test", "username": "user", "password": "synthetic-secret"},
            "notes_markdown": "A **note**.",
        }, purpose="test")

    def test_create_read_find_and_catalog(self):
        result = self.create()
        self.assertTrue(result["committed"])
        self.assertEqual(self.store.get(result["id"], "password"), "synthetic-secret")
        self.assertEqual(self.store.find("example.test")[0]["id"], result["id"])
        catalog_file = self.store.catalog / f"{result['id']}.md"
        self.assertTrue(catalog_file.exists())
        self.assertNotIn("synthetic-secret", catalog_file.read_text())
        self.assertTrue(self.store.audit_summary()["chain_valid"])

    def test_catalog_is_optional(self):
        store = GateStore(self.store.root.parent / "no-catalog")
        store.initialize()
        self.assertIsNone(store.catalog)
        store.create({"title": "Quiet", "category": "Secret", "fields": {"credential": "x"}})
        self.assertEqual(store.process_catalog_outbox(), 0)

    def test_patch_version_and_idempotency(self):
        result = self.create()
        changed = self.store.patch(result["id"], {"fields": {"password": "new"}}, expected_version=1, idempotency_key="patch-1")
        replay = self.store.patch(result["id"], {"fields": {"password": "wrong"}}, expected_version=1, idempotency_key="patch-1")
        self.assertEqual(changed, replay)
        self.assertEqual(self.store.get(result["id"], "password"), "new")
        with self.assertRaises(GateError) as caught:
            self.store.patch(result["id"], {"title": "late"}, expected_version=1)
        self.assertEqual(caught.exception.code, "VERSION_CONFLICT")

    def test_every_version_is_kept_as_encrypted_revision(self):
        result = self.create()
        self.store.patch(result["id"], {"fields": {"password": "second"}}, expected_version=1)
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            versions = [r[0] for r in conn.execute("SELECT version FROM revisions WHERE record_id=? ORDER BY version", (result["id"],))]
        self.assertEqual(versions, [1, 2])

    def test_exact_ambiguity_and_not_found(self):
        self.create("First")
        self.store.create({"title": "Second", "category": "Secret", "aliases": ["shared"], "fields": {"credential": "2"}})
        self.store.create({"title": "Third", "category": "Secret", "aliases": ["shared"], "fields": {"credential": "3"}})
        with self.assertRaises(GateError) as ambiguous:
            self.store.get("shared")
        self.assertEqual(ambiguous.exception.code, "AMBIGUOUS")
        with self.assertRaises(GateError) as missing:
            self.store.get("missing")
        self.assertEqual(missing.exception.code, "NOT_FOUND")

    def test_tamper_detection(self):
        result = self.create()
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            raw = conn.execute("SELECT ciphertext FROM records WHERE id=?", (result["id"],)).fetchone()[0]
            corrupt = bytes(raw[:-1]) + bytes([raw[-1] ^ 1])
            conn.execute("UPDATE records SET ciphertext=? WHERE id=?", (corrupt, result["id"]))
            conn.commit()
        with self.assertRaises(GateError) as caught:
            self.store.get(result["id"], "password")
        self.assertEqual(caught.exception.code, "INTEGRITY_FAILURE")

    def test_ciphertext_swapped_between_records_fails_authentication(self):
        first = self.create("First")
        second = self.store.create({"title": "Second", "category": "Secret", "fields": {"credential": "two"}})
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            row = conn.execute("SELECT nonce,ciphertext FROM records WHERE id=?", (first["id"],)).fetchone()
            conn.execute("UPDATE records SET nonce=?,ciphertext=? WHERE id=?", (row[0], row[1], second["id"]))
            conn.commit()
        with self.assertRaises(GateError) as caught:
            self.store.get(second["id"], "credential")
        self.assertEqual(caught.exception.code, "INTEGRITY_FAILURE")

    def test_aad_binds_record_version_and_type(self):
        keys = crypto.derive_keys(b"k" * 32)
        nonce, ciphertext = crypto.encrypt_payload(keys, "rid", 1, "record", {"a": "b"})
        self.assertEqual(crypto.decrypt_payload(keys, "rid", 1, "record", nonce, ciphertext), {"a": "b"})
        for args in (("other", 1, "record"), ("rid", 2, "record"), ("rid", 1, "other")):
            with self.subTest(args=args):
                with self.assertRaises(Exception):
                    crypto.decrypt_payload(keys, *args, nonce, ciphertext)

    def test_audit_tamper_blocks_plaintext_release(self):
        result = self.create()
        self.store.get(result["id"], "password")
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            conn.execute("UPDATE audit SET action='tampered' WHERE seq=(SELECT MIN(seq) FROM audit)")
            conn.commit()
        with self.assertRaises(GateError) as caught:
            self.store.get(result["id"], "password")
        self.assertEqual(caught.exception.code, "INTEGRITY_FAILURE")

    def test_audit_purpose_is_hashed(self):
        result = self.create()
        self.store.get(result["id"], "password", purpose="distinctive-purpose-text")
        self.assertNotIn(b"distinctive-purpose-text", self.store.db_path.read_bytes())

    def test_rejects_non_uuid_record_id(self):
        with self.assertRaises(GateError) as caught:
            self.store.create({"id": "../../escape", "title": "Bad", "category": "Secret", "fields": {"credential": "x"}})
        self.assertEqual(caught.exception.code, "INVALID")
        self.assertFalse((self.store.catalog.parent / "escape.md").exists())

    def test_markdown_roundtrip(self):
        result = self.create()
        record = self.store.get_record(result["id"])
        decoded = parse(render(record))
        self.assertEqual(decoded["fields"], record["fields"])
        self.assertEqual(decoded["notes_markdown"], record["notes_markdown"])

    def test_human_markdown_template_and_field_removal(self):
        self.assertEqual(parse(new_record_template())["category"], "Login")
        result = self.create()
        current = self.store.get_record(result["id"])
        edited = dict(current)
        edited["fields"] = {"username": "user", "password": "synthetic-secret"}
        changed = self.store.patch(
            result["id"], markdown_replacement_patch(current, edited), expected_version=current["version"],
        )
        record = self.store.get_record(result["id"])
        self.assertEqual(changed["version"], 2)
        self.assertNotIn("url", record["fields"])

    def test_recovery_envelope(self):
        store = GateStore(self.store.root.parent / "recovery-case")
        with patch("arcturion_gate.keychain.put_root_key") as put:
            recovery = store.initialize()
            original_key = put.call_args.args[0]
        self.assertEqual(len(original_key), 32)
        with patch("arcturion_gate.keychain.put_root_key") as put, \
                patch("arcturion_gate.keychain.get_root_key", return_value=original_key):
            store.sealed_path.write_text("sealed\n")
            store.unseal(recovery)
            put.assert_called_once()
            self.assertEqual(put.call_args.args[0], original_key)
        self.assertFalse(store.sealed_path.exists())

    def test_wrong_recovery_code_rejected(self):
        with self.assertRaises(GateError) as caught:
            self.store.unseal("not-the-recovery-code")
        self.assertEqual(caught.exception.code, "INVALID")

    def test_recovery_envelope_holds_no_plain_key(self):
        envelope = json.loads(self.store.envelope_path.read_text())
        self.assertEqual(envelope["kdf"], "pbkdf2-sha256")
        self.assertNotIn(crypto.b64e(b"r" * 32), json.dumps(envelope))

    def test_health_checks_authenticated_audit_and_anchor(self):
        result = self.create()
        self.assertTrue(self.store.health()["audit"]["chain_valid"])
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            old = conn.execute("SELECT value FROM meta WHERE key='audit_head'").fetchone()[0]
        self.store.get(result["id"], "password")
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            conn.execute("UPDATE meta SET value=? WHERE key='audit_head'", (old,))
            conn.commit()
        with self.assertRaises(GateError) as caught:
            self.store.health()
        self.assertEqual(caught.exception.code, "INTEGRITY_FAILURE")

    def test_health_rejects_audit_tamper(self):
        self.create()
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            conn.execute("UPDATE audit SET action='tampered'")
            conn.commit()
        with self.assertRaises(GateError) as caught:
            self.store.health()
        self.assertEqual(caught.exception.code, "INTEGRITY_FAILURE")

    def test_health_fails_when_sealed(self):
        self.create()
        self.store.sealed_path.write_text("sealed\n")
        with self.assertRaises(GateError) as caught:
            self.store.health()
        self.assertEqual(caught.exception.code, "SEALED")

    def test_no_plaintext_in_database(self):
        self.create("Distinctive Title")
        raw = self.store.db_path.read_bytes()
        self.assertNotIn(b"Distinctive Title", raw)
        self.assertNotIn(b"synthetic-secret", raw)

    def test_tombstone_hides_record_and_keeps_revisions(self):
        result = self.create()
        self.store.delete(result["id"], expected_version=1)
        self.assertEqual(self.store.find("Example"), [])
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM revisions WHERE record_id=?", (result["id"],)).fetchone()[0], 1)

    def test_exec_env_spec_parsing(self):
        self.assertEqual(_split_env("MY_VAR=My Service:credential"), ("MY_VAR", "My Service", "credential"))
        for bad in ("MY_VAR", "MY_VAR=record", "1BAD=record:field", "=record:field"):
            with self.subTest(spec=bad):
                with self.assertRaises(GateError):
                    _split_env(bad)


class StoreHardeningCase(unittest.TestCase):
    """Adversarial checks: an attacker who can edit gate.db but has no root key."""

    def setUp(self):
        self.base = isolate(self, root_key=b"h" * 32)
        self.store = GateStore(self.base / "state")
        self.store.initialize()

    def create(self, value="synthetic-v1"):
        return self.store.create({"title": "Hardening", "category": "Secret", "fields": {"credential": value}})

    def sql(self, *statements):
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            for statement, params in statements:
                conn.execute(statement, params)
            conn.commit()

    def assert_integrity_failure(self, call):
        with self.assertRaises(GateError) as caught:
            call()
        self.assertEqual(caught.exception.code, "INTEGRITY_FAILURE")

    def test_audit_tail_truncation_with_repointed_anchor_is_detected(self):
        rid = self.create()["id"]
        self.store.get(rid)
        self.store.get(rid)
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            conn.execute("DELETE FROM audit WHERE seq=(SELECT MAX(seq) FROM audit)")
            last = conn.execute("SELECT event_hmac FROM audit ORDER BY seq DESC LIMIT 1").fetchone()[0]
            # The pre-fix anchor format was simply the last event HMAC, which is stored in the table.
            conn.execute("UPDATE meta SET value=? WHERE key='audit_head'", (bytes(last).hex(),))
            conn.commit()
        self.assert_integrity_failure(self.store.health)
        self.assert_integrity_failure(lambda: self.store.get(rid))

    def test_deleted_anchor_with_truncated_chain_is_detected(self):
        rid = self.create()["id"]
        self.store.get(rid)
        self.sql(("DELETE FROM audit WHERE seq=(SELECT MAX(seq) FROM audit)", ()),
                 ("DELETE FROM meta WHERE key='audit_head'", ()))
        self.assert_integrity_failure(self.store.health)
        self.assert_integrity_failure(lambda: self.store.get(rid))

    def test_deleting_entire_audit_log_and_anchor_blocks_release_and_writes(self):
        rid = self.create()["id"]
        self.sql(("DELETE FROM audit", ()), ("DELETE FROM meta WHERE key='audit_head'", ()))
        self.assert_integrity_failure(lambda: self.store.get(rid))
        self.assert_integrity_failure(lambda: self.store.patch(rid, {"title": "x"}, expected_version=1))

    def test_record_rolled_back_to_older_revision_is_never_served(self):
        rid = self.create("synthetic-old")["id"]
        self.store.patch(rid, {"fields": {"credential": "synthetic-new"}}, expected_version=1)
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            nonce, ciphertext = conn.execute("SELECT nonce,ciphertext FROM revisions WHERE record_id=? AND version=1", (rid,)).fetchone()
            # A valid older blob: its AAD matches version 1, so decryption alone succeeds.
            conn.execute("UPDATE records SET version=1,nonce=?,ciphertext=? WHERE id=?", (nonce, ciphertext, rid))
            conn.commit()
        self.assert_integrity_failure(lambda: self.store.get(rid))
        self.assert_integrity_failure(lambda: self.store.get_record(rid))
        self.assert_integrity_failure(lambda: self.store.patch(rid, {"title": "x"}, expected_version=1))
        self.assert_integrity_failure(lambda: self.store.delete(rid, expected_version=1))

    def test_untombstoned_record_is_not_released(self):
        rid = self.create()["id"]
        self.store.delete(rid, expected_version=1)
        self.sql(("UPDATE records SET deleted_at=NULL WHERE id=?", (rid,)))
        self.assert_integrity_failure(lambda: self.store.get(rid))

    def test_release_uses_the_row_current_at_audit_time(self):
        rid = self.create("synthetic-before")["id"]
        real_resolve = self.store.resolve
        edited = []

        def resolve_then_concurrent_edit(reference):
            resolved = real_resolve(reference)
            if not edited:
                edited.append(True)
                # Another writer commits between name resolution and the audited release.
                self.store.patch(rid, {"fields": {"credential": "synthetic-after"}}, expected_version=1)
            return resolved

        with patch.object(self.store, "resolve", side_effect=resolve_then_concurrent_edit):
            self.assertEqual(self.store.get(rid), "synthetic-after")
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            read = conn.execute("SELECT version FROM audit WHERE action='read_field' ORDER BY seq DESC LIMIT 1").fetchone()[0]
        self.assertEqual(read, 2)

    def test_vault_files_are_owner_only_from_creation(self):
        old_umask = os.umask(0)
        try:
            # With chmod disabled, only the creation mode protects the files.
            with patch("os.chmod"):
                store = GateStore(self.base / "fresh")
                store.initialize()
                store.create({"title": "Perm", "category": "Secret", "fields": {"credential": "x"}})
                backup = store.backup(self.base / "backups" / "copy.db")
        finally:
            os.umask(old_umask)
        for path in (store.db_path, store.envelope_path, Path(backup["path"])):
            with self.subTest(path=path.name):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_backup_refuses_existing_destination_and_symlink(self):
        self.create()
        existing = self.base / "existing.db"
        existing.write_text("keep")
        with self.assertRaises(GateError) as caught:
            self.store.backup(existing)
        self.assertEqual(caught.exception.code, "INVALID")
        self.assertEqual(existing.read_text(), "keep")
        victim = self.base / "victim.txt"
        victim.write_text("keep")
        link = self.base / "link.db"
        link.symlink_to(victim)
        with self.assertRaises(GateError):
            self.store.backup(link)
        self.assertEqual(victim.read_text(), "keep")

    def test_recovery_envelope_work_factor_and_format_are_bounded(self):
        good = crypto.wrap_for_recovery(b"k" * 32, "synthetic-code")
        self.assertEqual(crypto.unwrap_recovery(good, "synthetic-code"), b"k" * 32)
        for change in ({"iterations": 1}, {"iterations": 599_999}, {"iterations": 10**12}, {"iterations": "600000"},
                       {"kdf": "pbkdf2-sha1"}, {"version": 2}, {"nonce": crypto.b64e(b"n" * 8)}, {"salt": crypto.b64e(b"s" * 4)}):
            with self.subTest(change=change):
                with patch("arcturion_gate.crypto.PBKDF2HMAC") as kdf:
                    with self.assertRaises(ValueError):
                        crypto.unwrap_recovery({**good, **change}, "synthetic-code")
                    kdf.assert_not_called()

    def test_audit_purpose_is_keyed_not_a_guessable_plain_hash(self):
        rid = self.create()["id"]
        self.store.get(rid, purpose="nightly sync")
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            purposes = [r[0] for r in conn.execute("SELECT purpose FROM audit WHERE action='read_field'")]
        self.assertEqual(len(purposes), 1)
        self.assertTrue(purposes[0].startswith("hmac:"))
        self.assertNotIn(hashlib.sha256(b"nightly sync").hexdigest(), purposes[0])

    def test_outbox_digest_is_keyed_not_a_plain_hash_of_the_title(self):
        rid = self.create()["id"]
        safe = {"id": rid, "title": "Hardening", "category": "Secret", "version": 1, "tags": [], "deleted": False}
        plain = hashlib.sha256(json.dumps(safe, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            stored = conn.execute("SELECT payload_hash FROM outbox WHERE record_id=?", (rid,)).fetchone()[0]
        self.assertNotEqual(stored, plain)


if __name__ == "__main__":
    unittest.main()
