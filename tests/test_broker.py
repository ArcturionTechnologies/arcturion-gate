from __future__ import annotations

import json
import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch

from arcturion_gate.broker import Broker
from arcturion_gate.errors import GateError
from arcturion_gate.store import GateStore

from helpers import isolate


class BrokerCase(unittest.TestCase):
    """Field-level private read/write semantics against a synthetic encrypted vault."""

    def setUp(self):
        base = isolate(self, root_key=b"r" * 32)
        self.store = GateStore(base / "state", catalog=base / "catalog")
        self.store.initialize()
        self.broker = Broker(self.store)
        self.secret = "synthetic-only:private:credential:794241"

    def create_pending(self, name="Pending test"):
        return self.broker.put_secret(
            name, self.secret, field="password", expected_version=0,
            metadata={"category": "Secret", "tags": ["pending", "personal"]},
            idempotency_key="test-create:" + name, purpose="synthetic fixture",
        )

    def test_upsert_and_return_shape(self):
        created = self.broker.put_secret("Upsert", self.secret, extra={"username": "fixture"})
        updated = self.broker.put_secret("Upsert", "synthetic replacement")
        self.assertEqual(created["id"], updated["id"])
        self.assertEqual(updated["version"], 2)
        self.assertEqual(self.broker.get_secret("Upsert"), "synthetic replacement")

    def test_version_checked_metadata_and_fields(self):
        created = self.create_pending()
        result = self.broker.put_secret(
            created["id"], "synthetic replacement", field="password",
            expected_version=1, idempotency_key="test-patch",
            metadata={"title": "Active fixture", "category": "Login",
                      "aliases": ["fixture-account"], "tags": ["active"],
                      "notes_markdown": "Encrypted fixture note."},
            extra={"username": "fixture", "url": "https://example.test"},
        )
        self.assertEqual(result["version"], 2)
        self.assertEqual(self.store.inspect("fixture-account")["id"], created["id"])
        record = self.store.get_record(created["id"])
        self.assertEqual(record["notes_markdown"], "Encrypted fixture note.")
        self.assertEqual(record["tags"], ["active"])
        self.assertEqual(record["category"], "Login")

    def test_stale_write_preserves_original_and_candidate_can_be_saved(self):
        created = self.create_pending()
        self.broker.put_secret(created["id"], "current synthetic", field="password", expected_version=1)
        with self.assertRaises(GateError) as caught:
            self.broker.put_secret(created["id"], self.secret, field="password", expected_version=1)
        self.assertEqual(caught.exception.code, "VERSION_CONFLICT")
        self.assertEqual(self.broker.get_secret(created["id"], "password"), "current synthetic")
        conflict = self.broker.put_secret(
            "Conflict fixture", self.secret, field="password", expected_version=0,
            metadata={"category": "Secret", "tags": ["pending", "conflict"]},
            idempotency_key="conflict-operation",
        )
        self.assertNotEqual(created["id"], conflict["id"])
        self.assertEqual(self.broker.get_secret(conflict["id"], "password"), self.secret)

    def test_missing_positive_version_never_creates(self):
        with self.assertRaises(GateError) as caught:
            self.broker.put_secret("Missing fixture", self.secret, expected_version=1)
        self.assertEqual(caught.exception.code, "VERSION_CONFLICT")
        self.assertEqual(self.store.find("Missing fixture"), [])

    def test_create_only_does_not_update_existing(self):
        created = self.create_pending()
        with self.assertRaises(GateError) as caught:
            self.broker.put_secret(
                "Pending test", "other synthetic", field="password", expected_version=0,
                metadata={"category": "Secret"}, idempotency_key="different-operation",
            )
        self.assertEqual(caught.exception.code, "VERSION_CONFLICT")
        self.assertEqual(self.broker.get_secret(created["id"], "password"), self.secret)

    def test_create_only_requires_key(self):
        with self.assertRaises(GateError) as caught:
            self.broker.put_secret("Fixture", self.secret, expected_version=0)
        self.assertEqual(caught.exception.code, "INVALID")

    def test_identical_create_and_patch_retries_return_original_receipt(self):
        first = self.create_pending()
        replay = self.create_pending()
        self.assertEqual(first, replay)
        request = dict(field="password", expected_version=1, idempotency_key="test-patch")
        changed = self.broker.put_secret(first["id"], "synthetic replacement", **request)
        replayed = self.broker.put_secret(first["id"], "synthetic replacement", **request)
        self.assertEqual(changed, replayed)
        self.assertEqual(self.store.inspect(first["id"])["version"], 2)

    def test_idempotency_cannot_replay_different_payload_or_target(self):
        first = self.create_pending()
        changed = self.broker.put_secret(first["id"], "synthetic replacement", field="password",
                                         expected_version=1, idempotency_key="operation-key")
        with self.assertRaises(GateError) as caught:
            self.broker.put_secret(first["id"], "wrong synthetic replacement", field="password",
                                   expected_version=1, idempotency_key="operation-key")
        self.assertEqual(caught.exception.code, "VERSION_CONFLICT")
        second = self.create_pending("Second fixture")
        other = self.broker.put_secret(second["id"], "synthetic replacement", field="password",
                                       expected_version=1, idempotency_key="operation-key")
        self.assertNotEqual(changed["id"], other["id"])

    def test_concurrent_create_only_cannot_duplicate_pending_record(self):
        barrier = Barrier(2)
        original_inspect = self.store.inspect

        def simultaneous_inspect(reference):
            try:
                return original_inspect(reference)
            finally:
                barrier.wait(timeout=5)

        def request():
            try:
                return self.create_pending("Concurrent fixture")
            except GateError as exc:
                return {"rejected": exc.code}

        with patch.object(self.store, "inspect", side_effect=simultaneous_inspect):
            with ThreadPoolExecutor(max_workers=2) as workers:
                results = list(workers.map(lambda _: request(), range(2)))
        committed = [result for result in results if result.get("committed")]
        rejected = [result for result in results if "rejected" in result]
        self.assertTrue(committed)
        self.assertEqual(len({result["id"] for result in committed}), 1)
        self.assertTrue(all(result["rejected"] in {"INVALID", "VERSION_CONFLICT"} for result in rejected))
        self.assertEqual(len(self.store.find("Concurrent fixture")), 1)
        self.assertEqual(self.store.inspect("Concurrent fixture")["version"], 1)

    def test_invalid_metadata_errors_do_not_echo_values(self):
        for metadata in ({"fields": {"credential": self.secret}},
                         {"category": self.secret}, {"tags": self.secret}):
            with self.subTest(metadata_keys=list(metadata)):
                with self.assertRaises(GateError) as caught:
                    self.broker.put_secret("Fixture", self.secret, metadata=metadata)
                self.assertEqual(caught.exception.code, "INVALID")
                self.assertNotIn(self.secret, str(caught.exception))
                self.assertNotIn(self.secret, json.dumps(caught.exception.to_dict()))

    def test_lookup_errors_do_not_echo_reference(self):
        with self.assertRaises(GateError) as caught:
            self.broker.get_secret(self.secret)
        self.assertEqual(caught.exception.code, "NOT_FOUND")
        self.assertNotIn(self.secret, str(caught.exception))

    def test_invalid_versions_and_extra_are_rejected(self):
        for version in (-1, True, "1", 1.5):
            with self.subTest(version_type=type(version).__name__):
                with self.assertRaises(GateError) as caught:
                    self.broker.put_secret("Fixture", self.secret, expected_version=version)
                self.assertEqual(caught.exception.code, "INVALID")
        with self.assertRaises(GateError):
            self.broker.put_secret("Fixture", self.secret, extra={"seed": None})

    def test_no_secrets_in_receipt_catalog_or_database(self):
        result = self.create_pending()
        self.assertNotIn(self.secret, json.dumps(result))
        self.assertNotIn(self.secret.encode(), self.store.db_path.read_bytes())
        for artifact in self.store.catalog.rglob("*"):
            if artifact.is_file():
                self.assertNotIn(self.secret.encode(), artifact.read_bytes())

    def test_audit_failure_withholds_reads_and_rolls_back_write(self):
        created = self.create_pending()
        with patch.object(self.store, "_audit", side_effect=RuntimeError("fixture audit failure")):
            with self.assertRaises(RuntimeError):
                self.broker.get_secret(created["id"], "password")
            with self.assertRaises(RuntimeError):
                self.broker.put_secret(created["id"], "synthetic replacement", field="password", expected_version=1)
        self.assertEqual(self.store.inspect(created["id"])["version"], 1)
        self.assertEqual(self.broker.get_secret(created["id"], "password"), self.secret)

    def test_storage_failure_does_not_return_commit_receipt(self):
        created = self.create_pending()
        with patch.object(self.store, "patch", side_effect=sqlite3.OperationalError("fixture storage failure")):
            with self.assertRaises(sqlite3.OperationalError):
                self.broker.put_secret(created["id"], "synthetic replacement", field="password", expected_version=1)
        self.assertEqual(self.store.inspect(created["id"])["version"], 1)


if __name__ == "__main__":
    unittest.main()
