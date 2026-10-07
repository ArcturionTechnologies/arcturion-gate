from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import unittest
from unittest.mock import patch

from arcturion_gate.broker import Broker
from arcturion_gate.errors import GateError
from arcturion_gate.store import Gate, GateStore
from arcturion_gate.mcp_server.service import Service, totp
from arcturion_gate.mcp_server.state import State, PrivateError, origin

from helpers import TEST_EXTENSION_ID, TEST_EXTENSION_ORIGIN as EXTENSION_ORIGIN, isolate


def fixture_target(**changes):
    target = {
        "tab_id": 10, "frame_id": 0, "document_id": "fixture-document",
        "origin": EXTENSION_ORIGIN, "document_path": "/fixture.html",
        "field": {"selector": "#password", "fingerprint": "fixture-password", "kind": "password"},
        "account_hash": "a" * 64, "synthetic": True,
    }
    target.update(changes)
    return target


class OperationSecurityCase(unittest.TestCase):
    def setUp(self):
        base = isolate(self)
        self.now = 1000.0
        self.state = State(base / "operations", clock=lambda: self.now, extension_id=TEST_EXTENSION_ID)
        self.target = fixture_target()
        published = self.state.publish("profile-one", [self.target])
        self.target_ref = published["targets"][0]["target_id"]

    def issue(self):
        return self.state.issue(self.target_ref, {"action": "fill", "kind": "password", "record_ref": "fixture-id", "version": 1})

    def test_complete_then_replay_never_claims_twice(self):
        issued = self.issue()
        handle = issued["operation_handle"]
        self.state.claim(handle, "profile-one", self.target)
        receipt = self.state.complete(handle, "profile-one", {"status": "filled"})
        self.assertEqual(self.state.receipt(handle), receipt)
        with self.assertRaises(PrivateError) as error:
            self.state.claim(handle, "profile-one", self.target)
        self.assertEqual(error.exception.code, "REPLAY")

    def test_expiry_boundary_is_exclusive(self):
        handle = self.issue()["operation_handle"]
        self.now = 1119.999
        self.assertEqual(self.state.describe(handle, "profile-one")["action"], "fill")
        self.now = 1120.0
        with self.assertRaises(PrivateError) as error:
            self.state.claim(handle, "profile-one", self.target)
        self.assertEqual(error.exception.code, "EXPIRED_HANDLE")

    def test_profile_and_every_target_binding_must_match(self):
        handle = self.issue()["operation_handle"]
        with self.assertRaises(PrivateError) as error:
            self.state.claim(handle, "profile-two", self.target)
        self.assertEqual(error.exception.code, "WRONG_PROFILE")
        alterations = [
            {"tab_id": 11}, {"frame_id": 1}, {"document_id": "navigated"},
            {"account_hash": "b" * 64}, {"document_path": "/another"},
            {"field": {"selector": "#other", "fingerprint": "other", "kind": "password"}},
            {"field": {"selector": "#password", "fingerprint": "fixture-password", "kind": "totp"}},
            {"origin": "https://other.example", "synthetic": False},
        ]
        for alteration in alterations:
            with self.subTest(changed=list(alteration)):
                with self.assertRaises(PrivateError):
                    self.state.claim(handle, "profile-one", fixture_target(**alteration))
        self.state.claim(handle, "profile-one", self.target)

    def test_concurrent_issue_and_claim_are_serialized(self):
        def issue():
            try:
                return self.issue()
            except PrivateError as error:
                return {"error": error.code}
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: issue(), range(2)))
        successes = [r for r in results if "operation_handle" in r]
        self.assertEqual(len(successes), 1)
        self.assertEqual([r["error"] for r in results if "error" in r], ["DESTINATION_BUSY"])
        handle = successes[0]["operation_handle"]
        def claim():
            try:
                self.state.claim(handle, "profile-one", self.target)
                return "claimed"
            except PrivateError as error:
                return error.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: claim(), range(2)))
        self.assertCountEqual(outcomes, ["claimed", "REPLAY"])

    def test_strict_https_origin(self):
        self.assertEqual(origin("https://example.test:443/"), "https://example.test")
        self.assertEqual(origin("https://example.test:8443"), "https://example.test:8443")
        for invalid in ("http://example.test", "https://user@example.test", "https://example.test/login",
                        "https://EXAMPLE.test", "https://example.test?credential=x",
                        "https://example.test:bad", "https://example.test#fragment"):
            with self.subTest(origin=invalid):
                with self.assertRaises(PrivateError):
                    origin(invalid)

    def test_profile_auth_is_not_a_self_reported_name(self):
        with self.assertRaises(PrivateError) as error:
            self.state.authenticate("profile-one", "a" * 64)
        self.assertEqual(error.exception.code, "WRONG_PROFILE")
        enrollment = {"nonce": "approved-enrollment", "expires": 1100}
        (self.state.root / "enrollment.json").write_text(json.dumps(enrollment))
        self.state.enroll("12345678-1234-1234-1234-123456789abc", "a" * 64, enrollment["nonce"])
        self.state.authenticate("12345678-1234-1234-1234-123456789abc", "a" * 64)
        with self.assertRaises(PrivateError):
            self.state.authenticate("12345678-1234-1234-1234-123456789abc", "b" * 64)
        self.assertFalse((self.state.root / "enrollment.json").exists())


class TotpSecurityCase(unittest.TestCase):
    def test_rfc6238_all_algorithms_and_times(self):
        fixtures = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ]
        for algorithm, raw, column in [
            ("SHA1", b"12345678901234567890", 1),
            ("SHA256", b"12345678901234567890123456789012", 2),
            ("SHA512", b"1234567890123456789012345678901234567890123456789012345678901234", 3),
        ]:
            seed = base64.b32encode(raw).decode()
            for row in fixtures:
                with self.subTest(algorithm=algorithm, timestamp=row[0]):
                    value, expires = totp(seed, row[0], digits=8, algorithm=algorithm)
                    self.assertEqual(value, row[column])
                    self.assertEqual(expires, (row[0] // 30 + 1) * 30)

    def test_expiry_exactly_tracks_step_boundary(self):
        seed = base64.b32encode(b"12345678901234567890").decode()
        before, expiry_before = totp(seed, 29.999)
        after, expiry_after = totp(seed, 30)
        self.assertNotEqual(before, after)
        self.assertEqual((expiry_before, expiry_after), (30, 60))

    def test_duplicate_setup_secrets_rejected(self):
        with self.assertRaises(PrivateError) as error:
            totp("otpauth://totp/fixture?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&secret=JBSWY3DPEHPK3PXP", 59)
        self.assertEqual(error.exception.code, "INVALID_TOTP")

    def test_invalid_seed_never_echoed(self):
        for seed in ("synthetic-invalid-value", "otpauth://hotp/fixture?secret=private-invalid",
                     "otpauth://totp/fixture?secret=invalid&period=0", ""):
            with self.subTest(kind=seed.split(":")[0]):
                with self.assertRaises(PrivateError) as error:
                    totp(seed, 59)
                self.assertNotIn(seed, str(error.exception)) if seed else None


class ServiceSecurityCase(unittest.TestCase):
    def setUp(self):
        root = isolate(self)
        self.store = GateStore(root / "vault", catalog=root / "catalog")
        self.store.initialize()
        self.gate = Gate(store=self.store)
        self.broker = Broker(self.store)
        self.state = State(root / "operations", clock=lambda: 1000, extension_id=TEST_EXTENSION_ID)
        self.service = Service(self.state, self.gate, self.broker)
        self.secret = "synthetic-only-browser-secret-81749"
        self.record = self.broker.put_secret("Fixture", self.secret, field="password", expected_version=0,
                                       metadata={"category": "Secret", "tags": ["gate:synthetic"]},
                                       idempotency_key="fixture-private-create")
        self.target = fixture_target()
        self.target_ref = self.state.publish("profile-one", [self.target])["targets"][0]["target_id"]

    def descriptor(self):
        handle = self.service.use(self.record["id"], self.target_ref)["operation_handle"]
        return self.state.claim(handle, "profile-one", self.target), handle

    def test_no_values_in_public_inspect_or_descriptor_or_operation_db(self):
        descriptor, handle = self.descriptor()
        for response in (self.service.inspect(self.record["id"]), self.service.search("Fixture"),
                         descriptor):
            self.assertNotIn(self.secret, json.dumps(response))
        self.assertNotIn(self.secret.encode(), self.state.db.read_bytes())
        self.assertNotIn(self.secret.encode(), self.store.db_path.read_bytes())
        for artifact in self.store.catalog.rglob("*"):
            if artifact.is_file():
                self.assertNotIn(self.secret.encode(), artifact.read_bytes())

    def test_audit_failure_withholds_browser_value(self):
        descriptor, handle = self.descriptor()
        with patch.object(self.store, "_audit", side_effect=RuntimeError("synthetic audit failure")):
            with self.assertRaises(Exception):
                self.service.native_execute(descriptor, handle=handle)

    def test_browser_version_race_withholds_changed_secret(self):
        descriptor, handle = self.descriptor()
        original_get = self.broker.get_secret
        def race(ref, field="credential", **kwargs):
            if field == "password":
                self.broker.put_secret(ref, "synthetic-racing-replacement", field="password", expected_version=1)
            return original_get(ref, field, **kwargs)
        with patch.object(self.broker, "get_secret", side_effect=race):
            with self.assertRaises(PrivateError) as error:
                self.service.native_execute(descriptor, handle=handle)
        self.assertEqual(error.exception.code, "VERSION_CONFLICT")

    def test_capture_stale_edit_preserves_both_candidates(self):
        handle = self.service.prepare_capture("Captured candidate", self.target_ref, "password",
                                             previous_record=self.record["id"], expected_version=1)["operation_handle"]
        descriptor = self.state.claim(handle, "profile-one", self.target)
        self.broker.put_secret(self.record["id"], "synthetic-current-working", field="password", expected_version=1)
        receipt = self.service.native_execute(descriptor, captured_value=self.secret, handle=handle)
        self.assertEqual(receipt["status"], "conflict_preserved")
        self.assertEqual(self.broker.get_secret(self.record["id"], "password"), "synthetic-current-working")
        self.assertEqual(self.broker.get_secret(receipt["record_id"], "password"), self.secret)
        self.assertNotIn(self.secret, json.dumps(receipt))

    def test_live_record_cannot_release_to_synthetic_fixture(self):
        meta = self.store.inspect(self.record["id"])
        self.store.patch(self.record["id"], {"tags": []}, expected_version=meta["version"])
        descriptor, handle = self.descriptor()
        with self.assertRaises(PrivateError) as error:
            self.service.native_execute(descriptor, handle=handle)
        self.assertEqual(error.exception.code, "LIVE_SECRET_ON_FIXTURE")

    def test_pending_totp_and_false_service_confirmation_rejected(self):
        seed = base64.b32encode(b"12345678901234567890").decode()
        pending = self.service._pending("Pending TOTP", "totp", {"totp": seed}, synthetic=True)
        real_target_ref = self.state.publish("profile-one", [fixture_target(synthetic=False, origin="https://example.test", document_path="/login",
            field={"selector": "#otp", "fingerprint": "otp", "kind": "totp"})])["targets"][0]["target_id"]
        with self.assertRaises(PrivateError) as error:
            self.service.use(pending["record_id"], real_target_ref, kind="totp")
        self.assertEqual(error.exception.code, "ENROLLMENT_HANDOFF_REQUIRED")
        with self.assertRaises(PrivateError) as error:
            self.service.workflow(pending["record_id"], "verify", expected_version=pending["version"])
        self.assertEqual(error.exception.code, "SERVICE_CONFIRMATION_REQUIRED")

    def test_service_rejection_keeps_previous_working_credential(self):
        pending = self.service.generate("Pending change", previous_record=self.record["id"], synthetic=True)
        rejection = self.service.workflow(pending["record_id"], "reject", expected_version=pending["version"])
        self.assertEqual(rejection["status"], "service_rejected")
        self.assertEqual(self.broker.get_secret(self.record["id"], "password"), self.secret)
        status = self.service.workflow(pending["record_id"])
        self.assertEqual(status["workflow"]["previous_record"], self.record["id"])

    def api_policy(self):
        client = self.state.root / "synthetic-client"
        client.write_text(
            "#!" + sys.executable + "\n"
            "import os, sys\n"
            "secret = os.environ['FIXTURE_CREDENTIAL']\n"
            "sys.stdout.write(secret)\n"
            "sys.stderr.write(secret)\n"
            "raise SystemExit(0 if secret else 9)\n"
        )
        client.chmod(0o700)
        policy = {"executable": str(client), "sha256": hashlib.sha256(client.read_bytes()).hexdigest(),
                  "env_key": "FIXTURE_CREDENTIAL", "field": "password", "synthetic": True, "argv": []}
        policy_path = self.state.root / "api-clients.json"
        policy_path.write_text(json.dumps({"fixture-client": policy}))
        policy_path.chmod(0o600)
        return client

    def test_api_client_output_is_private_and_receipt_value_free(self):
        self.api_policy()
        receipt = self.service.inject(self.record["id"], "fixture-client", expected_version=1)
        self.assertEqual(receipt["status"], "client_completed")
        self.assertEqual(receipt["exit_code"], 0)
        self.assertNotIn(self.secret, json.dumps(receipt))
        for artifact in self.state.root.rglob("*"):
            if artifact.is_file():
                self.assertNotIn(self.secret.encode(), artifact.read_bytes())

    def test_api_version_race_withholds_before_client_spawn(self):
        self.api_policy()
        original_get = self.broker.get_secret
        def race(ref, field="credential", **kwargs):
            if field == "password":
                self.broker.put_secret(ref, "synthetic-racing-replacement", field="password", expected_version=1)
            return original_get(ref, field, **kwargs)
        with patch.object(self.broker, "get_secret", side_effect=race), patch("arcturion_gate.mcp_server.service.subprocess.run") as run:
            with self.assertRaises(PrivateError) as error:
                self.service.inject(self.record["id"], "fixture-client", expected_version=1)
        self.assertEqual(error.exception.code, "VERSION_CONFLICT")
        run.assert_not_called()

    def test_audit_failure_withholds_before_client_spawn(self):
        self.api_policy()
        with patch.object(self.store, "_audit", side_effect=RuntimeError("synthetic audit failure")), patch("arcturion_gate.mcp_server.service.subprocess.run") as run:
            with self.assertRaises(Exception):
                self.service.inject(self.record["id"], "fixture-client", expected_version=1)
        run.assert_not_called()

    def test_unapproved_changed_and_live_to_fixture_clients_rejected(self):
        with self.assertRaises(PrivateError) as error:
            self.service.inject(self.record["id"], "arbitrary-program")
        self.assertEqual(error.exception.code, "CLIENT_NOT_APPROVED")
        client = self.api_policy()
        client.write_text("#!/bin/sh\nexit 0\n")
        with patch("arcturion_gate.mcp_server.service.subprocess.run") as run:
            with self.assertRaises(PrivateError) as error:
                self.service.inject(self.record["id"], "fixture-client")
        self.assertEqual(error.exception.code, "CLIENT_CHANGED")
        run.assert_not_called()
        self.api_policy()
        self.store.patch(self.record["id"], {"tags": []}, expected_version=1)
        with patch("arcturion_gate.mcp_server.service.subprocess.run") as run:
            with self.assertRaises(PrivateError) as error:
                self.service.inject(self.record["id"], "fixture-client")
        self.assertEqual(error.exception.code, "LIVE_SECRET_ON_FIXTURE")
        run.assert_not_called()

    def test_organization_cannot_forge_system_provenance_tags(self):
        with self.assertRaises(PrivateError):
            self.service.organize(self.record["id"], 1, tags=["gate:verified", "gate:synthetic"])

    def enroll_native_profile(self):
        profile = "12345678-1234-1234-1234-123456789abc"
        auth = "a" * 64
        (self.state.root / "enrollment.json").write_text(json.dumps({"nonce": "approved-enrollment", "expires": 1100}))
        self.state.enroll(profile, auth, "approved-enrollment")
        return profile, auth

    def test_wrong_native_extension_is_rejected_before_secret_read(self):
        from arcturion_gate.mcp_server.native import dispatch
        with patch.object(self.broker, "get_secret") as get:
            with self.assertRaises(PrivateError) as error:
                dispatch(self.service, {"protocol": 1, "action": "execute"}, "chrome-extension://attacker/")
        self.assertEqual(error.exception.code, "WRONG_EXTENSION")
        get.assert_not_called()

    def test_native_fill_completion_cannot_forge_service_verification(self):
        from arcturion_gate.mcp_server.native import dispatch
        profile, auth = self.enroll_native_profile()
        target_id = self.state.publish(profile, [self.target])["targets"][0]["target_id"]
        handle = self.service.use(self.record["id"], target_id)["operation_handle"]
        request = {"protocol": 1, "action": "execute", "profile_id": profile, "profile_auth": auth,
                   "handle": handle, "target": self.target}
        private_value = dispatch(self.service, request, EXTENSION_ORIGIN + "/")
        self.assertEqual(private_value["value"], self.secret)
        complete = {**request, "action": "complete", "lease_id": handle, "outcome": "service_verified",
                    "receipt": {"status": "service_verified", "record_id": self.record["id"]}}
        receipt = dispatch(self.service, complete, EXTENSION_ORIGIN + "/")
        self.assertEqual(receipt["status"], "rejected")
        self.assertFalse(receipt["service_confirmation"])
        self.assertNotIn(self.secret, json.dumps(receipt))


    def completed_fill(self, ref=None):
        from arcturion_gate.mcp_server.native import dispatch
        profile, auth = self.enroll_native_profile()
        target_id = self.state.publish(profile, [self.target])["targets"][0]["target_id"]
        ref = ref or self.record["id"]
        version = self.store.inspect(ref)["version"]
        issued = self.service.use(ref, target_id, expected_version=version)
        handle = issued["operation_handle"]
        request = {"protocol": 1, "action": "execute", "profile_id": profile, "profile_auth": auth,
                   "handle": handle, "target": self.target}
        private_fill = dispatch(self.service, request, EXTENSION_ORIGIN + "/")
        complete = {**request, "action": "complete", "lease_id": handle, "outcome": "filled"}
        dispatch(self.service, complete, EXTENSION_ORIGIN + "/")
        return profile, auth, target_id, handle, private_fill["value"]

    def verification_request(self, record_ref=None, confirmed=True, changes=None):
        from arcturion_gate.mcp_server.native import dispatch
        ref = record_ref or self.record["id"]
        version = self.store.inspect(ref)["version"]
        profile, auth, target_id, use_handle, private_value = self.completed_fill(ref)
        issued = self.service.workflow(ref, "prepare_verification", expected_version=version,
                                       destination_ref=target_id, use_receipt_handle=use_handle)
        handle = issued["operation_handle"]
        evidence = {k: self.target[k] for k in ("account_hash", "origin", "document_path", "document_id")}
        evidence.update(evidence_code="synthetic_fixture_accepted", confirmed=confirmed, private_value=private_value)
        evidence.update(changes or {})
        request = {"protocol": 1, "action": "execute", "profile_id": profile, "profile_auth": auth,
                   "handle": handle, "target": self.target, "verification": evidence}
        return dispatch(self.service, request, EXTENSION_ORIGIN + "/"), handle

    def test_synthetic_confirmation_promotes_pending_only_after_evidence(self):
        pending = self.service.generate("Synthetic pending", synthetic=True)
        receipt, handle = self.verification_request(pending["record_id"])
        self.assertEqual(receipt["status"], "service_verified")
        changed = self.service.workflow(pending["record_id"], "verify", expected_version=pending["version"], receipt_handle=handle)
        self.assertEqual(changed["status"], "verified")
        self.assertIn("gate:verified", self.store.inspect(pending["record_id"])["tags"])
        self.assertNotIn("gate:pending", self.store.inspect(pending["record_id"])["tags"])
        self.assertNotIn(self.secret, json.dumps(changed))

    def test_service_rejection_and_stale_evidence_cannot_promote(self):
        pending = self.service.generate("Synthetic pending", synthetic=True)
        receipt, handle = self.verification_request(pending["record_id"], confirmed=False)
        self.assertEqual(receipt["status"], "service_rejected")
        with self.assertRaises(PrivateError) as error:
            self.service.workflow(pending["record_id"], "verify", expected_version=pending["version"], receipt_handle=handle)
        self.assertEqual(error.exception.code, "SERVICE_CONFIRMATION_REQUIRED")

    def test_service_evidence_wrong_document_is_withheld(self):
        with self.assertRaises(PrivateError) as error:
            self.verification_request(changes={"document_id": "old-document"})
        self.assertEqual(error.exception.code, "INVALID_SERVICE_EVIDENCE")

    def test_stale_service_evidence_rejected_even_with_current_write_version(self):
        receipt, handle = self.verification_request()
        self.service.organize(self.record["id"], 1, title="Edited fixture")
        with self.assertRaises(PrivateError) as error:
            self.service.workflow(self.record["id"], "verify", expected_version=2, receipt_handle=handle)
        self.assertEqual(error.exception.code, "SERVICE_CONFIRMATION_REQUIRED")


    def test_api_driver_file_tamper_is_rejected_before_spawn(self):
        driver = self.state.root / "synthetic-driver.py"
        driver.write_text("import os\nraise SystemExit(0 if os.environ['FIXTURE_CREDENTIAL'] else 9)\n")
        interpreter = Path(sys.executable).resolve()
        policy = {"executable": str(interpreter), "sha256": hashlib.sha256(interpreter.read_bytes()).hexdigest(),
                  "env_key": "FIXTURE_CREDENTIAL", "field": "password", "synthetic": True,
                  "argv": [str(driver)], "argv_file_sha256": {str(driver): hashlib.sha256(driver.read_bytes()).hexdigest()}}
        (self.state.root / "api-clients.json").write_text(json.dumps({"fixture-driver": policy}))
        self.assertEqual(self.service.inject(self.record["id"], "fixture-driver")["status"], "client_completed")
        driver.write_text("raise SystemExit(0)\n")
        with patch("arcturion_gate.mcp_server.service.subprocess.run") as run:
            with self.assertRaises(PrivateError):
                self.service.inject(self.record["id"], "fixture-driver")
        run.assert_not_called()


    def test_fixture_acceptance_for_record_a_cannot_verify_record_b(self):
        other = self.service.generate("Other synthetic pending", synthetic=True)
        profile, auth, target_id, use_handle, private_value = self.completed_fill()
        with self.assertRaises(PrivateError):
            self.service.workflow(other["record_id"], "prepare_verification", expected_version=other["version"],
                                  destination_ref=target_id, use_receipt_handle=use_handle)
        self.assertEqual(self.service.workflow(other["record_id"])["workflow"]["state"], "stored_pending")

    def test_service_confirmation_must_match_private_candidate(self):
        with self.assertRaises(PrivateError):
            self.verification_request(changes={"private_value": "synthetic-wrong-candidate"})

    def test_verification_requires_completed_bound_use_receipt(self):
        profile, auth = self.enroll_native_profile()
        target_id = self.state.publish(profile, [self.target])["targets"][0]["target_id"]
        with self.assertRaises(PrivateError):
            self.service.workflow(self.record["id"], "prepare_verification", expected_version=1, destination_ref=target_id)

    def test_private_lease_cannot_outlive_issued_operation(self):
        from arcturion_gate.mcp_server.native import dispatch
        profile, auth = self.enroll_native_profile()
        target_id = self.state.publish(profile, [self.target])["targets"][0]["target_id"]
        issued = self.service.use(self.record["id"], target_id, expected_version=1)
        self.state.clock = lambda: 1118.5
        request = {"protocol": 1, "action": "execute", "profile_id": profile, "profile_auth": auth,
                   "handle": issued["operation_handle"], "target": self.target}
        released = dispatch(self.service, request, EXTENSION_ORIGIN + "/")
        self.assertLessEqual(released["expires_at"], issued["expires_at"])

    def test_operation_with_under_one_second_remaining_withholds_value(self):
        from arcturion_gate.mcp_server.native import dispatch
        profile, auth = self.enroll_native_profile()
        target_id = self.state.publish(profile, [self.target])["targets"][0]["target_id"]
        issued = self.service.use(self.record["id"], target_id, expected_version=1)
        self.state.clock = lambda: 1119.5
        request = {"protocol": 1, "action": "execute", "profile_id": profile, "profile_auth": auth,
                   "handle": issued["operation_handle"], "target": self.target}
        with self.assertRaises(PrivateError):
            dispatch(self.service, request, EXTENSION_ORIGIN + "/")


    def synthetic_totp_request(self, later=None):
        from arcturion_gate.mcp_server.native import dispatch
        seed = base64.b32encode(b"12345678901234567890").decode()
        pending = self.service._pending("Synthetic pending TOTP", "totp", {"totp": seed}, synthetic=True)
        profile, auth = self.enroll_native_profile()
        target = fixture_target(field={"selector": "#otp", "fingerprint": "fixture-otp", "kind": "totp"})
        target_id = self.state.publish(profile, [target])["targets"][0]["target_id"]
        issued = self.service.use(pending["record_id"], target_id, kind="totp", expected_version=pending["version"])
        if later is not None:
            self.state.clock = lambda: later
        request = {"protocol": 1, "action": "execute", "profile_id": profile, "profile_auth": auth,
                   "handle": issued["operation_handle"], "target": target}
        return dispatch(self.service, request, EXTENSION_ORIGIN + "/"), seed

    def test_pending_synthetic_totp_can_fill_fixture_privately(self):
        private, seed = self.synthetic_totp_request()
        self.assertEqual(private["value"], totp(seed, 1000)[0])
        self.assertNotEqual(private["value"], seed)
        self.assertEqual(private["expires_at"], 1020)

    def test_totp_lease_with_under_five_seconds_of_operation_lifetime_withheld(self):
        with self.assertRaises(PrivateError):
            self.synthetic_totp_request(later=1116)


    def verified_candidate(self):
        pending = self.service.generate("Verified change candidate", previous_record=self.record["id"], synthetic=True)
        receipt, handle = self.verification_request(pending["record_id"])
        verified = self.service.workflow(pending["record_id"], "verify", expected_version=pending["version"], receipt_handle=handle)
        return verified

    def test_verified_update_preserves_prior_encrypted_revision(self):
        candidate = self.verified_candidate()
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            prior = conn.execute("SELECT nonce,ciphertext FROM revisions WHERE record_id=? AND version=1", (self.record["id"],)).fetchone()
        changed = self.service.workflow(candidate["record_id"], "apply_verified", expected_version=candidate["version"])
        self.assertEqual(changed["record_id"], self.record["id"])
        self.assertTrue(changed["previous_revision_preserved"])
        self.assertEqual(self.broker.get_secret(self.record["id"], "password"), self.broker.get_secret(candidate["record_id"], "password"))
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            preserved = conn.execute("SELECT nonce,ciphertext FROM revisions WHERE record_id=? AND version=1", (self.record["id"],)).fetchone()
        self.assertEqual(prior, preserved)
        self.assertNotIn(self.secret, json.dumps(changed))

    def test_stale_verified_apply_preserves_current_and_candidate(self):
        candidate = self.verified_candidate()
        private_candidate = self.broker.get_secret(candidate["record_id"], "password")
        self.broker.put_secret(self.record["id"], "synthetic-owner-current", "password", expected_version=1)
        with self.assertRaises(GateError) as error:
            self.service.workflow(candidate["record_id"], "apply_verified", expected_version=candidate["version"])
        self.assertEqual(error.exception.code, "VERSION_CONFLICT")
        self.assertEqual(self.broker.get_secret(self.record["id"], "password"), "synthetic-owner-current")
        self.assertEqual(self.broker.get_secret(candidate["record_id"], "password"), private_candidate)

    def test_unverified_password_candidate_cannot_update_working_record(self):
        pending = self.service.generate("Unconfirmed candidate", previous_record=self.record["id"], synthetic=True)
        with self.assertRaises(PrivateError) as error:
            self.service.workflow(pending["record_id"], "apply_verified", expected_version=pending["version"])
        self.assertEqual(error.exception.code, "SERVICE_CONFIRMATION_REQUIRED")
        self.assertEqual(self.broker.get_secret(self.record["id"], "password"), self.secret)

    def test_private_note_apply_is_encrypted_and_repeated_apply_rejected(self):
        note = "synthetic-private-encrypted-note-865124"
        pending = self.service._pending("Private note candidate", "note", {"private_note": note},
                                        previous_record=self.record["id"], previous_version=1, synthetic=True)
        changed = self.service.workflow(pending["record_id"], "apply_private_note", expected_version=pending["version"])
        self.assertEqual(changed["status"], "applied")
        self.assertEqual(self.broker.get_secret(self.record["id"], "private_note"), note)
        self.assertEqual(self.store.get_record(self.record["id"])["notes_markdown"], note)
        self.assertEqual(self.broker.get_secret(self.record["id"], "password"), self.secret)
        self.assertNotIn(note, json.dumps(changed))
        self.assertNotIn(note.encode(), self.store.db_path.read_bytes())
        with self.assertRaises(GateError) as error:
            self.service.workflow(pending["record_id"], "apply_private_note", expected_version=pending["version"])
        self.assertEqual(error.exception.code, "VERSION_CONFLICT")

    def test_synthetic_note_candidate_cannot_modify_live_record(self):
        live = self.broker.put_secret("Live-like fixture", self.secret, "password", expected_version=0,
                                 idempotency_key="live-fixture", metadata={"category": "Secret"})
        pending = self.service._pending("Synthetic note", "note", {"private_note": "synthetic-note"},
                                        previous_record=live["id"], previous_version=1, synthetic=True)
        with self.assertRaises(PrivateError) as error:
            self.service.workflow(pending["record_id"], "apply_private_note", expected_version=pending["version"])
        self.assertEqual(error.exception.code, "LIVE_SECRET_ON_FIXTURE")
        self.assertEqual(self.store.inspect(live["id"])["version"], 1)

    def test_note_candidate_read_race_withholds_update(self):
        pending = self.service._pending("Synthetic note", "note", {"private_note": "synthetic-note"},
                                        previous_record=self.record["id"], previous_version=1, synthetic=True)
        original_get = self.broker.get_secret
        def race(ref, field="credential", **kwargs):
            if ref == pending["record_id"] and field == "private_note":
                self.broker.put_secret(ref, "synthetic-racing-note", field, expected_version=1)
            return original_get(ref, field, **kwargs)
        with patch.object(self.broker, "get_secret", side_effect=race):
            with self.assertRaises(PrivateError) as error:
                self.service.workflow(pending["record_id"], "apply_private_note", expected_version=1)
        self.assertEqual(error.exception.code, "VERSION_CONFLICT")
        self.assertEqual(self.store.inspect(self.record["id"])["version"], 1)
        self.assertEqual(self.broker.get_secret(self.record["id"], "password"), self.secret)



    def inventory_metadata(self, count=137):
        import uuid
        return [{"id": str(uuid.uuid5(uuid.NAMESPACE_URL, "inventory-fixture-" + str(i))),
                 "title": "Inventory fixture " + str(i), "category": "Secret",
                 "version": 1, "tags": ["personal"], "deleted": False} for i in range(count)]

    def test_pagination_completes_large_inventory_without_missing_or_duplicate_records(self):
        inventory = self.inventory_metadata()
        collected = []
        page_sizes = []
        offset = 0
        with patch.object(self.store, "find", return_value=inventory) as find, patch.object(self.broker, "get_secret") as get:
            while offset is not None:
                page = self.service.search("Inventory fixture", limit=50, offset=offset)
                self.assertEqual(page["total"], 137)
                self.assertNotIn(self.secret, json.dumps(page))
                page_sizes.append(len(page["records"]))
                collected.extend(record["id"] for record in page["records"])
                offset = page["next_offset"]
                self.assertLessEqual(len(page_sizes), 3)
            self.assertEqual(page_sizes, [50, 50, 37])
            self.assertEqual(collected, [record["id"] for record in inventory])
            self.assertEqual(len(set(collected)), 137)
            self.assertEqual(find.call_count, 3)
            for call in find.call_args_list:
                self.assertEqual(call.args, ("Inventory fixture",))
            get.assert_not_called()

    def test_pagination_limit_clamps_and_exhausted_offset_returns_empty(self):
        inventory = self.inventory_metadata()
        with patch.object(self.store, "find", return_value=inventory):
            first = self.service.search(limit=999, offset=0)
            self.assertEqual(len(first["records"]), 100)
            self.assertEqual(first["next_offset"], 100)
            last = self.service.search(limit=999, offset=first["next_offset"])
            self.assertEqual(len(last["records"]), 37)
            self.assertIsNone(last["next_offset"])
            exhausted = self.service.search(limit=50, offset=137)
            self.assertEqual(exhausted["records"], [])
            self.assertEqual(exhausted["total"], 137)
            self.assertIsNone(exhausted["next_offset"])

    def test_negative_pagination_offset_rejected_before_inventory_read(self):
        with patch.object(self.store, "find") as find:
            with self.assertRaises(PrivateError) as error:
                self.service.search(offset=-1)
        self.assertEqual(error.exception.code, "INVALID_OFFSET")
        find.assert_not_called()

    def test_health_browser_refresh_uses_only_fixed_private_routes(self):
        try:
            from arcturion_gate.mcp_server import server
        except ModuleNotFoundError as error:
            if error.name == "mcp":
                self.skipTest("Official SDK is tested in the isolated MCP environment")
            raise
        with patch.object(server, "service", return_value=self.service), patch.object(server, "open_operation") as launch:
            fixture = server.credential_health(synthetic_fixture=True)
            self.assertTrue(fixture["ok"])
            launch.assert_called_once_with("fixture")
            self.assertNotIn(self.secret, json.dumps(fixture))
            launch.reset_mock()
            discovered = server.credential_health(refresh_bridge=True)
            self.assertTrue(discovered["ok"])
            launch.assert_called_once_with("discover")
            launch.reset_mock()
            server.credential_health()
            launch.assert_not_called()

    def test_unconfigured_extension_fails_closed_before_secret_read(self):
        from arcturion_gate.mcp_server.native import dispatch
        unconfigured = State(self.state.root.parent / "unconfigured", clock=lambda: 1000, extension_id="")
        service = Service(unconfigured, self.gate, self.broker)
        with patch.object(self.broker, "get_secret") as get:
            with self.assertRaises(PrivateError) as error:
                dispatch(service, {"protocol": 1, "action": "execute"}, EXTENSION_ORIGIN + "/")
        self.assertEqual(error.exception.code, "EXTENSION_NOT_CONFIGURED")
        get.assert_not_called()

    def test_fixture_target_from_another_extension_origin_is_rejected(self):
        foreign = fixture_target(origin="chrome-extension://" + "p" * 32)
        with self.assertRaises(PrivateError) as error:
            self.state.publish("profile-one", [foreign])
        self.assertEqual(error.exception.code, "WRONG_ORIGIN")

    def test_error_envelopes_carry_codes_only(self):
        try:
            from arcturion_gate.mcp_server import server
        except ModuleNotFoundError as error:
            if error.name == "mcp":
                self.skipTest("MCP SDK not installed")
            raise
        def leak():
            raise RuntimeError(self.secret)
        envelope = server.safe(leak)
        self.assertEqual(envelope, {"ok": False, "error": {"code": "PRIVATE_OPERATION_FAILED"}})


if __name__ == "__main__":
    unittest.main()
