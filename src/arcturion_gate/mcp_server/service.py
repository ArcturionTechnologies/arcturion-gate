"""Credential lifecycle service. Public methods never accept or return secret values.

The only method that returns a value is ``native_execute`` for a fill, and it
is called exclusively by the native host, whose stdout is the private pipe to
the enrolled browser extension. Nothing here writes a value to the MCP channel.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path
import resource
import secrets
import string
import struct
import subprocess
import time
import uuid
from urllib.parse import parse_qs, urlsplit

from ..broker import Broker
from ..errors import GateError
from ..store import Gate
from .state import ABSENT_ACCOUNT, PrivateError, State, origin

SYNTHETIC_TAG = "gate:synthetic"
RESERVED_TAG_PREFIX = "gate:"


def totp(seed, timestamp=None, *, digits=6, period=30, algorithm="SHA1"):
    """RFC 6238 TOTP. Returns (code, expiry_timestamp). Never echoes the seed in errors."""
    if seed.startswith("otpauth://"):
        parsed = urlsplit(seed)
        if parsed.netloc != "totp" or parsed.fragment:
            raise PrivateError("INVALID_TOTP")
        values = parse_qs(parsed.query)
        if any(len(v) != 1 for v in values.values()):
            raise PrivateError("INVALID_TOTP")
        try:
            seed = values["secret"][0]
            digits = int(values.get("digits", ["6"])[0])
            period = int(values.get("period", ["30"])[0])
            algorithm = values.get("algorithm", ["SHA1"])[0].upper()
        except (ValueError, KeyError):
            raise PrivateError("INVALID_TOTP") from None
    if algorithm not in {"SHA1", "SHA256", "SHA512"} or digits not in {6, 8} or not 15 <= period <= 120:
        raise PrivateError("INVALID_TOTP")
    try:
        clean = "".join(seed.split()).upper()
        key = base64.b32decode(clean + "=" * (-len(clean) % 8), casefold=True)
        if len(key) < 10:
            raise ValueError()
        now = time.time() if timestamp is None else timestamp
        counter = int(now // period)
        if counter < 0:
            raise ValueError()
        digest = hmac.new(key, struct.pack(">Q", counter), getattr(hashlib, algorithm.lower())).digest()
        offset = digest[-1] & 15
        binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
        return str(binary % (10 ** digits)).zfill(digits), (counter + 1) * period
    except (ValueError, TypeError, base64.binascii.Error, struct.error):
        raise PrivateError("INVALID_TOTP") from None


def account_hash(username):
    return hashlib.sha256(username.strip().casefold().encode()).hexdigest()


class Service:
    def __init__(self, state=None, gate=None, broker=None):
        self.state = state or State()
        self.gate = gate or Gate()
        self.broker = broker or Broker(self.gate.store)

    def _receipt(self, status, **metadata):
        return {"status": status, "receipt_id": str(uuid.uuid4()), **metadata}

    def _workflow(self, ref):
        try:
            return json.loads(self.broker.get_secret(ref, "_gate_workflow", purpose="lifecycle state"))
        except (GateError, PrivateError) as exc:
            if getattr(exc, "code", None) == "NOT_FOUND":
                return {"state": "unmanaged", "kind": "unknown"}
            raise

    def search(self, query="", limit=50, offset=0):
        if offset < 0:
            raise PrivateError("INVALID_OFFSET")
        records = self.gate.store.find(query)
        size = max(1, min(limit, 100))
        page = records[offset:offset + size]
        following = offset + len(page)
        return {"records": page, "total": len(records),
                "next_offset": following if following < len(records) else None,
                "destinations": self.state.targets()}

    def inspect(self, record_ref):
        meta = self.gate.store.inspect(record_ref)
        # Field names, never field values.
        _, payload, _ = self.gate.store.resolve(meta["id"])
        names = set(payload.get("fields", {}))
        workflow = self._workflow(meta["id"])
        return {**meta, "field_names": sorted(n for n in names if not n.startswith("_")),
                "workflow": {k: workflow[k] for k in ("state", "kind", "previous_record") if k in workflow},
                "capabilities": {"password": "password" in names, "totp": bool(names & {"totp", "otp", "seed", "one-time password"}),
                                 "token": bool(names & {"credential", "token"}), "private_notes": bool(payload.get("notes_markdown"))}}

    def organize(self, record_ref, expected_version, title=None, aliases=None, tags=None, ownership=None, category=None):
        patch = {}
        if title is not None: patch["title"] = title
        if aliases is not None: patch["aliases"] = aliases
        if category is not None: patch["category"] = category
        if ownership not in {None, "personal", "business"}: raise PrivateError("INVALID_OWNERSHIP")
        if tags is not None or ownership:
            existing = self.gate.store.inspect(record_ref)["tags"]
            if tags is not None and any(t.startswith(RESERVED_TAG_PREFIX) for t in tags):
                raise PrivateError("RESERVED_TAG")
            values = list(tags if tags is not None else existing)
            values += [t for t in existing if t.startswith(RESERVED_TAG_PREFIX) and t not in values]
            if ownership:
                values = [t for t in values if not t.startswith("ownership:")] + ["ownership:" + ownership]
            patch["tags"] = values
        result = self.gate.store.patch(record_ref, patch, expected_version=expected_version, purpose="MCP organization")
        return self._receipt("organized", record_id=result["id"], version=result["version"])

    def _pending(self, title, kind, fields, *, target=None, previous_record=None, synthetic=False, key=None, source="capture", previous_version=None):
        state = {"state": "stored_pending", "kind": kind, "previous_record": previous_record, "source": source,
                 "binding": target or {}}
        if previous_record:
            state["previous_version"] = previous_version if previous_version is not None else self.gate.store.inspect(previous_record)["version"]
        key = key or str(uuid.uuid4())
        reference = str(uuid.uuid5(uuid.NAMESPACE_URL, "gate-mcp-pending:" + key))
        result = self.broker.put_secret(reference, json.dumps(state), "_gate_workflow", cat="Secret", extra=fields,
                                        expected_version=0, metadata={"title": title, "tags": ["gate:pending"] + ([SYNTHETIC_TAG] if synthetic else [])},
                                        purpose="MCP private pending capture", idempotency_key=key)
        return self._receipt("stored_pending", record_id=result["id"], version=result["version"])

    def generate(self, title, length=32, previous_record=None, synthetic=False, destination_ref=None):
        if not 20 <= length <= 128: raise PrivateError("INVALID_LENGTH")
        if previous_record and synthetic and SYNTHETIC_TAG not in self.gate.store.inspect(previous_record)["tags"]:
            raise PrivateError("LIVE_SECRET_ON_FIXTURE")
        target = None
        if destination_ref:
            destination = next((t for t in self.state.targets() if t["target_id"] == destination_ref), None)
            if not destination or destination["synthetic"] != synthetic: raise PrivateError("INVALID_TARGET")
            target = {k: destination[k] for k in ("origin", "account_hash")}
        alphabet = string.ascii_letters + string.digits + "!@#%+-_"
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        return self._pending(title, "password", {"password": value}, target=target, previous_record=previous_record, synthetic=synthetic, source="generated")

    def prepare_capture(self, title, target_id, kind, previous_record=None, expected_version=None):
        if kind not in {"password", "token", "totp", "recovery", "note"}: raise PrivateError("INVALID_CAPTURE")
        if previous_record:
            current = self.gate.store.inspect(previous_record)
            if expected_version != current["version"]: raise PrivateError("VERSION_CONFLICT")
        target = next((t for t in self.state.targets() if t["target_id"] == target_id), None)
        if not target: raise PrivateError("TARGET_STALE")
        accepted = {"password": {"password"}, "token": {"token"}, "totp": {"seed"}, "recovery": {"recovery"}, "note": {"note"}}
        if target["field"]["kind"] not in accepted[kind]: raise PrivateError("WRONG_FIELD")
        descriptor = {"action": "capture", "title": title, "kind": kind, "previous_record": previous_record,
                      "expected_version": expected_version}
        return self.state.issue(target_id, descriptor)

    def use(self, record_ref, destination_ref, kind="password", expected_version=None):
        if kind == "api": return self.inject(record_ref, destination_ref, expected_version=expected_version)
        if kind not in {"password", "totp", "token"}: raise PrivateError("INVALID_USE")
        meta = self.gate.store.inspect(record_ref)
        if expected_version is not None and meta["version"] != expected_version: raise PrivateError("VERSION_CONFLICT")
        workflow = self._workflow(meta["id"])
        if workflow["state"] in {"stored_pending", "service_rejected", "conflict"}:
            if workflow["state"] in {"service_rejected", "conflict"}: raise PrivateError("CANDIDATE_NOT_USABLE")
            target = next((t for t in self.state.targets() if t["target_id"] == destination_ref), None)
            # A pending (unconfirmed) authenticator seed or generated password must
            # not be pushed into a live service; that is an enrollment step for a human.
            if kind == "totp" and not (target and target["synthetic"] and SYNTHETIC_TAG in meta["tags"]):
                raise PrivateError("ENROLLMENT_HANDOFF_REQUIRED")
            if kind == "password" and SYNTHETIC_TAG not in meta["tags"] and workflow.get("source") == "generated":
                raise PrivateError("ENROLLMENT_HANDOFF_REQUIRED")
        return self.state.issue(destination_ref, {"action": "fill", "record_ref": meta["id"], "version": meta["version"], "kind": kind})

    def _assert_record_binding(self, descriptor):
        target = descriptor["target"]
        ref = descriptor["record_ref"]
        meta = self.gate.store.inspect(ref)
        if meta["version"] != descriptor["version"]: raise PrivateError("VERSION_CONFLICT")
        if target["synthetic"]:
            if SYNTHETIC_TAG not in meta["tags"]: raise PrivateError("LIVE_SECRET_ON_FIXTURE")
            return
        if target["account_hash"] == ABSENT_ACCOUNT: raise PrivateError("ACCOUNT_UNVERIFIED")
        workflow = self._workflow(ref)
        binding = workflow.get("binding", {})
        if binding:
            if binding.get("origin") != target["origin"] or binding.get("account_hash") != target["account_hash"]:
                raise PrivateError("WRONG_ACCOUNT_OR_ORIGIN")
        else:
            url = self.broker.get_secret(ref, "url", purpose="MCP destination verification")
            parsed = urlsplit(url)
            record_origin = origin("https://" + parsed.netloc) if parsed.scheme == "https" else ""
            username = self.broker.get_secret(ref, "username", purpose="MCP account verification")
            if record_origin != target["origin"] or account_hash(username) != target["account_hash"]:
                raise PrivateError("WRONG_ACCOUNT_OR_ORIGIN")

    def native_execute(self, descriptor, captured_value=None, handle=""):
        target = descriptor["target"]
        if descriptor["action"] == "capture":
            if not isinstance(captured_value, str) or not captured_value or len(captured_value) > 100000:
                raise PrivateError("INVALID_CAPTURE")
            if descriptor["kind"] == "totp": totp(captured_value, 59)
            field = {"password": "password", "token": "credential", "totp": "totp", "recovery": "recovery", "note": "private_note"}[descriptor["kind"]]
            previous = descriptor.get("previous_record")
            conflict = False
            if previous:
                conflict = self.gate.store.inspect(previous)["version"] != descriptor["expected_version"]
            result = self._pending(descriptor["title"], descriptor["kind"], {field: captured_value},
                                   target={k: target[k] for k in ("origin", "account_hash")}, previous_record=previous,
                                   synthetic=target["synthetic"], key=handle, previous_version=descriptor.get("expected_version"))
            if conflict:
                # The working record changed meanwhile: keep both, merge nothing.
                ref = result["record_id"]
                workflow = self._workflow(ref)
                workflow["state"] = "conflict"
                changed = self.broker.put_secret(ref, json.dumps(workflow), "_gate_workflow", expected_version=result["version"],
                                                 metadata={"tags": ["gate:conflict"] + ([SYNTHETIC_TAG] if target["synthetic"] else [])},
                                                 purpose="MCP conflict preservation")
                result.update(status="conflict_preserved", version=changed["version"])
            return result
        self._assert_record_binding(descriptor)
        kind = descriptor["kind"]
        if target["field"]["kind"] != kind: raise PrivateError("WRONG_FIELD")
        names = self.inspect(descriptor["record_ref"])["field_names"]
        candidates = {"password": ["password"], "token": ["credential", "token"], "totp": ["totp", "otp", "seed", "one-time password"]}[kind]
        field = next((f for f in candidates if f in names), None)
        if not field: raise PrivateError("FIELD_NOT_FOUND")
        value = self.broker.get_secret(descriptor["record_ref"], field, purpose="MCP private browser fill")
        # Re-check after the read: a concurrent edit withholds the older value.
        if self.gate.store.inspect(descriptor["record_ref"])["version"] != descriptor["version"]:
            raise PrivateError("VERSION_CONFLICT")
        expires = self.state.clock() + 10
        if kind == "totp":
            value, expires = totp(value, self.state.clock())
            if expires - self.state.clock() < 5: raise PrivateError("TOTP_BOUNDARY_RETRY")
        return {"value": value, "lease_id": handle, "expires_at": expires}

    def workflow(self, record_ref=None, action="status", expected_version=None, receipt_handle=None, destination_ref=None, use_receipt_handle=None):
        if action == "receipt":
            if not receipt_handle: raise PrivateError("HANDLE_REQUIRED")
            return self.state.receipt(receipt_handle)
        if not record_ref: raise PrivateError("RECORD_REQUIRED")
        meta = self.gate.store.inspect(record_ref)
        workflow = self._workflow(meta["id"])
        if action == "status": return self._receipt("workflow", record_id=meta["id"], version=meta["version"], workflow=workflow)
        if expected_version != meta["version"]: raise PrivateError("VERSION_CONFLICT")
        if action in {"apply_verified", "apply_private_note"}:
            previous = workflow.get("previous_record")
            if not previous or not workflow.get("previous_version"): raise PrivateError("PREVIOUS_RECORD_REQUIRED")
            if action == "apply_verified" and workflow["state"] != "verified": raise PrivateError("SERVICE_CONFIRMATION_REQUIRED")
            if action == "apply_private_note" and workflow["kind"] != "note": raise PrivateError("WRONG_FIELD")
            previous_meta = self.gate.store.inspect(previous)
            if SYNTHETIC_TAG in meta["tags"] and SYNTHETIC_TAG not in previous_meta["tags"]:
                raise PrivateError("LIVE_SECRET_ON_FIXTURE")
            field = {"password": "password", "token": "credential", "totp": "totp", "note": "private_note", "recovery": "recovery"}[workflow["kind"]]
            value = self.broker.get_secret(meta["id"], field, purpose="MCP verified candidate apply")
            if self.gate.store.inspect(meta["id"])["version"] != meta["version"]: raise PrivateError("VERSION_CONFLICT")
            result = self.broker.put_secret(previous, value, field, expected_version=workflow["previous_version"],
                                            metadata={"notes_markdown": value} if action == "apply_private_note" else None,
                                            purpose="MCP version-checked credential update")
            return self._receipt("applied", record_id=result["id"], version=result["version"], candidate_ref=meta["id"], previous_revision_preserved=True)
        if action == "prepare_verification":
            if not destination_ref: raise PrivateError("TARGET_REQUIRED")
            target = next((t for t in self.state.targets() if t["target_id"] == destination_ref), None)
            if not target: raise PrivateError("TARGET_STALE")
            # Only the packaged synthetic fixture has a service verifier in this
            # release. Real services need their own adapter (see README).
            if not target["synthetic"]: raise PrivateError("SERVICE_ADAPTER_UNAVAILABLE")
            if not use_receipt_handle: raise PrivateError("USE_RECEIPT_REQUIRED")
            self.assert_use_receipt(use_receipt_handle, meta["id"], meta["version"], target)
            return self.state.issue(destination_ref, {"action": "verify", "service": "synthetic_credential",
                                                      "record_ref": meta["id"], "version": meta["version"], "use_receipt_handle": use_receipt_handle})
        if action not in {"reject", "verify", "checkpoint"}: raise PrivateError("INVALID_WORKFLOW_ACTION")
        if action == "verify":
            if not receipt_handle: raise PrivateError("SERVICE_CONFIRMATION_REQUIRED")
            receipt = self.state.receipt(receipt_handle)
            if receipt.get("status") != "service_verified" or receipt.get("record_id") != meta["id"] or receipt.get("version") != meta["version"]:
                raise PrivateError("SERVICE_CONFIRMATION_REQUIRED")
            workflow["state"] = "verified"
        elif action == "reject":
            workflow["state"] = "service_rejected"
        else:
            workflow["state"] = workflow.get("state", "stored_pending")
        tags = [t for t in meta["tags"] if t not in {"gate:pending", "gate:verified", "gate:rejected"}]
        tags += ["gate:" + ("verified" if action == "verify" else "rejected" if action == "reject" else "pending")]
        changed = self.broker.put_secret(meta["id"], json.dumps(workflow), "_gate_workflow", expected_version=meta["version"],
                                         metadata={"tags": tags}, purpose="MCP lifecycle checkpoint")
        return self._receipt(workflow["state"], record_id=meta["id"], version=changed["version"])

    def assert_use_receipt(self, handle, record_ref, version, target):
        receipt = self.state.receipt(handle)
        operation = self.state.operation(handle)
        target = {k: v for k, v in target.items() if k not in {"target_id", "profile_id"}}
        if (receipt.get("status") != "filled" or receipt.get("record_id") != record_ref or receipt.get("version") != version
                or self.state.clock() - receipt.get("completed_at", 0) > 120 or operation.get("target") != target):
            raise PrivateError("USE_RECEIPT_MISMATCH")

    def inject(self, record_ref, destination_ref, expected_version=None):
        """Run a pre-approved, hash-pinned local program with one field in its environment.

        Approval lives in ``<bridge>/api-clients.json``, written by the owner.
        The program's stdout/stderr go to /dev/null so a value it prints never
        reaches the MCP response.
        """
        policy_path = self.state.root / "api-clients.json"
        if policy_path.is_symlink() or not policy_path.exists(): raise PrivateError("CLIENT_NOT_APPROVED")
        policies = json.loads(policy_path.read_text())
        policy = policies.get(destination_ref)
        if not policy: raise PrivateError("CLIENT_NOT_APPROVED")
        executable = Path(policy["executable"])
        if not executable.is_absolute() or executable.is_symlink(): raise PrivateError("UNSAFE_CLIENT")
        if hashlib.sha256(executable.read_bytes()).hexdigest() != policy["sha256"]: raise PrivateError("CLIENT_CHANGED")
        for file_path, digest in policy.get("argv_file_sha256", {}).items():
            candidate = Path(file_path)
            if not candidate.is_absolute() or candidate.is_symlink() or hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
                raise PrivateError("CLIENT_CHANGED")
        if any(Path(arg).is_file() and arg not in policy.get("argv_file_sha256", {}) for arg in policy.get("argv", [])):
            raise PrivateError("UNPINNED_CLIENT_FILE")
        meta = self.gate.store.inspect(record_ref)
        if expected_version is not None and meta["version"] != expected_version: raise PrivateError("VERSION_CONFLICT")
        if policy.get("synthetic") and SYNTHETIC_TAG not in meta["tags"]: raise PrivateError("LIVE_SECRET_ON_FIXTURE")
        if not policy.get("synthetic"):
            url = self.broker.get_secret(record_ref, "url", purpose="MCP API destination verification")
            if origin(policy["origin"]) != origin("https://" + urlsplit(url).netloc): raise PrivateError("WRONG_ORIGIN")
        value = self.broker.get_secret(record_ref, policy.get("field", "credential"), purpose="MCP approved API client injection")
        if self.gate.store.inspect(record_ref)["version"] != meta["version"]:
            raise PrivateError("VERSION_CONFLICT")
        env = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "LANG": "en_US.UTF-8", policy["env_key"]: value}
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result = subprocess.run([str(executable), *policy.get("argv", [])], env=env, shell=False, close_fds=True,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=min(policy.get("timeout", 30), 60))
        return self._receipt("client_completed" if result.returncode == 0 else "client_failed",
                             record_id=meta["id"], version=meta["version"], destination_ref=destination_ref, exit_code=result.returncode)

    def backup(self):
        destination = self.state.root / "backups" / (str(uuid.uuid4()) + ".db")
        destination.parent.mkdir(mode=0o700, exist_ok=True)
        result = self.gate.store.backup(destination)
        return self._receipt("backed_up", backup_ref=destination.name, bytes=result["bytes"])

    def health(self):
        return {"gate": self.gate.store.health(),
                "bridge": {"extension_id": self.state.extension_id, "targets": len(self.state.targets()),
                           "transport": "stdio + one-shot native messaging"}}
