"""Chrome one-shot native messaging host.

Chrome starts this process for each ``sendNativeMessage`` call, passes the
caller's origin as ``argv[1]``, writes one length-prefixed JSON request to
stdin and reads one response from stdout. stdout is therefore the private
channel to the enrolled extension and nothing else is ever printed.
"""
import hmac
import json
import resource
import struct
import sys

from .service import Service
from .state import PrivateError

MAX_MESSAGE = 1024 * 1024


def dispatch(service, request, caller_origin):
    # The allowed extension is checked before any record, profile or secret is touched.
    if caller_origin != service.state.extension_origin + "/": raise PrivateError("WRONG_EXTENSION")
    if not isinstance(request, dict) or request.get("protocol") != 1: raise PrivateError("INVALID_PROTOCOL")
    profile = request.get("profile_id", "")
    auth = request.get("profile_auth", "")
    action = request.get("action")
    if action == "enroll":
        return service.state.enroll(profile, auth, request.get("install_nonce", ""))
    service.state.authenticate(profile, auth)
    if action == "publish_targets": return service.state.publish(profile, request.get("targets", []))
    if action == "describe": return service.state.describe(request["handle"], profile)
    if action == "execute":
        handle = request["handle"]
        descriptor = service.state.claim(handle, profile, request["target"])
        try:
            if descriptor["action"] == "verify":
                target = descriptor["target"]
                evidence = request.get("verification", {})
                service._assert_record_binding(descriptor)
                if descriptor.get("service") != "synthetic_credential" or not target["synthetic"]:
                    raise PrivateError("SERVICE_ADAPTER_UNAVAILABLE")
                expected = {k: target[k] for k in ("account_hash", "origin", "document_path", "document_id")}
                if (not isinstance(evidence, dict) or any(evidence.get(k) != v for k, v in expected.items())
                        or evidence.get("evidence_code") != "synthetic_fixture_accepted" or type(evidence.get("confirmed")) is not bool):
                    raise PrivateError("INVALID_SERVICE_EVIDENCE")
                # Evidence must refer to the exact completed fill of this record/version,
                # and the accepted field value must equal the stored candidate.
                service.assert_use_receipt(descriptor.get("use_receipt_handle"), descriptor["record_ref"], descriptor["version"], target)
                private = service.native_execute({**descriptor, "action": "fill", "kind": target["field"]["kind"]})
                if not isinstance(evidence.get("private_value"), str) or not hmac.compare_digest(private["value"], evidence["private_value"]):
                    raise PrivateError("RECORD_EVIDENCE_MISMATCH")
                return service.state.complete(handle, profile, {"status": "service_verified" if evidence["confirmed"] else "service_rejected",
                                                                "record_id": descriptor["record_ref"], "version": descriptor["version"],
                                                                "service": "synthetic_credential"})
            result = service.native_execute(descriptor, request.get("captured_value"), handle)
            if descriptor["action"] == "capture":
                return service.state.complete(handle, profile, result)
            with service.state.connect() as conn:
                row = conn.execute("SELECT expires FROM operations WHERE handle=? AND state='claimed'", (handle,)).fetchone()
                if not row: raise PrivateError("REPLAY")
                # A value lease never outlives its operation handle.
                result["expires_at"] = min(result["expires_at"], row[0])
                if result["expires_at"] - service.state.clock() < (5 if descriptor["kind"] == "totp" else 1):
                    raise PrivateError("LEASE_EXPIRED")
                conn.execute("UPDATE operations SET expires=? WHERE handle=? AND state='claimed'", (result["expires_at"], handle))
            return result
        except Exception as exc:
            code = getattr(exc, "code", "PRIVATE_OPERATION_FAILED")
            service.state.complete(handle, profile, {"status": "withheld", "error_code": code})
            raise
    if action == "complete":
        handle = request["handle"]
        with service.state.connect() as conn:
            row = conn.execute("SELECT descriptor,expires FROM operations WHERE handle=?", (handle,)).fetchone()
        if not row or service.state.binding(request["target"]) != service.state.binding(json.loads(row["descriptor"])["target"]):
            raise PrivateError("DESTINATION_MISMATCH")
        if request.get("lease_id") != handle: raise PrivateError("INVALID_LEASE")
        descriptor = json.loads(row["descriptor"])
        # The extension may only report "filled" or not; it can never claim service confirmation.
        status = "filled" if request.get("outcome") == "filled" and service.state.clock() < row["expires"] else "rejected"
        return service.state.complete(handle, profile, {"status": status, "record_id": descriptor.get("record_ref"),
                                                        "version": descriptor.get("version"), "service_confirmation": False})
    raise PrivateError("INVALID_ACTION")


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        header = sys.stdin.buffer.read(4)
        if len(header) != 4: return
        length = struct.unpack("=I", header)[0]
        if not 0 < length <= MAX_MESSAGE: raise PrivateError("INVALID_MESSAGE")
        body = sys.stdin.buffer.read(length)
        if len(body) != length: raise PrivateError("INVALID_MESSAGE")
        request = json.loads(body)
        result = dispatch(Service(), request, sys.argv[1] if len(sys.argv) > 1 else "")
        response = {"ok": True, "data": result}
    except BaseException as exc:
        code = getattr(exc, "code", "PRIVATE_OPERATION_FAILED")
        if not isinstance(code, str) or not code.replace("_", "").isalnum(): code = "PRIVATE_OPERATION_FAILED"
        response = {"ok": False, "error": {"code": code}}
    encoded = json.dumps(response, separators=(",", ":")).encode()
    sys.stdout.buffer.write(struct.pack("=I", len(encoded)) + encoded)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
