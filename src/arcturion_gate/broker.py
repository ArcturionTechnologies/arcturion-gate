"""Private field-level read/write helper used by the MCP service and native host.

``Broker`` is a small, store-bound adapter with two calls:

- ``get_secret(ref, field, purpose=...)`` releases one field (audited).
- ``put_secret(ref, value, field, ...)`` writes one field plus optional extra
  fields and whitelisted metadata, with optimistic version checks.

Write semantics:

- ``expected_version=None``  upsert (create when missing, else patch current).
- ``expected_version=0``     create-only; requires an opaque idempotency key.
                             The record ID is derived from (ref, key) so two
                             identical racing retries cannot duplicate it.
- ``expected_version=N>0``   patch only if the record is still at version N;
                             never creates a missing record.

Every successful write returns the store's value-free commit receipt.
Error messages never echo values.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from .errors import GateError
from .store import ALLOWED_CATEGORIES, GateStore

_CATEGORY_ALIASES = {
    "api credential": "APICredential",
    "apicredential": "APICredential",
    "secure note": "Secret",
    "password": "Password",
    "login": "Login",
}
_METADATA_KEYS = {"title", "category", "aliases", "tags", "notes_markdown"}


def _category(value: str) -> str:
    return _CATEGORY_ALIASES.get(value.strip().casefold(), value.replace(" ", ""))


def _write_options(metadata: dict[str, Any] | None, expected_version: int | None, idempotency_key: str | None) -> dict[str, Any]:
    if expected_version is not None and (type(expected_version) is not int or expected_version < 0):
        raise GateError("INVALID", "expected_version must be a non-negative integer")
    if idempotency_key is not None and (not isinstance(idempotency_key, str) or not idempotency_key.strip()):
        raise GateError("INVALID", "idempotency_key must be a non-empty string")
    if expected_version == 0 and not idempotency_key:
        raise GateError("INVALID", "Create-only writes require an idempotency key")
    if metadata is None:
        return {}
    if not isinstance(metadata, dict) or set(metadata) - _METADATA_KEYS:
        raise GateError("INVALID", "Unsupported record metadata")
    result = dict(metadata)
    if "title" in result and (not isinstance(result["title"], str) or not result["title"].strip()):
        raise GateError("INVALID", "Record title is required")
    if "category" in result:
        if not isinstance(result["category"], str):
            raise GateError("INVALID", "Unsupported category")
        result["category"] = _category(result["category"])
        if result["category"] not in ALLOWED_CATEGORIES:
            raise GateError("INVALID", "Unsupported category")
    for key in ("aliases", "tags"):
        if key in result and (not isinstance(result[key], list) or any(not isinstance(v, str) or not v.strip() for v in result[key])):
            raise GateError("INVALID", "Aliases and tags must be lists of non-empty strings")
    if "notes_markdown" in result and not isinstance(result["notes_markdown"], str):
        raise GateError("INVALID", "Notes must be a string")
    return result


def _bound_write_key(item: str, fields: dict[str, str], metadata: dict[str, Any],
                     expected_version: int | None, idempotency_key: str | None) -> str | None:
    if not idempotency_key:
        return None
    # The idempotency key is bound to the whole request, so replaying the key
    # with a different payload or target cannot return a stale success.
    # The store persists only a keyed HMAC of this digest.
    request = json.dumps([item, fields, metadata, expected_version, idempotency_key],
                         sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "write-v1:" + hashlib.sha256(request).hexdigest()


class Broker:
    def __init__(self, store: GateStore) -> None:
        self.store = store

    def get_secret(self, item: str, field: str = "credential", *, purpose: str = "") -> str:
        return self.store.get(item, field, purpose=purpose or "broker read")

    def put_secret(
        self, item: str, value: str, field: str = "credential", *,
        cat: str = "APICredential", extra: dict[str, str] | None = None, purpose: str = "",
        expected_version: int | None = None, metadata: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        changes = _write_options(metadata, expected_version, idempotency_key)
        if not isinstance(item, str) or not item.strip():
            raise GateError("INVALID", "Record reference is required")
        if not isinstance(field, str) or not field.strip() or not isinstance(value, str):
            raise GateError("INVALID", "Credential field and value must be strings")
        if extra is not None and (not isinstance(extra, dict) or any(
            not isinstance(name, str) or not name.strip() or not isinstance(candidate, str)
            for name, candidate in extra.items()
        )):
            raise GateError("INVALID", "Extra credential fields must be strings")
        fields = {field: value, **(extra or {})}
        bound_key = _bound_write_key(item, fields, changes, expected_version, idempotency_key)
        try:
            meta = self.store.inspect(item)
        except GateError as exc:
            if exc.code != "NOT_FOUND":
                raise
            if expected_version not in (None, 0):
                raise GateError("VERSION_CONFLICT", "Record changed before this edit") from exc
            category = _category(cat)
            if category not in ALLOWED_CATEGORIES:
                raise GateError("INVALID", "Unsupported category") from exc
            data = {"title": item, "category": category, **changes, "fields": fields}
            if expected_version == 0:
                data["id"] = str(uuid.uuid5(uuid.NAMESPACE_URL, "arcturion-gate-create:" + item + ":" + idempotency_key))
            return self.store.create(data, purpose=purpose or "broker create", idempotency_key=bound_key)
        if expected_version == 0:
            # Create-only must never update an existing record, unless this is
            # an identical retry whose original receipt is already recorded.
            if bound_key:
                prior = self._prior_receipt(bound_key)
                if prior is not None:
                    return prior
            raise GateError("VERSION_CONFLICT", "Record already exists", record_id=meta["id"], version=meta["version"])
        return self.store.patch(
            meta["id"], {**changes, "fields": fields},
            expected_version=meta["version"] if expected_version is None else expected_version,
            purpose=purpose or "broker update", idempotency_key=bound_key,
        )

    def _prior_receipt(self, bound_key: str) -> dict | None:
        keys = self.store._keys()
        with self.store._connect() as conn:
            row = conn.execute("SELECT result_json FROM idempotency WHERE id=?",
                               (self.store._idempotency_token(keys, bound_key),)).fetchone()
        return json.loads(row[0]) if row else None
