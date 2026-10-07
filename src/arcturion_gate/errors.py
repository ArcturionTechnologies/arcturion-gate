"""Stable ArcturionGate error contract (codes map to CLI exit codes)."""

from __future__ import annotations


EXIT_CODES = {
    "INVALID": 2,
    "NOT_FOUND": 3,
    "AMBIGUOUS": 4,
    "VERSION_CONFLICT": 5,
    "SEALED": 6,
    "KEYCHAIN_UNAVAILABLE": 6,
    "INTEGRITY_FAILURE": 7,
    "AUDIT_FAILURE": 7,
    "TEMPORARY": 9,
    "INTERNAL": 9,
}


class GateError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        committed: bool = False,
        record_id: str | None = None,
        version: int | None = None,
        candidates: list[dict] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.committed = committed
        self.record_id = record_id
        self.version = version
        self.candidates = candidates or []

    @property
    def exit_code(self) -> int:
        return EXIT_CODES.get(self.code, 9)

    def to_dict(self) -> dict:
        out = {
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "committed": self.committed,
        }
        if self.record_id:
            out["record_id"] = self.record_id
        if self.version is not None:
            out["version"] = self.version
        if self.candidates:
            out["candidates"] = self.candidates
        return out

