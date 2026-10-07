"""The ``gate`` command.

Every command prints one JSON envelope ``{"ok", "data", "error", "meta"}`` and
exits with a stable code (see ``errors.EXIT_CODES``). ``view`` prints Markdown.

Commands that never print a value: init, find, inspect, create, patch, note,
copy, exec, status, health, audit, backup, seal, unseal.
Commands that print a value on purpose (for a human at a terminal): reveal,
markdown, view, edit.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

from . import config
from .errors import GateError
from .markdown import parse as parse_markdown, render as render_markdown
from .store import GateStore


def emit(data=None, *, error=None, meta=None, exit_code=0) -> int:
    payload = {"ok": error is None, "data": data, "error": error, "meta": meta or {}}
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return exit_code


def read_json_stdin() -> dict:
    try:
        value = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        raise GateError("INVALID", "stdin is not valid JSON") from exc
    if not isinstance(value, dict):
        raise GateError("INVALID", "stdin JSON must be an object")
    return value


def read_markdown_interactive(template: str) -> str:
    if not sys.stdin.isatty():
        return sys.stdin.read()
    print(template)
    print("\nEnter the complete replacement Markdown. Finish with a line containing only .gate-save")
    lines: list[str] = []
    while True:
        line = input()
        if line == ".gate-save":
            return "\n".join(lines) + "\n"
        lines.append(line)


def new_record_template() -> str:
    return render_markdown({
        "id": str(uuid.uuid4()), "version": 1, "title": "New credential",
        "category": "Login", "aliases": [], "tags": [],
        "fields": {"url": "", "username": "", "password": ""},
        "notes_markdown": "",
    })


def markdown_replacement_patch(current: dict, edited: dict) -> dict:
    fields = dict(edited["fields"])
    for name in current.get("fields", {}):
        if name not in fields:
            fields[name] = None
    return {
        "title": edited["title"], "category": edited["category"],
        "aliases": edited["aliases"], "tags": edited["tags"],
        "fields": fields, "notes_markdown": edited["notes_markdown"],
    }


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gate", description="ArcturionGate local credential store")
    p.add_argument("--root", default=None, help="vault directory (default: $ARCTURION_GATE_HOME/vault)")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create a new vault and print its recovery code").add_argument("--recovery-file")
    find = sub.add_parser("find", help="search titles, aliases and tags (no values)"); find.add_argument("query")
    inspect = sub.add_parser("inspect", help="show safe metadata for one record"); inspect.add_argument("record")
    reveal = sub.add_parser("reveal", help="print one field value (human use)"); reveal.add_argument("record"); reveal.add_argument("--field", default="credential"); reveal.add_argument("--purpose", default="")
    md = sub.add_parser("markdown", help="print a full record as Markdown inside JSON"); md.add_argument("record"); md.add_argument("--purpose", default="")
    view = sub.add_parser("view", help="print a full record as Markdown"); view.add_argument("record"); view.add_argument("--purpose", default="")
    create = sub.add_parser("create", help="create a record from JSON on stdin"); create.add_argument("--stdin-json", action="store_true"); create.add_argument("--purpose", default=""); create.add_argument("--idempotency-key")
    patch = sub.add_parser("patch", help="apply a JSON patch from stdin"); patch.add_argument("record"); patch.add_argument("--stdin-json", action="store_true"); patch.add_argument("--if-version", type=int, required=True); patch.add_argument("--purpose", default=""); patch.add_argument("--idempotency-key")
    edit = sub.add_parser("edit", help="edit a record as Markdown"); edit.add_argument("record"); edit.add_argument("--if-version", type=int); edit.add_argument("--purpose", default="")
    note = sub.add_parser("note", help="add or replace Markdown notes"); note_sub = note.add_subparsers(dest="note_command", required=True)
    for name in ("add", "replace"):
        n = note_sub.add_parser(name); n.add_argument("record"); n.add_argument("--stdin", action="store_true"); n.add_argument("--if-version", type=int, required=True); n.add_argument("--purpose", default="")
    copy = sub.add_parser("copy", help="copy a field to the clipboard and clear it after --ttl seconds"); copy.add_argument("record"); copy.add_argument("--field", default="password"); copy.add_argument("--ttl", type=int, default=30); copy.add_argument("--purpose", default="")
    clear = sub.add_parser("_clear-clipboard", help=argparse.SUPPRESS); clear.add_argument("ttl", type=int)
    execute = sub.add_parser("exec", help="run a command with fields injected as environment variables"); execute.add_argument("--env", action="append", default=[], metavar="NAME=RECORD:FIELD"); execute.add_argument("--purpose", default=""); execute.add_argument("remainder", nargs=argparse.REMAINDER)
    sub.add_parser("status"); sub.add_parser("health"); sub.add_parser("audit")
    backup = sub.add_parser("backup", help="copy the encrypted database"); backup.add_argument("destination")
    sub.add_parser("seal", help="remove the root key from the Keychain")
    unseal = sub.add_parser("unseal", help="restore the root key from the recovery code"); unseal.add_argument("--recovery-file")
    return p


MAX_CLIPBOARD_TTL = 3600


def _clipboard_env() -> dict:
    # pbcopy/pbpaste translate bytes using the locale; pin UTF-8 on both sides
    # so the cleared-or-not comparison sees the same bytes that were copied.
    return {**os.environ, "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8"}


def _store(args) -> GateStore:
    return GateStore(Path(args.root).expanduser() if args.root else config.vault_root())


def _split_env(spec: str) -> tuple[str, str, str]:
    if "=" not in spec or ":" not in spec.split("=", 1)[1]:
        raise GateError("INVALID", "--env must be NAME=RECORD:FIELD")
    name, target = spec.split("=", 1)
    record, field = target.rsplit(":", 1)
    if not name.isidentifier() or not record or not field:
        raise GateError("INVALID", "--env must be NAME=RECORD:FIELD")
    return name, record, field


def run(args: argparse.Namespace) -> int:
    store = _store(args)
    c = args.command
    if c == "init":
        recovery = store.initialize()
        if args.recovery_file:
            path = Path(args.recovery_file).expanduser()
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as handle:
                handle.write(recovery + "\n")
            return emit({"initialized": True, "recovery_file": str(path)})
        return emit({"initialized": True, "recovery_code": recovery})
    if c == "find": return emit(store.find(args.query))
    if c == "inspect": return emit(store.inspect(args.record))
    if c == "reveal": return emit({"record": args.record, "field": args.field, "value": store.get(args.record, args.field, purpose=args.purpose)})
    if c in {"markdown", "view"}:
        text = render_markdown(store.get_record(args.record, purpose=args.purpose))
        if c == "view": print(text); return 0
        return emit({"markdown": text})
    if c == "create":
        data = read_json_stdin() if args.stdin_json or not sys.stdin.isatty() else parse_markdown(read_markdown_interactive(new_record_template()))
        return emit(store.create(data, purpose=args.purpose, idempotency_key=args.idempotency_key))
    if c == "patch": return emit(store.patch(args.record, read_json_stdin(), expected_version=args.if_version, purpose=args.purpose, idempotency_key=args.idempotency_key))
    if c == "edit":
        current = store.get_record(args.record, purpose=args.purpose)
        version = args.if_version or current["version"]
        edited = parse_markdown(read_markdown_interactive(render_markdown(current)))
        return emit(store.patch(args.record, markdown_replacement_patch(current, edited), expected_version=version, purpose=args.purpose))
    if c == "note":
        text = sys.stdin.read() if args.stdin or not sys.stdin.isatty() else input("Markdown note: ")
        if args.note_command == "add": result = store.append_note(args.record, text, expected_version=args.if_version, purpose=args.purpose)
        else: result = store.patch(args.record, {"notes_markdown": text}, expected_version=args.if_version, purpose=args.purpose)
        return emit(result)
    if c == "copy":
        if not 1 <= args.ttl <= MAX_CLIPBOARD_TTL:
            raise GateError("INVALID", f"--ttl must be between 1 and {MAX_CLIPBOARD_TTL} seconds")
        value = store.get(args.record, args.field, purpose=args.purpose)
        # Bytes, not text mode: text mode rewrites \r and \r\n on read, so a value
        # containing them would never compare equal and never be cleared.
        data = value.encode("utf-8")
        subprocess.run(["/usr/bin/pbcopy"], input=data, check=True, env=_clipboard_env())
        digest = hashlib.sha256(data).hexdigest()
        # The digest goes to the timer over a pipe, never argv: argv is visible to
        # every local user via ps, and an unsalted hash is a guessing oracle.
        timer = subprocess.Popen([sys.executable, "-m", "arcturion_gate.cli", "--root", str(store.root), "_clear-clipboard", str(args.ttl)],
                                 stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        timer.stdin.write((digest + "\n").encode("ascii"))
        timer.stdin.close()
        return emit({"copied": True, "ttl": args.ttl})
    if c == "_clear-clipboard":
        digest = sys.stdin.readline().strip()
        if len(digest) != 64:
            return 2
        time.sleep(min(max(1, args.ttl), MAX_CLIPBOARD_TTL))
        current = subprocess.run(["/usr/bin/pbpaste"], capture_output=True, check=False, env=_clipboard_env()).stdout
        # Clear only if the clipboard still holds the value we put there.
        if hmac.compare_digest(hashlib.sha256(current).hexdigest(), digest):
            subprocess.run(["/usr/bin/pbcopy"], input=b"", check=False, env=_clipboard_env())
        return 0
    if c == "exec":
        command = list(args.remainder)
        if command and command[0] == "--": command.pop(0)
        if not command: raise GateError("INVALID", "gate exec requires a command after --")
        env = os.environ.copy()
        for spec in args.env:
            name, record, field = _split_env(spec)
            env[name] = store.get(record, field, purpose=args.purpose or f"execute {command[0]}")
        return subprocess.run(command, env=env, check=False).returncode
    if c in {"status", "health"}: return emit(store.health())
    if c == "audit": return emit(store.audit_summary())
    if c == "backup": return emit(store.backup(args.destination))
    if c == "seal": store.seal(); return emit({"sealed": True})
    if c == "unseal":
        code = Path(args.recovery_file).expanduser().read_text().strip() if args.recovery_file else getpass.getpass("Recovery code: ")
        store.unseal(code); return emit({"sealed": False})
    raise GateError("INVALID", "Unknown command")


def main() -> None:
    try:
        code = run(parser().parse_args())
    except GateError as exc:
        code = emit(None, error=exc.to_dict(), exit_code=exc.exit_code)
    except KeyboardInterrupt:
        code = emit(None, error={"code": "TEMPORARY", "message": "Interrupted", "retryable": True, "committed": False}, exit_code=9)
    except Exception as exc:
        code = emit(None, error={"code": "INTERNAL", "message": type(exc).__name__, "retryable": False, "committed": False}, exit_code=9)
    raise SystemExit(code)


if __name__ == "__main__":
    main()
