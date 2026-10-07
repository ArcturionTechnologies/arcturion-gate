# ArcturionGate

A local, encrypted password and API-key store built for AI agents.
An agent can **use** a credential without ever **seeing** it.

> **Security status: NOT independently audited. Do not use for production or team secrets.**
> This is an early, single-user project. Read [THREAT_MODEL.md](THREAT_MODEL.md) before you trust it with anything.

Implementation is AI-assisted; architecture, requirements, and testing directed by Robert Lingoes.

---

## The idea: a valet ticket

When you hand your car to a valet, you get a ticket. The ticket lets you get
the car back. It doesn't let you drive it.

ArcturionGate treats an AI agent the same way. The agent gets a **reference**
(a record ID, or a short-lived operation handle) and a **receipt** that says
what happened. The actual password or token is released only to the place that
needs it:

- a child process's environment (`gate exec`),
- the clipboard for a few seconds (`gate copy`),
- or one specific field on one specific web page, through a Chrome extension.

It is never returned through the MCP channel, so it never enters the model's
context window, its logs, or its transcript.

```
 agent / model                ArcturionGate                    destination
 ─────────────                ─────────────                    ───────────
 "use record R on      ──►  checks version, binding,   ──►  value goes straight to
  destination D"            audit chain; issues a           the bound field or the
                            120-second one-time handle      child process env
        ◄── receipt: {"status": "filled", "record_id": R, "version": 3}   (no value)
```

## What's in the box

| Part | What it does |
|---|---|
| **Encrypted store** (`arcturion_gate.store`) | SQLite file where every record is encrypted on its own. Root key in the macOS login Keychain. Versioned records, encrypted revision history, HMAC-chained audit log. |
| **`gate` CLI + Python API** | Find, inspect, create, patch, run a command with secrets injected (`exec`), copy with auto-clear. |
| **MCP server** (`gate-mcp`) | stdio MCP server. Every tool takes references and returns value-free receipts. |
| **Chrome bridge** (`extension/` + `gate-native`) | MV3 extension + native messaging host that fills or captures a field bound to an exact origin, tab, frame, document and field. Includes a synthetic test page. |

macOS only for now (it uses the login Keychain and `pbcopy`). Python 3.11+.

## Quickstart

```sh
git clone <this repo> arcturion-gate && cd arcturion-gate
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[mcp]'          # drop [mcp] if you only want the CLI

gate init --recovery-file ~/arcturion-gate-recovery.txt
# Store that recovery file somewhere offline. It is the only way back in
# if the Keychain item is lost. Then delete it from this machine.
```

Add a credential (values go in through stdin, not argv, so they stay out of
your shell history and process list):

```sh
gate create --stdin-json <<'EOF'
{"title": "Example API", "category": "APICredential",
 "aliases": ["example"], "fields": {"credential": "paste-the-key-here"}}
EOF

gate find example                 # metadata only, no values
gate inspect "Example API"
```

Use it without printing it:

```sh
gate exec --env EXAMPLE_API_KEY="Example API:credential" -- ./my-script.sh
gate copy "Example API" --field credential --ttl 20   # clipboard clears after 20s (1 to 3600)
```

Change it with a version check (fails with `VERSION_CONFLICT` if someone else
changed it first):

```sh
echo '{"fields": {"credential": "new-value"}}' | gate patch "Example API" --if-version 1
```

Every command prints one JSON envelope: `{"ok", "data", "error", "meta"}`.
`gate reveal`, `gate view` and `gate markdown` do print values; they exist for
a human at a terminal, not for agents.

### Python

```python
from arcturion_gate import Gate

gate = Gate()
receipt = gate.create({"title": "Example", "category": "Secret", "fields": {"credential": "..."}})
value = gate.get("Example", "credential", purpose="nightly sync")  # audited
gate.patch("Example", {"fields": {"credential": "..."}}, expected_version=receipt["version"])
```

### MCP server

Point any stdio MCP client at the `gate-mcp` entry point in your venv, for example:

```json
{"mcpServers": {"arcturion-gate": {"command": "/path/to/arcturion-gate/.venv/bin/gate-mcp"}}}
```

Tools: `credential_search`, `credential_inspect`, `credential_organize`,
`credential_generate`, `credential_capture`, `credential_use`,
`credential_workflow`, `credential_backup`, `credential_health`.
Errors come back as a code only (`{"ok": false, "error": {"code": "VERSION_CONFLICT"}}`),
never as exception text.

`credential_use(kind="api")` runs a program **you** pre-approved in
`<data dir>/bridge/api-clients.json`, pinned by SHA-256, with one field in its
environment. Its stdout and stderr go to `/dev/null`.

### Chrome bridge (optional)

1. Give the extension a stable ID. Either load `extension/` unpacked and copy
   the ID Chrome shows, or generate a key so the ID never changes:
   ```sh
   gate-bridge extension-key --private-key ~/.config/arcturion-gate/extension.pem
   ```
   Paste the printed `manifest_key` into `extension/manifest.json` as `"key"`
   (keep that edit local) and keep the `.pem` out of the repo.
2. Register the native host for exactly that ID:
   ```sh
   gate-bridge install-native --extension-id <ID> [--chrome-profile "Profile 1"]
   ```
   The default host name is `com.arcturiontech.gate`. If you change it with
   `--host-name`, change `extension/config.js` to match.
3. Load `extension/` in `chrome://extensions` (Developer mode, Load unpacked).
4. Enroll this Chrome profile: `gate-bridge enroll`. This writes a one-time
   nonce that expires in 120 seconds and opens the extension's enrollment page.
5. Try it on the built-in synthetic page first: `credential_health(synthetic_fixture=true)`.

## Architecture

```
┌──────────── your Mac, your user account ────────────────────────────────┐
│                                                                          │
│  Keychain ── root key (32 bytes)                                         │
│      │ HKDF                                                              │
│      ├─ encryption key ── AES-256-GCM per record, AAD = id:version:type  │
│      ├─ lookup key ────── HMAC tokens for titles/aliases                 │
│      └─ audit key ─────── HMAC chain over every read and write           │
│                                                                          │
│  vault/gate.db         records, encrypted revisions, audit, idempotency  │
│  vault/recovery-envelope.json  root key wrapped by recovery code (PBKDF2)│
│  bridge/operations.db  profiles, targets, one-time handles, receipts     │
│                        (no values, ever)                                 │
│                                                                          │
│  AI agent ──stdio──► gate-mcp ──► store         (references + receipts)  │
│                                                                          │
│  Chrome ext ──native messaging──► gate-native ──► store                  │
│      (checks origin, tab, frame, document, field,   (value only on this  │
│       visibility, form target before filling)        private pipe)       │
└──────────────────────────────────────────────────────────────────────────┘
```

Key properties, each covered by tests:

- **Per-record AEAD.** Ciphertext is bound to its record ID, version and
  payload type; swapping or replaying a blob fails authentication.
- **Versioned writes.** Every write names the version it expects. Stale writes
  fail and change nothing. Every version is kept as an encrypted revision.
- **Conflicts keep both sides.** A capture that races an edit is saved as a
  separate candidate; nothing is merged or overwritten.
- **Audit fails closed.** If the audit chain was edited or truncated, its
  keyed anchor is wrong or missing, or the audit write fails, the value is not
  released.
- **No silent per-record rollback.** A record row must match the newest
  version recorded in the authenticated audit chain before it is released or
  changed, so copying an older (still valid) encrypted revision back is caught.
  Restoring a whole older copy of the database is not caught (see
  [THREAT_MODEL.md](THREAT_MODEL.md)).
- **Recovery code.** The root key is also wrapped with a recovery code
  (PBKDF2-SHA256, 600k iterations). `gate seal` removes the Keychain copy;
  `gate unseal` restores it from the code.
- **Browser handles are narrow.** A handle is single-use, lives at most 120
  seconds, belongs to one enrolled profile, and is bound to one origin, tab,
  frame, document, path and field fingerprint. Only one operation per
  destination at a time. If a check after the value is set fails, the field is
  cleared before the failure is reported. Filling is never treated as proof the
  service accepted the credential.
- **Pending, then verified.** Generated or captured credentials start as
  `stored_pending`. They are applied to the working record only after
  independent service evidence (today: the synthetic fixture's verifier).

More detail: [extension/README.md](extension/README.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

## Running the tests

```sh
pip install -e '.[mcp]'
python -m unittest discover -s tests -t tests   # Python: store, broker, CLI, MCP, native host
node --test extension/*.test.mjs                 # extension logic (Node 20+)
```

All tests use synthetic data and a mocked Keychain. They never touch a real
vault, Keychain item or browser.

## Not included (yet)

- Two-way sync with Apple Passwords or Chrome's password manager.
- Service verifiers for real websites (only the synthetic fixture has one).
- Key backends for Linux or Windows.
- Team sharing, remote access, or any network service. There is none, on purpose.

## License

MIT. Copyright (c) 2026 Arcturion Technologies. See [LICENSE](LICENSE).
