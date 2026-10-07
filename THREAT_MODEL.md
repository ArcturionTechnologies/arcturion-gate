# Threat model

**Status: not independently audited.** This document describes what the design
is meant to do. It has not been checked by an outside security reviewer.

## The trust boundary is the logged-in macOS user

Everything that runs as your user account is on the trusted side. That
includes your shell, your editor, your AI agent's harness, and any program
that agent can start. The root key sits in your login Keychain, which that
same user can read without a prompt (it is stored noninteractively so agents
can work unattended).

So, plainly:

- **ArcturionGate does not protect you from malware running as your user.**
  Such a program can read the Keychain item, open the database, attach to the
  `gate` process, read the clipboard, or read a child process's environment.
- **ArcturionGate cannot take back a value once it has been released.** After a
  value is put into an environment variable, the clipboard, or a web form, the
  receiving program or site has it. Rotating the credential at the service is
  the only real revocation.
- **It does not stop a determined agent that can run shell commands.** An agent
  with unrestricted shell access can run `gate reveal`. The design keeps values
  out of the *MCP channel* and out of model context by default. Keeping an
  agent away from the CLI is your harness's job (permissions, sandboxing).

## What it is designed to protect against

| Risk | How it is handled |
|---|---|
| Secrets leaking into model context, chat logs, or MCP transcripts | MCP tools accept and return references and value-free receipts only. Errors are reduced to a code. Tests scan MCP output, receipts, the operations DB and the catalog for the synthetic secret. |
| The database file being copied (backup, sync folder, stolen disk image without the Keychain) | Every record is AES-256-GCM encrypted. Titles are not stored in the clear; lookups and the catalog outbox digest use keyed HMACs. Audit purposes are stored as keyed HMACs. Database, recovery envelope, backups and bridge enrollment file are created owner-only (0600) from the first byte, in 0700 directories. |
| Ciphertext swapped between records | AAD binds each ciphertext to record ID, version and payload type. |
| One record rolled back to an older revision (an old but valid blob copied back into `records`), or un-deleted | AAD alone cannot catch this, because the old blob is authentic for its old version. Before any release or write, the row must equal the newest version and tombstone state recorded in the authenticated audit chain; otherwise the operation fails with `INTEGRITY_FAILURE`. |
| Silent edits to the audit log, including deleting the newest events | HMAC chain whose head is anchored with a keyed HMAC over (event count, last event HMAC). Editing, removing or truncating events, or deleting the anchor, blocks every value release and write. |
| Two writers clobbering each other | Every write states the version it expects; stale writes fail. Conflicting captures are saved as separate candidates. Every version is kept as an encrypted revision. |
| A web page, or another extension, tricking the bridge into filling the wrong place | The native host only answers the one extension ID in its manifest and config, and only after a per-profile enrollment (one-time nonce, then a private profile secret). Each operation handle is single-use, expires within 120 seconds, and is bound to one profile, HTTPS origin, tab, frame, document ID, path, field fingerprint and account hash. Discovery scans only the tab the user is looking at, not every open tab. The extension re-checks visibility, readonly state, form target origin and binding before and after filling. If any check after the value is set fails, the field is cleared before the failure is reported. |
| A fill being mistaken for a successful login or password change | Fill receipts can never claim service confirmation. Pending credentials need separate verifier evidence before they replace the working record. |
| Leaking a value through a pre-approved API client's output | Approved clients are pinned by SHA-256 (and any script files they run), get a minimal environment, and their stdout/stderr go to `/dev/null`. |
| Losing the Keychain item | Recovery envelope: root key wrapped with a 256-bit random recovery code (PBKDF2-SHA256, 600,000 iterations, AES-GCM). Envelopes with an unknown format or a work factor outside 600,000 to 10,000,000 iterations are refused before any key derivation. |

## Known limits and sharp edges

- **Whole-database rollback is not detected.** Freshness and the audit anchor
  live in the same file as the data. Restoring an entire older copy of
  `gate.db` (records, audit log and anchor together) is self-consistent and
  passes every check. Only an anchor kept outside the file (not implemented)
  would catch that.
- **`operations.db` has no integrity protection.** Handle state, targets and
  receipts are plain SQLite. Anyone who can write that file is already on the
  trusted side (same user).
- **Account and username hashes are unsalted SHA-256.** Destination
  `account_hash` values (in `operations.db` and MCP output) can be confirmed by
  guessing a username or email. They are not secret, and are not treated as such.
- **The clipboard is a shared, observable channel.** `gate copy` clears the
  clipboard after the TTL only if it still holds the copied value. Clipboard
  history managers and Universal Clipboard may keep or sync their own copy, and
  the clear timer is a separate process, so a logout or reboot before the TTL
  skips the clear.
- **Audit attribution is self-reported.** `ARCTURION_GATE_ACTOR` and
  `ARCTURION_GATE_SESSION` are whatever the caller sets. The audit log tells
  you *that* a value was released, not reliably *who* asked.
- **Field names, record IDs, versions, categories and timestamps are not
  secret.** They are visible to anyone who can read the database file's
  structure, and the optional Markdown catalog contains titles.
- **The recovery code is as strong as where you keep it.** Anyone with the code
  and the envelope file can recover the root key.
- **The extension has broad host permissions** (`https://*/*`) because it must
  work on any login page. It accepts only operations the local host issued,
  but a compromised extension build would be serious. Load only code you have
  reviewed.
- **The synthetic fixture is the only service verifier.** Real sites have no
  verifier yet, so the "pending, then verified" flow is only end-to-end for the
  fixture.
- **No memory hygiene guarantees.** Python strings holding values are not
  zeroed. Core dumps are disabled in the MCP and native processes, but swap and
  memory inspection by the same user are out of scope.
- **macOS only.** Other platforms have no key backend.

## Reporting

See [SECURITY.md](SECURITY.md).
