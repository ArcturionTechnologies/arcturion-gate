# ArcturionGate Chrome bridge

A Manifest V3 extension that fills or captures one credential field at a time
for a local ArcturionGate vault. It talks only to the native messaging host
named in `config.js` (default `com.arcturiontech.gate`) using one-shot
`chrome.runtime.sendNativeMessage`. There is no network listener, no
`externally_connectable`, and no web-accessible resources.

The extension ID is not pinned in this repo. Chrome assigns one when you load
it unpacked, or you can generate a stable one with
`gate-bridge extension-key`. The native host manifest allows exactly that ID.

## Flow

1. **Enroll.** `gate-bridge enroll` writes a one-time nonce (120 s) and opens
   `operation.html#enroll=<nonce>`. The extension creates a random profile ID
   and a private profile auth value, keeps them in `chrome.storage.local`, and
   sends them to the host with the nonce. The host stores only a SHA-256 of
   the auth value. First-run profile creation runs under a Web Lock, so two
   operation pages opening at once cannot create competing profiles. A nonce
   that is not a 32 to 128 character URL-safe token is refused before the host
   is contacted.
2. **Discover.** `operation.html#discover` scans one tab for eligible fields:
   the active HTTPS tab of the last-focused window or, when the operation page
   itself has focus, the most recently used HTTPS tab of that window. Other
   open tabs are never scanned. It publishes safe target metadata: tab, frame, document ID, origin,
   path, field selector fingerprint, field kind, and a hash of the visible
   account name. No field values are read, except the username to hash it.
3. **Operate.** The agent asks the MCP server to use record R on target T. The
   server issues a single-use handle (120 s) and opens
   `operation.html#<handle>`. The page removes the handle from history, asks
   the host for the value-free descriptor, re-checks the live page against the
   binding, and only then asks for the value.
4. **Fill.** The value arrives over the native pipe as a lease with an expiry.
   The isolated-world helper checks expiry right before setting the field,
   after the input/change events, and after the post-fill binding check. If
   any check after the setter fails (expiry, the page rewriting the value, a
   binding or form-origin change), the field is cleared and input/change are
   dispatched again before the error is thrown. The operation page also sends a
   defensive `clear` to the bound field whenever a fill, or the check after
   it, is rejected. The value is never written to the page UI, logs or receipts.
5. **Complete.** The extension reports `filled` or `rejected`. It cannot report
   that the service accepted the credential.

## Native message envelope

```json
{"protocol": 1, "action": "describe", "profile_id": "...", "profile_auth": "...", "handle": "..."}
```

Actions: `enroll`, `publish_targets`, `describe`, `execute`, `complete`.
Replies are `{"ok": true, "data": ...}` or `{"ok": false, "error": {"code": "..."}}`.
Only a fill `execute` reply carries a `value`.

## What the page refuses

- Non-HTTPS pages, incognito tabs, and frames whose document ID, origin or
  path changed since discovery.
- Forms that submit to a different origin.
- Hidden, disabled, detached or (for fills) readonly fields.
- New-password fields, authenticator setup-key fields, and pages that look like
  2FA enrollment. These are handed back to a human (`PROTECTED_ENROLLMENT`).
- Any page mutation during the asynchronous fingerprint check.

## Synthetic fixture

`fixture.html` is a packaged test page. It creates random synthetic values in
the browser and has an independent verifier: password and token must match
the challenges created at load, and the code field must match the current
RFC 6238 test seed. Any input or change resets acceptance. Its private message
channel accepts messages only from this extension's operation page.
`operation.html#fixture` opens only this page, in a background tab, and
discovers only that tab. If the fixture never becomes ready or discovery fails,
the tab is closed. On success it stays open because it is the published
destination, and fixture tabs from earlier runs are closed first. Both page
channels (the fixture's private message receiver and the isolated-world
script) take the same `{command, target, lease}` request. The fixture verifier
is the one place a field value is returned (`private_value`), and only for the
fixture's own synthetic values. See the comment in `dom.js`. The host requires a `gate:synthetic` tag on any
record used with the fixture, so a real credential can never be sent there.

## Tests

```sh
node --test extension/*.test.mjs
```

These cover DOM binding, enrollment protection, readonly capture, the
operation page's native call order, lease expiry during async checks, clearing
the field after any post-fill failure, values absent from rendered UI, active-tab
discovery scope, atomic profile creation, nonce validation, fixture tab cleanup,
fixture challenge validation, and fixture navigation rejection. They run in Node with stubbed browser APIs. They do not prove a
real Chrome install or real native messaging; check that by hand on the
fixture before using a real credential.
