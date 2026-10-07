# Security policy

ArcturionGate is an early, unaudited project. Please do not use it for
production or shared team secrets. See [THREAT_MODEL.md](THREAT_MODEL.md) for
what it does and does not try to protect.

## Reporting a vulnerability

Please report privately. Do not open a public issue for a security problem.

1. Go to this repository's **Security** tab and choose **Report a vulnerability**
   (GitHub private vulnerability reporting).
2. Include what you found, how to reproduce it, and what an attacker would gain.
   Use synthetic data only. Never send real credentials, recovery codes or vault
   files.

We will acknowledge the report, work on a fix, and credit you in the release
notes if you want that. Because this is a small project, there is no bug
bounty and no guaranteed response time.

## In scope

- A credential value reaching MCP output, receipts, logs, the operations
  database, the catalog, or error messages.
- Ways to make the native host release a value to the wrong extension, profile,
  origin, tab, frame, document or field.
- Bypassing version checks, the audit chain, or the single-use / 120-second
  handle rules.
- Cryptographic mistakes in record encryption, key derivation or the recovery
  envelope.

## Out of scope

- Attacks that require code already running as the same macOS user (this is
  the documented trust boundary).
- Values after they have been deliberately released to a child process, the
  clipboard, or a web form.
