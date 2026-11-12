# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-11

First release.

### Added

- `firebase-launch-check scan [PATH]`: static scan of a Firebase project folder. Reads
  files only; never contacts Firebase, deploys or runs code; no network access.
- `firebase-launch-check rules`: every rule with why it matters and how to fix it.
- A small reader for the Firebase Security Rules language (comments, nested `match` blocks,
  `function` definitions with arguments and `let`, statements without `;`) and a JSON reader
  with line numbers for `database.rules.json` (comments and trailing commas allowed).
- Rules files discovered through `firebase.json` (including the list forms for multiple
  databases and buckets) and by `service` declaration.
- Firestore / Cloud Storage rules:
  - FLC001 `if true` or no condition
  - FLC002 test-mode rules (`request.time < timestamp.date(...)`), with expiry date
  - FLC003 `request.auth != null` as the only check on writes or user-owned data
  - FLC004 top-level recursive wildcard with a broad allow
  - FLC005 users can write privileged fields (`role`, `isAdmin`, `plan`, ...) on their own
    document (heuristic)
  - FLC101 Storage uploads without authentication
  - FLC102 Storage uploads without size / content-type limits
- Realtime Database rules:
  - FLC201 `".read"` / `".write"`: `true`
  - FLC202 test-mode `"now < <timestamp>"` rules, with expiry date
  - FLC203 `"auth != null"` as the only check
- Keys and code:
  - FLC301 service account private keys (masked to at most 4 characters), graded by git and
    Firebase Hosting status
  - FLC302 `firebase-admin` imported in browser code
  - FLC401 emulator connections not guarded for production (heuristic)
  - FLC402 `*_EMULATOR_HOST` variables in production env files
  - FLC403 emulators bound to all network interfaces
  - FLC404 Firebase service used by the client but no rules file in the project
- Text and JSON reports, a fix in the Firebase rules language for every finding with the
  finding's own path and wildcard names, `--fail-on`, `--min-severity`, `--disable`,
  `--exclude`, `--include-tests`, `--brief`, `--no-color`, `firebase-launch-check: ignore`
  comments, exit codes `0` / `1` / `2`.
- Demo project generator (`examples/make_demo.py`) and a GitHub Actions example.
