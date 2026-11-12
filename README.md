# firebase-launch-check

A static pre-launch security check for Firebase projects. Run it on your project folder
before you go live. It reads your rules files, `firebase.json` and code, and tells you
what a stranger with your public web config could do:

- **Firestore and Cloud Storage rules** (`firestore.rules`, `storage.rules`): `if true`,
  rules with no condition, leftover test-mode rules (`request.time < timestamp.date(...)`),
  `request.auth != null` as the only check, catch-all `match /{document=**}` blocks,
  uploads without auth or size/type limits, and users who can write their own `role` /
  `isAdmin` / `plan` fields.
- **Realtime Database rules** (`database.rules.json`): `".read": true`, `".write": true`,
  test-mode `"now < ..."` rules and `"auth != null"` on broad paths.
- **Keys and code**: service account private keys in the project or in the hosted folder,
  `firebase-admin` imported in browser code, emulator connections and emulator variables
  that would reach production.

Every finding has a rule id, a severity, `file:line`, the offending line (secrets masked to
at most 4 characters), why it matters, and a concrete fix written in the Firebase rules
language with your own paths and wildcard names filled in.

Zero dependencies (Python 3.10+ standard library only). **Static only:** it never
contacts Firebase, deploys anything or runs your code, and makes no network requests.
CI-friendly exit codes.

---

## Quick start

```bash
pipx install git+https://github.com/abhi12337/firebase-launch-check   # straight from GitHub
pipx install .                                  # from a clone of this repo (or: pip install .)

firebase-launch-check scan                      # current folder
firebase-launch-check scan path/to/project
firebase-launch-check scan . --json > report.json
firebase-launch-check rules                     # every rule, why it matters, how to fix it
```

Try it on the deliberately broken demo project (the vulnerable test fixture plus a fake
service account key):

```bash
python examples/make_demo.py demo-firebase
firebase-launch-check scan demo-firebase
```

Exit codes: `0` = nothing at or above `--fail-on` (default `high`), `1` = findings at or above
it, `2` = usage error. Use `--fail-on critical|high|medium|low|info|never` to tune CI.

## Example output

All output below was produced by running this version of the tool on the demo project and
the test fixtures in this repository (nothing is hand-edited).

`firebase-launch-check scan demo-firebase --brief`:

```text
firebase-launch-check 0.1.0
Scanned demo-firebase
10 file(s): 1 firebase.json, 1 Firestore rules, 1 Storage rules, 1 Realtime Database rules, 3 browser code file(s)

CRITICAL FLC001  Rule allows access to everyone (if true / no condition)
      at: firestore.rules:23
      Firestore rule `allow write` on /posts/{postId} has `if true`: anyone on the internet can
      change it, without signing in.
      code: allow write: if true;

CRITICAL FLC002  Test-mode rules (open to everyone until a date)
      at: firestore.rules:32
      Firestore test-mode rule: allow read, write for anyone on the whole database until
      2099-01-01 (no sign-in required).
      code: allow read, write: if request.time < timestamp.date(2099, 1, 1);

CRITICAL FLC004  Recursive wildcard opens the whole database or bucket
      at: storage.rules:5
      `match /{allPaths=**}` gives any signed-in user (anyone can sign up) read, write access to
      every file in the bucket, and overrides every stricter rule in this file (rules are OR'ed).
      code: allow read, write: if request.auth != null;

CRITICAL FLC201  Realtime Database open to everyone (".read"/".write": true)
      at: database.rules.json:6
      ".write": true at /chat: anyone with your database URL can write (create, change and delete)
      /chat and everything below it, without signing in.
      code: ".write": true

CRITICAL FLC202  Realtime Database test-mode rule (open until a date)
      at: database.rules.json:3
      Test-mode ".read" at /: anyone can read the entire database until 2100-01-01, without
      signing in.
      code: ".read": "now < 4102444800000",

CRITICAL FLC202  Realtime Database test-mode rule (open until a date)
      at: database.rules.json:4
      Test-mode ".write" at /: anyone can write (create, change and delete) the entire database
      until 2100-01-01, without signing in.
      code: ".write": "now < 4102444800000",

CRITICAL FLC301  Service account private key in the project
      at: serviceAccountKey.json:5
      Service account key file for project 'shop-demo' in serviceAccountKey.json: it is not
      covered by .gitignore.
      code: private_key = ----**** (319 chars), private_key_id = 0123**** (40 chars)

HIGH     FLC003  Only check is "signed in" (request.auth != null) [heuristic]
      at: firestore.rules:13
      Firestore rule `allow read` on /users/{userId} only checks that the caller is signed in: any
      user can read every other user's documents here.
      code: allow read: if isSignedIn();

HIGH     FLC003  Only check is "signed in" (request.auth != null)
      at: firestore.rules:18
      Firestore rule `allow read, write` on /orders/{orderId} only checks that the caller is
      signed in: any user can read and change or delete every other user's documents here.
      code: allow read, write: if request.auth != null;

HIGH     FLC005  Users can set privileged fields on their own document [heuristic]
      at: firestore.rules:14
      Your rules use get(.../users/$(request.auth.uid)).data.role to grant access, but `allow
      create, update` on /users/{userId} does not stop the user from writing 'role' on their own
      document: any user can grant themselves that access.
      code: allow create, update: if request.auth.uid == userId;

HIGH     FLC101  Storage upload rule without authentication
      at: storage.rules:11
      Storage rule `allow write` on /public-uploads/{fileName} never checks request.auth: anyone
      can upload, overwrite or delete files here without signing in.
      code: allow write: if request.resource.size < 10 * 1024 * 1024;

HIGH     FLC203  Realtime Database only checks "signed in" (auth != null)
      at: database.rules.json:10
      ".write": "auth != null" at /presence/$uid: any signed-in user (and anyone can sign up) can
      write (create, change and delete) /presence/$uid and everything below it, including other
      users' data.
      code: ".write": "auth != null"

HIGH     FLC302  Admin SDK (firebase-admin) in client code
      at: src/admin/promote.ts:1
      src/admin/promote.ts is browser code and imports firebase-admin, the server SDK that ignores
      security rules and needs a service account credential.
      code: import admin from "firebase-admin";

MEDIUM   FLC001  Rule allows access to everyone (if true / no condition)
      at: firestore.rules:22
      Firestore rule `allow read` on /posts/{postId} has no condition: anyone on the internet can
      read it, without signing in.
      code: allow read;

MEDIUM   FLC005  Users can set privileged fields on their own document [heuristic]
      at: firestore.rules:14
      Client code writes 'plan' to users documents (src/pages/Signup.tsx:7), and `allow create,
      update` on /users/{userId} does not restrict that field: a user can set any 'plan' value
      they like from the browser console.
      code: allow create, update: if request.auth.uid == userId;

MEDIUM   FLC102  Storage upload without size or content-type limits
      at: storage.rules:8
      Storage rule `allow write` on /avatars/{userId}/{fileName} has no size or content-type
      limit: a signed-in user can upload files of any size.
      code: allow write: if request.auth.uid == userId;

MEDIUM   FLC402  Emulator host variable in a production environment file
      at: .env.production:2
      FIREBASE_AUTH_EMULATOR_HOST is set in .env.production, a production configuration file: the
      Admin SDK will accept unsigned ID tokens, so token checks on your server can be forged.
      code: FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099

LOW      FLC401  Emulator connection not guarded for production [heuristic]
      at: src/lib/firebase.ts:21
      connectFirestoreEmulator() runs unconditionally at module level: production builds will also
      try to use the local emulator.
      code: connectFirestoreEmulator(db, "localhost", 8080);

LOW      FLC403  Emulators listen on all network interfaces
      at: firebase.json:8
      Emulators firestore listen on all network interfaces: anyone who can reach this machine can
      read and change emulator data and use the emulator UI.
      code: "firestore": { "host": "0.0.0.0", "port": 8080 },

Summary: 7 critical, 6 high, 4 medium, 2 low, 0 info
Exit code: 1
```

A full finding (without `--brief`), with the fix written for the rule's own path:

```text
HIGH     FLC003  Only check is "signed in" (request.auth != null) [heuristic]
      at: firestore.rules:13
      Firestore rule `allow read` on /users/{userId} only checks that the caller is signed in: any
      user can read every other user's documents here.
      code: allow read: if isSignedIn();
      why: `request.auth != null` only proves the caller has some account. With
           email/password, Google or anonymous sign-in enabled, anyone can create one in
           seconds from the browser console using your public config, and then read or
           overwrite every user's data that the rule covers.
      fix:
        Check that the caller owns the data, not just that they are signed in:

          match /users/{userId} {
            allow read: if request.auth != null && request.auth.uid == userId;
          }
```

The same project written safely (`tests/fixtures/clean`: owner checks, a protected `role`
field, size and type limits on uploads, guarded emulator calls, `firebase-admin` only in
`functions/`) produces no findings:

```text
firebase-launch-check 0.1.0
Scanned tests/fixtures/clean
11 file(s): 1 firebase.json, 1 Firestore rules, 1 Storage rules, 1 Realtime Database rules, 2 browser code file(s)

No findings. (This is not a guarantee: see 'What it does not check' in the README.)
Summary: 0 critical, 0 high, 0 medium, 0 low, 0 info
Exit code: 0
```

## What it checks

### Firestore and Cloud Storage rules

Rules files are found through `firebase.json` (`firestore.rules`, `storage.rules`, and the
list forms used for multiple databases and buckets) and by looking for `*.rules` files whose
`service` is `cloud.firestore` or `firebase.storage`. Comments are ignored, nested `match`
blocks are joined into full paths, and functions defined in the file (including ones with
arguments and `let` bindings) are inlined before a condition is judged. A condition is only
called "open" when every part of it is `true`, `request.auth != null` or a
`request.time < timestamp.date(...)` limit; anything else is left alone.

| Rule | Severity | What it finds |
|---|---|---|
| FLC001 | Critical (writes) / High (reads of user data) / Medium (other reads) | `allow ...: if true;` and `allow ...;` with no condition, which Firebase treats as always allowed. |
| FLC002 | Critical (writes) / High (reads) / Medium (expired) | Test-mode rules: the condition is only `request.time < timestamp.date(Y, M, D)`. The message gives the expiry date; an expired rule is reported as Medium because it now denies everything, and pushing the date forward reopens it. |
| FLC003 | High | `request.auth != null` (or `request.auth.uid != null`, directly or through a helper such as `isSignedIn()`) as the only check on rules that write, or that read user-owned data (paths with `{userId}` / `{uid}` style wildcards or collections such as `users`, `orders`, `messages`). Create-only rules and reads of shared data such as `products` are not reported. |
| FLC004 | Critical / High | A catch-all `match /{document=**}` (Firestore) or `match /{allPaths=**}` (Storage) at the top of the database or bucket with `if true`, no condition, or only a sign-in check. Recursive wildcards under an owner path (`/users/{userId}/{document=**}`) and collection-group matches (`/{path=**}/posts/{id}`) are not this rule. |
| FLC005 | High / Medium, **heuristic** | Users who can write privileged fields on their own document. High: the rules read `get(/databases/$(database)/documents/<coll>/$(request.auth.uid)).data.<field>` to grant access, and `allow create/update/write` on `/<coll>/{id}` never mentions `<field>` (and uses no `hasOnly` allow-list). Medium: client code writes `role`, `isAdmin`, `admin`, `plan`, `tier`, `isPro`, `credits`, `permissions`, ... in `setDoc` / `addDoc` / `updateDoc` / `.set` / `.update` to a collection whose owner-write rule does not restrict that field. |
| FLC101 | High | Storage `allow write/create/update` whose condition never mentions `request.auth`. |
| FLC102 | Medium (no size limit) / Low (no type limit) | Storage uploads that check auth but not `request.resource.size` and/or `request.resource.contentType`. |

### Realtime Database rules

`database.rules.json` (or whatever `firebase.json` points to, comments and trailing commas
allowed) is read with line numbers. Remember that Realtime Database rules cascade: a grant on
a parent path cannot be taken back further down.

| Rule | Severity | What it finds |
|---|---|---|
| FLC201 | Critical / High / Medium | `".read": true` / `".write": true` (or `"true"`). Root: Critical. First-level path: Critical for writes, High for reads of user data, Medium for other reads. Deeper: High for writes, Medium for reads. |
| FLC202 | Critical / High / Medium (expired) | Test-mode rules such as `".read": "now < 1735689600000"`, with the expiry date decoded. |
| FLC203 | High | `"auth != null"` (or `auth !== null`, `auth.uid != null`) as the whole rule for writes anywhere, and for reads at the root or on user-owned paths (`$uid` wildcards, `users`, ...). |

### Keys and code

| Rule | Severity | What it finds |
|---|---|---|
| FLC301 | Critical / Info | Service account keys: JSON files with `"type": "service_account"` and a real `private_key`, and PEM private keys in files that mention `private_key` / `gserviceaccount.com` (for example `FIREBASE_PRIVATE_KEY=` in `.env`). Critical if the file is inside the Firebase Hosting `public` folder, committed to git, or not git-ignored; Info if it is git-ignored. Runs on every folder, including tests and the hosted build folder. |
| FLC302 | High | `firebase-admin` imported (`import`, `require`, dynamic `import()`) in browser code: files with `"use client"`, files in the Hosting `public` folder, and files of a Vite / Create React App / Angular / Vue / Svelte / Expo / React Native package outside `functions/`, `server/`, `api/`, `scripts/` and config files. Next.js, Nuxt, SvelteKit, Remix, Astro and Express packages are only judged by `"use client"`, and `"use server"` / `server-only` files are skipped. |
| FLC401 | Low, **heuristic** | `connectFirestoreEmulator`, `connectAuthEmulator`, `connectStorageEmulator`, `connectDatabaseEmulator`, `connectFunctionsEmulator` and `.useEmulator(...)` called at the top level of a module with no `if`, `&&`, `?:` or env check around it. |
| FLC402 | Medium / Low | `FIREBASE_AUTH_EMULATOR_HOST` (Medium: the Admin SDK then accepts unsigned ID tokens) or another `*_EMULATOR_HOST` variable set in `.env.production`, `.env.prod`, `apphosting.yaml` or `app.yaml`. |
| FLC403 | Low | Emulators bound to `0.0.0.0` / `::` in `firebase.json`. |
| FLC404 | Info | Client code imports `firebase/firestore`, `firebase/storage` or `firebase/database` (or the React Native, AngularFire, Flutter, iOS or Android SDKs), but no rules file for that service exists in the project, or `firebase.json` points to a rules file that is missing. |

The Firebase web config (`apiKey: "AIza..."`, `projectId`, ...) is **not** reported: it is
public by design, and the rules are what protect your data.

`node_modules`, build output (`dist/`, `build/`, `.next/`, ...), hidden folders and test
folders are skipped, except that the Hosting `public` folder is always scanned and key
detection (FLC301) also runs in test folders. Use `--include-tests` to apply every rule to
test folders and `--exclude GLOB` to skip more.

## What it does not check

Be clear about the limits before relying on it:

- **It is not a penetration test** and gives **no guarantee**. A clean report means "none of
  these known patterns were found", nothing more. It does not prove your rules are correct.
- **It reads the rules in your repository, not the deployed ones.** Rules edited in the
  console and never pulled into the repo are invisible to it (FLC404 tells you when a rules
  file is missing entirely).
- **It does not evaluate rule logic.** An owner check on the wrong field
  (`request.auth.uid == resource.data.title`), a role check that can be bypassed in a way
  other than writing the field directly, or a `get()` on a document the user controls through
  another path, is treated as safe. Conditions it does not recognise are never reported.
- **FLC005 only sees one pattern of privilege**: fields read from the caller's own document
  via `get(.../$(request.auth.uid))`, or privileged-looking keys that client code writes.
  Roles read in Cloud Functions or checked only in the client are missed unless the client
  also writes them.
- **FLC003 decides what is "user data" by name** (wildcards like `{userId}`, collections like
  `users` or `orders`). Shared data under other names that should still be private is missed;
  data under those names that is meant to be shared with every signed-in user is reported
  (add an ignore comment).
- Storage rules that check auth but not ownership (any signed-in user can overwrite any
  file in a folder) are not reported unless they are sign-in-only.
- **Client-side checks are pattern-based.** Deciding whether a file runs in the browser uses
  `package.json` dependencies, folder names and `"use client"`; unusual layouts can be
  misclassified. Built bundles are only scanned if they are the Hosting `public` folder.
- It does not check App Check, Auth settings (enabled providers, email enumeration,
  authorised domains), API key restrictions, Cloud Functions code, IAM, Data Connect or
  indexes.
- Key detection looks for service account keys only. Use a general secret scanner (gitleaks,
  trufflehog) for other credentials.

Firebase's own Rules Playground and the emulator-based `@firebase/rules-unit-testing` are the
right tools for proving your rules behave as intended. This tool is a fast first pass.

## How to fix each finding

`firebase-launch-check rules` prints all of this, and every finding in the report includes
its fix with your own match path and wildcard names filled in.

**FLC001 / FLC003 / FLC004 - open or sign-in-only rules.** Compare the caller with the
owner, and delete catch-all blocks:

```
match /databases/{database}/documents {
  match /users/{userId} {
    allow read, write: if request.auth != null && request.auth.uid == userId;
  }
  match /orders/{orderId} {
    allow read, update, delete: if request.auth != null && request.auth.uid == resource.data.ownerId;
    allow create: if request.auth != null && request.auth.uid == request.resource.data.ownerId;
  }
}
```

**FLC002 / FLC202 - test mode.** Replace the time-limited rule with per-collection rules as
above. Do not push the date forward.

**FLC005 - privileged fields.**

```
match /users/{userId} {
  allow create: if request.auth != null && request.auth.uid == userId
                && !('role' in request.resource.data);
  allow update: if request.auth != null && request.auth.uid == userId
                && !request.resource.data.diff(resource.data).affectedKeys().hasAny(['role']);
}
```

Or use custom claims (`request.auth.token.admin == true`), which only the Admin SDK can set.

**FLC101 / FLC102 - Storage uploads.**

```
match /b/{bucket}/o {
  match /users/{userId}/{fileName} {
    allow read: if request.auth != null && request.auth.uid == userId;
    allow create, update: if request.auth != null && request.auth.uid == userId
                          && request.resource.size < 5 * 1024 * 1024
                          && request.resource.contentType.matches('image/.*');
    allow delete: if request.auth != null && request.auth.uid == userId;
  }
}
```

Size and type checks go on `create, update`, not on `delete`, where `request.resource` is null.

**FLC201 / FLC203 - Realtime Database.**

```json
{
  "rules": {
    "users": {
      "$uid": {
        ".read": "auth != null && auth.uid === $uid",
        ".write": "auth != null && auth.uid === $uid"
      }
    }
  }
}
```

**FLC301 - service account key.** Delete the key in Google Cloud console -> IAM & Admin ->
Service Accounts -> Keys, remove the file from git history (`git filter-repo` / BFG), and use
built-in credentials (`initializeApp()` with no key) on Cloud Functions, App Hosting and
Cloud Run.

**FLC302 - firebase-admin in client code.** Use the client SDK (`firebase/app`,
`firebase/firestore`) in the browser; move privileged work to a Cloud Function or server
route that verifies the caller's ID token.

**FLC401 / FLC402 / FLC403 - emulator settings.** Wrap emulator connections in
`if (import.meta.env.DEV) { ... }` (or your framework's equivalent), keep `*_EMULATOR_HOST`
out of production env files, and bind emulators to `127.0.0.1`.

**FLC404 - no rules file.** `firebase init firestore` (or `storage` / `database`), commit the
rules, deploy them with `firebase deploy --only firestore:rules`, and scan again.

## Suppressing a finding

Add `firebase-launch-check: ignore` as a comment on the reported line, or on its own comment
line directly above it (works in `.rules` files, `database.rules.json`, JS/TS and env files):

```
match /posts/{postId} {
  allow read: if true;   // firebase-launch-check: ignore  (blog posts are public)
}
```

To turn a rule off for a whole run: `--disable FLC404` (repeatable). To hide lower
severities: `--min-severity medium`.

## Use in CI

See [`examples/github-actions/firebase-launch-check.yml`](examples/github-actions/firebase-launch-check.yml).
It runs on every pull request, fails the build on Critical/High findings, and uploads the
JSON report as an artifact.

## JSON output

`--json` prints the same findings with the fix text included (abbreviated here; the first
finding of `firebase-launch-check scan demo-firebase --json`):

```json
{
  "tool": "firebase-launch-check",
  "version": "0.1.0",
  "target": "/abs/path/demo-firebase",
  "files_scanned": 10,
  "firebase_json": [
    "firebase.json"
  ],
  "rules_files": {
    "firestore": [
      "firestore.rules"
    ],
    "storage": [
      "storage.rules"
    ],
    "database": [
      "database.rules.json"
    ]
  },
  "client_files": 3,
  "exit_code": 1,
  "summary": {
    "critical": 7,
    "high": 6,
    "medium": 4,
    "low": 2,
    "info": 0
  },
  "findings": [
    {
      "rule_id": "FLC001",
      "severity": "critical",
      "message": "Firestore rule `allow write` on /posts/{postId} has `if true`: anyone on the internet can change it, without signing in.",
      "file": "firestore.rules",
      "line": 23,
      "evidence": "allow write: if true;",
      "heuristic": false,
      "extra": {
        "service": "firestore",
        "path": "/posts/{postId}",
        "ops": [
          "write"
        ]
      },
      "title": "Rule allows access to everyone (if true / no condition)",
      "why": "`allow ...: if true;` (or an `allow` with no condition at all) grants the request to anyone on the internet, signed in or not, using only the public config in your web app. Rules are OR'ed: if any allow statement matches, the request is granted, so one open rule cannot be narrowed by stricter rules elsewhere.",
      "fix": "Require the owner instead of everyone:\n\n  match /posts/{postId} {\n    allow update, delete: if request.auth != null && request.auth.uid == resource.data.ownerId;\n    allow create: if request.auth != null && request.auth.uid == request.resource.data.ownerId;\n  }\n\n(ownerId = the field where you store the creator's uid; set it on create.)"
    },
    ...
  ]
}
```

## Development

```bash
pip install -e ".[test]"
pytest
```

Test fixtures never contain real or real-looking secrets in the repository: fake keys are
assembled at runtime in `tests/conftest.py` and `examples/make_demo.py`. Every rule has
tests for code that must be reported and for safe code that must not be, and the clean
fixture must produce no findings at all.

## License

MIT, Copyright (c) 2026 Abheesht Tripathi. See [LICENSE](LICENSE).

---

Questions, or want a second pair of eyes on your Firebase rules before launch? abheeshttripathi890@gmail.com
