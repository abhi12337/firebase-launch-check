"""Finding model and the rule catalogue (ids, severities, why it matters, how to fix)."""

from __future__ import annotations

import re
import textwrap
from dataclasses import asdict, dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}  # lower = worse

IGNORE_MARKER = "firebase-launch-check: ignore"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    why: str
    fix: str


RULES: dict[str, Rule] = {}


def _rule(id: str, title: str, why: str, fix: str) -> None:
    RULES[id] = Rule(id, title, " ".join(why.split()), textwrap.dedent(fix).strip(chr(10)))


# ---------------------------------------------------------------- Firestore / Storage rules
_rule(
    "FLC001",
    "Rule allows access to everyone (if true / no condition)",
    """
`allow ...: if true;` (or an `allow` with no condition at all) grants the request to anyone
on the internet, signed in or not, using only the public config in your web app. Rules are
OR'ed: if any allow statement matches, the request is granted, so one open rule cannot be
narrowed by stricter rules elsewhere.
""",
    """
Limit access to the owner of each document, e.g.:

  match /users/{userId} {
    allow read, write: if request.auth != null && request.auth.uid == userId;
  }

For documents that store the owner in a field:

  allow read, update, delete: if request.auth != null && request.auth.uid == resource.data.ownerId;
  allow create: if request.auth != null && request.auth.uid == request.resource.data.ownerId;

If the data is meant to be public, allow reads only and keep writes closed:

  allow read: if true;
""",
)
_rule(
    "FLC002",
    "Test-mode rules (open to everyone until a date)",
    """
"Start in test mode" creates `allow read, write: if request.time < timestamp.date(...)`.
Until that date anyone can read, change and delete everything the rule covers. After the
date every request is denied, so the app breaks and people often just push the date
forward, keeping the database open.
""",
    """
Replace the time-limited rule with real rules before launch, e.g.:

  rules_version = '2';
  service cloud.firestore {
    match /databases/{database}/documents {
      match /users/{userId} {
        allow read, write: if request.auth != null && request.auth.uid == userId;
      }
      // one match block per collection; everything else stays denied
    }
  }
""",
)
_rule(
    "FLC003",
    "Only check is \"signed in\" (request.auth != null)",
    """
`request.auth != null` only proves the caller has some account. With email/password,
Google or anonymous sign-in enabled, anyone can create one in seconds from the browser
console using your public config, and then read or overwrite every user's data that the
rule covers.
""",
    """
Compare the signed-in user with the owner of the data, e.g.:

  match /users/{userId} {
    allow read, write: if request.auth != null && request.auth.uid == userId;
  }

or, when the owner is stored in a field:

  allow read, update, delete: if request.auth != null && request.auth.uid == resource.data.ownerId;
  allow create: if request.auth != null && request.auth.uid == request.resource.data.ownerId;
""",
)
_rule(
    "FLC004",
    "Recursive wildcard opens the whole database or bucket",
    """
`match /{document=**}` (Firestore) or `match /{allPaths=**}` (Storage) at the top level
matches every document or file, including subcollections and collections you add later.
A broad allow there overrides every stricter rule in the file, because rules are OR'ed.
""",
    """
Delete the catch-all block and write one match block per collection; anything not matched
is denied by default:

  match /databases/{database}/documents {
    // removed: match /{document=**} { allow read, write: if ...; }
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
""",
)
_rule(
    "FLC005",
    "Users can set privileged fields on their own document",
    """
If a user can write their own profile document without field validation, they can also
write fields such as `role`, `isAdmin` or `plan`. When those fields are used to decide
access (for example `get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role`
in your rules, or a plan check in a Cloud Function), any user can make themselves an admin
or a paying customer from the browser console.
""",
    """
Forbid clients from setting or changing the field (and keep setting it from the Admin SDK
or a Cloud Function), e.g.:

  match /users/{userId} {
    allow create: if request.auth != null && request.auth.uid == userId
                  && !('role' in request.resource.data);
    allow update: if request.auth != null && request.auth.uid == userId
                  && !request.resource.data.diff(resource.data).affectedKeys().hasAny(['role']);
  }

or store roles as custom claims (request.auth.token.admin == true), which only the Admin
SDK can set.
""",
)

# ---------------------------------------------------------------- Storage
_rule(
    "FLC101",
    "Storage upload rule without authentication",
    """
This rule lets callers upload, overwrite or delete files without checking `request.auth`.
Anyone can fill your bucket (and your bill), replace your users' files, or host malware on
your project's storage domain.
""",
    """
Require a signed-in owner, e.g. store files under the user's id:

  match /users/{userId}/{fileName} {
    allow read: if request.auth != null && request.auth.uid == userId;
    allow create, update: if request.auth != null && request.auth.uid == userId
                          && request.resource.size < 5 * 1024 * 1024
                          && request.resource.contentType.matches('image/.*');
    allow delete: if request.auth != null && request.auth.uid == userId;
  }
""",
)
_rule(
    "FLC102",
    "Storage upload without size or content-type limits",
    """
Without `request.resource.size` and `request.resource.contentType` checks, a signed-in user
can upload files of any size and type: gigabytes that you pay to store and serve, or HTML /
SVG files that run script when opened from your storage URL.
""",
    """
Limit size and type on create/update (not on delete, where request.resource is null):

  allow create, update: if request.auth != null && request.auth.uid == userId
                        && request.resource.size < 5 * 1024 * 1024
                        && request.resource.contentType.matches('image/.*');
  allow delete: if request.auth != null && request.auth.uid == userId;
""",
)

# ---------------------------------------------------------------- Realtime Database
_rule(
    "FLC201",
    "Realtime Database open to everyone (\".read\"/\".write\": true)",
    """
Realtime Database rules cascade: a `true` at a path grants access to that path and
everything below it, and deeper rules cannot take it back. Anyone with your database URL
(it is in your web app's config) can read or overwrite that whole subtree with a plain HTTP
request.
""",
    """
Scope access to the signed-in owner, e.g. in database.rules.json:

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

Keep ".read": true only on paths that hold genuinely public data, and never ".write": true.
""",
)
_rule(
    "FLC202",
    "Realtime Database test-mode rule (open until a date)",
    """
Test mode creates `".read": "now < <timestamp>"` and the same for `.write`. Until that
moment anyone can read and overwrite the entire database; afterwards everything is denied.
""",
    """
Replace the time-limited rule with real rules, e.g.:

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
""",
)
_rule(
    "FLC203",
    "Realtime Database only checks \"signed in\" (auth != null)",
    """
`auth != null` only proves the caller has some account, and anyone can create one with
your public config. Because rules cascade, this grants every signed-in user access to the
whole subtree, including other users' data.
""",
    """
Compare the signed-in user with the owner key, e.g.:

  "users": {
    "$uid": {
      ".read": "auth != null && auth.uid === $uid",
      ".write": "auth != null && auth.uid === $uid"
    }
  }
""",
)

# ---------------------------------------------------------------- code and secrets
_rule(
    "FLC301",
    "Service account private key in the project",
    """
A service account key lets its holder use the Admin SDK: it bypasses all security rules
and can read, change and delete everything in Firestore, Realtime Database, Storage and
Auth. Keys in a repository or in a hosted folder get scraped and used, and they stay in
git history after the file is deleted.
""",
    """
1. Delete the key now: Google Cloud console -> IAM & Admin -> Service Accounts -> the account
   -> Keys -> delete. Assume the old key is public.
2. Remove the file from git history (git filter-repo / BFG) and add it to .gitignore.
3. On Cloud Functions, App Hosting and Cloud Run use the built-in credentials:
     initializeApp()   // no key file needed
   Elsewhere, load the key from a secret manager or an environment variable that is not
   committed and never sent to the browser.
""",
)
_rule(
    "FLC302",
    "Admin SDK (firebase-admin) in client code",
    """
firebase-admin is the server SDK. It needs a service account credential and ignores every
security rule. Importing it in browser or mobile code means either the build ships a
credential to every user, or the code is broken and someone will "fix" it by adding one.
""",
    """
Use the client SDK in browser code:

  import { initializeApp } from "firebase/app";
  import { getFirestore } from "firebase/firestore";

and move privileged work (admin actions, custom claims, cross-user writes) to a Cloud
Function or a server route that imports firebase-admin and checks the caller's ID token.
""",
)

# ---------------------------------------------------------------- configuration
_rule(
    "FLC401",
    "Emulator connection not guarded for production",
    """
connectFirestoreEmulator / connectAuthEmulator / useEmulator calls that run
unconditionally make a production build talk to localhost: the app silently breaks for
users, and the usual quick fix is to delete or loosen rules instead of the call.
""",
    """
Only connect to the emulators in development builds, e.g.:

  if (import.meta.env.DEV) {            // or process.env.NODE_ENV !== "production"
    connectFirestoreEmulator(db, "127.0.0.1", 8080);
    connectAuthEmulator(auth, "http://127.0.0.1:9099");
  }
""",
)
_rule(
    "FLC402",
    "Emulator host variable in a production environment file",
    """
When FIREBASE_AUTH_EMULATOR_HOST is set, the Admin SDK talks to the Auth emulator and
accepts unsigned ID tokens, so a server that verifies tokens would trust anything. The
other *_EMULATOR_HOST variables send production server traffic to localhost.
""",
    """
Remove the *_EMULATOR_HOST lines from production env files (.env.production,
apphosting.yaml, app.yaml, ...). Set them only in your local shell or in a development
file such as .env.local, or let `firebase emulators:start` set them for you.
""",
)
_rule(
    "FLC403",
    "Emulators listen on all network interfaces",
    """
`"host": "0.0.0.0"` in the emulators section of firebase.json exposes the emulators, which
have no authentication and an admin UI, to everyone on your network (cafe Wi-Fi, office
LAN, or the internet on a cloud VM).
""",
    """
Bind to localhost unless you really need access from another device:

  "emulators": {
    "firestore": { "host": "127.0.0.1", "port": 8080 },
    "ui": { "enabled": true, "host": "127.0.0.1" }
  }
""",
)
_rule(
    "FLC404",
    "Firebase service used but no rules file in the project",
    """
The client code uses this service, but no rules file for it was found, so the rules that
protect it live only in the Firebase console and could not be checked. Rules edited only in
the console are easy to leave in test mode and cannot be reviewed or versioned.
""",
    """
Pull the current rules into the repo and deploy them from there:

  firebase init firestore      # or: firebase init storage / firebase init database
  firebase deploy --only firestore:rules

Then run firebase-launch-check again.
""",
)


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    file: str | None = None
    line: int | None = None
    evidence: str | None = None
    heuristic: bool = False
    extra: dict = field(default_factory=dict)
    custom_fix: str | None = None

    @property
    def rule(self) -> Rule:
        return RULES[self.rule_id]

    @property
    def location(self) -> str:
        if self.file is None:
            return ""
        return f"{self.file}:{self.line}" if self.line else self.file

    @property
    def fix(self) -> str:
        """The fix written for this finding (paths and names filled in) or the rule's generic fix."""
        return self.custom_fix or self.rule.fix

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("custom_fix")
        d["title"] = self.rule.title
        d["why"] = self.rule.why
        d["fix"] = self.fix
        if not d["extra"]:
            d.pop("extra")
        return d


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (SEVERITY_RANK[f.severity], f.rule_id, f.file or "", f.line or 0),
    )


def mask_secret(value: str) -> str:
    """Show at most the first 4 characters of a secret, never enough to use it."""
    keep = min(4, len(value) // 4)
    return f"{value[:keep]}**** ({len(value)} chars)"


_PRIVATE_KEY_BODY = re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[^\"'`]*?(?:-----END (?:[A-Z]+ )?PRIVATE KEY-----"
                               r"(?:\\n|\n)?|(?=[\"'`]|$))")
_KEY_ID = re.compile(r"(\"?private_key_id\"?\s*[:=]\s*[\"']?)([0-9a-f]{40})")


def redact_line(line: str, limit: int = 160) -> str:
    """Strip a source/config line for display, masking anything secret-shaped."""
    s = line.strip()
    s = _PRIVATE_KEY_BODY.sub(lambda m: mask_secret(m.group(0)), s)
    s = _KEY_ID.sub(lambda m: m.group(1) + mask_secret(m.group(2)), s)
    if len(s) > limit:
        s = s[: limit - 3] + "..."
    return s
