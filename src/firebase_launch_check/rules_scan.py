"""Checks for Firestore and Cloud Storage security rules (FLC001-FLC005, FLC101-FLC102)."""

from __future__ import annotations

import datetime as _dt
import re

from .findings import Finding, redact_line
from .rules_lang import Allow, RulesFile, classify, expand, parse_rules

READ_OPS = {"read", "get", "list"}
WRITE_OPS = {"write", "create", "update", "delete"}
UPLOAD_OPS = {"write", "create", "update"}

USER_WILDCARD = re.compile(r"(?i)^(uid|user|user_?id|owner_?id|owner_?uid|account_?id|member_?id|profile_?id|"
                           r"customer_?id|author_?id)$")
USER_COLLECTIONS = {"users", "user", "profiles", "profile", "accounts", "customers", "orders", "payments", "invoices",
                    "messages", "chats", "conversations", "notifications", "settings", "private", "carts",
                    "subscriptions", "transactions", "addresses", "userdata", "user_data", "members", "uploads",
                    "documents_private", "medical", "health", "receipts", "billing"}

_FS_PREFIX = re.compile(r"^/databases/\{[^}]+\}/documents")
_ST_PREFIX = re.compile(r"^/b/\{[^}]+\}/o")
_ROOT_RECURSIVE = re.compile(r"^/\{[^}=]+=\*\*\}$")
_PRIV_GET = re.compile(
    r"get(?:After)?\(\s*/databases/\$\(\s*database\s*\)/documents/([\w-]+)/\$\(\s*request\.auth\.uid\s*\)\s*\)"
    r"\s*\.data\s*(?:\.\s*(\w+)|\[\s*['\"](\w+)['\"]\s*\])")


def _service_prefix(service: str) -> re.Pattern[str]:
    return _ST_PREFIX if service == "storage" else _FS_PREFIX


def relative_path(allow: Allow) -> str:
    """Path below /databases/{db}/documents (Firestore) or /b/{bucket}/o (Storage)."""
    p = _service_prefix(allow.service).sub("", allow.full_path)
    return p or "/"


def segments(allow: Allow) -> list[str]:
    return [s for s in relative_path(allow).split("/") if s]


def user_wildcard(allow: Allow) -> str | None:
    """The innermost wildcard that names a user ({userId}, {uid}, ...), if any."""
    for seg in reversed(segments(allow)):
        m = re.fullmatch(r"\{(\w+)\}", seg)
        if m and USER_WILDCARD.match(m.group(1)):
            return m.group(1)
    return None


def is_user_owned(allow: Allow) -> bool:
    if user_wildcard(allow):
        return True
    return any(s.lower() in USER_COLLECTIONS for s in segments(allow) if not s.startswith("{"))


def is_root_recursive(allow: Allow) -> bool:
    return bool(_ROOT_RECURSIVE.match(relative_path(allow)))


def _ops(allow: Allow) -> tuple[bool, bool]:
    ops = set(allow.ops)
    return bool(ops & READ_OPS), bool(ops & WRITE_OPS)


def _svc(service: str) -> str:
    return {"firestore": "Firestore", "storage": "Storage"}.get(service, "Rules")


# ---------------------------------------------------------------- fixes
def _owner_lines(allow: Allow) -> list[str]:
    has_read, has_write = _ops(allow)
    ops = set(allow.ops)
    w = user_wildcard(allow)
    lines: list[str] = []
    if allow.service == "storage":
        w = w or "userId"
        own = f"request.auth != null && request.auth.uid == {w}"
        if has_read:
            lines.append(f"allow read: if {own};")
        if ops & UPLOAD_OPS:
            lines.append(f"allow create, update: if {own}")
            lines.append("                      && request.resource.size < 5 * 1024 * 1024   // 5 MB")
            lines.append("                      && request.resource.contentType.matches('image/.*');")
        if ops & {"write", "delete"}:
            lines.append(f"allow delete: if {own};")
        return lines
    if w:
        names = ", ".join(o for o in allow.ops)
        return [f"allow {names}: if request.auth != null && request.auth.uid == {w};"]
    if has_read:
        lines.append("allow read: if request.auth != null && request.auth.uid == resource.data.ownerId;")
    if ops & {"write", "update", "delete"}:
        names = ", ".join(o for o in ("update", "delete") if "write" in ops or o in ops)
        lines.append(f"allow {names}: if request.auth != null && request.auth.uid == resource.data.ownerId;")
    if ops & {"write", "create"}:
        lines.append("allow create: if request.auth != null && request.auth.uid == request.resource.data.ownerId;")
    return lines


def _block(match: str, lines: list[str]) -> str:
    body = "\n".join("    " + ln for ln in lines)
    return f"  match {match} {{\n{body}\n  }}"


def owner_fix(allow: Allow, intro: str, public_note: bool = False) -> str:
    match = allow.match
    if allow.service == "storage" and not user_wildcard(allow):
        match = "/users/{userId}/{fileName}"
        intro += " Store each user's files under their uid, e.g.:"
    text = f"{intro}\n\n{_block(match, _owner_lines(allow))}"
    if allow.service == "firestore" and not user_wildcard(allow):
        text += ("\n\n(ownerId = the field where you store the creator's uid; set it on create.)")
    if allow.service == "storage":
        text += "\n\n(Adjust the size limit and content type to what your app really uploads.)"
    if public_note:
        text += ("\n\nIf this data is intentionally public, keep reads only (`allow read: if true;`), never\n"
                 "writes, and add `// firebase-launch-check: ignore` to that line.")
    return text


def test_mode_fix(allow: Allow) -> str:
    if allow.service == "storage":
        sample = _block("/users/{userId}/{fileName}", [
            "allow read: if request.auth != null && request.auth.uid == userId;",
            "allow create, update: if request.auth != null && request.auth.uid == userId",
            "                      && request.resource.size < 5 * 1024 * 1024",
            "                      && request.resource.contentType.matches('image/.*');",
            "allow delete: if request.auth != null && request.auth.uid == userId;"])
        head = "Replace the time-limited rule with per-path rules (everything not matched is denied):"
        return f"{head}\n\n  rules_version = '2';\n  service firebase.storage {{\n    match /b/{{bucket}}/o {{\n" + \
            "\n".join("  " + ln for ln in sample.splitlines()) + "\n    }\n  }"
    return RULES_FIX_FS_TEST


RULES_FIX_FS_TEST = """\
Replace the time-limited rule with one match block per collection (everything not matched
is denied):

  rules_version = '2';
  service cloud.firestore {
    match /databases/{database}/documents {
      match /users/{userId} {
        allow read, write: if request.auth != null && request.auth.uid == userId;
      }
      match /posts/{postId} {
        allow read: if true;   // public data: reads only
        allow create: if request.auth != null && request.auth.uid == request.resource.data.ownerId;
        allow update, delete: if request.auth != null && request.auth.uid == resource.data.ownerId;
      }
    }
  }"""


def recursive_fix(allow: Allow, line: int) -> str:
    if allow.service == "storage":
        example = _block("/users/{userId}/{fileName}", [
            "allow read: if request.auth != null && request.auth.uid == userId;",
            "allow create, update: if request.auth != null && request.auth.uid == userId",
            "                      && request.resource.size < 5 * 1024 * 1024",
            "                      && request.resource.contentType.matches('image/.*');",
            "allow delete: if request.auth != null && request.auth.uid == userId;"])
        return (f"Delete the `match {allow.match}` block (line {line}) and add one block per folder;\n"
                f"anything not matched is denied:\n\n  match /b/{{bucket}}/o {{\n"
                + "\n".join("  " + ln for ln in example.splitlines()) + "\n  }")
    return (f"Delete the `match {allow.match}` block (line {line}) and add one block per collection;\n"
            "anything not matched is denied:\n\n"
            "  match /databases/{database}/documents {\n"
            "    match /users/{userId} {\n"
            "      allow read, write: if request.auth != null && request.auth.uid == userId;\n"
            "    }\n"
            "  }")


def privileged_fix(match: str, wildcard: str, field: str, ops: set[str]) -> str:
    lines = []
    if ops & {"write", "create"}:
        lines += [f"allow create: if request.auth != null && request.auth.uid == {wildcard}",
                  f"              && !('{field}' in request.resource.data);"]
    if ops & {"write", "update"}:
        lines += [f"allow update: if request.auth != null && request.auth.uid == {wildcard}",
                  f"              && !request.resource.data.diff(resource.data).affectedKeys().hasAny(['{field}']);"]
    if "write" in ops or "delete" in ops:
        lines += [f"allow delete: if request.auth != null && request.auth.uid == {wildcard};"]
    return ("Stop clients from setting or changing the field; set it only from the Admin SDK or a\n"
            f"Cloud Function:\n\n{_block(match, lines)}\n\n"
            f"or move '{field}' to a custom claim (request.auth.token.{field}), which only the Admin\n"
            "SDK can set.")


def upload_fix(allow: Allow, missing: list[str]) -> str:
    w = user_wildcard(allow) or "userId"
    own = f"request.auth != null && request.auth.uid == {w}"
    lines = [f"allow create, update: if {own}",
             "                      && request.resource.size < 5 * 1024 * 1024   // 5 MB",
             "                      && request.resource.contentType.matches('image/.*');"]
    if set(allow.ops) & {"write", "delete"}:
        lines.append(f"allow delete: if {own};")
    match = allow.match if user_wildcard(allow) else "/users/{userId}/{fileName}"
    head = f"Add the missing {' and '.join(missing)} check(s) to uploads (not to delete, where\n" \
           "request.resource is null):"
    return f"{head}\n\n{_block(match, lines)}\n\n(Adjust the size limit and content type to what your app really uploads.)"


# ---------------------------------------------------------------- the scan
def privileged_reads(rf: RulesFile) -> dict[str, set[str]]:
    """{collection: {fields}} for `get(.../<collection>/$(request.auth.uid)).data.<field>` in the rules."""
    out: dict[str, set[str]] = {}
    for m in _PRIV_GET.finditer(rf.clean_text):
        out.setdefault(m.group(1), set()).add(m.group(2) or m.group(3))
    return out


def _doc_wildcard(allow: Allow, collection: str) -> str | None:
    segs = segments(allow)
    if len(segs) == 2 and segs[0] == collection:
        m = re.fullmatch(r"\{(\w+)\}", segs[1])
        if m:
            return m.group(1)
    return None


def scan_rules_text(rel: str, text: str, *, service_hint: str | None = None,
                    client_privileged: dict[str, list[tuple[str, int, str]]] | None = None,
                    today: _dt.date | None = None) -> tuple[RulesFile, list[Finding]]:
    today = today or _dt.date.today()
    rf = parse_rules(text)
    if rf.service == "unknown" and service_hint:
        rf.service = service_hint
        for a in rf.allows:
            if a.service == "unknown":
                a.service = service_hint
    lines = text.splitlines()
    findings: list[Finding] = []

    def ev(line: int) -> str:
        return redact_line(lines[line - 1]) if 0 < line <= len(lines) else ""

    for a in rf.allows:
        if a.service not in ("firestore", "storage"):
            continue
        cond = expand(a.condition, rf.functions) if a.condition is not None else None
        kind, date = classify(cond)
        has_read, has_write = _ops(a)
        svc = _svc(a.service)
        rel_path = relative_path(a)
        ops_txt = ", ".join(a.ops)
        extra = {"service": a.service, "path": rel_path, "ops": a.ops}
        if kind == "test_mode":
            y, mo, d = date
            try:
                expiry = _dt.date(y, mo, d)
            except ValueError:
                expiry = None
            expired = expiry is not None and expiry <= today
            when = expiry.isoformat() if expiry else f"{y}-{mo}-{d}"
            scope = "the whole database" if a.service == "firestore" and is_root_recursive(a) else \
                "every file in the bucket" if is_root_recursive(a) else rel_path
            if expired:
                msg = (f"{svc} test-mode rule (allow {ops_txt}) expired on {when}: it now denies every request to "
                       f"{scope}. If the app still works, the deployed rules differ from this file; if someone "
                       f"pushes the date forward, {scope} is open to everyone again.")
                sev = "medium"
            else:
                msg = (f"{svc} test-mode rule: allow {ops_txt} for anyone on {scope} until {when} "
                       "(no sign-in required).")
                sev = "critical" if has_write else "high"
            findings.append(Finding("FLC002", sev, msg, rel, a.line, ev(a.line), extra={**extra, "expires": when},
                                    custom_fix=test_mode_fix(a)))
            continue
        if is_root_recursive(a) and kind in ("true", "auth_only"):
            who = "anyone on the internet" if kind == "true" else "any signed-in user (anyone can sign up)"
            what = "document in the database" if a.service == "firestore" else "file in the bucket"
            sev = "critical" if kind == "true" else ("critical" if has_write else "high")
            findings.append(Finding(
                "FLC004", sev,
                f"`match {a.match}` gives {who} {ops_txt} access to every {what}, and overrides every "
                f"stricter rule in this file (rules are OR'ed).",
                rel, a.line, ev(a.line), extra=extra, custom_fix=recursive_fix(a, a.line)))
            continue
        if kind == "true":
            if has_write:
                sev = "critical"
            else:
                sev = "high" if is_user_owned(a) else "medium"
            how = "no condition" if a.condition is None else "`if true`"
            findings.append(Finding(
                "FLC001", sev,
                f"{svc} rule `allow {ops_txt}` on {rel_path} has {how}: anyone on the internet can "
                f"{'read and change' if has_read and has_write else 'change' if has_write else 'read'} it, "
                "without signing in.",
                rel, a.line, ev(a.line), extra=extra,
                custom_fix=owner_fix(a, "Require the owner instead of everyone:", public_note=not has_write)))
            continue
        if kind == "auth_only":
            owned = is_user_owned(a)
            if has_write or (has_read and owned):
                parts = []
                if has_read and owned:
                    parts.append("read")
                if has_write:
                    parts.append("change or delete" if set(a.ops) & {"write", "update", "delete"} else "create")
                if set(a.ops) == {"create"}:
                    continue   # create-only with a sign-in check is a common, acceptable pattern
                findings.append(Finding(
                    "FLC003", "high",
                    f"{svc} rule `allow {ops_txt}` on {rel_path} only checks that the caller is signed in: "
                    f"any user can {' and '.join(parts)} every other user's "
                    f"{'documents' if a.service == 'firestore' else 'files'} here.",
                    rel, a.line, ev(a.line), heuristic=not has_write, extra=extra,
                    custom_fix=owner_fix(a, "Check that the caller owns the data, not just that they are signed in:")))
            continue
        # kind == "other": storage upload checks
        if a.service == "storage" and set(a.ops) & UPLOAD_OPS and cond is not None:
            if "request.auth" not in cond:
                findings.append(Finding(
                    "FLC101", "high",
                    f"Storage rule `allow {ops_txt}` on {rel_path} never checks request.auth: anyone can upload, "
                    "overwrite or delete files here without signing in.",
                    rel, a.line, ev(a.line), extra=extra,
                    custom_fix=owner_fix(a, "Require a signed-in owner:")))
                continue
            missing = []
            if "request.resource.size" not in cond:
                missing.append("size")
            if "request.resource.contentType" not in cond:
                missing.append("content-type")
            if missing:
                findings.append(Finding(
                    "FLC102", "medium" if "size" in missing else "low",
                    f"Storage rule `allow {ops_txt}` on {rel_path} has no {' or '.join(missing)} limit: a signed-in "
                    + ("user can upload files of any size." if "size" in missing else
                       "user can upload any file type, including HTML/SVG that runs script when opened."),
                    rel, a.line, ev(a.line), extra={**extra, "missing": missing},
                    custom_fix=upload_fix(a, missing)))

    # FLC005: privileged fields the user can write on their own document
    if rf.service == "firestore":
        targets: dict[str, dict[str, tuple[str, str, int | None]]] = {}   # coll -> field -> (source, file, line)
        for coll, fields in privileged_reads(rf).items():
            for fld in fields:
                targets.setdefault(coll, {})[fld] = ("rules", rel, None)
        for coll, uses in (client_privileged or {}).items():
            for (file, line, fld) in uses:
                targets.setdefault(coll, {}).setdefault(fld, ("client", file, line))
        for coll, fields in targets.items():
            for a in rf.allows:
                w = _doc_wildcard(a, coll)
                if not w or not set(a.ops) & {"write", "create", "update"} or a.condition is None:
                    continue
                cond = expand(a.condition, rf.functions)
                if classify(cond)[0] != "other" or "request.auth" not in cond:
                    continue   # broad rules are reported above; skip conditions we cannot judge
                for fld, (source, src_file, src_line) in sorted(fields.items()):
                    if re.search(rf"\b{re.escape(fld)}\b", cond) or ".hasOnly(" in cond:
                        continue
                    if source == "rules":
                        why = (f"your rules use get(.../{coll}/$(request.auth.uid)).data.{fld} to grant access, but "
                               f"`allow {', '.join(a.ops)}` on /{coll}/{{{w}}} does not stop the user from writing "
                               f"'{fld}' on their own document: any user can grant themselves that access.")
                        sev = "high"
                    else:
                        why = (f"client code writes '{fld}' to {coll} documents ({src_file}:{src_line}), and "
                               f"`allow {', '.join(a.ops)}` on /{coll}/{{{w}}} does not restrict that field: a user "
                               f"can set any '{fld}' value they like from the browser console.")
                        sev = "medium"
                    findings.append(Finding(
                        "FLC005", sev, why[0].upper() + why[1:], rel, a.line, ev(a.line), heuristic=True,
                        extra={"service": "firestore", "path": f"/{coll}/{{{w}}}", "field": fld, "ops": a.ops},
                        custom_fix=privileged_fix(a.match, w, fld, set(a.ops))))
    return rf, findings
