"""Checks on source and config files: service account keys (FLC301), firebase-admin in client
code (FLC302), emulator settings (FLC401, FLC402) and which Firebase services the client uses."""

from __future__ import annotations

import json
import re

from .findings import Finding, mask_secret, redact_line

# ---------------------------------------------------------------- FLC301 service account keys
_PEM = re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----(?:\\n|\\r|\s)*[A-Za-z0-9+/=]{40}")
_SA_CONTEXT = re.compile(r"gserviceaccount\.com|private_key|PRIVATE_KEY|service_account", re.I)


def find_service_account_key(text: str) -> tuple[int, str, str] | None:
    """Return (line, description, masked evidence) if the text holds a service account private key."""
    m = _PEM.search(text)
    if not m:
        return None
    stripped = text.lstrip("﻿ \t\r\n")
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
        except ValueError:
            obj = None
        if isinstance(obj, dict) and obj.get("type") == "service_account" and isinstance(obj.get("private_key"), str):
            line = text.count("\n", 0, m.start()) + 1
            pid = obj.get("project_id") or "?"
            key_id = str(obj.get("private_key_id") or "")
            ev = f"private_key = {mask_secret(obj['private_key'])}"
            if key_id:
                ev += f", private_key_id = {mask_secret(key_id)}"
            return line, f"Service account key file for project '{pid}'", ev
    if not _SA_CONTEXT.search(text):
        return None
    line = text.count("\n", 0, m.start()) + 1
    raw = text.splitlines()[line - 1] if text.splitlines() else ""
    return line, "A private key (service account credential)", redact_line(raw)


# ---------------------------------------------------------------- FLC302 firebase-admin in client code
_ADMIN_IMPORT = re.compile(
    r"""(?:\bfrom\s+|\brequire\s*\(\s*|\bimport\s*\(\s*|^\s*import\s+)['"]firebase-admin(?:/[\w/-]*)?['"]""", re.M)


def find_admin_imports(text: str) -> list[int]:
    return [text.count("\n", 0, m.start()) + 1 for m in _ADMIN_IMPORT.finditer(text)]


# ---------------------------------------------------------------- FLC401 emulator connection
_EMU_CALL = re.compile(r"\b(connect(?:Firestore|Auth|Storage|Database|Functions)Emulator|\.useEmulator)\s*\(")
_GUARD_HINT = re.compile(r"\bif\s*\(|\?|&&|\|\||import\.meta\.env|process\.env|location\.host|__DEV__|\bisDev|"
                         r"\bDEV\b|emulator", re.I)


def find_unguarded_emulator(text: str) -> list[tuple[int, str]]:
    """Emulator connections at the top level of a module with no condition around them."""
    lines = text.splitlines()
    out = []
    for idx, raw in enumerate(lines):
        m = _EMU_CALL.search(raw)
        if not m or raw[:1].isspace() or raw.lstrip().startswith(("//", "*", "/*")):
            continue
        if _GUARD_HINT.search(raw[: m.start()]) or "&&" in raw or "?" in raw:
            continue
        prev = [ln for ln in lines[max(0, idx - 3):idx] if ln.strip()]
        if prev and (prev[-1].rstrip().endswith(("{", "(", ",", "?", ":", "&&", "||")) or
                     any(re.search(r"\bif\s*\(|\belse\b", p) for p in prev[-1:])):
            continue
        out.append((idx + 1, m.group(1).lstrip(".")))
    return out


# ---------------------------------------------------------------- FLC402 emulator env in production config
_EMU_ENV = re.compile(r"\b(FIREBASE_AUTH_EMULATOR_HOST|FIRESTORE_EMULATOR_HOST|FIREBASE_DATABASE_EMULATOR_HOST|"
                      r"FIREBASE_STORAGE_EMULATOR_HOST|STORAGE_EMULATOR_HOST)\b")
PROD_ENV_NAMES = re.compile(r"^(\.env\.(production|prod)(\.local)?|apphosting\.yaml|apphosting\.(production|prod)\.yaml|"
                            r"app\.yaml)$", re.I)


def find_emulator_env(text: str) -> list[tuple[int, str]]:
    out = []
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        m = _EMU_ENV.search(s)
        if not m:
            continue
        after = s[m.end():].lstrip()
        before = s[: m.start()]
        if after.startswith(("=", ":")) or re.search(r"variable\s*:\s*$", before):
            out.append((i, m.group(1)))
    return out


# ---------------------------------------------------------------- which services does the client use
_SDK_USE = {
    "firestore": re.compile(r"""['"](?:firebase/(?:compat/)?firestore(?:/lite)?|@react-native-firebase/firestore|"""
                            r"""@angular/fire/(?:compat/)?firestore|package:cloud_firestore/[\w/]+\.dart)['"]|"""
                            r"""^\s*import\s+FirebaseFirestore\b|\bcom\.google\.firebase\.firestore\b""", re.M),
    "storage": re.compile(r"""['"](?:firebase/(?:compat/)?storage|@react-native-firebase/storage|"""
                          r"""@angular/fire/(?:compat/)?storage|package:firebase_storage/[\w/]+\.dart)['"]|"""
                          r"""^\s*import\s+FirebaseStorage\b|\bcom\.google\.firebase\.storage\b""", re.M),
    "database": re.compile(r"""['"](?:firebase/(?:compat/)?database|@react-native-firebase/database|"""
                           r"""@angular/fire/(?:compat/)?database|package:firebase_database/[\w/]+\.dart)['"]|"""
                           r"""^\s*import\s+FirebaseDatabase\b|\bcom\.google\.firebase\.database\b""", re.M),
}


def services_used(text: str) -> set[str]:
    return {svc for svc, pat in _SDK_USE.items() if pat.search(text)}


# ---------------------------------------------------------------- privileged fields written by the client
PRIVILEGED_FIELDS = ("role", "roles", "isAdmin", "is_admin", "admin", "superAdmin", "isSuperAdmin", "plan", "tier",
                     "isPro", "isPremium", "premium", "subscriptionStatus", "subscriptionTier", "credits",
                     "permissions", "isStaff", "isModerator")
_PRIV_KEY = re.compile(r"(?:^|[{,\s])(['\"]?)(" + "|".join(PRIVILEGED_FIELDS) + r")\1\s*:(?!:)")
_MODULAR_WRITE = re.compile(r"\b(setDoc|addDoc|updateDoc)\s*\(")
_REF_COLL = re.compile(r"\b(?:doc|collection)\s*\(\s*[\w.]+\s*,\s*['\"`]([\w-]+)['\"`]")
_NS_WRITE = re.compile(r"\.collection\(\s*['\"]([\w-]+)['\"]\s*\)(?:\s*\.doc\([^()]*(?:\([^()]*\))?[^()]*\))?"
                       r"\s*\.(set|update|add)\s*\(")


def _balanced(text: str, open_pos: int, limit: int = 3000) -> str:
    depth, i, end = 0, open_pos, min(len(text), open_pos + limit)
    while i < end:
        ch = text[i]
        if ch in "'\"`":
            j = text.find(ch, i + 1)
            i = end if j == -1 else j + 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i]
        i += 1
    return text[open_pos + 1:end]


def _top_level_keys(args: str) -> list[str]:
    """Privileged keys written at the top level of object literals passed as call arguments."""
    stack: list[str] = []
    buf = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for ch in args:
        if ch in "([{":
            stack.append(ch)
            buf.append(" ")
            continue
        if ch in ")]}":
            if stack and stack[-1] == pairs[ch]:
                stack.pop()
            buf.append(" ")
            continue
        buf.append(ch if stack == ["{"] else " ")
    return [m.group(2) for m in _PRIV_KEY.finditer("".join(buf))]


def find_privileged_writes(text: str) -> list[tuple[str, int, str]]:
    """[(collection, line, field)] for client writes that set privileged-looking fields."""
    out = []
    for m in _MODULAR_WRITE.finditer(text):
        args = _balanced(text, m.end() - 1)
        cm = _REF_COLL.search(args)
        if not cm:
            continue
        for fld in _top_level_keys(args):
            out.append((cm.group(1), text.count("\n", 0, m.start()) + 1, fld))
    for m in _NS_WRITE.finditer(text):
        args = _balanced(text, m.end() - 1)
        for fld in _top_level_keys(args):
            out.append((m.group(1), text.count("\n", 0, m.start()) + 1, fld))
    seen, uniq = set(), []
    for item in out:
        if (item[0], item[2]) not in seen:
            seen.add((item[0], item[2]))
            uniq.append(item)
    return uniq
