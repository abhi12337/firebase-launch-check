"""Checks for Realtime Database rules (database.rules.json): FLC201-FLC203."""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass

from .findings import Finding, redact_line
from .rules_scan import USER_COLLECTIONS


# ---------------------------------------------------------------- a JSON reader that keeps line numbers
@dataclass
class Node:
    value: object          # dict[str, (Node)], list[Node], str, int, float, bool, None
    line: int


class JsonError(ValueError):
    pass


class _Reader:
    """JSON with // and /* */ comments and trailing commas (as the Firebase CLI accepts)."""

    def __init__(self, text: str):
        self.t = text
        self.i = 0
        self.line = 1

    def _ws(self) -> None:
        t = self.t
        while self.i < len(t):
            ch = t[self.i]
            if ch == "\n":
                self.line += 1
                self.i += 1
            elif ch in " \t\r﻿":
                self.i += 1
            elif t.startswith("//", self.i):
                j = t.find("\n", self.i)
                self.i = len(t) if j == -1 else j
            elif t.startswith("/*", self.i):
                j = t.find("*/", self.i + 2)
                j = len(t) if j == -1 else j + 2
                self.line += t.count("\n", self.i, j)
                self.i = j
            else:
                break

    def parse(self) -> Node:
        self._ws()
        node = self._value()
        self._ws()
        if self.i != len(self.t):
            raise JsonError(f"unexpected text at line {self.line}")
        return node

    def _value(self) -> Node:
        self._ws()
        if self.i >= len(self.t):
            raise JsonError("unexpected end of file")
        ch = self.t[self.i]
        line = self.line
        if ch == "{":
            self.i += 1
            obj: dict[str, Node] = {}
            keys: dict[str, int] = {}
            while True:
                self._ws()
                if self.i < len(self.t) and self.t[self.i] == "}":
                    self.i += 1
                    break
                key_line = self.line
                key = self._string()
                self._ws()
                if self.i >= len(self.t) or self.t[self.i] != ":":
                    raise JsonError(f"expected ':' at line {self.line}")
                self.i += 1
                val = self._value()
                obj[key] = val
                keys[key] = key_line
                self._ws()
                if self.i < len(self.t) and self.t[self.i] == ",":
                    self.i += 1
                    continue
                self._ws()
                if self.i < len(self.t) and self.t[self.i] == "}":
                    self.i += 1
                    break
                raise JsonError(f"expected ',' or '}}' at line {self.line}")
            node = Node(obj, line)
            node.key_lines = keys   # type: ignore[attr-defined]
            return node
        if ch == "[":
            self.i += 1
            arr: list[Node] = []
            while True:
                self._ws()
                if self.i < len(self.t) and self.t[self.i] == "]":
                    self.i += 1
                    break
                arr.append(self._value())
                self._ws()
                if self.i < len(self.t) and self.t[self.i] == ",":
                    self.i += 1
                    continue
                self._ws()
                if self.i < len(self.t) and self.t[self.i] == "]":
                    self.i += 1
                    break
                raise JsonError(f"expected ',' or ']' at line {self.line}")
            return Node(arr, line)
        if ch == '"':
            return Node(self._string(), line)
        m = re.compile(r"-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null").match(self.t, self.i)
        if not m:
            raise JsonError(f"unexpected character {ch!r} at line {self.line}")
        self.i = m.end()
        tok = m.group(0)
        val: object = {"true": True, "false": False, "null": None}.get(tok, tok)
        if isinstance(val, str):
            val = float(tok) if any(c in tok for c in ".eE") else int(tok)
        return Node(val, line)

    def _string(self) -> str:
        if self.i >= len(self.t) or self.t[self.i] != '"':
            raise JsonError(f"expected a string at line {self.line}")
        j = self.i + 1
        out = []
        while j < len(self.t):
            ch = self.t[j]
            if ch == "\\" and j + 1 < len(self.t):
                nxt = self.t[j + 1]
                out.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\", "/": "/"}.get(nxt, nxt))
                j += 2
                continue
            if ch == '"':
                break
            if ch == "\n":
                self.line += 1
            out.append(ch)
            j += 1
        self.i = j + 1
        return "".join(out)


def parse_json_lines(text: str) -> Node:
    return _Reader(text).parse()


def to_plain(node: Node) -> object:
    v = node.value
    if isinstance(v, dict):
        return {k: to_plain(n) for k, n in v.items()}
    if isinstance(v, list):
        return [to_plain(n) for n in v]
    return v


# ---------------------------------------------------------------- checks
_AUTH_ONLY = {"auth!=null", "auth!==null", "null!=auth", "null!==auth", "auth.uid!=null", "auth.uid!==null",
              "auth!=null&&auth.uid!=null", "auth!==null&&auth.uid!==null"}
_NOW = re.compile(r"\(?now<(\d{12,14})\)?")


def _compact(expr: str) -> str:
    s = "".join(expr.split())
    while s.startswith("(") and s.endswith(")") and s.count("(") == s.count(")"):
        inner = s[1:-1]
        depth, ok = 0, True
        for ch in inner:
            depth += ch == "("
            depth -= ch == ")"
            if depth < 0:
                ok = False
                break
        if not ok:
            break
        s = inner
    return s


def looks_like_rtdb_rules(obj: object) -> bool:
    return isinstance(obj, dict) and isinstance(obj.get("rules"), dict)


def rtdb_fix(path: list[str]) -> str:
    """An owner-scoped example rooted at the reported path."""
    wild = next((p for p in path if p.startswith("$")), None)
    lit = [p for p in path if not p.startswith("$")]
    coll = lit[0] if lit else "users"
    var = wild or "$uid"
    lines = [
        "Remove the broad rule and grant access per user, e.g. in database.rules.json:",
        "",
        "  {",
        '    "rules": {',
        f'      "{coll}": {{',
        f'        "{var}": {{',
        f'          ".read": "auth != null && auth.uid === {var}",',
        f'          ".write": "auth != null && auth.uid === {var}"',
        "        }",
        "      }",
        "    }",
        "  }",
        "",
        "Rules cascade: a grant on a parent path cannot be revoked by a child, so the",
        "broad rule has to go, not just be overridden lower down.",
    ]
    if path:
        lines += [f"If /{'/'.join(path)} is genuinely public data, keep \".read\": true there only, never",
                  "\".write\": true, and add `// firebase-launch-check: ignore` to the line."]
    return "\n".join(lines)


def scan_rtdb_text(rel: str, text: str, today: _dt.date | None = None) -> tuple[bool, list[Finding]]:
    """Returns (parsed_as_rtdb_rules, findings)."""
    today = today or _dt.date.today()
    try:
        root = parse_json_lines(text)
    except JsonError:
        return False, []
    if not isinstance(root.value, dict) or "rules" not in root.value or not isinstance(root.value["rules"].value, dict):
        return False, []
    lines = text.splitlines()
    findings: list[Finding] = []

    def ev(line: int) -> str:
        return redact_line(lines[line - 1]) if 0 < line <= len(lines) else ""

    def walk(node: Node, path: list[str]) -> None:
        if not isinstance(node.value, dict):
            return
        key_lines = getattr(node, "key_lines", {})
        disp = "/" + "/".join(path)
        depth = len(path)
        has_wild = any(p.startswith("$") for p in path)
        for key in (".read", ".write"):
            if key not in node.value:
                continue
            raw = node.value[key].value
            line = key_lines.get(key, node.line)
            is_write = key == ".write"
            verb = "write (create, change and delete)" if is_write else "read"
            extra = {"path": disp, "key": key}
            if raw is True or (isinstance(raw, str) and _compact(raw) == "true"):
                if depth == 0:
                    sev = "critical"
                elif depth == 1 and not has_wild:
                    sev = "critical" if is_write else ("high" if path[0].lower() in USER_COLLECTIONS else "medium")
                else:
                    sev = "high" if is_write else "medium"
                where = "the entire database" if depth == 0 else f"{disp} and everything below it"
                findings.append(Finding(
                    "FLC201", sev, f'"{key}": true at {disp}: anyone with your database URL can {verb} {where}, '
                                   "without signing in.",
                    rel, line, ev(line), extra=extra, custom_fix=rtdb_fix(path)))
                continue
            if not isinstance(raw, str):
                continue
            c = _compact(raw)
            m = _NOW.fullmatch(c)
            if m:
                ts = int(m.group(1)) / 1000
                try:
                    expiry = _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).date()
                except (OverflowError, OSError, ValueError):
                    continue
                where = "the entire database" if depth == 0 else f"{disp} and everything below it"
                if expiry <= today:
                    findings.append(Finding(
                        "FLC202", "medium",
                        f'Test-mode "{key}" at {disp} expired on {expiry.isoformat()}: it now denies every request. '
                        f"If someone pushes the timestamp forward, {where} is open to everyone again.",
                        rel, line, ev(line), extra={**extra, "expires": expiry.isoformat()},
                        custom_fix=rtdb_fix(path)))
                else:
                    findings.append(Finding(
                        "FLC202", "critical" if is_write or depth == 0 else "high",
                        f'Test-mode "{key}" at {disp}: anyone can {verb} {where} until {expiry.isoformat()}, '
                        "without signing in.",
                        rel, line, ev(line), extra={**extra, "expires": expiry.isoformat()},
                        custom_fix=rtdb_fix(path)))
                continue
            if c in _AUTH_ONLY:
                owned = has_wild or any(p.lower() in USER_COLLECTIONS for p in path)
                if not is_write and depth > 0 and not owned:
                    continue   # shared data readable by signed-in users is a common, deliberate design
                sev = "high"
                where = "the entire database" if depth == 0 else f"{disp} and everything below it"
                findings.append(Finding(
                    "FLC203", sev, f'"{key}": "{raw}" at {disp}: any signed-in user (and anyone can sign up) can '
                                   f"{verb} {where}, including other users' data.",
                    rel, line, ev(line), extra=extra, custom_fix=rtdb_fix(path)))
        for key, child in node.value.items():
            if not key.startswith("."):
                walk(child, path + [key])

    walk(root.value["rules"], [])
    return True, findings
