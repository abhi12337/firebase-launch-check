"""A small, forgiving reader for the Firebase Security Rules language (Firestore and
Cloud Storage `.rules` files).

It does not evaluate rules. It extracts `service`, nested `match` blocks, `function`
definitions and `allow` statements with their conditions and line numbers, and offers
helpers to inline local functions so conditions can be classified."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class Allow:
    ops: list[str]
    condition: str | None          # None = `allow read;` (no condition: always allowed)
    line: int
    end_line: int
    paths: list[str]               # match paths from outermost to innermost
    service: str                   # "firestore", "storage" or "unknown"

    @property
    def full_path(self) -> str:
        return "".join(self.paths)

    @property
    def match(self) -> str:
        return self.paths[-1] if self.paths else "/"


@dataclass
class Function:
    name: str
    params: list[str]
    expr: str                      # the return expression, with `let` bindings inlined
    line: int


@dataclass
class RulesFile:
    service: str
    allows: list[Allow] = field(default_factory=list)
    functions: dict[str, Function] = field(default_factory=dict)
    clean_text: str = ""           # comments removed, line structure kept


# ---------------------------------------------------------------- lexing helpers
def strip_comments(text: str) -> str:
    """Blank out // and /* */ comments (outside strings), keeping newlines and offsets."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "'\"":
            j = i + 1
            while j < n and text[j] != ch and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        i += 1
    return "".join(out)


def _skip_string(text: str, i: int) -> int:
    q = text[i]
    j = i + 1
    while j < len(text) and text[j] != q:
        j += 2 if text[j] == "\\" else 1
    return j + 1


def _find_close(text: str, i: int, open_ch: str, close_ch: str) -> int:
    """Index of the bracket closing the one at text[i] (or len(text))."""
    depth = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in "'\"":
            i = _skip_string(text, i)
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def split_top(expr: str, sep: str) -> list[str]:
    """Split on `&&` / `||` / `,` at bracket depth 0, outside strings."""
    parts, depth, start, i = [], 0, 0, 0
    n = len(expr)
    while i < n:
        ch = expr[i]
        if ch in "'\"":
            i = _skip_string(expr, i)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0 and expr.startswith(sep, i):
            parts.append(expr[start:i])
            i += len(sep)
            start = i
            continue
        i += 1
    parts.append(expr[start:])
    return [p.strip() for p in parts]


def normalize(expr: str) -> str:
    """Collapse whitespace and strip redundant outer parentheses."""
    s = " ".join(expr.split())
    while s.startswith("(") and _find_close(s, 0, "(", ")") == len(s) - 1:
        s = s[1:-1].strip()
    return s


# ---------------------------------------------------------------- parser
_MATCH = re.compile(r"match\s+(/(?:[^\s{}]|\{[^}\s]*\})*)\s*\{")
_SERVICE = re.compile(r"service\s+([\w.]+)\s*\{")
_FUNCTION = re.compile(r"function\s+(\w+)\s*\(([^)]*)\)\s*\{")
_ALLOW = re.compile(r"allow\s+((?:[a-z]+\s*,\s*)*[a-z]+)\b")
_WORD_START = re.compile(r"[A-Za-z_]")


def _service_name(name: str) -> str:
    if name == "cloud.firestore":
        return "firestore"
    if name == "firebase.storage":
        return "storage"
    return "unknown"


def _function_expr(body: str) -> str:
    """Return expression of a function body, with `let x = ...;` bindings substituted."""
    lets: list[tuple[str, str]] = []
    expr = ""
    for stmt in split_top(body, ";"):
        stmt = stmt.strip()
        m = re.match(r"let\s+(\w+)\s*=\s*(.+)$", stmt, re.S)
        if m:
            lets.append((m.group(1), m.group(2).strip()))
        elif stmt.startswith("return"):
            expr = stmt[len("return"):].strip()
    for name, value in reversed(lets):
        expr = re.sub(rf"(?<![\w.]){re.escape(name)}\b", f"({value})", expr)
    return expr


def parse_rules(text: str) -> RulesFile:
    clean = strip_comments(text)
    line_starts = [0] + [m.end() for m in re.finditer("\n", clean)]

    def line_of(pos: int) -> int:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    m = _SERVICE.search(clean)
    rf = RulesFile(service=_service_name(m.group(1)) if m else "unknown", clean_text=clean)
    stack: list[str | None] = []    # match path, or None for service/function/other blocks
    service = rf.service
    i, n = 0, len(clean)
    while i < n:
        ch = clean[i]
        if ch.isspace():
            i += 1
            continue
        if ch in "'\"":
            i = _skip_string(clean, i)
            continue
        if ch == "}":
            if stack:
                stack.pop()
            i += 1
            continue
        if ch == "{":
            stack.append(None)
            i += 1
            continue
        if not _WORD_START.match(ch) or (i > 0 and (clean[i - 1].isalnum() or clean[i - 1] in "_.")):
            i += 1
            continue
        if m := _SERVICE.match(clean, i):
            service = _service_name(m.group(1))
            stack.append(None)
            i = m.end()
            continue
        if m := _MATCH.match(clean, i):
            stack.append(m.group(1))
            i = m.end()
            continue
        if m := _FUNCTION.match(clean, i):
            open_pos = m.end() - 1
            close = _find_close(clean, open_pos, "{", "}")
            params = [p.strip() for p in m.group(2).split(",") if p.strip()]
            rf.functions[m.group(1)] = Function(m.group(1), params, _function_expr(clean[open_pos + 1:close]),
                                                line_of(i))
            i = close + 1
            continue
        if m := _ALLOW.match(clean, i):
            ops = [o.strip() for o in m.group(1).split(",")]
            j = m.end()
            while j < n and clean[j].isspace():
                j += 1
            cond: str | None = None
            if j < n and clean[j] == ":":
                j += 1
                k, depth = j, 0
                while k < n:
                    c = clean[k]
                    if c in "'\"":
                        k = _skip_string(clean, k)
                        continue
                    if c in "([{":
                        depth += 1
                    elif c in ")]}":
                        if depth == 0:
                            break          # `}` closing the match block: statement without `;`
                        depth -= 1
                    elif c == ";" and depth == 0:
                        break
                    k += 1
                cond = clean[j:k].strip()
                cond = re.sub(r"^if\b", "", cond).strip()
                end = k
            else:
                end = j
            paths = [p for p in stack if p is not None]
            rf.allows.append(Allow(ops, cond, line_of(i), line_of(max(i, end - 1)), paths, service))
            i = end + 1 if end < n and clean[end] == ";" else end
            continue
        # some other identifier: skip it
        m = re.compile(r"[A-Za-z_][\w.]*").match(clean, i)
        i = m.end() if m else i + 1
    return rf


# ---------------------------------------------------------------- condition helpers
def expand(cond: str, functions: dict[str, Function], depth: int = 0) -> str:
    """Inline calls to functions defined in the same file (up to 5 levels)."""
    if depth > 5 or not functions:
        return cond
    out, i, n, changed = [], 0, len(cond), False
    pat = re.compile(r"(?<![\w.])(" + "|".join(re.escape(f) for f in functions) + r")\s*\(")
    while i < n:
        m = pat.search(cond, i)
        if not m:
            out.append(cond[i:])
            break
        out.append(cond[i:m.start()])
        open_pos = m.end() - 1
        close = _find_close(cond, open_pos, "(", ")")
        fn = functions[m.group(1)]
        args_text = cond[open_pos + 1:close].strip()
        args = split_top(args_text, ",") if args_text else []
        body = fn.expr
        if len(args) == len(fn.params):
            for p, a in zip(fn.params, args):
                body = re.sub(rf"(?<![\w.]){re.escape(p)}\b", lambda _m, a=a: f"({a})", body)
        out.append(f"({body})")
        changed = True
        i = close + 1
    result = "".join(out)
    return expand(result, functions, depth + 1) if changed else result


_AUTH_ONLY = {"request.auth!=null", "null!=request.auth", "request.auth.uid!=null", "null!=request.auth.uid",
              "request.auth!=null&&request.auth.uid!=null"}
_TEST_MODE = re.compile(r"request\.time<timestamp\.date\((\d{4}),(\d{1,2}),(\d{1,2})\)")


def conjuncts(cond: str) -> list[str]:
    """Top-level `&&` parts, each normalized; nested parenthesised `&&` groups are flattened."""
    s = normalize(cond)
    parts = split_top(s, "&&")
    if len(parts) == 1 or len(split_top(s, "||")) > 1:   # `a || b && c` is one disjunction
        return [s]
    out: list[str] = []
    for part in parts:
        out.extend(conjuncts(part))
    return out


def classify(cond: str | None) -> tuple[str, tuple[int, int, int] | None]:
    """Classify an (already expanded) condition.

    Returns (kind, test_mode_date) where kind is one of:
      "true"       - always allowed (`if true` or no condition)
      "test_mode"  - only a `request.time < timestamp.date(...)` check
      "auth_only"  - only `request.auth != null` (optionally plus a time limit)
      "other"      - anything else (not judged)
    """
    if cond is None:
        return "true", None
    date: tuple[int, int, int] | None = None
    kinds = set()
    for c in conjuncts(cond):
        compact = c.replace(" ", "")
        m = _TEST_MODE.fullmatch(compact)
        if m:
            date = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
            kinds.add("time")
        elif compact == "true":
            kinds.add("true")
        elif compact in _AUTH_ONLY:
            kinds.add("auth")
        else:
            return "other", date
    if "auth" in kinds:
        return "auth_only", date
    if "time" in kinds:
        return "test_mode", date
    return "true", None
