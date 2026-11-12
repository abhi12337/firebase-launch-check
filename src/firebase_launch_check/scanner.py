"""Walks a project folder and dispatches files to the rules / RTDB / code checks.
Reads local files only. Never deploys, imports, runs or connects to anything it scans."""

from __future__ import annotations

import datetime as _dt
import fnmatch
import json
import os
import posixpath
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import code_scan
from .findings import IGNORE_MARKER, Finding
from .rtdb_scan import JsonError, parse_json_lines, scan_rtdb_text, to_plain
from .rules_scan import scan_rules_text

MAX_BYTES_DEFAULT = 2 * 1024 * 1024
SKIP_DIRS = {"node_modules", "dist", "build", "out", ".next", ".nuxt", "venv", "env", "__pycache__", "site-packages",
             "coverage", "target", "vendor", "Pods", "DerivedData", "bower_components", "lib-cov"}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "fixtures", "__fixtures__", "testdata", "e2e", "cypress",
             "playwright"}
JS_EXT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro"}
MOBILE_EXT = {".dart", ".kt", ".java", ".swift"}
SECRET_EXT = {".json", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".py", ".yaml", ".yml", ".toml", ".txt",
              ".properties", ".ini", ".cfg", ".conf", ".xml", ".plist", ".dart", ".kt", ".java", ".swift", ".go",
              ".rb", ".php", ".cs", ".sh", ".tf"}
SERVER_DIRS = {"functions", "server", "api", "backend", "scripts", "script", "cloud-functions", "cloudfunctions",
               "lambda", "lambdas", "netlify", "edge-functions", "workers", "cron", "jobs", "admin-scripts", "tools",
               "migrations", "seed", "seeds"}
SPA_DEPS = {"vite", "react-scripts", "@angular/core", "vue", "svelte", "expo", "react-native", "@vue/cli-service",
            "parcel", "@ionic/react", "@ionic/angular", "@ionic/vue", "@capacitor/core", "solid-js", "preact"}
SERVER_DEPS = {"next", "nuxt", "@remix-run/node", "@remix-run/react", "@sveltejs/kit", "astro", "express", "fastify",
               "koa", "@nestjs/core", "hono", "firebase-functions", "@angular/ssr", "@nguniversal/express-engine",
               "@react-router/node", "@tanstack/react-start", "@solidjs/start", "gatsby"}
_USE_CLIENT = re.compile(r"""\A(?:\s|//[^\n]*\n|/\*.*?\*/)*['"]use client['"]""", re.S)
_SERVER_ONLY = re.compile(r"""['"](?:use server|server-only)['"]""")


@dataclass
class ScanResult:
    root: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    firebase_json: list[str] = field(default_factory=list)
    rules_files: dict[str, list[str]] = field(default_factory=lambda: {"firestore": [], "storage": [], "database": []})
    client_files: int = 0


# ---------------------------------------------------------------- helpers
def _read(p: Path, max_bytes: int) -> str | None:
    try:
        if p.stat().st_size > max_bytes:
            return None
        data = p.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def _git(root: Path, *args: str) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None


def _git_status(root: Path, rels: list[str]) -> tuple[bool, set[str], set[str]]:
    """(is_git_repo, tracked, ignored) for the given root-relative paths."""
    cp = _git(root, "rev-parse", "--show-toplevel")
    if cp is None or cp.returncode != 0 or not rels:
        return (cp is not None and cp.returncode == 0), set(), set()
    tracked: set[str] = set()
    ignored: set[str] = set()
    cp = _git(root, "ls-files", "--", *rels)
    if cp and cp.returncode == 0:
        tracked = {ln.strip() for ln in cp.stdout.splitlines() if ln.strip()}
    cp = _git(root, "check-ignore", "--", *rels)
    if cp and cp.returncode in (0, 1):
        ignored = {ln.strip() for ln in cp.stdout.splitlines() if ln.strip()}
    return True, tracked, ignored


def _gitignore_covers(root: Path, rel: str) -> bool:
    """Minimal .gitignore check for folders that are not git repositories (root .gitignore only)."""
    gi = root / ".gitignore"
    if not gi.is_file():
        return False
    name = rel.rsplit("/", 1)[-1]
    covered = False
    for raw in gi.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        neg = line.startswith("!")
        pat = (line[1:] if neg else line).lstrip("/").rstrip("/")
        parts = rel.split("/")
        dirs = ["/".join(parts[:i]) for i in range(1, len(parts))]
        if (fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, f"*/{pat}")
                or any(fnmatch.fnmatch(d, pat) or fnmatch.fnmatch(d.rsplit("/", 1)[-1], pat) for d in dirs)):
            covered = not neg
    return covered


def _is_test_file(name: str) -> bool:
    n = name.lower()
    return n.startswith("test_") or bool(re.search(r"[._-](test|spec)\.[a-z]+$", n)) or n.endswith("_test.py")


def _in_dirs(rel: str, names: set[str]) -> bool:
    return any(part.lower() in names for part in rel.split("/")[:-1])


def _norm(path: str) -> str:
    p = posixpath.normpath(path.replace("\\", "/"))
    return "" if p == "." else p


# ---------------------------------------------------------------- firebase.json
@dataclass
class FirebaseConfig:
    rel: str
    rules: dict[str, list[str]] = field(default_factory=lambda: {"firestore": [], "storage": [], "database": []})
    hosting_public: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def read_firebase_json(rel: str, text: str) -> FirebaseConfig | None:
    try:
        obj = to_plain(parse_json_lines(text))
    except JsonError:
        return None
    if not isinstance(obj, dict):
        return None
    cfg = FirebaseConfig(rel)
    base = posixpath.dirname(rel)

    def entries(v) -> list[dict]:
        if isinstance(v, dict):
            return [v]
        if isinstance(v, list):
            return [e for e in v if isinstance(e, dict)]
        return []

    for svc in ("firestore", "storage", "database"):
        for e in entries(obj.get(svc)):
            if isinstance(e.get("rules"), str):
                cfg.rules[svc].append(_norm(posixpath.join(base, e["rules"])))
    for e in entries(obj.get("hosting")):
        if isinstance(e.get("public"), str):
            cfg.hosting_public.append(_norm(posixpath.join(base, e["public"])))
    emu = obj.get("emulators")
    if isinstance(emu, dict):
        open_hosts = sorted(name for name, v in emu.items()
                            if isinstance(v, dict) and str(v.get("host", "")).strip() in ("0.0.0.0", "::", "[::]"))
        if open_hosts:
            lines = text.splitlines()
            line = next((i for i, ln in enumerate(lines, 1)
                         if re.search(r'"host"\s*:\s*"(0\.0\.0\.0|::|\[::\])"', ln)), None)
            cfg.findings.append(Finding(
                "FLC403", "low",
                f"Emulators {', '.join(open_hosts)} listen on all network interfaces: anyone who can reach this "
                "machine can read and change emulator data and use the emulator UI.",
                rel, line, lines[line - 1].strip() if line else None, extra={"emulators": open_hosts}))
    return cfg


# ---------------------------------------------------------------- walking
def _walk(root: Path, start: Path, excludes: list[str], skip_dirs: set[str]) -> list[tuple[Path, str]]:
    out = []
    for dirpath, dirnames, filenames in os.walk(start):
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        keep = []
        for d in sorted(dirnames):
            if d in skip_dirs or d.startswith("."):
                continue
            if any(fnmatch.fnmatch(rel_dir + d, pat) or fnmatch.fnmatch(rel_dir + d + "/", pat) for pat in excludes):
                continue
            keep.append(d)
        dirnames[:] = keep
        for fn in sorted(filenames):
            rel = rel_dir + fn
            if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(fn, pat) for pat in excludes):
                continue
            out.append((Path(dirpath) / fn, rel))
    return out


def _package_info(files: list[tuple[Path, str]], max_bytes: int) -> dict[str, set[str]]:
    """{package dir (root-relative, '' for root): dependency names} for every package.json found."""
    pkgs: dict[str, set[str]] = {}
    for p, rel in files:
        if p.name != "package.json":
            continue
        text = _read(p, max_bytes)
        try:
            obj = json.loads(text) if text else {}
        except ValueError:
            obj = {}
        deps: set[str] = set()
        if isinstance(obj, dict):
            for k in ("dependencies", "devDependencies", "peerDependencies"):
                if isinstance(obj.get(k), dict):
                    deps |= set(obj[k])
        pkgs[posixpath.dirname(rel)] = deps
    return pkgs


def _nearest_pkg(rel: str, pkgs: dict[str, set[str]]) -> set[str] | None:
    d = posixpath.dirname(rel)
    while True:
        if d in pkgs:
            return pkgs[d]
        if not d:
            return None
        d = posixpath.dirname(d)


def is_client_file(rel: str, text: str, pkgs: dict[str, set[str]], hosting: list[str]) -> bool:
    if _SERVER_ONLY.search(text[:2000]):
        return False
    if _USE_CLIENT.match(text):
        return True
    if any(h and (rel == h or rel.startswith(h + "/")) for h in hosting):
        return True
    name = posixpath.basename(rel).lower()
    if _in_dirs(rel, SERVER_DIRS) or ".config." in name or ".server." in name or name.startswith("server."):
        return False
    deps = _nearest_pkg(rel, pkgs)
    if not deps or deps & SERVER_DEPS:
        return False
    return bool(deps & SPA_DEPS)


# ---------------------------------------------------------------- main entry
def scan_path(target: str, *, excludes: list[str] | None = None, include_tests: bool = False,
              max_bytes: int = MAX_BYTES_DEFAULT, today: _dt.date | None = None) -> ScanResult:
    excludes = excludes or []
    root = Path(target).resolve()
    res = ScanResult(str(root))
    files = _walk(root, root, excludes, SKIP_DIRS)
    texts: dict[str, str] = {}

    def text_of(p: Path, rel: str) -> str | None:
        if rel not in texts:
            t = _read(p, max_bytes)
            if t is None:
                return None
            texts[rel] = t
            res.files_scanned += 1
        return texts[rel]

    # firebase.json first: it says where the rules and the hosted folder are
    configs: list[FirebaseConfig] = []
    for p, rel in files:
        if p.name == "firebase.json" and (include_tests or not _in_dirs(rel, TEST_DIRS)):
            t = text_of(p, rel)
            cfg = read_firebase_json(rel, t) if t is not None else None
            if cfg:
                configs.append(cfg)
                res.firebase_json.append(rel)
                res.findings += cfg.findings
    hosting = sorted({h for c in configs for h in c.hosting_public if h})
    known = {(p, rel) for p, rel in files}
    for h in hosting:   # hosted folders are often build output (dist/, build/): scan them anyway
        hp = root / h
        if hp.is_dir() and any(part in SKIP_DIRS or part.startswith(".") for part in h.split("/")):
            for item in _walk(root, hp, excludes, {"node_modules"}):
                if item not in known:
                    files.append(item)
                    known.add(item)

    referenced = {svc: {r for c in configs for r in c.rules[svc]} for svc in ("firestore", "storage", "database")}
    for svc, rels in referenced.items():
        for r in sorted(rels):
            if not (root / r).is_file():
                res.findings.append(Finding(
                    "FLC404", "info", f"firebase.json points the {svc} rules at {r}, but that file does not exist.",
                    next((c.rel for c in configs if r in c.rules[svc]), None), extra={"service": svc}))
    pkgs = _package_info(files, max_bytes)

    rules_jobs: list[tuple[Path, str, str | None]] = []
    rtdb_jobs: list[tuple[Path, str]] = []
    used: dict[str, str] = {}                     # service -> first client file using it
    client_priv: dict[str, list[tuple[str, int, str]]] = {}
    secret_candidates: list[tuple[str, int, str, str]] = []   # rel, line, description, evidence

    ref_all = {r: svc for svc, rels in referenced.items() for r in rels}
    for p, rel in files:
        name = p.name
        lname = name.lower()
        suffix = p.suffix.lower()
        is_test = _in_dirs(rel, TEST_DIRS) or _is_test_file(name)
        # FLC301 runs everywhere, including tests: a key in a fixture is still a leaked key
        if suffix in SECRET_EXT or lname.startswith(".env") or lname.endswith((".env", ".pem", ".key")):
            t = text_of(p, rel)
            if t is not None:
                hit = code_scan.find_service_account_key(t)
                if hit:
                    secret_candidates.append((rel, *hit))
        if is_test and not include_tests:
            continue
        if rel in ref_all and ref_all[rel] == "database":
            rtdb_jobs.append((p, rel))
            continue
        if rel in ref_all or suffix == ".rules":
            rules_jobs.append((p, rel, ref_all.get(rel) or ("storage" if "storage" in lname else
                                                            "firestore" if "firestore" in lname else None)))
            continue
        if suffix == ".json" and ("rules" in lname or "database" in lname) and name != "firebase.json":
            rtdb_jobs.append((p, rel))
            continue
        if code_scan.PROD_ENV_NAMES.match(name):
            t = text_of(p, rel)
            for line, var in code_scan.find_emulator_env(t or ""):
                auth = var == "FIREBASE_AUTH_EMULATOR_HOST"
                res.findings.append(Finding(
                    "FLC402", "medium" if auth else "low",
                    f"{var} is set in {name}, a production configuration file: "
                    + ("the Admin SDK will accept unsigned ID tokens, so token checks on your server can be forged."
                       if auth else "server code using the Admin SDK will talk to a local emulator instead of "
                                    "production."),
                    rel, line, (t or "").splitlines()[line - 1].strip(), extra={"variable": var}))
            continue
        if suffix in JS_EXT or suffix in MOBILE_EXT:
            t = text_of(p, rel)
            if t is None:
                continue
            server_side = _in_dirs(rel, SERVER_DIRS) or bool(_SERVER_ONLY.search(t[:2000]))
            if not server_side:
                for svc in code_scan.services_used(t):
                    used.setdefault(svc, rel)
                for coll, line, fld in code_scan.find_privileged_writes(t) if suffix in JS_EXT else []:
                    client_priv.setdefault(coll, []).append((rel, line, fld))
            if suffix not in JS_EXT:
                continue
            client = is_client_file(rel, t, pkgs, hosting)
            res.client_files += client
            if client:
                for line in code_scan.find_admin_imports(t):
                    res.findings.append(Finding(
                        "FLC302", "high",
                        f"{rel} is browser code and imports firebase-admin, the server SDK that ignores security "
                        "rules and needs a service account credential.",
                        rel, line, t.splitlines()[line - 1].strip()))
            if not server_side and not re.search(r"emulator|\bdev\b|local|seed|setup", lname, re.I) \
                    and ".config." not in lname:
                for line, call in code_scan.find_unguarded_emulator(t):
                    res.findings.append(Finding(
                        "FLC401", "low",
                        f"{call}() runs unconditionally at module level: production builds will also try to use "
                        "the local emulator.",
                        rel, line, t.splitlines()[line - 1].strip(), heuristic=True))

    # rules files
    for p, rel, hint in rules_jobs:
        t = text_of(p, rel)
        if t is None:
            continue
        rf, fs = scan_rules_text(rel, t, service_hint=hint, client_privileged=client_priv, today=today)
        if rf.service in ("firestore", "storage"):
            res.rules_files[rf.service].append(rel)
            res.findings += fs
    for p, rel in rtdb_jobs:
        t = text_of(p, rel)
        if t is None:
            continue
        ok, fs = scan_rtdb_text(rel, t, today=today)
        if ok:
            res.rules_files["database"].append(rel)
            res.findings += fs

    # FLC404: services used by the client with no rules in the repo
    for svc, rel in sorted(used.items()):
        if not res.rules_files[svc] and not referenced[svc]:
            label = {"firestore": "Firestore", "storage": "Cloud Storage", "database": "Realtime Database"}[svc]
            res.findings.append(Finding(
                "FLC404", "info",
                f"Client code uses {label} (first seen in {rel}) but no {label} rules file was found, so its "
                "rules could not be checked.", rel, None, extra={"service": svc}))

    # FLC301: decide severity from git / hosting status
    if secret_candidates:
        rels = [c[0] for c in secret_candidates]
        is_git, tracked, ignored = _git_status(root, rels)
        for rel, line, desc, ev in secret_candidates:
            hosted = next((h for h in hosting if rel.startswith(h + "/")), None)
            if hosted is not None:
                sev, how = "critical", (f"it is inside the Firebase Hosting public folder '{hosted}/', so anyone can "
                                        "download it from your site")
            elif is_git and rel in tracked:
                sev, how = "critical", "it is committed to git"
            elif (is_git and rel in ignored) or (not is_git and _gitignore_covers(root, rel)):
                sev, how = "info", "it is git-ignored; keep it out of the repo, builds and deploy folders"
            elif is_git:
                sev, how = "critical", "it is not git-ignored, one `git add .` away from being committed"
            else:
                sev, how = "critical", "it is not covered by .gitignore"
            res.findings.append(Finding("FLC301", sev, f"{desc} in {rel}: {how}.", rel, line, ev,
                                        extra={"location_status": how.split(",")[0].split(";")[0]}))

    res.findings = [f for f in res.findings if not _suppressed(f, texts)]
    return res


def _suppressed(f: Finding, texts: dict[str, str]) -> bool:
    if not f.file or not f.line or f.file not in texts:
        return False
    lines = texts[f.file].splitlines()
    cands = [lines[f.line - 1]] if f.line <= len(lines) else []
    if 1 < f.line <= len(lines) + 1 and lines[f.line - 2].strip().startswith(("//", "#", "/*")):
        cands.append(lines[f.line - 2])
    return any(IGNORE_MARKER in c for c in cands)
