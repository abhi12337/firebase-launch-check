"""Command line interface.

  firebase-launch-check scan [PATH]
  firebase-launch-check rules
"""

from __future__ import annotations

import argparse
import os
import sys
import textwrap

from . import __version__
from .findings import RULES, SEVERITIES, SEVERITY_RANK, Finding
from .report import render_json, render_text, use_color
from .scanner import MAX_BYTES_DEFAULT, scan_path

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _exit_code(findings: list[Finding], fail_on: str) -> int:
    if fail_on == "never":
        return EXIT_OK
    lim = SEVERITY_RANK[fail_on]
    return EXIT_FINDINGS if any(SEVERITY_RANK[f.severity] <= lim for f in findings) else EXIT_OK


def _filter_min(findings: list[Finding], min_sev: str) -> list[Finding]:
    lim = SEVERITY_RANK[min_sev]
    return [f for f in findings if SEVERITY_RANK[f.severity] <= lim]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="firebase-launch-check",
        description="Static pre-launch security check for Firebase projects: Firestore, Storage and Realtime "
                    "Database rules, service account keys, firebase-admin in client code. Reads files only.",
        epilog="A clean report is not a guarantee. See 'What it does not check' in the README.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="static scan of a project folder (no network)")
    s.add_argument("path", nargs="?", default=".", help="project folder to scan (default: .)")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="glob of paths to skip (repeatable), e.g. --exclude 'docs/*'")
    s.add_argument("--include-tests", action="store_true",
                   help="also apply rules/code checks to test and fixture folders (key detection always runs)")
    s.add_argument("--disable", action="append", default=[], metavar="RULE",
                   help="ignore a rule id (repeatable), e.g. --disable FLC404")
    s.add_argument("--max-file-mb", type=float, default=MAX_BYTES_DEFAULT / 1024 / 1024,
                   help="skip files larger than this (default: 2)")
    s.add_argument("--json", action="store_true", help="print a JSON report instead of text")
    s.add_argument("--fail-on", choices=[*SEVERITIES, "never"], default="high",
                   help="exit 1 if any finding is at or above this severity (default: high)")
    s.add_argument("--min-severity", choices=SEVERITIES, default="info",
                   help="hide findings below this severity (default: info = show all)")
    s.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    s.add_argument("--brief", action="store_true", help="omit the why/fix text")

    sub.add_parser("rules", help="list every rule with why it matters and how to fix it")
    return parser


def cmd_scan(args) -> int:
    if not os.path.isdir(args.path):
        print(f"error: {args.path} is not a directory", file=sys.stderr)
        return EXIT_ERROR
    unknown = [r for r in args.disable if r.upper() not in RULES]
    if unknown:
        print(f"error: unknown rule id(s): {', '.join(unknown)} (see `firebase-launch-check rules`)", file=sys.stderr)
        return EXIT_ERROR
    res = scan_path(args.path, excludes=args.exclude, include_tests=args.include_tests,
                    max_bytes=int(args.max_file_mb * 1024 * 1024))
    disabled = {r.upper() for r in args.disable}
    findings = [f for f in res.findings if f.rule_id not in disabled]
    exit_code = _exit_code(findings, args.fail_on)
    shown = _filter_min(findings, args.min_severity)
    rf = res.rules_files
    if args.json:
        sys.stdout.write(render_json(shown, meta={
            "target": res.root, "files_scanned": res.files_scanned, "firebase_json": res.firebase_json,
            "rules_files": rf, "client_files": res.client_files, "exit_code": exit_code,
        }))
    else:
        header = [f"Scanned {args.path}",
                  f"{res.files_scanned} file(s): {len(res.firebase_json)} firebase.json, "
                  f"{len(rf['firestore'])} Firestore rules, {len(rf['storage'])} Storage rules, "
                  f"{len(rf['database'])} Realtime Database rules, {res.client_files} browser code file(s)"]
        if not res.firebase_json and not any(rf.values()):
            header.append("No firebase.json or rules files found: only key and code checks ran.")
        sys.stdout.write(render_text(shown, header=header, color=use_color(force=False if args.no_color else None),
                                     verbose_fix=not args.brief, footer=[f"Exit code: {exit_code}"]))
    return exit_code


def cmd_rules(_args) -> int:
    for r in RULES.values():
        print(f"{r.id}  {r.title}")
        print(textwrap.fill(r.why, 92, initial_indent="    ", subsequent_indent="    "))
        print("    Fix:")
        print(textwrap.indent(r.fix, "      "))
        print()
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass
    args = build_parser().parse_args(argv)
    return {"scan": cmd_scan, "rules": cmd_rules}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
