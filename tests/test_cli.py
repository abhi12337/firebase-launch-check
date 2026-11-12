import json
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import FAKE_KEY_ID, FAKE_PEM, fake_service_account

from firebase_launch_check.cli import main
from firebase_launch_check.findings import RULES, SEVERITIES, mask_secret

FIX = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).parent.parent

VULNERABLE_RULES = ["FLC001", "FLC001", "FLC002", "FLC003", "FLC003", "FLC004", "FLC005", "FLC005", "FLC101",
                    "FLC102", "FLC201", "FLC202", "FLC202", "FLC203", "FLC302", "FLC401", "FLC402", "FLC403"]


def run(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_vulnerable_fixture_text_report(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "vulnerable"), "--no-color")
    assert code == 1
    assert "CRITICAL FLC002" in out and "firestore.rules:32" in out
    assert "why:" in out and "fix:" in out
    assert "allow read: if request.auth != null && request.auth.uid == userId;" in out
    assert "1 firebase.json, 1 Firestore rules, 1 Storage rules, 1 Realtime Database rules" in out
    assert "Exit code: 1" in out


def test_vulnerable_fixture_finds_exactly_the_planted_issues(capsys):
    _, out, _ = run(capsys, "scan", str(FIX / "vulnerable"), "--json")
    assert sorted(f["rule_id"] for f in json.loads(out)["findings"]) == VULNERABLE_RULES


def test_clean_fixture_has_no_findings(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "clean"), "--no-color", "--fail-on", "info")
    assert code == 0
    assert "No findings" in out


def test_json_report_shape(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "vulnerable"), "--json")
    doc = json.loads(out)
    assert code == 1 and doc["exit_code"] == 1 and doc["tool"] == "firebase-launch-check"
    assert doc["firebase_json"] == ["firebase.json"]
    assert doc["rules_files"] == {"firestore": ["firestore.rules"], "storage": ["storage.rules"],
                                  "database": ["database.rules.json"]}
    assert set(doc["summary"]) == set(SEVERITIES)
    first = doc["findings"][0]
    assert first["severity"] == "critical"
    assert {"rule_id", "severity", "message", "file", "line", "evidence", "title", "why", "fix"} <= set(first)
    assert "custom_fix" not in first


def test_every_finding_has_location_evidence_why_and_fix(capsys):
    _, out, _ = run(capsys, "scan", str(FIX / "vulnerable"), "--json")
    for f in json.loads(out)["findings"]:
        assert f["file"] and f["line"] and f["evidence"] and len(f["why"]) > 40 and len(f["fix"]) > 40


def test_fail_on_min_severity_and_disable(capsys):
    assert run(capsys, "scan", str(FIX / "vulnerable"), "--fail-on", "never")[0] == 0
    code, out, _ = run(capsys, "scan", str(FIX / "vulnerable"), "--json", "--min-severity", "critical")
    assert {f["severity"] for f in json.loads(out)["findings"]} == {"critical"} and code == 1
    disable = ["--disable", "FLC001", "--disable", "flc002", "--disable", "FLC003", "--disable", "FLC004",
               "--disable", "FLC005", "--disable", "FLC101", "--disable", "FLC201", "--disable", "FLC202",
               "--disable", "FLC203", "--disable", "FLC302"]
    code, out, _ = run(capsys, "scan", str(FIX / "vulnerable"), "--json", *disable)
    assert code == 0                    # only medium/low left, default --fail-on high
    assert run(capsys, "scan", str(FIX / "vulnerable"), *disable, "--fail-on", "medium")[0] == 1


def test_fail_on_info(capsys, make_repo):
    root = make_repo({"src/db.ts": 'import { getFirestore } from "firebase/firestore";\n'})
    assert run(capsys, "scan", str(root))[0] == 0
    assert run(capsys, "scan", str(root), "--fail-on", "info")[0] == 1


def test_brief_omits_why_and_fix(capsys):
    _, out, _ = run(capsys, "scan", str(FIX / "vulnerable"), "--brief", "--no-color")
    assert "why:" not in out and "fix:" not in out and "code:" in out


def test_usage_errors(capsys, tmp_path):
    code, _, err = run(capsys, "scan", str(tmp_path / "nope"))
    assert code == 2 and "not a directory" in err
    code, _, err = run(capsys, "scan", str(tmp_path), "--disable", "FLC999")
    assert code == 2 and "unknown rule" in err
    with pytest.raises(SystemExit) as e:
        main(["scan", str(tmp_path), "--fail-on", "sometimes"])
    assert e.value.code == 2


def test_inline_ignore_on_same_line_and_line_above(capsys, make_repo):
    rules = """service cloud.firestore {
  match /databases/{database}/documents {
    match /posts/{postId} {
      allow read: if true;  // firebase-launch-check: ignore
    }
    match /stats/{id} {
      // firebase-launch-check: ignore  (public counters)
      allow read: if true;
    }
    match /open/{id} {
      allow read: if true;
    }
  }
}
"""
    root = make_repo({"firestore.rules": rules,
                      "database.rules.json": '{\n  "rules": {\n    "news": { ".read": true }  '
                                             '// firebase-launch-check: ignore\n  }\n}\n'})
    _, out, _ = run(capsys, "scan", str(root), "--json")
    assert [(f["rule_id"], f["line"]) for f in json.loads(out)["findings"]] == [("FLC001", 11)]


def test_exclude_glob(capsys, copy_fixture):
    root = copy_fixture("vulnerable")
    _, out, _ = run(capsys, "scan", str(root), "--json", "--exclude", "*.rules", "--exclude", "src/*")
    ids = {f["rule_id"] for f in json.loads(out)["findings"]}
    assert not ids & {"FLC001", "FLC002", "FLC003", "FLC004", "FLC005", "FLC101", "FLC102", "FLC302", "FLC401"}
    assert "FLC201" in ids


def test_tests_folders_skipped_unless_included(capsys, make_repo):
    root = make_repo({"tests/firestore.rules": (FIX / "vulnerable" / "firestore.rules").read_text()})
    _, out, _ = run(capsys, "scan", str(root), "--json")
    assert json.loads(out)["findings"] == []
    _, out, _ = run(capsys, "scan", str(root), "--json", "--include-tests")
    assert len(json.loads(out)["findings"]) == 6


def test_output_never_contains_secrets(capsys, make_repo):
    root = make_repo({"service-account.json": fake_service_account(),
                      ".env": 'FIREBASE_PRIVATE_KEY="' + FAKE_PEM.replace("\n", "\\n") + '"\n'})
    body = FAKE_PEM.splitlines()[1]
    for fmt in ([], ["--json"]):
        code, out, _ = run(capsys, "scan", str(root), "--no-color", *fmt)
        assert code == 1
        assert body[:12] not in out and FAKE_KEY_ID[:8] not in out
        assert "BEGIN PRIVATE" not in out


def test_mask_secret_shows_at_most_four_chars():
    assert mask_secret("abcdefghijklmnopqrstuvwxyz") == "abcd**** (26 chars)"
    assert mask_secret("abcdefgh") == "ab**** (8 chars)"
    assert mask_secret("abc") == "**** (3 chars)"


def test_rules_lists_every_rule(capsys):
    code, out, _ = run(capsys, "rules")
    assert code == 0
    for rid, r in RULES.items():
        assert rid in out and r.title in out


def test_every_rule_has_title_why_fix():
    for r in RULES.values():
        assert r.title and len(r.why) > 40 and len(r.fix) > 40


def test_module_entry_point():
    env = {"PYTHONPATH": str(ROOT / "src")}
    if sys.platform == "win32":
        env.update({"SYSTEMROOT": "C:\\Windows", "PATH": ""})
    res = subprocess.run([sys.executable, "-m", "firebase_launch_check", "scan", str(FIX / "clean"), "--brief"],
                         capture_output=True, text=True, env=env)
    assert res.returncode == 0, res.stderr
    assert "No findings" in res.stdout


def test_no_network_imports():
    """The scanner must never be able to contact anything."""
    for p in (ROOT / "src" / "firebase_launch_check").glob("*.py"):
        text = p.read_text(encoding="utf-8")
        for mod in ("urllib.request", "http.client", "socket", "requests", "httpx", "ssl"):
            assert f"import {mod}" not in text and f"from {mod} import" not in text, (p.name, mod)
