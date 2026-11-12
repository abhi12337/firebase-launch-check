import json

import pytest
from conftest import TODAY

from firebase_launch_check.rtdb_scan import JsonError, parse_json_lines, scan_rtdb_text
from firebase_launch_check.rules_scan import scan_rules_text

HEAD = "rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n"
TAIL = "  }\n}\n"


def st(body: str):
    _, findings = scan_rules_text("storage.rules", HEAD + body + TAIL, today=TODAY)
    return findings


# ---------------------------------------------------------------- Storage
def test_default_auth_only_catch_all_is_flc004():
    [f] = st("    match /{allPaths=**} {\n      allow read, write: if request.auth != null;\n    }\n")
    assert (f.rule_id, f.severity) == ("FLC004", "critical")
    assert "every file in the bucket" in f.message
    assert "request.resource.size < 5 * 1024 * 1024" in f.fix


def test_storage_if_true_on_folder():
    [f] = st("    match /uploads/{fileName} {\n      allow read, write: if true;\n    }\n")
    assert (f.rule_id, f.severity) == ("FLC001", "critical")
    assert "match /users/{userId}/{fileName}" in f.fix and "allow delete:" in f.fix


def test_upload_without_auth_is_flc101():
    [f] = st("    match /public/{fileName} {\n      allow write: if request.resource.size < 1024 * 1024;\n    }\n")
    assert (f.rule_id, f.severity) == ("FLC101", "high")


def test_upload_without_size_or_type_is_flc102_medium():
    [f] = st("    match /avatars/{userId}/{fileName} {\n      allow write: if request.auth.uid == userId;\n    }\n")
    assert (f.rule_id, f.severity) == ("FLC102", "medium")
    assert f.extra["missing"] == ["size", "content-type"]
    assert "allow create, update: if request.auth != null && request.auth.uid == userId" in f.fix
    assert "allow delete: if request.auth != null && request.auth.uid == userId;" in f.fix


def test_upload_with_size_but_no_type_is_low():
    [f] = st("    match /avatars/{userId}/{fileName} {\n      allow create: if request.auth.uid == userId"
             " && request.resource.size < 1024 * 1024;\n    }\n")
    assert (f.rule_id, f.severity, f.extra["missing"]) == ("FLC102", "low", ["content-type"])


def test_safe_storage_rules():
    body = ("    match /users/{userId}/{fileName} {\n"
            "      allow read: if request.auth != null && request.auth.uid == userId;\n"
            "      allow create, update: if request.auth != null && request.auth.uid == userId\n"
            "        && request.resource.size < 5 * 1024 * 1024\n"
            "        && request.resource.contentType.matches('image/.*');\n"
            "      allow delete: if request.auth != null && request.auth.uid == userId;\n"
            "    }\n"
            "    match /public/{fileName} {\n      allow read: if request.auth != null;\n    }\n")
    assert st(body) == []


def test_unknown_service_is_ignored():
    _, findings = scan_rules_text("x.rules", "service other.thing { match /a { allow read: if true; } }", today=TODAY)
    assert findings == []


# ---------------------------------------------------------------- Realtime Database
def rtdb(rules: dict | str):
    text = rules if isinstance(rules, str) else json.dumps({"rules": rules}, indent=2)
    ok, findings = scan_rtdb_text("database.rules.json", text, today=TODAY)
    assert ok
    return findings


def test_root_true_is_critical():
    fs = rtdb({".read": True, ".write": True})
    assert [(f.rule_id, f.severity, f.extra["key"]) for f in fs] == [
        ("FLC201", "critical", ".read"), ("FLC201", "critical", ".write")]
    assert fs[0].line == 3 and fs[0].evidence == '".read": true,'


def test_string_true_and_nested_paths():
    fs = rtdb({"posts": {".read": "true"}, "users": {".read": True}, "chat": {"$room": {".write": True}}})
    got = {(f.extra["path"], f.extra["key"]): f.severity for f in fs}
    assert got == {("/posts", ".read"): "medium", ("/users", ".read"): "high", ("/chat/$room", ".write"): "high"}


def test_test_mode_now_timestamp():
    fs = rtdb({".read": "now < 4102444800000", ".write": "now < 1700000000000"})
    assert [(f.rule_id, f.severity) for f in fs] == [("FLC202", "critical"), ("FLC202", "medium")]
    assert "2100-01-01" in fs[0].message and "expired on 2023-11-14" in fs[1].message


def test_auth_only():
    fs = rtdb({".read": "auth != null", "presence": {"$uid": {".write": "auth !== null"}},
               "lobby": {".read": "auth != null"}})
    assert [(f.rule_id, f.extra["path"], f.severity) for f in fs] == [
        ("FLC203", "/", "high"), ("FLC203", "/presence/$uid", "high")]


def test_owner_scoped_rtdb_is_clean_and_comments_allowed():
    text = """{
  // comments are allowed in database.rules.json
  "rules": {
    "users": {
      "$uid": {
        ".read": "auth != null && auth.uid === $uid",
        ".write": "auth != null && auth.uid === $uid",   /* trailing comma */
      },
    },
    ".read": false,
  },
}"""
    assert rtdb(text) == []


def test_not_rtdb_json():
    assert scan_rtdb_text("x.json", '{"name": "x"}')[0] is False
    assert scan_rtdb_text("x.json", "{not json")[0] is False


def test_json_reader_line_numbers():
    node = parse_json_lines('{\n  "a": {\n    "b": 1\n  }\n}')
    assert node.value["a"].line == 2 and node.value["a"].value["b"].line == 3
    with pytest.raises(JsonError):
        parse_json_lines('{"a" 1}')
