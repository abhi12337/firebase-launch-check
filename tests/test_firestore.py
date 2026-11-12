import pytest
from conftest import TODAY

from firebase_launch_check.rules_scan import scan_rules_text

HEAD = "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n"
TAIL = "  }\n}\n"


def fs(body: str, client_privileged=None):
    _, findings = scan_rules_text("firestore.rules", HEAD + body + TAIL, client_privileged=client_privileged,
                                  today=TODAY)
    return findings


def ids(findings):
    return sorted(f.rule_id for f in findings)


# ---------------------------------------------------------------- FLC001 if true / no condition
def test_if_true_write_is_critical_with_owner_fix():
    [f] = fs("    match /users/{userId} {\n      allow read, write: if true;\n    }\n")
    assert f.rule_id == "FLC001" and f.severity == "critical"
    assert f.file == "firestore.rules" and f.line == 5
    assert f.evidence == "allow read, write: if true;"
    assert "allow read, write: if request.auth != null && request.auth.uid == userId;" in f.fix
    assert "match /users/{userId} {" in f.fix


def test_no_condition_counts_as_true():
    [f] = fs("    match /orders/{orderId} {\n      allow write;\n    }\n")
    assert f.rule_id == "FLC001" and f.severity == "critical"
    assert "request.auth.uid == request.resource.data.ownerId" in f.fix
    assert "request.auth.uid == resource.data.ownerId" in f.fix


def test_public_read_is_medium_and_on_user_data_high():
    [f] = fs("    match /posts/{postId} {\n      allow read: if true;\n    }\n")
    assert (f.rule_id, f.severity) == ("FLC001", "medium")
    assert "intentionally public" in f.fix
    [f] = fs("    match /users/{userId} {\n      allow get: if true;\n    }\n")
    assert (f.rule_id, f.severity) == ("FLC001", "high")


def test_true_through_a_function():
    body = "    function open() { return true; }\n    match /a/{b} {\n      allow write: if open();\n    }\n"
    assert ids(fs(body)) == ["FLC001"]


# ---------------------------------------------------------------- FLC002 test mode
def test_test_mode_future_is_critical():
    [f] = fs("    match /{document=**} {\n      allow read, write: if request.time < timestamp.date(2099, 1, 1);\n    }\n")
    assert f.rule_id == "FLC002" and f.severity == "critical"
    assert "2099-01-01" in f.message and "whole database" in f.message
    assert f.extra["expires"] == "2099-01-01"
    assert "match /users/{userId}" in f.fix


def test_test_mode_expired_is_medium():
    [f] = fs("    match /{document=**} {\n      allow read, write: if request.time < timestamp.date(2024, 5, 1);\n    }\n")
    assert f.rule_id == "FLC002" and f.severity == "medium" and "expired on 2024-05-01" in f.message


def test_test_mode_read_only_is_high():
    [f] = fs("    match /{document=**} {\n      allow read: if request.time < timestamp.date(2099, 1, 1);\n    }\n")
    assert (f.rule_id, f.severity) == ("FLC002", "high")


# ---------------------------------------------------------------- FLC003 auth-only
def test_auth_only_write_is_high():
    [f] = fs("    match /projects/{projectId} {\n      allow read, update: if request.auth != null;\n    }\n")
    assert (f.rule_id, f.severity) == ("FLC003", "high")
    assert not f.heuristic


def test_auth_only_read_on_user_data_is_high_heuristic():
    [f] = fs("    function signedIn() { return request.auth != null; }\n"
             "    match /users/{userId} {\n      allow read: if signedIn();\n    }\n")
    assert (f.rule_id, f.severity, f.heuristic) == ("FLC003", "high", True)
    assert "allow read: if request.auth != null && request.auth.uid == userId;" in f.fix


@pytest.mark.parametrize("body", [
    # shared catalogue readable by signed-in users: deliberate
    "    match /products/{productId} {\n      allow read: if request.auth != null;\n    }\n",
    # create-only with a sign-in check
    "    match /feedback/{id} {\n      allow create: if request.auth != null;\n    }\n",
    # owner checks
    "    match /users/{userId} {\n      allow read, write: if request.auth != null && request.auth.uid == userId;\n    }\n",
    "    match /orders/{id} {\n      allow read: if request.auth.uid == resource.data.ownerId;\n    }\n",
    # custom claims
    "    match /admin/{id} {\n      allow read, write: if request.auth.token.admin == true;\n    }\n",
    # closed
    "    match /{document=**} {\n      allow read, write: if false;\n    }\n",
])
def test_safe_rules_do_not_fire(body):
    assert fs(body) == []


# ---------------------------------------------------------------- FLC004 recursive wildcard
def test_root_recursive_if_true_is_critical():
    [f] = fs("    match /{document=**} {\n      allow read, write: if true;\n    }\n")
    assert (f.rule_id, f.severity) == ("FLC004", "critical")
    assert "every document in the database" in f.message
    assert "Delete the `match /{document=**}` block (line 5)" in f.fix


def test_root_recursive_auth_only_read_is_high():
    [f] = fs("    match /{path=**} {\n      allow read: if request.auth != null;\n    }\n")
    assert (f.rule_id, f.severity) == ("FLC004", "high")


def test_nested_recursive_wildcard_with_owner_check_is_fine():
    assert fs("    match /users/{userId}/{document=**} {\n"
              "      allow read, write: if request.auth != null && request.auth.uid == userId;\n    }\n") == []


def test_collection_group_wildcard_is_not_root():
    [f] = fs("    match /{path=**}/posts/{postId} {\n      allow read: if true;\n    }\n")
    assert f.rule_id == "FLC001"


# ---------------------------------------------------------------- FLC005 privileged fields
ROLE_FN = ("    function isAdmin() {\n      return get(/databases/$(database)/documents/users/$(request.auth.uid))"
           ".data.role == 'admin';\n    }\n    match /admin/{id} {\n      allow read: if isAdmin();\n    }\n")


def test_role_read_from_own_user_doc_and_unvalidated_write_is_high():
    findings = fs(ROLE_FN + "    match /users/{userId} {\n      allow write: if request.auth.uid == userId;\n    }\n")
    [f] = [x for x in findings if x.rule_id == "FLC005"]
    assert f.severity == "high" and f.heuristic and f.extra["field"] == "role"
    assert "affectedKeys().hasAny(['role'])" in f.fix and "!('role' in request.resource.data)" in f.fix


def test_role_protected_by_diff_check_is_fine():
    body = ROLE_FN + ("    match /users/{userId} {\n"
                      "      allow create: if request.auth.uid == userId && !('role' in request.resource.data);\n"
                      "      allow update: if request.auth.uid == userId\n"
                      "        && !request.resource.data.diff(resource.data).affectedKeys().hasAny(['role']);\n"
                      "    }\n")
    assert fs(body) == []


def test_has_only_whitelist_is_fine():
    body = ROLE_FN + ("    match /users/{userId} {\n      allow update: if request.auth.uid == userId\n"
                      "        && request.resource.data.diff(resource.data).affectedKeys().hasOnly(['name']);\n    }\n")
    assert fs(body) == []


def test_bracket_field_access_is_recognised():
    body = ("    match /admin/{id} {\n      allow read: if get(/databases/$(database)/documents/profiles/"
            "$(request.auth.uid)).data['isAdmin'] == true;\n    }\n"
            "    match /profiles/{uid} {\n      allow update: if request.auth.uid == uid;\n    }\n")
    [f] = fs(body)
    assert f.rule_id == "FLC005" and f.extra["field"] == "isAdmin"


def test_client_written_privileged_field_is_medium():
    body = "    match /users/{userId} {\n      allow create: if request.auth.uid == userId;\n    }\n"
    [f] = fs(body, client_privileged={"users": [("src/Signup.tsx", 7, "plan")]})
    assert (f.rule_id, f.severity, f.extra["field"]) == ("FLC005", "medium", "plan")
    assert "src/Signup.tsx:7" in f.message


def test_no_privileged_reads_no_finding():
    assert fs("    match /users/{userId} {\n      allow write: if request.auth.uid == userId;\n    }\n") == []
