import pytest

from firebase_launch_check.rules_lang import classify, conjuncts, expand, normalize, parse_rules, strip_comments


def test_strip_comments_keeps_lines_and_strings():
    text = "a // x\n/* b\nc */ d 'e // not a comment'\n"
    out = strip_comments(text)
    assert out.count("\n") == text.count("\n")
    assert "x" not in out and "b" not in out and "'e // not a comment'" in out


def test_parse_nested_matches_functions_and_lines():
    rf = parse_rules("""rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function isOwner(userId) {
      return request.auth != null && request.auth.uid == userId;
    }
    match /users/{userId} {
      allow read: if isOwner(userId);
      allow create,
            update: if isOwner(userId)
                    && request.resource.data.name is string;
      match /notes/{noteId} {
        allow read, write: if isOwner(userId)
      }
    }
  }
}
""")
    assert rf.service == "firestore"
    assert [a.ops for a in rf.allows] == [["read"], ["create", "update"], ["read", "write"]]
    assert [a.line for a in rf.allows] == [8, 9, 13]
    assert rf.allows[1].end_line == 11
    assert rf.allows[2].full_path == "/databases/{database}/documents/users/{userId}/notes/{noteId}"
    assert rf.allows[2].match == "/notes/{noteId}"
    assert rf.allows[2].condition == "isOwner(userId)"       # statement without `;` before `}`
    assert rf.functions["isOwner"].params == ["userId"]


def test_allow_without_condition():
    rf = parse_rules("service cloud.firestore { match /databases/{d}/documents { match /a/{b} { allow read; } } }")
    [a] = rf.allows
    assert a.condition is None and classify(None)[0] == "true"


def test_storage_service_and_commented_out_rules_ignored():
    rf = parse_rules("""service firebase.storage {
  match /b/{bucket}/o {
    // allow read, write: if true;
    /* match /{allPaths=**} { allow read, write; } */
    match /x/{f} { allow read: if request.auth != null && request.auth.uid == 'a'; }
  }
}""")
    assert rf.service == "storage"
    assert len(rf.allows) == 1 and rf.allows[0].match == "/x/{f}"


def test_expand_inlines_functions_with_arguments_and_let():
    rf = parse_rules("""service cloud.firestore { match /databases/{d}/documents {
  function signedIn() { return request.auth != null; }
  function owns(id) { let uid = request.auth.uid; return signedIn() && uid == id; }
  match /a/{x} { allow read: if owns(x); }
} }""")
    out = normalize(expand(rf.allows[0].condition, rf.functions))
    assert "request.auth != null" in out and "(request.auth.uid) == (x)" in out


@pytest.mark.parametrize("cond,kind", [
    ("true", "true"),
    ("(true)", "true"),
    ("request.auth != null", "auth_only"),
    ("request.auth!=null", "auth_only"),
    ("(request.auth != null)", "auth_only"),
    ("request.auth.uid != null", "auth_only"),
    ("request.auth != null && request.time < timestamp.date(2030, 1, 1)", "auth_only"),
    ("request.time < timestamp.date(2030, 1, 1)", "test_mode"),
    ("request.time <  timestamp.date( 2030 , 1 , 1 )", "test_mode"),
    ("request.auth != null && request.auth.uid == userId", "other"),
    ("request.auth != null || request.auth.uid == userId", "other"),
    ("false", "other"),
    ("request.auth.token.admin == true", "other"),
    ("request.auth != null && request.auth.token.email_verified", "other"),
])
def test_classify(cond, kind):
    assert classify(cond)[0] == kind


def test_classify_returns_test_mode_date():
    assert classify("request.time < timestamp.date(2030, 2, 3)") == ("test_mode", (2030, 2, 3))


def test_conjuncts_respects_or_precedence():
    assert conjuncts("a || b && c") == ["a || b && c"]
    assert conjuncts("(a && b) && c") == ["a", "b", "c"]
