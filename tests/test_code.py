import json
import shutil
import subprocess

import pytest
from conftest import FAKE_KEY_ID, FAKE_PEM, fake_service_account

from firebase_launch_check.code_scan import (find_admin_imports, find_emulator_env, find_privileged_writes,
                                             find_service_account_key, find_unguarded_emulator, services_used)
from firebase_launch_check.scanner import scan_path

VITE_PKG = {"name": "app", "dependencies": {"firebase": "^11.0.0", "react": "^18.3.1"},
            "devDependencies": {"vite": "^5.4.0"}}
NEXT_PKG = {"name": "app", "dependencies": {"firebase": "^11.0.0", "firebase-admin": "^13.0.0", "next": "15.0.0"}}


def rule(res, rid):
    return [f for f in res.findings if f.rule_id == rid]


# ---------------------------------------------------------------- FLC301 service account keys
def test_service_account_json_not_ignored_is_critical(make_repo):
    root = make_repo({"serviceAccountKey.json": fake_service_account()})
    [f] = rule(scan_path(str(root)), "FLC301")
    assert f.severity == "critical" and f.file == "serviceAccountKey.json" and f.line == 5
    assert "demo-project" in f.message and "not covered by .gitignore" in f.message
    assert FAKE_PEM[:40] not in f.evidence and FAKE_KEY_ID not in f.evidence
    assert f.evidence.startswith("private_key = ----**** (")


def test_service_account_git_ignored_is_info(make_repo):
    root = make_repo({"keys/sa.json": fake_service_account(), ".gitignore": "node_modules\nkeys/\n"})
    [f] = rule(scan_path(str(root)), "FLC301")
    assert f.severity == "info" and "git-ignored" in f.message


def test_service_account_in_hosting_folder_is_critical_even_if_ignored(make_repo):
    root = make_repo({"firebase.json": {"hosting": {"public": "dist"}}, "dist/sa.json": fake_service_account(),
                      ".gitignore": "dist\n"})
    [f] = rule(scan_path(str(root)), "FLC301")
    assert f.severity == "critical" and "Firebase Hosting public folder 'dist/'" in f.message


def test_private_key_in_env_file(make_repo):
    env = 'FIREBASE_CLIENT_EMAIL=x@demo.iam.gserviceaccount.com\nFIREBASE_PRIVATE_KEY="' + \
        FAKE_PEM.replace("\n", "\\n") + '"\n'
    root = make_repo({".env": env})
    [f] = rule(scan_path(str(root)), "FLC301")
    assert f.severity == "critical" and f.line == 2
    assert "FAKEfake" not in f.evidence and "----****" in f.evidence


def test_key_in_test_folder_is_still_reported(make_repo):
    root = make_repo({"tests/fixtures/sa.json": fake_service_account()})
    assert len(rule(scan_path(str(root)), "FLC301")) == 1


@pytest.mark.parametrize("content", [
    json.dumps({"type": "service_account", "project_id": "x", "private_key": "", "client_email": "a@b.c"}),
    "const docs = 'paste your -----BEGIN PRIVATE KEY----- here';\n",
    "-----BEGIN " + "PRIVATE KEY-----\n" + "A" * 64 + "\n-----END " + "PRIVATE KEY-----\n",   # a TLS key, no SA context
])
def test_not_service_account_keys(content):
    assert find_service_account_key(content) is None


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_service_account_committed_to_git(make_repo):
    root = make_repo({"sa.json": fake_service_account()})
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "sa.json"], check=True)
    [f] = rule(scan_path(str(root)), "FLC301")
    assert f.severity == "critical" and "committed to git" in f.message


# ---------------------------------------------------------------- FLC302 firebase-admin in client code
@pytest.mark.parametrize("line", ['import admin from "firebase-admin";', "import { getAuth } from 'firebase-admin/auth';",
                                  "const admin = require('firebase-admin');", 'await import("firebase-admin")'])
def test_admin_import_patterns(line):
    assert find_admin_imports("// x\n" + line + "\n") == [2]


def test_admin_in_vite_spa_src_is_high(make_repo):
    root = make_repo({"package.json": VITE_PKG, "src/admin.ts": 'import admin from "firebase-admin";\n'})
    [f] = rule(scan_path(str(root)), "FLC302")
    assert (f.severity, f.file, f.line) == ("high", "src/admin.ts", 1)


def test_admin_in_use_client_component_is_high(make_repo):
    root = make_repo({"package.json": NEXT_PKG,
                      "app/page.tsx": '"use client";\nimport { getFirestore } from "firebase-admin/firestore";\n'})
    [f] = rule(scan_path(str(root)), "FLC302")
    assert f.line == 2


def test_admin_in_hosted_public_js_is_high(make_repo):
    root = make_repo({"firebase.json": {"hosting": {"public": "public"}},
                      "public/app.js": "const admin = require('firebase-admin');\n"})
    assert len(rule(scan_path(str(root)), "FLC302")) == 1


@pytest.mark.parametrize("files", [
    {"package.json": VITE_PKG, "functions/src/index.ts": 'import * as admin from "firebase-admin";\n'},
    {"package.json": VITE_PKG, "server/api.ts": 'import * as admin from "firebase-admin";\n'},
    {"package.json": NEXT_PKG, "app/api/route.ts": 'import { getAuth } from "firebase-admin/auth";\n'},
    {"package.json": NEXT_PKG, "lib/admin.ts": 'import "server-only";\nimport admin from "firebase-admin";\n'},
    {"package.json": VITE_PKG, "vite.config.ts": 'import admin from "firebase-admin";\n'},
    {"package.json": {"dependencies": {"express": "4"}}, "src/index.ts": 'import admin from "firebase-admin";\n'},
])
def test_admin_in_server_code_is_fine(make_repo, files):
    assert rule(scan_path(str(make_repo(files))), "FLC302") == []


# ---------------------------------------------------------------- FLC401 emulator
def test_unguarded_emulator():
    text = 'const db = getFirestore(app);\nconnectFirestoreEmulator(db, "localhost", 8080);\n' \
           'connectAuthEmulator(auth, "http://localhost:9099");\n'
    assert find_unguarded_emulator(text) == [(2, "connectFirestoreEmulator"), (3, "connectAuthEmulator")]


@pytest.mark.parametrize("text", [
    'if (import.meta.env.DEV) {\n  connectFirestoreEmulator(db, "localhost", 8080);\n}\n',
    'if (location.hostname === "localhost")\nconnectFirestoreEmulator(db, "localhost", 8080);\n',
    'import.meta.env.DEV && connectFirestoreEmulator(db, "localhost", 8080);\n',
    'USE_EMULATOR ? connectFirestoreEmulator(db, "localhost", 8080) : null;\n',
    'function dev() {\n  connectFirestoreEmulator(db, "localhost", 8080);\n}\n',
    '// connectFirestoreEmulator(db, "localhost", 8080);\n',
])
def test_guarded_emulator(text):
    assert find_unguarded_emulator(text) == []


def test_emulator_in_scan(make_repo):
    code = 'connectFirestoreEmulator(db, "localhost", 8080);\n'
    root = make_repo({"src/firebase.ts": code, "src/emulators.ts": code, "functions/src/x.ts": code})
    [f] = rule(scan_path(str(root)), "FLC401")
    assert (f.file, f.severity, f.heuristic) == ("src/firebase.ts", "low", True)


# ---------------------------------------------------------------- FLC402 emulator env in production
def test_emulator_env_values():
    text = "# FIREBASE_AUTH_EMULATOR_HOST=x\nFIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099\nFIRESTORE_EMULATOR_HOST: x\n" \
           "OTHER=FIRESTORE_EMULATOR_HOST\n"
    assert find_emulator_env(text) == [(2, "FIREBASE_AUTH_EMULATOR_HOST"), (3, "FIRESTORE_EMULATOR_HOST")]


def test_emulator_env_in_production_files_only(make_repo):
    root = make_repo({".env.production": "FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099\n",
                      "apphosting.yaml": "env:\n  - variable: FIRESTORE_EMULATOR_HOST\n    value: 127.0.0.1:8080\n",
                      ".env.local": "FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099\n",
                      "apphosting.emulator.yaml": "env:\n  - variable: FIRESTORE_EMULATOR_HOST\n    value: x\n"})
    got = sorted((f.file, f.severity) for f in rule(scan_path(str(root)), "FLC402"))
    assert got == [(".env.production", "medium"), ("apphosting.yaml", "low")]


# ---------------------------------------------------------------- FLC403 emulators on 0.0.0.0
def test_emulators_on_all_interfaces(make_repo):
    root = make_repo({"firebase.json": '{\n  "emulators": {\n    "auth": { "host": "0.0.0.0", "port": 9099 },\n'
                                       '    "ui": { "enabled": true }\n  }\n}\n'})
    [f] = rule(scan_path(str(root)), "FLC403")
    assert (f.severity, f.line, f.extra["emulators"]) == ("low", 3, ["auth"])
    root2 = make_repo({"firebase.json": {"emulators": {"auth": {"host": "127.0.0.1"}}}})
    assert rule(scan_path(str(root2)), "FLC403") == []


# ---------------------------------------------------------------- FLC404 no rules in repo
def test_services_used():
    assert services_used('import { getFirestore } from "firebase/firestore";') == {"firestore"}
    assert services_used("import 'package:cloud_firestore/cloud_firestore.dart';") == {"firestore"}
    assert services_used('import { ref } from "firebase/storage";\nimport "firebase/compat/database";') == \
        {"storage", "database"}
    assert services_used('import { getFirestore } from "firebase-admin/firestore";') == set()


def test_client_uses_firestore_without_rules(make_repo):
    root = make_repo({"src/db.ts": 'import { getFirestore } from "firebase/firestore";\n'})
    [f] = rule(scan_path(str(root)), "FLC404")
    assert f.severity == "info" and f.extra["service"] == "firestore" and f.file == "src/db.ts"
    root = make_repo({"firestore.rules": "service cloud.firestore { match /databases/{d}/documents { } }\n"})
    assert rule(scan_path(str(root)), "FLC404") == []


def test_firebase_json_points_at_missing_rules(make_repo):
    root = make_repo({"firebase.json": {"firestore": {"rules": "rules/firestore.rules"}}})
    [f] = rule(scan_path(str(root)), "FLC404")
    assert "rules/firestore.rules" in f.message and f.file == "firebase.json"


def test_rules_paths_from_firebase_json_including_lists(make_repo):
    root = make_repo({
        "firebase.json": {"firestore": [{"database": "(default)", "rules": "config/main.rules"}],
                          "storage": [{"bucket": "b", "rules": "config/files.rules"}],
                          "database": {"rules": "config/rtdb.json"}},
        "config/main.rules": "service cloud.firestore { match /databases/{d}/documents { "
                             "match /a/{b} { allow write: if true; } } }",
        "config/files.rules": "service firebase.storage { match /b/{bucket}/o { "
                              "match /x/{f} { allow write: if true; } } }",
        "config/rtdb.json": {"rules": {".write": True}},
    })
    res = scan_path(str(root))
    assert res.rules_files == {"firestore": ["config/main.rules"], "storage": ["config/files.rules"],
                               "database": ["config/rtdb.json"]}
    assert sorted(f.rule_id for f in res.findings) == ["FLC001", "FLC001", "FLC201"]


# ---------------------------------------------------------------- privileged writes in client code
def test_find_privileged_writes():
    text = """
await setDoc(doc(db, "users", uid), { email, role: "member", profile: { plan: "x" } });
await updateDoc(doc(db, 'accounts', id), { isAdmin: false });
db.collection("profiles").doc(uid).set({ plan: "free" });
await setDoc(doc(db, "users", uid), { email });
const button = { role: "button" };
"""
    assert find_privileged_writes(text) == [("users", 2, "role"), ("accounts", 3, "isAdmin"), ("profiles", 4, "plan")]
