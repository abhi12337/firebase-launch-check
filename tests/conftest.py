"""Shared helpers. The fake service account key is assembled at runtime so that no
secret-shaped string is ever committed to this repository (keeps secret scanners quiet)."""

from __future__ import annotations

import datetime as dt
import json
import shutil
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
TODAY = dt.date(2026, 11, 11)

_BODY = ("MIIEvAIBADANBgkqhkiG9w0BAQEFAASC" + "FAKEfakeFAKEfake0123456789" * 8)
FAKE_PEM = "-----BEGIN " + "PRIVATE KEY-----\n" + _BODY + "\n-----END " + "PRIVATE KEY-----\n"
FAKE_KEY_ID = "0123456789abcdef" + "0123456789abcdef" + "01234567"


def fake_service_account(project: str = "demo-project") -> str:
    return json.dumps({
        "type": "service_account",
        "project_id": project,
        "private_key_id": FAKE_KEY_ID,
        "private_key": FAKE_PEM,
        "client_email": f"firebase-adminsdk-x@{project}.iam.gserviceaccount.com",
        "client_id": "100000000000000000000",
    }, indent=2) + "\n"


@pytest.fixture
def make_repo(tmp_path):
    """make_repo({"rel/path": "content" | dict, ...}) -> Path. dict values are written as JSON."""

    def _make(files: dict) -> Path:
        root = tmp_path / "repo"
        root.mkdir(exist_ok=True)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, (dict, list)):
                content = json.dumps(content, indent=2)
            p.write_text(content, encoding="utf-8")
        return root

    return _make


@pytest.fixture
def copy_fixture(tmp_path):
    def _copy(name: str) -> Path:
        dst = tmp_path / name
        shutil.copytree(FIXTURES / name, dst)
        return dst

    return _copy
