"""Generate a deliberately insecure demo Firebase project to try firebase-launch-check on.

    python examples/make_demo.py demo-firebase
    firebase-launch-check scan demo-firebase

The demo is the vulnerable test fixture (tests/fixtures/vulnerable) plus a fake service
account key file. The fake key is assembled at runtime so this repository never contains
a secret-shaped string. Nothing in it works anywhere.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURE = HERE.parent / "tests" / "fixtures" / "vulnerable"

FAKE_PEM = ("-----BEGIN " + "PRIVATE KEY-----\n" + "MIIEvAIBADANBgkqhkiG9w0BAQEFAASC"
            + "DEMOdemoNOTaREALkey0123456789" * 8 + "\n-----END " + "PRIVATE KEY-----\n")

SERVICE_ACCOUNT = {
    "type": "service_account",
    "project_id": "shop-demo",
    "private_key_id": "0123456789abcdef" * 2 + "01234567",
    "private_key": FAKE_PEM,
    "client_email": "firebase-adminsdk-demo@shop-demo.iam.gserviceaccount.com",
    "client_id": "100000000000000000000",
}


def main(dest: str) -> None:
    root = Path(dest)
    if root.exists():
        shutil.rmtree(root)
    shutil.copytree(FIXTURE, root)
    (root / "serviceAccountKey.json").write_text(json.dumps(SERVICE_ACCOUNT, indent=2) + "\n", encoding="utf-8")
    print(f"Demo project written to {root}. Now run:  firebase-launch-check scan {root}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "demo-firebase")
