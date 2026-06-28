#!/usr/bin/env python3
"""Regenerate playground Floci sample plans.

Generates:
- site/playground/floci-create-plan.json
- site/playground/floci-destroy-plan.json
- site/playground/floci-samples.meta.json

Prereqs:
- Floci running at http://localhost:4566
- terraform installed
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PLAYGROUND = REPO / "site" / "playground"
SOURCE_TF = PLAYGROUND / "floci-demo.tf"
CREATE_JSON = PLAYGROUND / "floci-create-plan.json"
DESTROY_JSON = PLAYGROUND / "floci-destroy-plan.json"
META_JSON = PLAYGROUND / "floci-samples.meta.json"
FLOCI_ENDPOINT = "http://localhost:4566"


def run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, check=True, text=True, capture_output=True)


def assert_floci_up() -> None:
    try:
        with urllib.request.urlopen(FLOCI_ENDPOINT, timeout=3) as r:  # nosec B310
            _ = r.status
    except Exception as exc:
        raise SystemExit(
            "Floci is not reachable at http://localhost:4566. "
            "Start it first: docker run -d --rm -p 4566:4566 -v /var/run/docker.sock:/var/run/docker.sock floci/floci:latest"  # noqa: E501
        ) from exc


def terraform_version() -> str:
    try:
        cp = run(["terraform", "version", "-json"], REPO)
        data = json.loads(cp.stdout)
        return data.get("terraform_version", "unknown")
    except Exception:
        return "unknown"


def main() -> None:
    if not SOURCE_TF.exists():
        raise SystemExit(f"Missing source terraform file: {SOURCE_TF}")

    assert_floci_up()

    with tempfile.TemporaryDirectory(prefix="floci-samples-") as td:
        work = Path(td)
        shutil.copy2(SOURCE_TF, work / "main.tf")

        env = {
            "AWS_ACCESS_KEY_ID": "test",
            "AWS_SECRET_ACCESS_KEY": "test",
            "AWS_DEFAULT_REGION": "us-east-1",
        }

        def run_env(cmd: list[str]) -> subprocess.CompletedProcess:
            full_env = os.environ.copy()
            full_env.update(env)
            return subprocess.run(cmd, cwd=work, check=True, text=True, capture_output=True, env=full_env)  # noqa: E501

        run_env(["terraform", "init", "-input=false"])

        # Create plan from empty state
        run_env(["terraform", "plan", "-out", "create.tfplan", "-input=false"])
        cp_create = run_env(["terraform", "show", "-json", "create.tfplan"])
        CREATE_JSON.write_text(cp_create.stdout, encoding="utf-8")

        # Apply then generate destroy plan from created state
        run_env(["terraform", "apply", "-auto-approve", "-input=false", "create.tfplan"])
        run_env(["terraform", "plan", "-destroy", "-out", "destroy.tfplan", "-input=false"])
        cp_destroy = run_env(["terraform", "show", "-json", "destroy.tfplan"])
        DESTROY_JSON.write_text(cp_destroy.stdout, encoding="utf-8")

        # Best-effort cleanup of emulated resources
        try:
            run_env(["terraform", "destroy", "-auto-approve", "-input=false"])
        except Exception:
            pass

    meta = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "site/playground/floci-demo.tf",
        "generator": "site/scripts/regenerate_floci_samples.py",
        "terraform_version": terraform_version(),
        "floci_endpoint": FLOCI_ENDPOINT,
    }
    META_JSON.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    print("Regenerated:")
    print(f"- {CREATE_JSON}")
    print(f"- {DESTROY_JSON}")
    print(f"- {META_JSON}")


if __name__ == "__main__":
    main()
