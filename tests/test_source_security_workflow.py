from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "source-secret-scan.yml"
GITLEAKS_CONFIG = ROOT / ".gitleaks.toml"
DOGFOOD_BASELINE = ROOT / ".github" / "readtheplan-scan-baseline.json"
CHECKOUT_REF = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
GITLEAKS_IMAGE = (
    "ghcr.io/gitleaks/gitleaks:v8.30.1"
    "@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
)


def _workflow() -> tuple[str, dict[str, object]]:
    raw = WORKFLOW.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8")
    parsed = yaml.load(text, Loader=yaml.BaseLoader)
    assert isinstance(parsed, dict)
    return text, parsed


def test_source_secret_scan_has_a_read_only_fork_safe_trigger() -> None:
    text, workflow = _workflow()

    triggers = workflow["on"]
    assert isinstance(triggers, dict)
    assert set(triggers) == {"pull_request", "push"}
    assert triggers["push"] == {"branches": ["main"]}
    assert workflow["permissions"] == {"contents": "read"}

    lowered = text.lower()
    for forbidden in (
        "pull_request_target",
        "workflow_dispatch",
        "schedule:",
        "secrets.",
        "vars.",
        "id-token:",
        "contents: write",
        "self-hosted",
        "continue-on-error",
        "environment:",
        "upload-artifact",
    ):
        assert forbidden not in lowered


def test_source_secret_scan_is_immutable_networkless_and_tree_only() -> None:
    text, workflow = _workflow()

    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    assert set(jobs) == {"gitleaks-source"}
    job = jobs["gitleaks-source"]
    assert isinstance(job, dict)
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["timeout-minutes"] == "10"

    steps = job["steps"]
    assert isinstance(steps, list)
    checkout = steps[0]
    assert checkout["uses"] == CHECKOUT_REF
    assert checkout["with"]["persist-credentials"] == "false"

    scan = steps[1]
    assert scan["env"] == {"GITLEAKS_IMAGE": GITLEAKS_IMAGE}
    command = scan["run"]
    for required in (
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--user 65532:65532",
        "--tmpfs /tmp:rw,noexec,nosuid,size=64m",
        "target=/repo,readonly",
        '"$GITLEAKS_IMAGE" dir /repo',
        "--config /repo/.gitleaks.toml",
        "--no-banner",
        "--redact",
    ):
        assert required in command

    lowered = text.lower()
    assert "fetch-depth: 0" not in lowered
    assert "gitleaks git" not in lowered
    assert "gitleaks detect" not in lowered
    for mutation in (
        "git push",
        "docker push",
        "cosign sign",
        "twine upload",
        "npm publish",
        "gh release",
        "kubectl apply",
        "terraform apply",
    ):
        assert mutation not in lowered


def test_gitleaks_allowlists_are_exact_rule_path_and_line_exceptions() -> None:
    config = tomllib.loads(GITLEAKS_CONFIG.read_text(encoding="utf-8"))

    assert config["extend"] == {"useDefault": True}
    allowlists = {entry["description"]: entry for entry in config["allowlists"]}
    assert set(allowlists) == {
        "Synthetic private-key fixtures",
        "Synthetic curl authorization fixture",
        "Synthetic Packer password fixture",
        "Changelog dynamic-secret wording",
        "Carvel API group literal",
        "Ansible role metadata identifier",
        "Terraform resource names that resemble Cloudflare API keys",
    }

    assert allowlists["Synthetic private-key fixtures"] == {
        "description": "Synthetic private-key fixtures",
        "targetRules": ["private-key"],
        "paths": [
            r"^(/repo/)?tests/fixtures/cloud_init_risky\.yml$",
            r"^(/repo/)?tests/fixtures/ansible_inventory_risky\.yml$",
            r"^(/repo/)?tests/fixtures/tfe_provider_plan_risky\.json$",
        ],
    }
    assert allowlists["Synthetic curl authorization fixture"] == {
        "description": "Synthetic curl authorization fixture",
        "targetRules": ["curl-auth-header"],
        "paths": [r"^(/repo/)?tests/fixtures/inspec_profile_risky/controls/main\.rb$"],
    }
    assert allowlists["Synthetic Packer password fixture"] == {
        "description": "Synthetic Packer password fixture",
        "targetRules": ["hashicorp-tf-password"],
        "paths": [r"^(/repo/)?tests/fixtures/packer_template_risky\.pkr\.hcl$"],
    }

    exact_generic_exceptions = {
        "Changelog dynamic-secret wording": (
            r"^(/repo/)?CHANGELOG\.md$",
            r"dynamic-secret engines",
        ),
        "Carvel API group literal": (
            r"^(/repo/)?src/readtheplan/adapters/carvel\.py$",
            r'api_group == "vendir\.k14s\.io"',
        ),
        "Ansible role metadata identifier": (
            r"^(/repo/)?src/readtheplan/adapters/ansible_project\.py$",
            r"allowed_keys=_ROLE_META_KEYS",
        ),
    }
    for description, (path, line_regex) in exact_generic_exceptions.items():
        assert allowlists[description] == {
            "description": description,
            "targetRules": ["generic-api-key"],
            "condition": "AND",
            "regexTarget": "line",
            "paths": [path],
            "regexes": [line_regex],
        }

    cloudflare = allowlists[
        "Terraform resource names that resemble Cloudflare API keys"
    ]
    assert cloudflare == {
        "description": "Terraform resource names that resemble Cloudflare API keys",
        "targetRules": ["cloudflare-api-key"],
        "condition": "AND",
        "regexTarget": "line",
        "paths": [r"^(/repo/)?tests/test_rules\.py$"],
        "regexes": [
            r'"cloudflare_(access_application|access_policy|teams_rules)"'
        ],
    }

    for entry in allowlists.values():
        assert "commits" not in entry
        assert "stopwords" not in entry
        if "regexes" in entry:
            assert entry["condition"] == "AND"
            assert entry["regexTarget"] == "line"
            assert entry["paths"]

    expected_root_paths = [
        "tests/fixtures/cloud_init_risky.yml",
        "tests/fixtures/ansible_inventory_risky.yml",
        "tests/fixtures/tfe_provider_plan_risky.json",
        "tests/fixtures/inspec_profile_risky/controls/main.rb",
        "tests/fixtures/packer_template_risky.pkr.hcl",
        "CHANGELOG.md",
        "src/readtheplan/adapters/carvel.py",
        "src/readtheplan/adapters/ansible_project.py",
        "tests/test_rules.py",
    ]
    path_patterns = [
        pattern for entry in config["allowlists"] for pattern in entry["paths"]
    ]
    assert len(path_patterns) == len(expected_root_paths)
    for pattern, root_path in zip(path_patterns, expected_root_paths, strict=True):
        assert re.fullmatch(pattern, root_path)
        assert re.fullmatch(pattern, f"/repo/{root_path}")
        assert not re.fullmatch(pattern, f"nested/{root_path}")
        assert not re.fullmatch(pattern, f"/repo/nested/{root_path}")


def test_dogfood_baseline_accounts_for_the_new_scanned_workflow() -> None:
    baseline = json.loads(DOGFOOD_BASELINE.read_text(encoding="utf-8"))

    assert baseline == {
        "schema": "readtheplan-scan-baseline-v1",
        "maximum_risk_counts": {
            "safe": 17,
            "review": 159,
            "dangerous": 156,
            "irreversible": 0,
        },
        "maximum_errors": 0,
        "minimum_scanned_files": 13,
    }
