from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.terraform_lock import (
    TerraformLockAdapter,
    TerraformLockInputError,
    _constraint_allows,
    analyze_terraform_lock,
    parse_terraform_lock,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes(name: str):
    data = parse_terraform_lock((FIXTURES / name).read_text(encoding="utf-8"))
    return data, TerraformLockAdapter().analyze(
        data,
        tool_name="Terraform/OpenTofu lock",
    )


def test_lock_detects_version_source_constraint_and_checksum_risks() -> None:
    data, changes = _changes("terraform_lock_risky.hcl")
    assert len(data["terraform_lock"]["providers"]) == 3
    kinds = {change.resource_type for change in changes}
    assert {
        "terraform_lock_locked_provider",
        "terraform_lock_unbounded_constraint_context",
        "terraform_lock_single_package_checksum",
        "terraform_lock_missing_registry_hashes",
        "terraform_lock_prerelease_provider",
        "terraform_lock_local_provider_origin",
        "terraform_lock_missing_constraint_context",
        "terraform_lock_missing_preferred_hash",
        "terraform_lock_unsupported_hash_scheme",
        "terraform_lock_missing_checksums",
        "terraform_lock_constraint_selection_mismatch",
        "terraform_lock_lock_boundary",
    } <= kinds
    assert sum(change.risk == "dangerous" for change in changes) == 6


def test_complete_lock_still_reports_review_and_honest_boundary() -> None:
    _, changes = _changes("terraform_lock_complete.hcl")
    assert len(changes) == 2
    assert all(change.risk == "review" for change in changes)
    assert changes[-1].resource_type == "terraform_lock_lock_boundary"
    assert "signer identities" in changes[-1].explanation
    assert "remote module versions" in changes[-1].explanation


def test_gate_contract_counts_providers_and_findings() -> None:
    data = parse_terraform_lock(
        (FIXTURES / "terraform_lock_risky.hcl").read_text(encoding="utf-8")
    )
    gate = analyze_terraform_lock(data)
    assert gate["adapter"] == "terraform-lock"
    assert gate["provider_count"] == 3
    assert gate["total_changes"] == 14
    assert gate["decision"] == "block"


def test_lock_parser_never_executes_terraform_or_tofu(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("Terraform/OpenTofu execution is forbidden")

    monkeypatch.setattr("subprocess.run", fail)
    _, changes = _changes("terraform_lock_risky.hcl")
    assert changes


@pytest.mark.parametrize(
    "source, message",
    [
        ("", "empty"),
        ('terraform { required_version = \">= 1.0\" }', "no provider lock blocks"),
        (
            'provider "registry.terraform.io/hashicorp/aws" {'
            ' version="1.0.0" hashes=[] }\n'
            'provider "registry.terraform.io/hashicorp/aws" {'
            ' version="1.0.0" hashes=[] }',
            "duplicate provider lock block",
        ),
        (
            'provider "registry.terraform.io/hashicorp/aws" {'
            ' version="1.0.0" version="2.0.0" hashes=[] }',
            "duplicate provider attribute",
        ),
        (
            'provider "registry.terraform.io/hashicorp/aws" {'
            ' version="1.0.0" source="mirror" hashes=[] }',
            "unsupported provider attribute",
        ),
        (
            'provider "hashicorp/aws" { version="1.0.0" hashes=[] }',
            "invalid provider source address",
        ),
        (
            'provider "registry.terraform.io/hashicorp/aws" { hashes=[] }',
            "missing selected version",
        ),
        (
            'provider "registry.terraform.io/hashicorp/aws" {'
            ' version="latest" hashes=[] }',
            "invalid selected version",
        ),
        (
            'provider "registry.terraform.io/hashicorp/aws" {'
            ' version="1.0.0" hashes=["zh:abc"] }',
            "malformed zh checksum",
        ),
        (
            'provider "registry.terraform.io/hashicorp/aws" {'
            ' version="1.0.0" hashes=["h1:not-base64"] }',
            "malformed h1 checksum",
        ),
        (
            'provider "registry.terraform.io/hashicorp/aws" {'
            ' version="1.0.0" hashes=["bad"] }',
            "malformed checksum entry",
        ),
        (
            'provider "registry.terraform.io/hashicorp/aws" {'
            ' version="1.0.0" hashes=["zh:' + "a" * 64 + '", "zh:' + "a" * 64 + '"] }',
            "duplicate hashes",
        ),
        (
            'provider "registry.terraform.io/hashicorp/aws" {'
            ' version="1.0.0" hashes=[] }\nunexpected = true',
            "content outside provider blocks",
        ),
        (
            'provider "registry.terraform.io/hashicorp/aws" {'
            ' version="1.0.0" hashes=[]',
            "unterminated provider block",
        ),
    ],
)
def test_lock_rejects_ambiguous_or_malformed_input(source: str, message: str) -> None:
    with pytest.raises(TerraformLockInputError, match=message):
        parse_terraform_lock(source)


def test_custom_registry_is_review_not_assumed_untrusted() -> None:
    source = '''provider "providers.example.com/acme/widget" {
      version = "1.2.3"
      hashes = [
        "h1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        "zh:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      ]
    }'''
    data = parse_terraform_lock(source)
    changes = TerraformLockAdapter().analyze(data, tool_name="Terraform/OpenTofu lock")
    custom = next(
        change
        for change in changes
        if change.resource_type == "terraform_lock_custom_provider_origin"
    )
    assert custom.risk == "review"


@pytest.mark.parametrize(
    "version, constraint, expected",
    [
        ("5.80.0", "~> 5.0", True),
        ("5.80.0", ">= 5.0, < 6.0", True),
        ("5.80.0", "~> 4.0", False),
        ("5.80.0", "!= 5.80.0", False),
        ("5.80.0", "~> 5.79.2", False),
        ("5.80.0", "not-a-constraint", None),
    ],
)
def test_constraint_selection_checks_common_terraform_operators(
    version: str,
    constraint: str,
    expected: bool | None,
) -> None:
    assert _constraint_allows(version, constraint) is expected


def test_unparsed_constraint_syntax_is_reported_honestly() -> None:
    source = '''provider "registry.terraform.io/hashicorp/aws" {
      version = "1.0.0-beta.1"
      constraints = ">= 1.0.0-beta.1"
      hashes = [
        "h1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        "zh:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      ]
    }'''
    data = parse_terraform_lock(source)
    kinds = {
        change.resource_type
        for change in TerraformLockAdapter().analyze(
            data,
            tool_name="Terraform/OpenTofu lock",
        )
    }
    assert "terraform_lock_unverified_constraint_syntax" in kinds


def test_comments_do_not_create_fake_provider_blocks() -> None:
    source = '''
    # provider "fake.invalid/acme/fake" { version = "bad" }
    provider "registry.terraform.io/hashicorp/aws" {
      version = "1.2.3"
      hashes = []
    }
    '''
    data = parse_terraform_lock(source)
    assert len(data["terraform_lock"]["providers"]) == 1


def test_adapter_rejects_wrong_shape() -> None:
    assert not TerraformLockAdapter().can_handle({})
    assert not TerraformLockAdapter().can_handle({"terraform_lock": {}})


def test_terraform_lock_cli_emits_gate_contract(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        main(
            [
                "terraform-lock",
                "--framework",
                "soc2",
                str(FIXTURES / "terraform_lock_risky.hcl"),
            ]
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "terraform-lock"
    assert payload["provider_count"] == 3
    assert payload["decision"] == "block"
