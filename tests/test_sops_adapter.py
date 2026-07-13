from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.sops import SOPSAdapter, SOPSInputError, analyze_sops, parse_sops
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _risks(data: dict) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for change in SOPSAdapter().analyze(data, use_rules=False):
        grouped.setdefault(change.resource_type, []).append(change.risk)
    return grouped


def test_sops_policy_flags_identity_scope_threshold_selectors_and_publication() -> None:
    source = (FIXTURES / "sops_policy_risky.yaml").read_text(encoding="utf-8")
    data = parse_sops(source, ".sops.yaml")
    risks = _risks(data)

    assert risks["sops_path_scope"] == ["review", "review"]
    assert risks["sops_encryption_identity"] == ["review", "review"]
    assert risks["sops_shamir_threshold"] == ["dangerous"]
    assert risks["sops_selective_encryption"] == ["dangerous", "review", "dangerous"]
    assert risks["sops_conflicting_selectors"] == ["dangerous"]
    assert risks["sops_partial_integrity"] == ["dangerous"]
    assert risks["sops_delegated_identity"] == ["dangerous"]
    assert risks["sops_ssh_identity"] == ["review"]
    assert risks["sops_invalid_regex"] == ["dangerous"]
    assert risks["sops_secret_publication"] == ["dangerous"]


def test_sops_yaml_document_checks_encryption_plaintext_recipients_and_mac() -> None:
    source = (FIXTURES / "secret.sops.yaml").read_text(encoding="utf-8")
    data = parse_sops(source, "secret.sops.yaml")
    risks = _risks(data)

    assert risks["sops_encrypted_payload"] == ["safe"]
    assert risks["sops_plaintext_value"] == ["review", "dangerous"]
    assert risks["sops_encryption_identity"] == ["review", "review"]
    assert risks["sops_integrity"] == ["safe"]
    payload = analyze_sops(data)
    assert payload["adapter"] == "sops"
    assert payload["decision"] == "block"
    assert "literal-token-must-not-leak" not in json.dumps(payload)


def test_sops_dotenv_document_is_parsed_without_exposing_values() -> None:
    source = (FIXTURES / "secret.sops.env").read_text(encoding="utf-8")
    data = parse_sops(source, "secret.sops.env")
    risks = _risks(data)

    assert risks["sops_encrypted_payload"] == ["safe"]
    assert risks["sops_plaintext_value"] == ["dangerous"]
    assert risks["sops_encryption_identity"] == ["review"]
    assert risks["sops_integrity"] == ["safe"]


def test_sops_ini_document_flags_unprotected_mac_and_plaintext() -> None:
    source = (FIXTURES / "secret.sops.ini").read_text(encoding="utf-8")
    data = parse_sops(source, "secret.sops.ini")
    risks = _risks(data)

    assert risks["sops_encrypted_payload"] == ["safe"]
    assert risks["sops_plaintext_value"] == ["dangerous"]
    assert risks["sops_encryption_identity"] == ["review"]
    assert risks["sops_integrity"] == ["dangerous"]


def test_sops_json_document_and_binary_shape_are_supported() -> None:
    data = parse_sops(
        json.dumps(
            {
                "data": "ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]",
                "sops": {
                    "age": [{"recipient": "age1example", "enc": "ciphertext"}],
                    "mac": "ENC[AES256_GCM,data:m,iv:i,tag:t,type:str]",
                    "version": "3.10.2",
                },
            }
        ),
        "secret.sops.json",
    )
    risks = _risks(data)
    assert risks["sops_encrypted_payload"] == ["safe"]
    assert risks["sops_encryption_identity"] == ["review"]


def test_sops_policy_flags_empty_key_groups_and_ignored_direct_identities() -> None:
    data = parse_sops(
        "creation_rules:\n"
        "  - age: age1ignored\n"
        "    key_groups:\n"
        "      - {}\n"
        "    shamir_threshold: 2\n",
        ".sops.yaml",
    )
    risks = _risks(data)
    assert risks["sops_missing_identity"] == ["dangerous"]
    assert risks["sops_invalid_key_groups"] == ["dangerous"]
    assert risks["sops_ignored_identity"] == ["review"]
    assert risks["sops_shamir_threshold"] == ["dangerous"]


def test_sops_policy_counts_comma_separated_and_merged_identities() -> None:
    data = parse_sops(
        "creation_rules:\n"
        "  - key_groups:\n"
        "      - merge:\n"
        "          - age: age1first, age1second\n"
        "          - pgp:\n"
        "              - ABCDEF\n"
        "    shamir_threshold: 0\n",
        ".sops.yaml",
    )
    artifact = data["sops_artifact"]
    changes = SOPSAdapter().extract_changes(data)
    identities = [change for change in changes if change["Kind"] == "encryption_identity"]
    assert artifact["kind"] == "config"
    assert any("2 age recipient(s)" in change["Explanation"] for change in identities)
    assert any("1 pgp recipient(s)" in change["Explanation"] for change in identities)


def test_sops_cli_emits_framework_gate(capsys) -> None:
    assert main(
        ["sops", "--framework", "soc2", str(FIXTURES / "secret.sops.yaml")]
    ) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "sops"
    assert payload["decision"] == "block"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


@pytest.mark.parametrize(
    ("source", "filename"),
    [
        ("", ".sops.yaml"),
        ("[]", ".sops.yaml"),
        ("key: value", "secret.sops.yaml"),
        ("sops: {}\nsops: {}", "secret.sops.yaml"),
        ('{"sops": {}, "sops": {}}', "secret.sops.json"),
        ("KEY=value", "secret.sops.env"),
        ("[data]\nkey=value", "secret.sops.ini"),
    ],
)
def test_sops_parser_rejects_invalid_or_unrecognized_input(source: str, filename: str) -> None:
    with pytest.raises(SOPSInputError):
        parse_sops(source, filename)
