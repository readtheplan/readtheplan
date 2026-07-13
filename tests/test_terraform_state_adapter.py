from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.terraform_state import (
    TerraformStateAdapter,
    TerraformStateInputError,
    analyze_terraform_state,
    parse_terraform_state,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _data(name: str):
    return parse_terraform_state((FIXTURES / name).read_text(encoding="utf-8"))


def _changes(name: str):
    return TerraformStateAdapter().analyze(
        _data(name),
        tool_name="Terraform/OpenTofu state",
    )


def test_show_json_state_applies_deep_rules_checks_and_secret_metadata() -> None:
    changes = _changes("terraform_state_show_risky.json")
    by_type: dict[str, list] = {}
    for change in changes:
        by_type.setdefault(change.resource_type, []).append(change)

    assert by_type["aws_s3_bucket"][0].risk == "dangerous"
    assert by_type["aws_db_instance"][0].risk == "review"
    assert by_type["terraform_state_public_database"][0].risk == "dangerous"
    assert by_type["terraform_state_unencrypted_database_storage"][0].risk == "dangerous"
    assert by_type["aws_security_group"][0].risk == "dangerous"
    assert by_type["terraform_state_unmarked_sensitive_output"][0].risk == "dangerous"
    assert by_type["terraform_state_unmarked_sensitive_attribute"][0].risk == "dangerous"
    assert by_type["terraform_state_sensitive_attributes"][0].risk == "review"
    assert by_type["terraform_state_failed_check"][0].risk == "dangerous"
    assert by_type["terraform_state_state_boundary"][0].risk == "review"


def test_raw_state_surfaces_internal_format_taint_deposed_and_secret_marking() -> None:
    changes = _changes("terraform_state_raw_risky.json")
    kinds = {change.resource_type for change in changes}

    assert {
        "terraform_state_unstable_raw_format",
        "terraform_state_unmarked_sensitive_output",
        "terraform_state_unmarked_sensitive_attribute",
        "terraform_state_sensitive_attributes",
        "terraform_state_tainted_instance",
        "terraform_state_deposed_instance",
        "terraform_state_state_boundary",
        "aws_s3_bucket",
    } <= kinds


def test_report_never_serializes_state_values_private_blobs_or_check_messages() -> None:
    show = json.dumps(analyze_terraform_state(_data("terraform_state_show_risky.json")))
    raw = json.dumps(analyze_terraform_state(_data("terraform_state_raw_risky.json")))
    combined = show + raw

    for secret in (
        "output-secret-value",
        "marked-output-secret",
        "marked-resource-secret",
        "unmarked-resource-secret",
        "internal-check-message-secret",
        "raw-output-secret",
        "raw-marked-resource-secret",
        "raw-unmarked-resource-secret",
        "provider-private-blob",
    ):
        assert secret not in combined


def test_adapter_redacts_marked_and_unmarked_secrets_before_resource_rules() -> None:
    adapter = TerraformStateAdapter()
    show_changes = adapter.extract_changes(_data("terraform_state_show_risky.json"))
    raw_changes = adapter.extract_changes(_data("terraform_state_raw_risky.json"))
    serialized = json.dumps(show_changes + raw_changes)

    assert "marked-resource-secret" not in serialized
    assert "unmarked-resource-secret" not in serialized
    assert "raw-marked-resource-secret" not in serialized
    assert "raw-unmarked-resource-secret" not in serialized
    assert serialized.count("<sensitive>") >= 4


def test_review_state_has_only_review_findings() -> None:
    changes = _changes("terraform_state_show_review.json")
    assert changes
    assert {change.risk for change in changes} == {"review"}


def test_gate_contract_counts_resources_outputs_and_raw_serial() -> None:
    show = analyze_terraform_state(_data("terraform_state_show_risky.json"))
    raw = analyze_terraform_state(_data("terraform_state_raw_risky.json"))

    assert show["adapter"] == "terraform-state"
    assert show["artifact"] == "show-json"
    assert show["resource_count"] == 3
    assert show["output_count"] == 2
    assert show["serial"] is None
    assert show["decision"] == "block"
    assert raw["artifact"] == "raw-v4"
    assert raw["resource_count"] == 1
    assert raw["output_count"] == 1
    assert raw["serial"] == 42


@pytest.mark.parametrize(
    "source,error",
    [
        ("", "empty"),
        ("[]", "JSON object"),
        ('{"version":4,"version":4}', "duplicate JSON key"),
        ('{"resource_changes":[]}', "plan representation"),
        (
            '{"format_version":"2.0","terraform_version":"1.14.0","values":{}}',
            "unsupported terraform show",
        ),
        (
            '{"format_version":"1.0","terraform_version":"latest","values":{}}',
            "exact semantic version",
        ),
        (
            '{"version":3,"terraform_version":"1.14.0","serial":1,'
            '"lineage":"8afed2ab-700c-4c78-b994-1ffb7f0f64f8","resources":[]}',
            "unsupported raw state",
        ),
        (
            '{"version":4,"terraform_version":"1.14.0","serial":-1,'
            '"lineage":"8afed2ab-700c-4c78-b994-1ffb7f0f64f8","resources":[]}',
            "serial",
        ),
        (
            '{"version":4,"terraform_version":"1.14.0","serial":1,'
            '"lineage":"not-a-uuid","resources":[]}',
            "lineage",
        ),
        ("{\"services\":{}}", "not terraform show"),
    ],
)
def test_parser_rejects_ambiguous_or_malformed_state(source: str, error: str) -> None:
    with pytest.raises(TerraformStateInputError, match=error):
        parse_terraform_state(source)


def test_parser_and_analyzer_never_execute_terraform_or_tofu(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("Terraform/OpenTofu execution is forbidden")

    monkeypatch.setattr("subprocess.run", fail)
    assert _changes("terraform_state_show_risky.json")


def test_adapter_rejects_wrong_shape() -> None:
    adapter = TerraformStateAdapter()
    assert not adapter.can_handle({})
    assert not adapter.can_handle({"terraform_state": {}})


def test_terraform_state_cli_emits_framework_gate(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        main(
            [
                "terraform-state",
                "--framework",
                "soc2",
                str(FIXTURES / "terraform_state_show_risky.json"),
            ]
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "terraform-state"
    assert payload["artifact"] == "show-json"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
