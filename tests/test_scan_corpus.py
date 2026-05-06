from __future__ import annotations

import json
from pathlib import Path

import tools.scan_corpus as scan_corpus


FIXTURES = Path(__file__).parent / "fixtures"


def test_find_plan_files_recurses_only_plan_json(tmp_path: Path) -> None:
    root_plan = tmp_path / "plan.json"
    nested = tmp_path / "nested"
    nested.mkdir()
    nested_plan = nested / "plan.json"
    ignored = nested / "not-plan.json"

    root_plan.write_text("{}", encoding="utf-8")
    nested_plan.write_text("{}", encoding="utf-8")
    ignored.write_text("{}", encoding="utf-8")

    assert scan_corpus.find_plan_files(tmp_path) == [root_plan, nested_plan]


def test_write_bundle_from_fixture_without_raw_plan(tmp_path: Path) -> None:
    bundle = scan_corpus.write_bundle(
        FIXTURES / "valid_plan.json",
        output_dir=tmp_path,
    )

    assert (bundle / "readtheplan.json").is_file()
    assert (bundle / "readtheplan.md").is_file()
    assert (bundle / "metadata.json").is_file()
    assert (bundle / "feedback.yaml").is_file()
    assert not (bundle / "plan.json").exists()
    assert not (bundle / "plan.redacted.json").exists()

    payload = json.loads((bundle / "readtheplan.json").read_text(encoding="utf-8"))
    assert payload["resource_change_count"] == 3
    assert payload["risks"] == {"dangerous": 1, "review": 1, "safe": 1}


def test_feedback_template_contains_expected_fields(tmp_path: Path) -> None:
    bundle = scan_corpus.write_bundle(
        FIXTURES / "valid_plan.json",
        output_dir=tmp_path,
    )

    feedback = (bundle / "feedback.yaml").read_text(encoding="utf-8")
    assert "schema_version: readtheplan-feedback-v0" in feedback
    assert "scan_id:" in feedback
    assert "overall_human_risk:" in feedback
    assert "readtheplan_overall_risk: dangerous" in feedback
    assert "resource_feedback:" in feedback
    assert "issue_type:" in feedback
    assert "expected_reason:" in feedback
    assert "suggested_rule:" in feedback
    assert 'address: "aws_s3_bucket.logs"' in feedback


def test_metadata_records_counts_and_security_flags(tmp_path: Path) -> None:
    bundle = scan_corpus.write_bundle(
        FIXTURES / "valid_plan.json",
        output_dir=tmp_path,
    )

    metadata = json.loads((bundle / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["schema_version"] == "readtheplan-corpus-scan-v0"
    assert metadata["source_path"] == "valid_plan.json"
    assert metadata["source_path_redacted"] is True
    assert metadata["source_kind"] == "terraform_plan_json"
    assert metadata["plan_sha256"].startswith("sha256:")
    assert metadata["resource_change_count"] == 3
    assert metadata["risk_counts"] == {"dangerous": 1, "review": 1, "safe": 1}
    assert metadata["readtheplan_overall_risk"] == "dangerous"
    assert metadata["raw_plan_included"] is False
    assert metadata["redacted_plan_included"] is False
    assert "Raw Terraform plan JSON is local/private" in metadata["security_boundary"]


def test_redact_writes_minimized_plan_without_raw_copy(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "terraform_version": "1.8.0",
                "variables": {"secret": {"value": "do-not-copy"}},
                "resource_changes": [
                    {
                        "address": "aws_iam_role.prod_123456789012",
                        "mode": "managed",
                        "type": "aws_iam_role",
                        "name": "prod_123456789012",
                        "change": {
                            "actions": ["update"],
                            "before": {
                                "arn": "arn:aws:iam::123456789012:role/prod",
                                "password": "secret",
                            },
                            "after": {
                                "arn": "arn:aws:iam::123456789012:role/prod",
                                "public_ip": "203.0.113.10",
                            },
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    bundle = scan_corpus.write_bundle(plan, output_dir=tmp_path / "out", redact=True)

    assert not (bundle / "plan.json").exists()
    redacted_path = bundle / "plan.redacted.json"
    assert redacted_path.is_file()
    redacted_text = redacted_path.read_text(encoding="utf-8")
    assert "123456789012" not in redacted_text
    assert "203.0.113.10" not in redacted_text
    assert "do-not-copy" not in redacted_text
    assert "<redacted>" in redacted_text


def test_include_raw_plan_requires_explicit_flag(tmp_path: Path) -> None:
    source = FIXTURES / "valid_plan.json"
    bundle = scan_corpus.write_bundle(
        source,
        output_dir=tmp_path,
        include_raw_plan=True,
    )

    assert (bundle / "plan.json").read_text(encoding="utf-8") == source.read_text(
        encoding="utf-8"
    )


def test_main_rejects_raw_and_redacted_together(tmp_path: Path, capsys) -> None:
    result = scan_corpus.main(
        [
            "--output-dir",
            str(tmp_path),
            "--include-raw-plan",
            "--redact",
            str(FIXTURES / "valid_plan.json"),
        ]
    )
    captured = capsys.readouterr()

    assert result == 1
    assert "mutually exclusive" in captured.err
