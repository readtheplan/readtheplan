from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.pulumi import (
    PulumiAdapter,
    PulumiPreviewError,
    analyze_pulumi,
    parse_pulumi_preview,
)
from readtheplan.cli import main

FIXTURE = Path("tests/fixtures/pulumi_preview_mixed.json")


def test_detects_preview_digest_and_extracts_real_schema() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    adapter = detect_adapter(data)
    assert isinstance(adapter, PulumiAdapter)

    changes = adapter.analyze(data, use_rules=False, tool_name="Pulumi")
    assert [change.resource_type for change in changes] == [
        "aws_s3_bucket",
        "aws_security_group",
        "aws_db_instance",
    ]
    assert [change.risk for change in changes] == ["safe", "review", "irreversible"]
    assert changes[0].address.endswith("::logs")


def test_shared_rules_receive_pulumi_inputs() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    changes = PulumiAdapter().analyze(data, tool_name="Pulumi")
    security_group = changes[1]
    assert security_group.risk == "dangerous"
    assert "internet-wide access" in security_group.explanation


def test_replacement_and_import_classification() -> None:
    adapter = PulumiAdapter()
    replacement = adapter.normalize_change(
        {"op": "create-replacement", "type": "aws:kms/key:Key", "urn": "key"}
    )
    imported = adapter.normalize_change(
        {"op": "import", "type": "aws:s3/bucket:Bucket", "urn": "bucket"}
    )
    assert replacement.risk == "dangerous"
    assert replacement.actions == ("delete", "create")
    assert imported.risk == "review"
    assert imported.actions == ("update",)


def test_streaming_resource_pre_events() -> None:
    data = {
        "events": [
            {"sequence": 0, "stdoutEvent": {"message": "previewing"}},
            {
                "sequence": 1,
                "resourcePreEvent": {
                    "metadata": {
                        "op": "update",
                        "urn": "urn:pulumi:dev::app::gcp:storage/bucket:Bucket::assets",
                        "type": "gcp:storage/bucket:Bucket",
                        "old": {"inputs": {"location": "US"}},
                        "new": {"inputs": {"location": "EU"}},
                        "diffs": ["location"],
                    }
                },
            },
        ]
    }
    adapter = detect_adapter(data)
    assert isinstance(adapter, PulumiAdapter)
    changes = adapter.analyze(data, use_rules=False)
    assert len(changes) == 1
    assert changes[0].resource_type == "google_storage_bucket"
    assert changes[0].risk == "review"


def test_gate_contract_and_cli_digest(capsys) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    gate = analyze_pulumi(data)
    assert gate["schema"] == "rtp-agent-gate-v1"
    assert gate["adapter"] == "pulumi"
    assert gate["total_changes"] == 3
    assert gate["decision"] == "block"

    assert main(["pulumi", str(FIXTURE)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision"] == "block"


def test_cli_accepts_json_lines(tmp_path, capsys) -> None:
    events = tmp_path / "preview.jsonl"
    events.write_text(
        "\n".join(
            [
                json.dumps({"sequence": 0, "stdoutEvent": {"message": "preview"}}),
                json.dumps(
                    {
                        "sequence": 1,
                        "resourcePreEvent": {
                            "metadata": {
                                "op": "create",
                                "urn": "urn:pulumi:dev::app::aws:s3/bucket:Bucket::logs",
                                "type": "aws:s3/bucket:Bucket",
                                "new": {"inputs": {"bucket": "logs"}},
                            }
                        },
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )
    assert main(["pulumi", str(events)]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "proceed"


def test_cli_rejects_invalid_or_unrelated_json(tmp_path, capsys) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{not json", encoding="utf-8")
    assert main(["pulumi", str(invalid)]) == 1
    assert "invalid Pulumi preview JSON" in capsys.readouterr().err

    unrelated = tmp_path / "unrelated.json"
    unrelated.write_text('{"resource_changes": []}', encoding="utf-8")
    assert main(["pulumi", str(unrelated)]) == 1
    assert "not recognized" in capsys.readouterr().err


def test_parser_rejects_empty_and_scalar_input() -> None:
    for source in ("", "42", '"preview"'):
        with pytest.raises(PulumiPreviewError):
            parse_pulumi_preview(source)
