from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from readtheplan import controls
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_load_soc2_catalog_smoke() -> None:
    cat = controls.load_catalog("soc2")

    assert cat.framework == "soc2"
    assert cat.framework_version == "2017-tsc"
    assert cat.schema_version == 1


def test_load_iso27001_catalog_smoke() -> None:
    cat = controls.load_catalog("iso27001")

    assert cat.framework == "iso27001"
    assert cat.framework_version == "2022"
    assert cat.schema_version == 1


def test_unknown_framework_raises() -> None:
    with pytest.raises(controls.FrameworkNotFoundError) as exc:
        controls.load_catalog("soc3")

    assert "soc2" in str(exc.value)


def test_available_frameworks_includes_soc2() -> None:
    assert "soc2" in controls.available_frameworks()


def test_available_frameworks_includes_iso27001() -> None:
    frameworks = controls.available_frameworks()

    assert "iso27001" in frameworks
    assert "soc2" in frameworks
    assert list(frameworks) == sorted(frameworks)


def test_controls_for_kms_create_returns_cc61_and_cc81() -> None:
    cat = controls.load_catalog("soc2")
    out = cat.controls_for(resource_type="aws_kms_key", actions=["create"])
    ids = [control.id for control in out]

    assert ids == ["CC6.1", "CC8.1"]


def test_controls_for_kms_replace_returns_full_set() -> None:
    cat = controls.load_catalog("soc2")
    out = cat.controls_for(resource_type="aws_kms_key", actions=["delete", "create"])
    ids = {control.id for control in out}

    assert ids == {"CC6.1", "CC6.7", "CC8.1", "A1.2", "C1.1"}


def test_iso27001_controls_for_kms_create() -> None:
    cat = controls.load_catalog("iso27001")
    out = cat.controls_for(resource_type="aws_kms_key", actions=["create"])
    ids = [control.id for control in out]

    assert ids == ["A.8.24", "A.8.32", "A.8.9"]


def test_iso27001_controls_for_kms_replace() -> None:
    cat = controls.load_catalog("iso27001")
    out = cat.controls_for(resource_type="aws_kms_key", actions=["delete", "create"])
    ids = {control.id for control in out}

    assert ids == {"A.8.10", "A.8.24", "A.8.32"}


def test_controls_for_replace_order_invariant() -> None:
    cat = controls.load_catalog("soc2")
    forward = cat.controls_for(
        resource_type="aws_kms_key", actions=["delete", "create"]
    )
    reverse = cat.controls_for(
        resource_type="aws_kms_key", actions=["create", "delete"]
    )

    assert {control.id for control in forward} == {control.id for control in reverse}
    assert len(forward) > 0


def test_iso27001_replace_order_invariant() -> None:
    cat = controls.load_catalog("iso27001")
    forward = cat.controls_for(
        resource_type="aws_kms_key", actions=["delete", "create"]
    )
    reverse = cat.controls_for(
        resource_type="aws_kms_key", actions=["create", "delete"]
    )

    assert {control.id for control in forward} == {control.id for control in reverse}
    assert len(forward) > 0


def test_controls_for_unmapped_resource_returns_empty() -> None:
    cat = controls.load_catalog("soc2")
    out = cat.controls_for(
        resource_type="aws_lambda_function",
        actions=["update"],
    )

    assert out == ()


def test_controls_for_dedup_first_seen_order(tmp_path: Path) -> None:
    catalog = tmp_path / "dedup.yaml"
    catalog.write_text(
        """
framework: test
framework_version: "1"
schema_version: 1
mappings:
  - resource_type: aws_example
    actions: [create]
    controls:
      - id: C1
        title: First
        rationale: First match.
      - id: C2
        title: Second
        rationale: Second match.
  - resource_type: aws_example
    actions: [create]
    controls:
      - id: C2
        title: Second duplicate
        rationale: Should be ignored.
      - id: C3
        title: Third
        rationale: Third match.
""".lstrip(),
        encoding="utf-8",
    )

    cat = controls._load_from_path(catalog)
    out = cat.controls_for(resource_type="aws_example", actions=["create"])

    assert [control.id for control in out] == ["C1", "C2", "C3"]
    assert out[1].title == "Second"


def test_cli_markdown_includes_controls_column(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(
        ["analyze", "--framework", "soc2", str(FIXTURES / "soc2_plan.json")]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert (
        "| Risk | Actions | Resource | Type | Explanation | Controls |" in captured.out
    )
    assert "CC6.1" in captured.out


def test_cli_iso27001_markdown_includes_controls(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(
        ["analyze", "--framework", "iso27001", str(FIXTURES / "iso27001_plan.json")]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert (
        "| Risk | Actions | Resource | Type | Explanation | Controls |" in captured.out
    )
    assert "A.8.32" in captured.out


def test_cli_json_includes_controls_field(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(
        [
            "analyze",
            "--framework",
            "soc2",
            "--format",
            "json",
            str(FIXTURES / "soc2_plan.json"),
        ]
    )

    captured = capsys.readouterr()
    payload = _loads_json(captured.out)
    change = _change_by_address(payload, "aws_kms_key.customer_data")
    ids = {control["id"] for control in change["controls"]}
    assert exit_code == 0
    assert captured.err == ""
    assert payload["framework"] == {
        "name": "soc2",
        "version": "2017-tsc",
        "schema_version": 1,
    }
    assert ids == {"CC6.1", "CC6.7", "CC8.1", "A1.2", "C1.1"}


def test_cli_iso27001_json_framework_metadata(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(
        [
            "analyze",
            "--framework",
            "iso27001",
            "--format",
            "json",
            str(FIXTURES / "iso27001_plan.json"),
        ]
    )

    captured = capsys.readouterr()
    payload = _loads_json(captured.out)
    assert exit_code == 0
    assert payload["framework"] == {
        "name": "iso27001",
        "version": "2022",
        "schema_version": 1,
    }


def test_cli_default_output_unchanged(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["analyze", str(FIXTURES / "valid_plan.json")])
    markdown = capsys.readouterr()

    assert exit_code == 0
    assert markdown.err == ""
    assert "| Risk | Actions | Resource | Type | Explanation |" in markdown.out
    assert "Controls" not in markdown.out

    exit_code = main(["analyze", "--format", "json", str(FIXTURES / "valid_plan.json")])
    json_output = capsys.readouterr()
    payload = _loads_json(json_output.out)

    assert exit_code == 0
    assert json_output.err == ""
    assert "framework" not in payload
    assert all("controls" not in change for change in payload["changes"])


def test_cli_unknown_framework_errors(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(
        [
            "analyze",
            "--framework",
            "soc3",
            str(FIXTURES / "soc2_plan.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code != 0
    assert captured.out == ""
    assert "soc3" in captured.err
    assert "soc2" in captured.err
    assert "Traceback" not in captured.err


def test_cli_unknown_framework_lists_both(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(
        [
            "analyze",
            "--framework",
            "soc3",
            str(FIXTURES / "soc2_plan.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code != 0
    assert captured.err != ""
    assert "soc3" in captured.err
    assert "iso27001" in captured.err
    assert "soc2" in captured.err
    assert "Traceback" not in captured.err


def test_catalog_schema_error_on_missing_framework_key(tmp_path: Path) -> None:
    catalog = tmp_path / "missing-framework.yaml"
    catalog.write_text(
        """
framework_version: "1"
schema_version: 1
mappings: []
""".lstrip(),
        encoding="utf-8",
    )

    with pytest.raises(controls.CatalogSchemaError) as exc:
        controls._load_from_path(catalog)

    assert str(catalog) in str(exc.value)
    assert "framework" in str(exc.value)


def _loads_json(text: str) -> dict[str, Any]:
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise AssertionError("expected JSON object")
    return cast(dict[str, Any], payload)


def _change_by_address(payload: dict[str, Any], address: str) -> dict[str, Any]:
    changes = payload["changes"]
    if not isinstance(changes, list):
        raise AssertionError("expected changes list")
    for change in changes:
        if not isinstance(change, dict):
            raise AssertionError("expected change object")
        typed_change = cast(dict[str, Any], change)
        if typed_change["address"] == address:
            return typed_change
    raise AssertionError(f"missing change: {address}")
