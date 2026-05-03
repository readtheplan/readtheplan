from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan import controls, overlays
from readtheplan.cli import main
from readtheplan.plan import ResourceChange

FIXTURES = Path(__file__).parent / "fixtures"


def test_overlay_loads_with_v1_schema() -> None:
    overlay = overlays.load_overlay(FIXTURES / "overlay_example.yaml")

    assert overlay.schema == overlays.OVERLAY_SCHEMA
    assert overlay.name == "acme-prod-overlay"
    assert len(overlay.risk_overrides) == 3
    assert overlay.control_additions is not None
    assert overlay.control_additions["framework"] == "soc2"


def test_overlay_rejects_unknown_schema(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        """
schema: rtp-overlay-v2
name: bad
description: wrong schema
""".lstrip(),
        encoding="utf-8",
    )

    with pytest.raises(overlays.OverlayError) as exc:
        overlays.load_overlay(path)

    assert "rtp-overlay-v1" in str(exc.value)


def test_overlay_rejects_missing_required_field(tmp_path: Path) -> None:
    path = tmp_path / "missing.yaml"
    path.write_text(
        """
schema: rtp-overlay-v1
description: missing name
""".lstrip(),
        encoding="utf-8",
    )

    with pytest.raises(overlays.OverlayError) as exc:
        overlays.load_overlay(path)

    assert "$.name" in str(exc.value)


def test_risk_override_match_resource_type() -> None:
    overlay = overlays.load_overlay(FIXTURES / "overlay_example.yaml")
    change = _change(
        address="aws_lambda_function.handler",
        resource_type="aws_lambda_function",
        risk="safe",
    )

    out = overlays.apply_overlay_to_change(change, overlay)

    assert out.risk == "review"
    assert "app owner review" in out.explanation


def test_risk_override_match_address_prefix() -> None:
    overlay = overlays.load_overlay(FIXTURES / "overlay_example.yaml")
    change = _change(
        address="aws_kms_key.customer_data",
        resource_type="aws_kms_key",
        risk="dangerous",
    )

    out = overlays.apply_overlay_to_change(change, overlay)

    assert out.risk == "irreversible"
    assert "CISO sign-off" in out.explanation


def test_risk_override_match_account_id() -> None:
    overlay = overlays.load_overlay(FIXTURES / "overlay_example.yaml")
    change = _change(
        address="aws_cloudwatch_log_group.app",
        resource_type="aws_cloudwatch_log_group",
        risk="safe",
    )

    out = overlays.apply_overlay_to_change(
        change,
        overlay,
        plan_account_id="1234567890",
    )

    assert out.risk == "review"
    assert "Sandbox account" in out.explanation


def test_risk_override_does_not_downgrade() -> None:
    overlay = overlays.Overlay(
        schema=overlays.OVERLAY_SCHEMA,
        name="downgrade",
        description="attempt downgrade",
        risk_overrides=(
            overlays.RiskOverride(
                match={"resource_type": "aws_kms_key"},
                risk="safe",
                explanation="Should not lower risk.",
            ),
        ),
        control_additions=None,
    )
    change = _change(
        address="aws_kms_key.customer_data",
        resource_type="aws_kms_key",
        risk="dangerous",
    )

    out = overlays.apply_overlay_to_change(change, overlay)

    assert out == change


def test_control_addition_appends_to_catalog() -> None:
    overlay = overlays.load_overlay(FIXTURES / "overlay_example.yaml")
    catalog = controls.load_catalog("soc2")

    out = overlays.apply_overlay_to_catalog(catalog, overlay)

    assert (
        catalog.controls_for(
            resource_type="aws_lambda_function",
            actions=["update"],
        )
        == ()
    )
    assert [
        control.id
        for control in out.controls_for(
            resource_type="aws_lambda_function",
            actions=["update"],
        )
    ] == ["CC6.1"]


def test_multiple_overlays_apply_in_order(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    first = tmp_path / "first.yaml"
    second = tmp_path / "second.yaml"
    plan = tmp_path / "plan.json"
    first.write_text(
        """
schema: rtp-overlay-v1
name: first
description: first overlay
risk_overrides:
  - match:
      resource_type: aws_cloudwatch_log_group
    risk: review
    explanation: First overlay review.
""".lstrip(),
        encoding="utf-8",
    )
    second.write_text(
        """
schema: rtp-overlay-v1
name: second
description: second overlay
risk_overrides:
  - match:
      address_prefix: aws_cloudwatch_log_group.app
    risk: dangerous
    explanation: Second overlay escalation.
""".lstrip(),
        encoding="utf-8",
    )
    plan.write_text(
        json.dumps(
            {
                "format_version": "1.2",
                "resource_changes": [
                    {
                        "address": "aws_cloudwatch_log_group.app",
                        "type": "aws_cloudwatch_log_group",
                        "change": {"actions": ["create"]},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "analyze",
            "--format",
            "json",
            "--rules-file",
            str(first),
            "--rules-file",
            str(second),
            str(plan),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    change = payload["changes"][0]
    assert exit_code == 0
    assert change["risk"] == "dangerous"
    assert "First overlay review" in change["explanation"]
    assert "Second overlay escalation" in change["explanation"]


def test_cli_rules_file_integration(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(
        [
            "analyze",
            "--framework",
            "soc2",
            "--rules-file",
            str(FIXTURES / "overlay_example.yaml"),
            str(FIXTURES / "soc2_plan.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert "aws_lambda_function.handler" in captured.out
    assert "app owner review" in captured.out
    assert "CC6.1" in captured.out


def _change(
    *,
    address: str,
    resource_type: str,
    risk: str,
) -> ResourceChange:
    return ResourceChange(
        address=address,
        resource_type=resource_type,
        actions=("create",),
        risk=risk,
        explanation="Built-in explanation.",
    )
