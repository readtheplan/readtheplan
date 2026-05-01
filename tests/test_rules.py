from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from readtheplan.plan import analyze_plan_file
from readtheplan.rules import load_rule_overrides


def _write_plan(tmp_path: Path, resource_change: dict[str, Any]) -> Path:
    path = tmp_path / "plan.json"
    path.write_text(
        json.dumps(
            {
                "format_version": "1.2",
                "terraform_version": "1.6.6",
                "resource_changes": [resource_change],
            }
        ),
        encoding="utf-8",
    )
    return path


def _change(
    resource_type: str,
    actions: list[str],
    *,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
) -> dict[str, Any]:
    change: dict[str, Any] = {"actions": actions}
    if before is not None:
        change["before"] = before
    if after is not None:
        change["after"] = after
    return {
        "address": f"{resource_type}.example",
        "type": resource_type,
        "name": "example",
        "change": change,
    }


def _policy(statements: list[dict[str, Any]]) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def test_tier_a_resource_rules_add_explainers(tmp_path: Path) -> None:
    cases = [
        (
            _change("aws_db_instance", ["delete", "create"]),
            "dangerous",
            "RDS instance",
        ),
        (
            _change(
                "aws_rds_cluster",
                ["update"],
                before={"engine_version": "13.8"},
                after={"engine_version": "14.1"},
            ),
            "dangerous",
            "major version",
        ),
        (
            _change(
                "aws_s3_bucket",
                ["delete"],
                before={"force_destroy": True},
            ),
            "irreversible",
            "force_destroy",
        ),
        (
            _change(
                "aws_s3_bucket_policy",
                ["update"],
                before={"policy": _policy([])},
                after={
                    "policy": _policy(
                        [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]
                    )
                },
            ),
            "dangerous",
            "public access",
        ),
        (
            _change("aws_kms_key", ["delete"]),
            "irreversible",
            "KMS key",
        ),
        (
            _change(
                "aws_iam_role",
                ["update"],
                before={"assume_role_policy": _policy([])},
                after={
                    "assume_role_policy": _policy(
                        [{"Effect": "Allow", "Principal": {"AWS": "*"}}]
                    )
                },
            ),
            "dangerous",
            "trust policy",
        ),
        (
            _change("aws_route53_zone", ["delete"]),
            "irreversible",
            "Route53 hosted zone",
        ),
        (
            _change("aws_eks_node_group", ["delete", "create"]),
            "dangerous",
            "EKS node group",
        ),
    ]

    for resource_change, expected_risk, expected_explanation in cases:
        summary = analyze_plan_file(_write_plan(tmp_path, resource_change))
        change = summary.resource_changes[0]

        assert change.risk == expected_risk
        assert expected_explanation in change.explanation


def test_iam_removed_deny_escalates_to_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_iam_policy",
            ["update"],
            before={"policy": _policy([{"Effect": "Deny", "Action": "iam:*"}])},
            after={"policy": _policy([{"Effect": "Allow", "Action": "s3:GetObject"}])},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "dangerous"
    assert "remove deny statements" in summary.resource_changes[0].explanation


def test_resource_rules_can_be_disabled(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_rds_cluster",
            ["update"],
            before={"engine_version": "13.8"},
            after={"engine_version": "14.1"},
        ),
    )

    summary = analyze_plan_file(plan, use_rules=False)

    assert summary.resource_changes[0].risk == "review"
    assert "update this resource in place" in summary.resource_changes[0].explanation


def test_generic_resource_rules_cover_more_aws_blast_radius(tmp_path: Path) -> None:
    cases = [
        (_change("aws_dynamodb_table", ["delete"]), "irreversible", "point-in-time recovery"),
        (_change("aws_lb_listener", ["update"]), "dangerous", "load-balancing"),
        (_change("aws_api_gateway_stage", ["update"]), "dangerous", "API Gateway"),
        (_change("aws_security_group_rule", ["update"]), "review", "network access"),
    ]

    for resource_change, expected_risk, expected_text in cases:
        summary = analyze_plan_file(_write_plan(tmp_path, resource_change))
        change = summary.resource_changes[0]

        assert change.risk == expected_risk
        assert expected_text in change.explanation
        assert change.rule_id != "action-baseline"


def test_rule_overrides_match_tags_and_render_explanation(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lambda_function",
            ["update"],
            after={"tags": {"compliance": "pci"}},
        ),
    )
    overrides_path = tmp_path / "rules.json"
    overrides_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "pci-scope",
                        "risk": "dangerous",
                        "match": {"tags": {"compliance": "pci"}},
                        "explanation": "$address is in PCI scope.",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    summary = analyze_plan_file(plan, rule_overrides=load_rule_overrides(overrides_path))

    assert summary.risk_level == "dangerous"
    assert summary.resource_changes[0].rule_id == "pci-scope"
    assert summary.resource_changes[0].explanation == "aws_lambda_function.example is in PCI scope."
