from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from readtheplan.plan import analyze_plan_file


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


def test_lb_listener_default_action_change_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lb_listener",
            ["update"],
            before={"default_action": [{"type": "forward", "target_group_arn": "old"}]},
            after={"default_action": [{"type": "forward", "target_group_arn": "new"}]},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "dangerous"
    assert "default_action" in summary.resource_changes[0].explanation


def test_lb_listener_port_change_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lb_listener",
            ["update"],
            before={"port": 80, "protocol": "HTTP"},
            after={"port": 443, "protocol": "HTTPS"},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "dangerous"
    assert "port or protocol" in summary.resource_changes[0].explanation


def test_lb_scheme_change_is_irreversible(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lb",
            ["update"],
            before={"internal": True},
            after={"internal": False},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "irreversible"
    assert "scheme" in summary.resource_changes[0].explanation


def test_lb_target_group_health_check_change_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lb_target_group",
            ["update"],
            before={"health_check": {"interval": 30, "threshold": 3}},
            after={"health_check": {"interval": 5, "threshold": 2}},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "review"
    assert "health check" in summary.resource_changes[0].explanation


def test_lb_listener_rule_priority_change_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lb_listener_rule",
            ["update"],
            before={"priority": 100},
            after={"priority": 50},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "review"
    assert "priority" in summary.resource_changes[0].explanation


def test_lb_target_group_target_type_change_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lb_target_group",
            ["delete", "create"],
            before={"target_type": "instance"},
            after={"target_type": "ip"},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "dangerous"
    assert "target_type" in summary.resource_changes[0].explanation


def test_lb_delete_is_irreversible(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change("aws_lb", ["delete"]),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "irreversible"
    assert "delete this load balancer" in summary.resource_changes[0].explanation


def test_lambda_package_type_change_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lambda_function",
            ["update"],
            before={"package_type": "Zip"},
            after={"package_type": "Image"},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "dangerous"
    assert "package_type" in summary.resource_changes[0].explanation


def test_lambda_code_signing_change_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lambda_function",
            ["update"],
            before={"code_signing_config_arn": "arn:aws:lambda:us-east-1:123:csc/old"},
            after={"code_signing_config_arn": "arn:aws:lambda:us-east-1:123:csc/new"},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "review"
    assert "code_signing_config_arn" in summary.resource_changes[0].explanation


def test_lambda_vpc_config_change_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lambda_function",
            ["update"],
            before={"vpc_config": None},
            after={"vpc_config": {"subnet_ids": ["subnet-123"], "security_group_ids": ["sg-123"]}},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "review"
    assert "vpc_config" in summary.resource_changes[0].explanation


def test_lambda_runtime_major_change_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lambda_function",
            ["update"],
            before={"runtime": "nodejs20.x"},
            after={"runtime": "nodejs22.x"},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "review"
    assert "runtime" in summary.resource_changes[0].explanation


def test_lambda_role_change_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lambda_function",
            ["update"],
            before={"role": "arn:aws:iam::123:role/old"},
            after={"role": "arn:aws:iam::123:role/new"},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "review"
    assert "role" in summary.resource_changes[0].explanation


def test_lambda_runtime_minor_change_not_flagged(tmp_path: Path) -> None:
    """Same major runtime (python3.11 -> python3.12) should not trigger runtime rule."""
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_lambda_function",
            ["update"],
            before={"runtime": "python3.11"},
            after={"runtime": "python3.12"},
        ),
    )

    summary = analyze_plan_file(plan)

    # Should still be review from generic update, but not from runtime rule
    assert "runtime" not in summary.resource_changes[0].explanation


def test_platform_service_rules_cover_ecr_sqs_and_glue(tmp_path: Path) -> None:
    cases = [
        (
            _change("aws_ecr_repository", ["delete"]),
            "irreversible",
            "ECR repository",
        ),
        (
            _change(
                "aws_sqs_queue_policy",
                ["update"],
                before={"policy": _policy([])},
                after={
                    "policy": _policy(
                        [
                            {
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "sqs:SendMessage",
                            }
                        ]
                    )
                },
            ),
            "dangerous",
            "public access",
        ),
        (
            _change("aws_glue_job", ["delete"]),
            "irreversible",
            "Glue job",
        ),
    ]

    for resource_change, expected_risk, expected_explanation in cases:
        summary = analyze_plan_file(_write_plan(tmp_path, resource_change))
        change = summary.resource_changes[0]

        assert change.risk == expected_risk
        assert expected_explanation in change.explanation


def test_network_topology_route_to_internet_gateway_is_dangerous(
    tmp_path: Path,
) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_route",
            ["create"],
            after={
                "destination_cidr_block": "0.0.0.0/0",
                "gateway_id": "igw-example",
            },
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "dangerous"
    assert (
        "default route to an internet gateway"
        in summary.resource_changes[0].explanation
    )


def test_security_group_open_ingress_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_security_group",
            ["update"],
            before={
                "ingress": [
                    {
                        "from_port": 443,
                        "to_port": 443,
                        "protocol": "tcp",
                        "cidr_blocks": ["10.0.0.0/16"],
                    }
                ]
            },
            after={
                "ingress": [
                    {
                        "from_port": 443,
                        "to_port": 443,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0"],
                    }
                ]
            },
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "dangerous"
    assert "internet-wide access" in summary.resource_changes[0].explanation


def test_vpc_security_group_ingress_rule_open_ipv4_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_vpc_security_group_ingress_rule",
            ["create"],
            after={
                "from_port": 22,
                "to_port": 22,
                "ip_protocol": "tcp",
                "cidr_ipv4": "0.0.0.0/0",
            },
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "dangerous"
    assert "internet-wide access" in summary.resource_changes[0].explanation


def test_vpc_security_group_egress_rule_non_public_is_review(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_vpc_security_group_egress_rule",
            ["update"],
            before={"cidr_ipv4": "10.0.0.0/16"},
            after={"cidr_ipv4": "172.16.0.0/12"},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "review"
    assert "change security group rules" in summary.resource_changes[0].explanation


def test_cloudwatch_log_group_retention_decrease_is_dangerous(tmp_path: Path) -> None:
    plan = _write_plan(
        tmp_path,
        _change(
            "aws_cloudwatch_log_group",
            ["update"],
            before={"retention_in_days": 365},
            after={"retention_in_days": 30},
        ),
    )

    summary = analyze_plan_file(plan)

    assert summary.resource_changes[0].risk == "dangerous"
    assert "retention is decreasing" in summary.resource_changes[0].explanation


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
