from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from string import Template
from typing import Any


RISK_ORDER = {
    "safe": 0,
    "review": 1,
    "dangerous": 2,
    "irreversible": 3,
}


@dataclass(frozen=True)
class RuleResult:
    risk: str
    explanation: str
    rule_id: str = "resource-rule"


@dataclass(frozen=True)
class RuleOverride:
    id: str
    risk: str | None = None
    bump: int = 0
    explanation: str | None = None
    account_ids: tuple[str, ...] = ()
    tags: tuple[tuple[str, str], ...] = ()
    address_regex: str | None = None
    resource_types: tuple[str, ...] = ()


@dataclass(frozen=True)
class GenericResourceRule:
    id: str
    resource_types: tuple[str, ...]
    actions: tuple[str, ...]
    risk: str
    explanation: str


GENERIC_RESOURCE_RULES: tuple[GenericResourceRule, ...] = (
    GenericResourceRule(
        id="aws-network-access-change",
        resource_types=(
            "aws_security_group",
            "aws_security_group_rule",
            "aws_network_acl",
            "aws_network_acl_rule",
        ),
        actions=("update", "delete", "replace"),
        risk="review",
        explanation=(
            "$address changes network access controls. Review exposed ports, "
            "egress, and rule ordering before apply."
        ),
    ),
    GenericResourceRule(
        id="aws-ebs-volume-delete-or-replace",
        resource_types=("aws_ebs_volume",),
        actions=("delete", "replace"),
        risk="dangerous",
        explanation=(
            "$address removes or replaces an EBS volume. Confirm snapshots, "
            "attachments, and recovery steps."
        ),
    ),
    GenericResourceRule(
        id="aws-runtime-service-change",
        resource_types=("aws_lambda_function", "aws_ecs_service"),
        actions=("update", "delete", "replace"),
        risk="review",
        explanation=(
            "$address changes runtime service infrastructure. Review deployment, "
            "alias, traffic shifting, and rollback behavior."
        ),
    ),
    GenericResourceRule(
        id="aws-load-balancer-change",
        resource_types=(
            "aws_lb",
            "aws_alb",
            "aws_elb",
            "aws_lb_listener",
            "aws_lb_target_group",
        ),
        actions=("update", "delete", "replace"),
        risk="dangerous",
        explanation=(
            "$address changes load-balancing infrastructure. Review listener, "
            "target, health-check, and downtime impact."
        ),
    ),
    GenericResourceRule(
        id="aws-cloudfront-distribution-change",
        resource_types=("aws_cloudfront_distribution",),
        actions=("update", "delete", "replace"),
        risk="dangerous",
        explanation=(
            "$address changes a CloudFront distribution. Review cache behavior, "
            "origins, certificates, and global rollout timing."
        ),
    ),
    GenericResourceRule(
        id="aws-acm-certificate-change",
        resource_types=("aws_acm_certificate",),
        actions=("delete", "replace"),
        risk="review",
        explanation=(
            "$address changes a TLS certificate. Review validation, rotation "
            "timing, and listener attachments."
        ),
    ),
    GenericResourceRule(
        id="aws-secret-delete-or-replace",
        resource_types=("aws_secretsmanager_secret", "aws_ssm_parameter"),
        actions=("delete", "replace"),
        risk="dangerous",
        explanation=(
            "$address removes secret or parameter data. Confirm recovery window, "
            "rotation impact, and dependent service rollout."
        ),
    ),
    GenericResourceRule(
        id="aws-network-foundation-change",
        resource_types=("aws_vpc", "aws_subnet", "aws_nat_gateway"),
        actions=("delete", "replace"),
        risk="dangerous",
        explanation=(
            "$address changes foundational network infrastructure. Replacement "
            "can break routing for many dependent services."
        ),
    ),
    GenericResourceRule(
        id="aws-identity-pool-change",
        resource_types=("aws_cognito_user_pool", "aws_cognito_identity_pool"),
        actions=("update", "delete", "replace"),
        risk="review",
        explanation=(
            "$address changes authentication infrastructure. Review sign-in, "
            "token, and client compatibility impact."
        ),
    ),
    GenericResourceRule(
        id="aws-dynamodb-table-delete-or-replace",
        resource_types=("aws_dynamodb_table",),
        actions=("delete", "replace"),
        risk="irreversible",
        explanation=(
            "$address removes a DynamoDB table. Confirm point-in-time recovery, "
            "exports, and restore ownership before apply."
        ),
    ),
    GenericResourceRule(
        id="aws-cache-cluster-change",
        resource_types=("aws_elasticache_cluster", "aws_elasticache_replication_group"),
        actions=("delete", "replace"),
        risk="dangerous",
        explanation=(
            "$address changes cache infrastructure with outage or warmup impact. "
            "Review failover and client retry behavior."
        ),
    ),
    GenericResourceRule(
        id="aws-rds-parameter-group-change",
        resource_types=("aws_db_parameter_group", "aws_rds_cluster_parameter_group"),
        actions=("update", "delete", "replace"),
        risk="review",
        explanation=(
            "$address changes database parameters. Review apply timing, reboot "
            "requirements, and engine compatibility."
        ),
    ),
    GenericResourceRule(
        id="aws-workflow-and-event-change",
        resource_types=(
            "aws_sfn_state_machine",
            "aws_cloudwatch_event_rule",
            "aws_eventbridge_rule",
            "aws_sns_topic",
            "aws_sqs_queue",
        ),
        actions=("update", "delete", "replace"),
        risk="review",
        explanation=(
            "$address changes async workflow or event infrastructure. Review "
            "delivery, retries, dead letters, and downstream consumers."
        ),
    ),
    GenericResourceRule(
        id="aws-api-gateway-change",
        resource_types=(
            "aws_api_gateway_rest_api",
            "aws_api_gateway_stage",
            "aws_apigatewayv2_api",
            "aws_apigatewayv2_stage",
        ),
        actions=("update", "delete", "replace"),
        risk="dangerous",
        explanation=(
            "$address changes API Gateway infrastructure. Review routes, stages, "
            "authorizers, and client-facing downtime."
        ),
    ),
    GenericResourceRule(
        id="aws-streaming-data-change",
        resource_types=("aws_kinesis_stream", "aws_opensearch_domain"),
        actions=("update", "delete", "replace"),
        risk="dangerous",
        explanation=(
            "$address changes streaming or search data infrastructure. Review "
            "retention, shard/capacity changes, and restore path."
        ),
    ),
    GenericResourceRule(
        id="aws-iam-user-change",
        resource_types=("aws_iam_user", "aws_iam_access_key"),
        actions=("update", "delete", "replace"),
        risk="dangerous",
        explanation=(
            "$address changes IAM user or access key infrastructure. Review "
            "human access, service credentials, and break-glass paths."
        ),
    ),
)


def action_explanation(actions: tuple[str, ...]) -> str:
    if not actions:
        return "Terraform action metadata is missing or unknown; human review is required."
    action_set = set(actions)
    if "delete" in action_set and "create" in action_set:
        return (
            "Terraform will replace this resource. Review downtime, identity "
            "changes, and any state that must be migrated or restored."
        )
    if "delete" in action_set:
        return (
            "Terraform will delete this resource. Verify recovery, backups, and "
            "external dependencies before applying."
        )
    if "update" in action_set:
        return (
            "Terraform will update this resource in place. Review the changed "
            "attributes and rollout timing before applying."
        )
    if action_set <= {"no-op", "read"}:
        return "Terraform is only reading or refreshing this resource."
    if "create" in action_set:
        return "Terraform will create a new resource without changing existing state."
    return "Terraform action metadata is missing or unknown; human review is required."


def apply_resource_rules(
    *,
    address: str,
    resource_type: str,
    actions: tuple[str, ...],
    change: dict[str, Any],
    baseline: RuleResult,
    overrides: tuple[RuleOverride, ...] = (),
) -> RuleResult:
    result = baseline
    for candidate in _rule_candidates(address, resource_type, actions, change):
        result = _max_result(result, candidate)
    for override in overrides:
        if _override_matches(override, address, resource_type, change):
            result = _max_result(result, _override_result(override, result, address, resource_type, actions))
    return result


def _rule_candidates(
    address: str,
    resource_type: str,
    actions: tuple[str, ...],
    change: dict[str, Any],
) -> list[RuleResult]:
    action_set = set(actions)
    candidates: list[RuleResult] = []

    if resource_type in {"aws_db_instance", "aws_rds_cluster"}:
        candidates.extend(_rds_candidates(resource_type, action_set, change))
    if resource_type in {"aws_s3_bucket", "aws_s3_bucket_acl", "aws_s3_bucket_policy"}:
        candidates.extend(_s3_candidates(resource_type, action_set, change))
    if resource_type == "aws_kms_key":
        candidates.extend(_kms_candidates(action_set))
    if resource_type in {"aws_iam_role", "aws_iam_policy", "aws_iam_role_policy"}:
        candidates.extend(_iam_candidates(resource_type, action_set, change))
    if resource_type == "aws_route53_zone":
        candidates.extend(_route53_candidates(action_set))
    if resource_type == "aws_eks_node_group":
        candidates.extend(_eks_node_group_candidates(action_set))
    candidates.extend(_generic_candidates(address, resource_type, action_set))
    return candidates


def load_rule_overrides(path: str | Path) -> tuple[RuleOverride, ...]:
    override_path = Path(path)
    try:
        raw = override_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"could not read rule override file: {exc}") from exc

    try:
        if override_path.suffix.lower() == ".json":
            data = json.loads(raw)
        else:
            try:
                import yaml
            except ImportError as exc:
                raise ValueError(
                    "YAML rule override files require PyYAML; install readtheplan with YAML support"
                ) from exc
            data = yaml.safe_load(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON rule override file: {exc}") from exc
    except Exception as exc:
        if exc.__class__.__name__.endswith("YAMLError"):
            raise ValueError(f"invalid YAML rule override file: {exc}") from exc
        raise

    return parse_rule_overrides(data)


def parse_rule_overrides(data: Any) -> tuple[RuleOverride, ...]:
    if data is None:
        return ()
    if not isinstance(data, dict):
        raise ValueError("rule override file must contain an object at the top level")
    rules = data.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError("rule override field 'rules' must be a list")
    return tuple(_parse_override(item, index) for index, item in enumerate(rules, start=1))


def _parse_override(item: Any, index: int) -> RuleOverride:
    if not isinstance(item, dict):
        raise ValueError(f"rule override #{index} must be an object")
    rule_id = item.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise ValueError(f"rule override #{index} must have a non-empty id")

    risk = item.get("risk", item.get("tier"))
    if risk is not None and risk not in RISK_ORDER:
        raise ValueError(f"rule override {rule_id!r} has invalid risk {risk!r}")

    bump = item.get("bump", 0)
    if not isinstance(bump, int) or bump < 0:
        raise ValueError(f"rule override {rule_id!r} bump must be a non-negative integer")

    match = item.get("match", {})
    if not isinstance(match, dict):
        raise ValueError(f"rule override {rule_id!r} match must be an object")
    tags = match.get("tags") or {}
    if not isinstance(tags, dict):
        raise ValueError(f"rule override {rule_id!r} match.tags must be an object")

    return RuleOverride(
        id=rule_id,
        risk=risk,
        bump=bump,
        explanation=item.get("explanation"),
        account_ids=tuple(str(value) for value in match.get("account_ids", ()) or ()),
        tags=tuple((str(key), str(value)) for key, value in tags.items()),
        address_regex=match.get("address_regex"),
        resource_types=tuple(str(value) for value in match.get("resource_types", ()) or ()),
    )


def _rds_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = "RDS cluster" if resource_type == "aws_rds_cluster" else "RDS instance"
    candidates: list[RuleResult] = []
    if "create" in action_set and "delete" in action_set:
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    f"Terraform will replace this {label}. Confirm snapshots, "
                    "restore path, endpoint changes, and maintenance-window impact."
                ),
            )
        )
    elif "delete" in action_set:
        candidates.append(
            RuleResult(
                "irreversible",
                (
                    f"Terraform will delete this {label}. Without a verified final "
                    "snapshot or restore plan, database data may be lost."
                ),
            )
        )
    elif "update" in action_set:
        candidates.append(
            RuleResult(
                "review",
                (
                    f"Terraform will update this {label}. Check backup state, "
                    "maintenance windows, and whether the provider will force replacement."
                ),
            )
        )

    if _major_version_changed(change, "engine_version"):
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    f"The {label} engine_version appears to cross a major version. "
                    "Major database upgrades can be irreversible or require downtime."
                ),
            )
        )
    return candidates


def _s3_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []
    force_destroy = bool(_before_value(change, "force_destroy"))

    if "delete" in action_set:
        if force_destroy:
            candidates.append(
                RuleResult(
                    "irreversible",
                    (
                        "Terraform will delete an S3 bucket with force_destroy enabled. "
                        "Objects can be removed along with the bucket, making recovery unlikely."
                    ),
                )
            )
        else:
            candidates.append(
                RuleResult(
                    "irreversible",
                    (
                        "Terraform will delete an S3 bucket or bucket control resource. "
                        "Confirm object retention, replication, and recovery requirements."
                    ),
                )
            )
    elif "update" in action_set:
        candidates.append(
            RuleResult(
                "review",
                (
                    "Terraform will update S3 bucket controls. Review public access, "
                    "retention, encryption, and data exposure settings."
                ),
            )
        )
    elif "create" in action_set:
        candidates.append(
            RuleResult(
                "safe",
                (
                    "Terraform will create S3 bucket infrastructure. Confirm public "
                    "access blocks and data classification before storing sensitive data."
                ),
            )
        )

    if _s3_public_exposure(resource_type, change):
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    "This S3 change appears to allow public access through an ACL or "
                    "bucket policy. Public data exposure requires security review."
                ),
            )
        )
    return candidates


def _kms_candidates(action_set: set[str]) -> list[RuleResult]:
    if "create" in action_set and "delete" in action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "Terraform will replace a KMS key. Key identity changes can break "
                    "decrypt access for data and services that depend on the old key."
                ),
            )
        ]
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "Terraform will schedule deletion of a KMS key. Once the deletion "
                    "window completes, data encrypted only by that key cannot be decrypted."
                ),
            )
        ]
    if "update" in action_set:
        return [
            RuleResult(
                "review",
                (
                    "Terraform will update a KMS key. Review key policy, rotation, "
                    "deletion window, and service dependencies."
                ),
            )
        ]
    return []


def _iam_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []
    if "delete" in action_set:
        candidates.append(
            RuleResult(
                "irreversible",
                (
                    "Terraform will delete IAM authorization infrastructure. Confirm "
                    "no workloads, humans, or break-glass paths depend on it."
                ),
            )
        )
    elif "update" in action_set:
        candidates.append(
            RuleResult(
                "review",
                (
                    "Terraform will update IAM authorization. Review trust policies, "
                    "permission boundaries, and deny statements for lockout or escalation risk."
                ),
            )
        )

    if resource_type == "aws_iam_role" and _attribute_changed(
        change, "assume_role_policy"
    ):
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    "The IAM role trust policy is changing. A bad assume_role_policy "
                    "can lock out workloads or allow unintended principals to assume the role."
                ),
            )
        )

    policy_attr = "assume_role_policy" if resource_type == "aws_iam_role" else "policy"
    before_policy = _policy_document(_before_value(change, policy_attr))
    after_policy = _policy_document(_after_value(change, policy_attr))
    if before_policy is not None and after_policy is not None:
        if _has_deny_statement(before_policy) and not _has_deny_statement(after_policy):
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "This IAM policy change appears to remove deny statements. "
                        "Removing explicit denies can widen access even when allow rules look unchanged."
                    ),
                )
            )

    return candidates


def _route53_candidates(action_set: set[str]) -> list[RuleResult]:
    if "create" in action_set and "delete" in action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "Terraform will replace a Route53 hosted zone. Name server changes "
                    "can take production DNS offline until delegations and records are repaired."
                ),
            )
        ]
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "Terraform will delete a Route53 hosted zone. DNS for the zone can "
                    "go dark, and recreating it may produce different name servers."
                ),
            )
        ]
    if "update" in action_set:
        return [
            RuleResult(
                "review",
                (
                    "Terraform will update a Route53 hosted zone. Review delegation, "
                    "record ownership, and downstream DNS dependencies."
                ),
            )
        ]
    return []


def _eks_node_group_candidates(action_set: set[str]) -> list[RuleResult]:
    if "create" in action_set and "delete" in action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "Terraform will replace an EKS node group. Expect pod evictions, "
                    "capacity churn, and possible cluster disruption during rollout."
                ),
            )
        ]
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "Terraform will delete an EKS node group. Confirm replacement "
                    "capacity and disruption budgets before applying."
                ),
            )
        ]
    if "update" in action_set:
        return [
            RuleResult(
                "review",
                (
                    "Terraform will update an EKS node group. Review rollout settings, "
                    "surge capacity, labels, taints, and workload disruption budgets."
                ),
            )
        ]
    return []


def _generic_candidates(
    address: str,
    resource_type: str,
    action_set: set[str],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []
    for rule in GENERIC_RESOURCE_RULES:
        if resource_type not in rule.resource_types:
            continue
        if not _actions_match(rule.actions, action_set):
            continue
        candidates.append(
            RuleResult(
                risk=rule.risk,
                explanation=_render(
                    rule.explanation,
                    address=address,
                    resource_type=resource_type,
                    actions=tuple(action_set),
                    risk=rule.risk,
                    rule_id=rule.id,
                ),
                rule_id=rule.id,
            )
        )
    return candidates


def _actions_match(rule_actions: tuple[str, ...], action_set: set[str]) -> bool:
    if "replace" in rule_actions and {"delete", "create"}.issubset(action_set):
        return True
    return bool(action_set.intersection(rule_actions))


def _override_matches(
    override: RuleOverride,
    address: str,
    resource_type: str,
    change: dict[str, Any],
) -> bool:
    if override.resource_types and resource_type not in override.resource_types:
        return False
    if override.address_regex and not re.search(override.address_regex, address):
        return False
    if override.account_ids:
        account_id = _account_id(change)
        if account_id not in override.account_ids:
            return False
    if override.tags:
        tags = _tags(change)
        for key, value in override.tags:
            if str(tags.get(key)) != value:
                return False
    return bool(
        override.resource_types
        or override.address_regex
        or override.account_ids
        or override.tags
    )


def _override_result(
    override: RuleOverride,
    current: RuleResult,
    address: str,
    resource_type: str,
    actions: tuple[str, ...],
) -> RuleResult:
    risk = override.risk or _bump_risk(current.risk, override.bump)
    explanation = override.explanation or (
        "Organization rule $rule_id matched $address and set risk to $risk."
    )
    return RuleResult(
        risk=risk,
        explanation=_render(
            explanation,
            address=address,
            resource_type=resource_type,
            actions=actions,
            risk=risk,
            rule_id=override.id,
        ),
        rule_id=override.id,
    )


def _bump_risk(risk: str, bump: int) -> str:
    index = min(RISK_ORDER.get(risk, RISK_ORDER["review"]) + bump, len(RISK_ORDER) - 1)
    for tier, tier_index in RISK_ORDER.items():
        if tier_index == index:
            return tier
    return "review"


def _max_result(current: RuleResult, candidate: RuleResult) -> RuleResult:
    current_rank = RISK_ORDER.get(current.risk, RISK_ORDER["review"])
    candidate_rank = RISK_ORDER.get(candidate.risk, RISK_ORDER["review"])
    if candidate_rank >= current_rank:
        return candidate
    return current


def _before_value(change: dict[str, Any], key: str) -> Any:
    before = change.get("before")
    if isinstance(before, dict):
        return before.get(key)
    return None


def _after_value(change: dict[str, Any], key: str) -> Any:
    after = change.get("after")
    if isinstance(after, dict):
        return after.get(key)
    return None


def _render(
    template: str,
    *,
    address: str,
    resource_type: str,
    actions: tuple[str, ...],
    risk: str,
    rule_id: str,
) -> str:
    return Template(template).safe_substitute(
        {
            "address": address,
            "type": resource_type,
            "actions": "/".join(sorted(actions)) if actions else "unknown",
            "risk": risk,
            "rule_id": rule_id,
        }
    )


def _attribute_changed(change: dict[str, Any], key: str) -> bool:
    before = change.get("before")
    after = change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    return before.get(key) != after.get(key)


def _major_version_changed(change: dict[str, Any], key: str) -> bool:
    if not _attribute_changed(change, key):
        return False
    before_major = _major_version(_before_value(change, key))
    after_major = _major_version(_after_value(change, key))
    return before_major is not None and after_major is not None and after_major != before_major


def _major_version(value: Any) -> int | None:
    if value is None:
        return None
    match = re.match(r"^\s*(\d+)", str(value))
    if match is None:
        return None
    return int(match.group(1))


def _s3_public_exposure(resource_type: str, change: dict[str, Any]) -> bool:
    acl = _after_value(change, "acl")
    if isinstance(acl, str) and acl.lower() in {"public-read", "public-read-write"}:
        return True

    if resource_type == "aws_s3_bucket_policy" or _after_value(change, "policy"):
        policy = _policy_document(_after_value(change, "policy"))
        return policy is not None and _policy_allows_public(policy)
    return False


def _policy_document(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return None
        if isinstance(decoded, dict):
            return decoded
    return None


def _policy_allows_public(policy: dict[str, Any]) -> bool:
    return any(
        _statement_effect(statement) == "allow" and _principal_is_public(statement)
        for statement in _statements(policy)
    )


def _has_deny_statement(policy: dict[str, Any]) -> bool:
    return any(_statement_effect(statement) == "deny" for statement in _statements(policy))


def _statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    return [statement for statement in statements if isinstance(statement, dict)]


def _statement_effect(statement: dict[str, Any]) -> str:
    return str(statement.get("Effect", "")).lower()


def _principal_is_public(statement: dict[str, Any]) -> bool:
    principal = statement.get("Principal")
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any(_contains_public_principal(value) for value in principal.values())
    return False


def _contains_public_principal(value: Any) -> bool:
    if value == "*":
        return True
    if isinstance(value, list):
        return any(item == "*" for item in value)
    return False


def _account_id(change: dict[str, Any]) -> str | None:
    for source in (_after_mapping(change), _before_mapping(change)):
        for key in ("account_id", "account", "aws_account_id"):
            if key in source:
                return str(source[key])
    return None


def _tags(change: dict[str, Any]) -> dict[str, Any]:
    tags: dict[str, Any] = {}
    for source in (_before_mapping(change), _after_mapping(change)):
        for key in ("tags_all", "tags"):
            value = source.get(key)
            if isinstance(value, dict):
                tags.update(value)
    return tags


def _before_mapping(change: dict[str, Any]) -> dict[str, Any]:
    before = change.get("before")
    return before if isinstance(before, dict) else {}


def _after_mapping(change: dict[str, Any]) -> dict[str, Any]:
    after = change.get("after")
    return after if isinstance(after, dict) else {}
