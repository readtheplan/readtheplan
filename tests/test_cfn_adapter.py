import json
from pathlib import Path

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.cloudformation import CloudFormationAdapter, analyze_cloudformation


def test_cfn_adapter_can_handle_change_set():
    adapter = CloudFormationAdapter()
    data = {"Changes": [{"ResourceChange": {}}]}
    assert adapter.can_handle(data) is True

def test_cfn_adapter_can_handle_template_diff():
    adapter = CloudFormationAdapter()
    data = {"old_template": {}, "new_template": {}}
    assert adapter.can_handle(data) is True

def test_cfn_adapter_rejects_terraform_and_arbitrary_json():
    adapter = CloudFormationAdapter()
    assert adapter.can_handle({"resource_changes": []}) is False
    assert adapter.can_handle({"foo": "bar"}) is False

def test_cfn_adapter_normalization_add():
    adapter = CloudFormationAdapter()
    raw = {
        "Action": "Add",
        "LogicalResourceId": "MyBucket",
        "ResourceType": "AWS::S3::Bucket"
    }
    rc = adapter.normalize_change(raw)
    assert rc.address == "MyBucket"
    assert rc.resource_type == "aws_s3_bucket"
    assert rc.actions == ("create",)
    assert rc.risk == "safe"

def test_cfn_adapter_normalization_modify_replace():
    adapter = CloudFormationAdapter()
    raw = {
        "Action": "Modify",
        "LogicalResourceId": "MyKey",
        "ResourceType": "AWS::KMS::Key",
        "Replacement": "True"
    }
    rc = adapter.normalize_change(raw)
    assert rc.actions == ("delete", "create")
    assert rc.risk == "dangerous"

def test_cfn_adapter_normalization_modify_in_place():
    adapter = CloudFormationAdapter()
    raw = {
        "Action": "Modify",
        "LogicalResourceId": "MyDB",
        "ResourceType": "AWS::RDS::DBInstance",
        "Replacement": "False"
    }
    rc = adapter.normalize_change(raw)
    assert rc.actions == ("update",)
    assert rc.risk == "review"

def test_cfn_adapter_normalization_remove():
    adapter = CloudFormationAdapter()
    raw = {
        "Action": "Remove",
        "LogicalResourceId": "MyRole",
        "ResourceType": "AWS::IAM::Role"
    }
    rc = adapter.normalize_change(raw)
    assert rc.actions == ("delete",)
    assert rc.risk == "irreversible"

def test_cfn_adapter_resource_type_normalization():
    adapter = CloudFormationAdapter()
    assert adapter._normalize_resource_type("AWS::RDS::DBInstance") == "aws_db_instance"
    assert adapter._normalize_resource_type("AWS::S3::Bucket") == "aws_s3_bucket"

def test_analyze_cloudformation_integration():
    data = {
        "Changes": [
            {
                "ResourceChange": {
                    "Action": "Remove",
                    "LogicalResourceId": "MyDB",
                    "ResourceType": "AWS::RDS::DBInstance"
                }
            }
        ]
    }
    gate = analyze_cloudformation(data)
    assert gate["decision"] == "block"
    assert gate["risk"] == "irreversible"

def test_detect_adapter():
    data = {"Changes": [{"ResourceChange": {}}]}
    adapter = detect_adapter(data)
    assert isinstance(adapter, CloudFormationAdapter)

def test_template_diff_extraction():
    data = {
        "old_template": {"Resources": {"A": {"Type": "T"}}},
        "new_template": {"Resources": {"B": {"Type": "T"}}}
    }
    adapter = CloudFormationAdapter()
    changes = adapter.extract_changes(data)
    # A is removed, B is added
    actions = {c["Action"] for c in changes}
    assert "Add" in actions
    assert "Remove" in actions

def test_fixtures_mixed_gate_contract():
    fixture_path = Path("tests/fixtures/cfn_change_set_mixed.json")
    data = json.loads(fixture_path.read_text())
    gate = analyze_cloudformation(data)
    # Mixed has a Remove KMS -> irreversible -> block
    assert gate["decision"] == "block"
    assert gate["risk"] == "irreversible"

def test_cfn_adapter_normalization_import():
    adapter = CloudFormationAdapter()
    raw = {
        "Action": "Import",
        "LogicalResourceId": "MyBucket",
        "ResourceType": "AWS::S3::Bucket"
    }
    rc = adapter.normalize_change(raw)
    assert rc.risk == "review"
    assert rc.actions == ("update",)
    assert "ownership" in rc.explanation

def test_cfn_adapter_normalization_dynamic():
    adapter = CloudFormationAdapter()
    raw = {
        "Action": "Dynamic",
        "LogicalResourceId": "MyBucket",
        "ResourceType": "AWS::S3::Bucket"
    }
    rc = adapter.normalize_change(raw)
    assert rc.risk == "review"
    assert rc.actions == ("unknown",)

def test_cfn_adapter_normalization_conditional():
    adapter = CloudFormationAdapter()
    raw = {
        "Action": "Modify",
        "LogicalResourceId": "MyBucket",
        "ResourceType": "AWS::S3::Bucket",
        "Replacement": "Conditional"
    }
    rc = adapter.normalize_change(raw)
    assert rc.risk == "review"
    assert rc.actions == ("update",)

def test_cfn_adapter_normalization_unknown_action():
    adapter = CloudFormationAdapter()
    raw = {
        "Action": "SomethingElse",
        "LogicalResourceId": "MyBucket",
        "ResourceType": "AWS::S3::Bucket"
    }
    rc = adapter.normalize_change(raw)
    assert rc.risk == "review"

def test_cfn_adapter_physical_id_fallback():
    adapter = CloudFormationAdapter()
    raw = {
        "Action": "Remove",
        "PhysicalResourceId": "arn:aws:s3:::my-bucket",
        "ResourceType": "AWS::S3::Bucket"
    }
    rc = adapter.normalize_change(raw)
    assert rc.address == "arn:aws:s3:::my-bucket"

def test_type_map_coverage():
    adapter = CloudFormationAdapter()
    assert adapter._normalize_resource_type("AWS::EC2::Subnet") == "aws_subnet"
    assert adapter._normalize_resource_type("AWS::RDS::DBInstance") == "aws_db_instance"

def test_rules_escalation_fires():
    adapter = CloudFormationAdapter()
    raw = {
        "Action": "Remove",
        "LogicalResourceId": "MyDB",
        "ResourceType": "AWS::RDS::DBInstance"
    }
    # We need to use adapter.analyze to trigger _apply_resource_rules
    changes = adapter.analyze({"Changes": [{"ResourceChange": raw}]})
    rc = changes[0]
    assert rc.risk == "irreversible"
    assert "RDS" in rc.explanation

def test_analyze_cloudformation_required_checks():
    # For a block decision (Remove action), verify full agent-gate contract
    data = {
        "Changes": [
            {
                "ResourceChange": {
                    "Action": "Remove",
                    "LogicalResourceId": "MyDB",
                    "ResourceType": "AWS::RDS::DBInstance"
                }
            }
        ]
    }
    gate = analyze_cloudformation(data)
    assert gate["schema"] == "rtp-agent-gate-v1"
    assert gate["decision"] == "block"
    assert gate["risk"] == "irreversible"
    assert len(gate["required_checks"]) > 0
    assert "rtp.check.human_approval" in gate["required_checks"]
    assert "rtp.check.security_review" in gate["required_checks"]
    # Verify the full contract fields are present
    for key in (
        "allowed_next_actions", "prohibited_next_actions", "reason",
        "pr_comment", "evidence_checklist", "auditor_summary", "risk_counts",
        "adapter", "total_changes",
    ):
        assert key in gate, f"Missing agent-gate field: {key}"
    assert gate["adapter"] == "cloudformation"
    assert gate["total_changes"] == 1
    assert "rtp.check.human_approval" in gate["required_checks"]


def test_security_group_maps_correctly() -> None:
    """AWS::EC2::SecurityGroup must map to aws_security_group, not the
    naive fallback aws_ec2_securitygroup that bypasses security rules."""
    adapter = CloudFormationAdapter()
    assert adapter._normalize_resource_type("AWS::EC2::SecurityGroup") == "aws_security_group"
    assert adapter._normalize_resource_type("AWS::EC2::SecurityGroupIngress") == "aws_security_group_rule"  # noqa: E501
    assert adapter._normalize_resource_type("AWS::EC2::SecurityGroupEgress") == "aws_security_group_rule"  # noqa: E501


def test_all_type_map_values_match_rules_engine() -> None:
    """Every _TYPE_MAP value should be a key the rules engine recognises.

    Regression test for the original bug where unmapped CFN types fell
    through to the naive ``::`` -> ``_`` lower transform and produced
    type names that rules.py did not match (e.g. aws_ec2_securitygroup).
    """
    # Resource types the rules engine knows about (extracted from rules.py)
    rules_engine_types = {
        "aws_cloudwatch_event_rule", "aws_cloudwatch_event_target",
        "aws_cloudwatch_log_group", "aws_cloudwatch_metric_alarm",
        "aws_db_instance", "aws_ecr_lifecycle_policy",
        "aws_ecr_repository", "aws_ecr_repository_policy",
        "aws_ecs_service", "aws_eks_node_group",
        "aws_glue_catalog_database", "aws_glue_catalog_table",
        "aws_glue_job", "aws_iam_policy", "aws_iam_role",
        "aws_iam_role_policy", "aws_internet_gateway", "aws_kms_key",
        "aws_lambda_alias", "aws_lambda_event_source_mapping",
        "aws_lambda_function", "aws_lb", "aws_lb_listener",
        "aws_lb_listener_rule", "aws_lb_target_group",
        "aws_lb_target_group_attachment", "aws_nat_gateway",
        "aws_rds_cluster", "aws_route", "aws_route_table",
        "aws_route_table_association", "aws_security_group",
        "aws_security_group_rule", "aws_sqs_queue",
        "aws_sqs_queue_policy", "aws_subnet",
        "aws_vpc_security_group_egress_rule",
        "aws_vpc_security_group_ingress_rule",
    }
    # S3 and Route53 are in _TYPE_MAP but intentionally have no rules-engine
    # entry yet — they are handled as generic safe/create resources.
    intentionally_unmapped = {"aws_s3_bucket", "aws_route53_zone"}

    adapter = CloudFormationAdapter()
    for cfn_type, tf_type in adapter._TYPE_MAP.items():
        if tf_type in intentionally_unmapped:
            continue
        assert tf_type in rules_engine_types, (
            f"{cfn_type} -> {tf_type} is not a rules-engine type. "
            "This means the resource will bypass all security rules."
        )

