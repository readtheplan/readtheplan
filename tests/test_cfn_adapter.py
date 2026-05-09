import json
import pytest
from pathlib import Path
from readtheplan.adapters.cloudformation import CloudFormationAdapter, analyze_cloudformation
from readtheplan.adapters import detect_adapter

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
