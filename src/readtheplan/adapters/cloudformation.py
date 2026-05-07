from __future__ import annotations

from typing import Any

from readtheplan.adapters.base import BaseAdapter, GateDecision
from readtheplan.plan import ResourceChange


class CloudFormationAdapter(BaseAdapter):
    _TYPE_MAP = {
        "AWS::RDS::DBInstance": "aws_db_instance",
        "AWS::RDS::DBCluster": "aws_rds_cluster",
        "AWS::S3::Bucket": "aws_s3_bucket",
        "AWS::KMS::Key": "aws_kms_key",
        "AWS::IAM::Role": "aws_iam_role",
        "AWS::IAM::Policy": "aws_iam_policy",
        "AWS::Route53::HostedZone": "aws_route53_zone",
        "AWS::EKS::Nodegroup": "aws_eks_node_group",
        "AWS::ElasticLoadBalancingV2::LoadBalancer": "aws_lb",
        "AWS::ElasticLoadBalancingV2::Listener": "aws_lb_listener",
        "AWS::ElasticLoadBalancingV2::ListenerRule": "aws_lb_listener_rule",
        "AWS::ElasticLoadBalancingV2::TargetGroup": "aws_lb_target_group",
        "AWS::Lambda::Function": "aws_lambda_function",
        "AWS::Lambda::Alias": "aws_lambda_alias",
        "AWS::ECR::Repository": "aws_ecr_repository",
        "AWS::SQS::Queue": "aws_sqs_queue",
        "AWS::Glue::Database": "aws_glue_catalog_database",
        "AWS::Glue::Table": "aws_glue_catalog_table",
        "AWS::Glue::Job": "aws_glue_job",
        "AWS::EC2::Subnet": "aws_subnet",
        "AWS::EC2::RouteTable": "aws_route_table",
        "AWS::EC2::Route": "aws_route",
        "AWS::EC2::NatGateway": "aws_nat_gateway",
        "AWS::EC2::InternetGateway": "aws_internet_gateway",
        "AWS::CloudWatch::Alarm": "aws_cloudwatch_metric_alarm",
        "AWS::Events::Rule": "aws_cloudwatch_event_rule",
        "AWS::CloudWatch::LogGroup": "aws_cloudwatch_log_group",
    }

    @property
    def adapter_name(self) -> str:
        return "cloudformation"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        # Check for Change Set format
        if "Changes" in input_data and isinstance(input_data["Changes"], list):
            for change in input_data["Changes"]:
                if "ResourceChange" in change:
                    return True
        
        # Check for Template Diff format
        if "old_template" in input_data and "new_template" in input_data:
            return True
            
        return False

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        if "Changes" in input_data:
            return self._extract_from_change_set(input_data)
        elif "old_template" in input_data:
            return self._extract_from_template_diff(input_data)
        return []

    def _extract_from_change_set(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        changes = []
        for item in data.get("Changes", []):
            rc = item.get("ResourceChange")
            if rc:
                changes.append(rc)
        return changes

    def _extract_from_template_diff(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        old_resources = data.get("old_template", {}).get("Resources", {})
        new_resources = data.get("new_template", {}).get("Resources", {})
        
        changes = []
        
        # Added resources
        for logical_id, resource in new_resources.items():
            if logical_id not in old_resources:
                changes.append({
                    "Action": "Add",
                    "LogicalResourceId": logical_id,
                    "ResourceType": resource.get("Type"),
                    "Replacement": "False"
                })
            elif old_resources[logical_id] != resource:
                # Modified resources
                changes.append({
                    "Action": "Modify",
                    "LogicalResourceId": logical_id,
                    "ResourceType": resource.get("Type"),
                    "Replacement": "Conditional", # Default for template diff
                    "_metadata": {"details": "Template properties changed"}
                })
        
        # Removed resources
        for logical_id, resource in old_resources.items():
            if logical_id not in new_resources:
                changes.append({
                    "Action": "Remove",
                    "LogicalResourceId": logical_id,
                    "ResourceType": resource.get("Type"),
                    "Replacement": "False"
                })
                
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        action = raw.get("Action", "Unknown")
        replacement = str(raw.get("Replacement", "False"))
        resource_type = raw.get("ResourceType", "Unknown")
        logical_id = raw.get("LogicalResourceId")
        physical_id = raw.get("PhysicalResourceId")
        address = logical_id or physical_id or "<unknown>"

        # Mapping table per brief
        risk = "review"
        actions = ("unknown",)
        explanation = f"CloudFormation action '{action}' requires review."

        if action == "Add":
            risk = "safe"
            actions = ("create",)
            explanation = "CloudFormation will create this resource."
        elif action == "Modify":
            if replacement == "True":
                risk = "dangerous"
                actions = ("delete", "create")
                explanation = "CloudFormation will replace this resource (destroy and recreate)."
            elif replacement == "Conditional":
                risk = "review"
                actions = ("update",)
                explanation = "CloudFormation may replace this resource depending on runtime evaluation. Review replacement conditions before applying."
            else:
                risk = "review"
                actions = ("update",)
                explanation = "CloudFormation will update this resource in place."
        elif action == "Remove":
            risk = "irreversible"
            actions = ("delete",)
            explanation = "CloudFormation will delete this resource."
        elif action == "Import":
            risk = "safe"
            actions = ("no-op",)
            explanation = "CloudFormation will import this existing resource into the stack."
        elif action == "Dynamic":
            risk = "review"
            actions = ("unknown",)
            explanation = "CloudFormation will determine the change at runtime."

        normalized_type = self._normalize_resource_type(resource_type)
        
        return ResourceChange(
            address=address,
            resource_type=normalized_type,
            actions=actions,
            risk=risk,
            explanation=explanation
        )

    def _normalize_resource_type(self, cfn_type: str) -> str:
        # Check explicit mapping first
        if cfn_type in self._TYPE_MAP:
            return self._TYPE_MAP[cfn_type]
            
        # Fallback to old transform: AWS::RDS::DBInstance -> aws_rds_dbinstance
        if not cfn_type or not isinstance(cfn_type, str):
            return "unknown"
        return cfn_type.replace("::", "_").lower()


def analyze_cloudformation(data: dict[str, Any]) -> GateDecision:
    from readtheplan.agent_gate import _decision_for_risk
    from readtheplan.rules import RISK_ORDER
    
    adapter = CloudFormationAdapter()
    changes = adapter.analyze(data)
    
    if not changes:
        max_risk = "safe"
    else:
        max_risk = max(
            (c.risk for c in changes),
            key=lambda r: RISK_ORDER.get(r, 1)
        )
    
    decision = _decision_for_risk(max_risk)
    reason = f"CloudFormation analysis completed with maximum risk: {max_risk}. Total changes: {len(changes)}"
    
    required_checks = []
    if decision == "block":
        required_checks = [
            "rtp.check.human_approval",
            "rtp.check.security_review",
            "rtp.check.change_record",
            "rtp.check.evidence_packet"
        ]
    elif decision == "warn":
        required_checks = ["rtp.check.peer_review", "rtp.check.change_evidence"]

    return GateDecision(
        decision=decision,
        risk=max_risk,
        reason=reason,
        required_checks=required_checks
    )
