from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange

_TYPE_MAP = {
    "microsoft.authorization/roleassignments": "azurerm_role_assignment",
    "microsoft.compute/virtualmachines": "azurerm_virtual_machine",
    "microsoft.containerregistry/registries": "azurerm_container_registry",
    "microsoft.containerservice/managedclusters": "azurerm_kubernetes_cluster",
    "microsoft.dbforpostgresql/flexibleservers": "azurerm_postgresql_flexible_server",
    "microsoft.keyvault/vaults": "azurerm_key_vault",
    "microsoft.network/loadbalancers": "azurerm_lb",
    "microsoft.network/networksecuritygroups": "azurerm_network_security_group",
    "microsoft.network/networksecuritygroups/securityrules": "azurerm_network_security_rule",
    "microsoft.network/publicipaddresses": "azurerm_public_ip",
    "microsoft.network/virtualnetworks": "azurerm_virtual_network",
    "microsoft.network/virtualnetworks/subnets": "azurerm_subnet",
    "microsoft.sql/servers/databases": "azurerm_mssql_database",
    "microsoft.storage/storageaccounts": "azurerm_storage_account",
    "microsoft.web/sites": "azurerm_app_service",
}


def _snake_case(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_").lower()


def _normalize_properties(value: Any) -> Any:
    if isinstance(value, dict):
        return {_snake_case(str(key)): _normalize_properties(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_properties(item) for item in value]
    return value


def _type_from_resource_id(resource_id: str) -> str:
    parts = [part for part in resource_id.strip("/").split("/") if part]
    try:
        provider_index = next(
            index for index, part in enumerate(parts) if part.lower() == "providers"
        )
    except StopIteration:
        return ""
    provider_parts = parts[provider_index + 1 :]
    if len(provider_parts) < 2:
        return ""
    namespace = provider_parts[0]
    resource_types = provider_parts[1::2]
    return "/".join([namespace, *resource_types])


def _rule_metadata(state: Any, resource_type: str) -> dict[str, Any]:
    normalized = _normalize_properties(state if isinstance(state, dict) else {})
    if not isinstance(normalized, dict):
        return {}
    properties = normalized.get("properties", {})
    if resource_type.lower() == "microsoft.compute/virtualmachines" and isinstance(
        properties, dict
    ):
        hardware = properties.get("hardware_profile", {})
        if isinstance(hardware, dict):
            normalized["vm_size"] = hardware.get("vm_size")
        normalized["license_type"] = properties.get("license_type")
        zones = normalized.get("zones")
        normalized["zone"] = zones[0] if isinstance(zones, list) and zones else None
    return normalized


class AzureWhatIfAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "azure"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        for field in ("changes", "potentialChanges"):
            items = input_data.get(field)
            if isinstance(items, list) and any(
                isinstance(item, dict)
                and "changeType" in item
                and "resourceId" in item
                for item in items
            ):
                return True
        has_result_list = any(
            field in input_data and isinstance(input_data.get(field), list)
            for field in ("changes", "potentialChanges", "diagnostics")
        )
        return isinstance(input_data.get("status"), str) and (
            has_result_list or isinstance(input_data.get("error"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for field, potential in (("changes", False), ("potentialChanges", True)):
            items = input_data.get(field, [])
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                resource_id = str(item.get("resourceId", ""))
                before = item.get("before", {})
                after = item.get("after", {})
                before_type = before.get("type") if isinstance(before, dict) else None
                after_type = after.get("type") if isinstance(after, dict) else None
                resource_type = str(
                    after_type or before_type or _type_from_resource_id(resource_id)
                )
                changes.append(
                    {
                        "changeType": item.get("changeType", "Unsupported"),
                        "resourceId": resource_id,
                        "resourceType": resource_type,
                        "potential": potential,
                        "delta": item.get("delta", []),
                        "_metadata": {
                            "before": _rule_metadata(before, resource_type),
                            "after": _rule_metadata(after, resource_type),
                        },
                    }
                )

        diagnostics = input_data.get("diagnostics", [])
        if isinstance(diagnostics, list):
            for index, diagnostic in enumerate(diagnostics):
                if not isinstance(diagnostic, dict):
                    continue
                message = str(
                    diagnostic.get("message")
                    or diagnostic.get("description")
                    or "Azure What-If could not fully evaluate part of the deployment."
                )
                changes.append(
                    {
                        "changeType": "Unsupported",
                        "resourceId": f"azure-what-if-diagnostic:{index + 1}",
                        "resourceType": "Microsoft.Resources/deployments",
                        "diagnostic": message,
                        "potential": True,
                        "_metadata": {},
                    }
                )
        error = input_data.get("error")
        if isinstance(error, dict):
            message = str(
                error.get("message")
                or error.get("code")
                or "Azure What-If failed before producing a complete result."
            )
            changes.append(
                {
                    "changeType": "Unsupported",
                    "resourceId": "azure-what-if-error",
                    "resourceType": "Microsoft.Resources/deployments",
                    "diagnostic": message,
                    "potential": True,
                    "_metadata": {},
                }
            )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        change_type = str(raw.get("changeType", "Unsupported")).lower()
        resource_type = str(raw.get("resourceType", ""))
        risk = "review"
        actions = ("unknown",)
        explanation = f"Azure What-If change '{change_type}' requires review."

        if change_type == "create":
            risk = "safe"
            actions = ("create",)
            explanation = "Azure Resource Manager will create this resource."
        elif change_type == "modify":
            actions = ("update",)
            explanation = "Azure Resource Manager will modify this resource."
        elif change_type == "delete":
            risk = "irreversible"
            actions = ("delete",)
            explanation = "Azure Resource Manager will delete this resource."
        elif change_type in {"ignore", "nochange"}:
            risk = "safe"
            actions = ("no-op",)
            explanation = f"Azure What-If reports '{change_type}' for this resource."
        elif change_type == "deploy":
            actions = ("update",)
            explanation = (
                "Azure What-If reports only that this resource will deploy. Generate "
                "FullResourcePayloads output for property-level review."
            )
        elif change_type == "unsupported":
            explanation = str(
                raw.get("diagnostic")
                or "Azure What-If could not evaluate this resource; manual review is required."
            )

        if raw.get("potential") and risk == "safe":
            risk = "review"
            explanation = (
                "Azure What-If lists this as a potential change that could not be fully "
                "resolved; manual review is required."
            )

        return ResourceChange(
            address=str(raw.get("resourceId") or "<unknown>"),
            resource_type=self._normalize_resource_type(resource_type),
            actions=actions,
            risk=risk,
            explanation=explanation,
        )

    def _normalize_resource_type(self, arm_type: str) -> str:
        normalized = arm_type.strip("/").lower()
        if normalized in _TYPE_MAP:
            return _TYPE_MAP[normalized]
        if not arm_type:
            return "unknown"
        token = arm_type.strip("/").split("/")[-1]
        return f"azurerm_{_snake_case(token)}"


def analyze_azure_whatif(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = AzureWhatIfAdapter().analyze(data, tool_name="Azure Resource Manager")
    summary = PlanSummary(
        path=Path("azure-what-if://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(
        summary,
        catalog=catalog,
        tool_name="Azure Resource Manager",
    )
    gate["adapter"] = "azure"
    gate["total_changes"] = len(changes)
    return gate
