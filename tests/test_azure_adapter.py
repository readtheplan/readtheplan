from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.azure import (
    AzureWhatIfAdapter,
    _type_from_resource_id,
    analyze_azure_whatif,
)
from readtheplan.cli import main
from readtheplan.mcp_server import MCPToolInputError, agent_gate_azure

FIXTURE = Path("tests/fixtures/azure_whatif_mixed.json")


def test_detects_full_resource_payloads_and_normalizes_types() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    adapter = detect_adapter(data)
    assert isinstance(adapter, AzureWhatIfAdapter)

    changes = adapter.analyze(data, use_rules=False)
    assert [change.resource_type for change in changes] == [
        "azurerm_storage_account",
        "azurerm_virtual_machine",
        "azurerm_role_assignment",
        "azurerm_kubernetes_cluster",
        "azurerm_deployments",
    ]
    assert [change.risk for change in changes] == [
        "safe",
        "review",
        "safe",
        "irreversible",
        "review",
    ]


def test_existing_azure_rules_receive_normalized_before_after() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    changes = AzureWhatIfAdapter().analyze(data, tool_name="Azure Resource Manager")
    vm = changes[1]
    role = changes[2]
    assert vm.risk == "dangerous"
    assert "size, zone, or license_type" in vm.explanation
    assert role.risk == "review"
    assert "role assignment" in role.explanation


def test_azure_security_rules_escalate_public_and_privileged_changes() -> None:
    data = {
        "changes": [
            {
                "resourceId": "/providers/Microsoft.Storage/storageAccounts/publicdata",
                "changeType": "Create",
                "after": {
                    "type": "Microsoft.Storage/storageAccounts",
                    "properties": {"allowBlobPublicAccess": True},
                },
            },
            {
                "resourceId": "/providers/Microsoft.Authorization/roleAssignments/owner",
                "changeType": "Create",
                "after": {
                    "type": "Microsoft.Authorization/roleAssignments",
                    "properties": {
                        "roleDefinitionId": (
                            "/providers/Microsoft.Authorization/roleDefinitions/"
                            "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
                        )
                    },
                },
            },
            {
                "resourceId": "/providers/Microsoft.Network/networkSecurityGroups/admin",
                "changeType": "Modify",
                "after": {
                    "type": "Microsoft.Network/networkSecurityGroups",
                    "properties": {
                        "securityRules": [
                            {
                                "properties": {
                                    "access": "Allow",
                                    "direction": "Inbound",
                                    "sourceAddressPrefix": "Internet",
                                    "destinationPortRange": "22",
                                }
                            }
                        ]
                    },
                },
            },
        ]
    }
    changes = AzureWhatIfAdapter().analyze(data, tool_name="Azure Resource Manager")
    assert [change.risk for change in changes] == ["dangerous"] * 3
    assert "blob public access" in changes[0].explanation
    assert "Owner, Contributor" in changes[1].explanation
    assert "internet-wide inbound" in changes[2].explanation


def test_resource_id_type_fallback_handles_child_resources() -> None:
    resource_id = (
        "/subscriptions/000/resourceGroups/rg/providers/Microsoft.Network/"
        "networkSecurityGroups/web/securityRules/https"
    )
    assert (
        _type_from_resource_id(resource_id)
        == "Microsoft.Network/networkSecurityGroups/securityRules"
    )
    adapter = AzureWhatIfAdapter()
    assert (
        adapter._normalize_resource_type(_type_from_resource_id(resource_id))
        == "azurerm_network_security_rule"
    )


def test_resource_id_only_and_potential_changes_require_review() -> None:
    resource_id_only = {
        "changes": [
            {
                "resourceId": "/subscriptions/000/providers/Microsoft.Storage/storageAccounts/logs",
                "changeType": "Deploy",
            }
        ]
    }
    deploy = AzureWhatIfAdapter().analyze(resource_id_only, use_rules=False)[0]
    assert deploy.risk == "review"
    assert "FullResourcePayloads" in deploy.explanation

    potential = {
        "potentialChanges": [
            {
                "resourceId": "/subscriptions/000/providers/Microsoft.Storage/storageAccounts/logs",
                "changeType": "Create",
            }
        ]
    }
    change = AzureWhatIfAdapter().analyze(potential, use_rules=False)[0]
    assert change.risk == "review"
    assert "potential change" in change.explanation


def test_empty_and_failed_whatif_results_are_recognized() -> None:
    empty = {"status": "Succeeded", "changes": [], "diagnostics": []}
    adapter = AzureWhatIfAdapter()
    assert adapter.can_handle(empty)
    assert analyze_azure_whatif(empty)["decision"] == "proceed"

    failed = {
        "status": "Failed",
        "error": {"code": "InvalidTemplate", "message": "Template validation failed."},
    }
    assert adapter.can_handle(failed)
    gate = analyze_azure_whatif(failed)
    assert gate["decision"] == "warn"
    assert gate["total_changes"] == 1


def test_gate_cli_and_mcp_contract(capsys) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    gate = analyze_azure_whatif(data)
    assert gate["schema"] == "rtp-agent-gate-v1"
    assert gate["adapter"] == "azure"
    assert gate["total_changes"] == 5
    assert gate["decision"] == "block"

    assert main(["azure", str(FIXTURE)]) == 2
    assert json.loads(capsys.readouterr().out)["adapter"] == "azure"

    mcp_gate = agent_gate_azure(str(FIXTURE), "soc2")
    assert mcp_gate["adapter"] == "azure"
    assert any("soc2 catalog" in item for item in mcp_gate["evidence_checklist"])


def test_cli_and_mcp_reject_unrelated_json(tmp_path, capsys) -> None:
    unrelated = tmp_path / "unrelated.json"
    unrelated.write_text('{"resources": []}', encoding="utf-8")
    assert main(["azure", str(unrelated)]) == 1
    assert "not recognized" in capsys.readouterr().err

    with pytest.raises(MCPToolInputError) as exc_info:
        agent_gate_azure(str(unrelated))
    assert exc_info.value.code == "INVALID_INPUT"
