from __future__ import annotations

from typing import Any

from readtheplan.rules._shared import (
    RuleResult,
    _attribute_changed,
    register_rule,
)


@register_rule("azurerm_virtual_machine")
def _azurerm_virtual_machine_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []

    if "delete" in action_set and "create" in action_set:
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    "__TOOL__ will replace this Azure VM. OS disk, "
                    "data disks, NIC, and public IP may be recreated, "
                    "causing workload downtime."
                ),
            )
        )
    elif "delete" in action_set:
        candidates.append(
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete this Azure VM. Confirm OS "
                    "disk deletion policy, backup config, and any "
                    "attached managed disks before applying."
                ),
            )
        )
    elif "update" in action_set:
        if any(
            _attribute_changed(change, key)
            for key in ("vm_size", "zone", "license_type")
        ):
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "Azure VM size, zone, or license_type is "
                        "changing. This may force a restart or "
                        "replacement of the VM."
                    ),
                )
            )
        else:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "__TOOL__ will update this Azure VM. Review "
                        "OS profile, disk config, and NIC changes."
                    ),
                )
            )

    return candidates




@register_rule("azurerm_kubernetes_cluster")
def _azurerm_kubernetes_cluster_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []

    if "delete" in action_set and "create" in action_set:
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    "__TOOL__ will replace this AKS cluster. kubeconfig, "
                    "node pools, and all workloads will be recreated."
                ),
            )
        )
    elif "delete" in action_set:
        candidates.append(
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete this AKS cluster. All "
                    "workloads, PVs, and cluster-scoped resources "
                    "are removed. Confirm backup and migration."
                ),
            )
        )
    elif "update" in action_set:
        candidates.append(
            RuleResult(
                "review",
                (
                    "__TOOL__ will update this AKS cluster. Review "
                    "Kubernetes version upgrades, node pool scaling, "
                    "network profile, and maintenance settings."
                ),
            )
        )

    return candidates




@register_rule("azurerm_storage_account")
def _azurerm_storage_account_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []

    if "delete" in action_set and "create" in action_set:
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    "__TOOL__ will replace this storage account. "
                    "Primary and secondary endpoints, access keys, "
                    "and SAS tokens will change."
                ),
            )
        )
    elif "delete" in action_set:
        candidates.append(
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete this storage account. "
                    "All blobs, tables, queues, files, and share "
                    "snapshots will be removed."
                ),
            )
        )
    elif "update" in action_set:
        candidates.append(
            RuleResult(
                "review",
                (
                    "__TOOL__ will update this storage account. "
                    "Review network rules, encryption, blob soft "
                    "delete, and replication settings."
                ),
            )
        )

    return candidates




@register_rule("azurerm_role_assignment")
def _azurerm_role_assignment_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    if "delete" in action_set and "create" in action_set:
        return [
            RuleResult(
                "dangerous",
                (
                    "__TOOL__ will replace a role assignment. "
                    "Permissions for the assigned principal will "
                    "be removed and re-granted; verify scope and "
                    "role definition are correct."
                ),
            )
        ]
    if "delete" in action_set:
        return [
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete a role assignment. "
                    "The assigned principal will lose access to "
                    "the scope; confirm no workloads depend on it."
                ),
            )
        ]
    if "create" in action_set or "update" in action_set:
        return [
            RuleResult(
                "review",
                (
                    "__TOOL__ will change a role assignment. "
                    "Review role definition, scope, and principal "
                    "for privilege escalation or lockout risk."
                ),
            )
        ]
    return []




@register_rule("azurerm_network_security_group", "azurerm_network_security_rule")
def _azurerm_network_security_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []
    label = "NSG" if resource_type == "azurerm_network_security_group" else "NSG rule"

    if "delete" in action_set and "create" in action_set:
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    f"__TOOL__ will replace a {label}. Network "
                    "access for associated subnets or NICs may "
                    "be disrupted."
                ),
            )
        )
    elif "delete" in action_set:
        candidates.append(
            RuleResult(
                "irreversible",
                (
                    f"__TOOL__ will delete a {label}. Workloads "
                    "relying on this security rule may lose "
                    "expected network access."
                ),
            )
        )
    elif "update" in action_set or "create" in action_set:
        candidates.append(
            RuleResult(
                "review",
                (
                    f"__TOOL__ will change a {label}. Review "
                    "source/destination prefixes, port ranges, "
                    "and protocol before applying."
                ),
            )
        )

    return candidates


# ---------------------------------------------------------------------------
# kubernetes_* (K8s) provider rules
# ---------------------------------------------------------------------------


