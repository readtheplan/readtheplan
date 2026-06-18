from __future__ import annotations

from typing import Any

from readtheplan.rules._shared import (
    RuleResult,
    _attribute_changed,
    _before_value,
    _major_version_changed,
)


def _gcp_compute_instance_candidates(
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []

    if "delete" in action_set and "create" in action_set:
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    "__TOOL__ will replace this Compute Engine instance. "
                    "Ephemeral disks, instance metadata, and internal IP "
                    "assignments will be recreated."
                ),
            )
        )
    elif "delete" in action_set:
        candidates.append(
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete this Compute Engine instance. "
                    "Confirm boot disk retention policy, snapshots, and "
                    "attached persistent disks before applying."
                ),
            )
        )
    elif "update" in action_set:
        # Check for destructive attribute changes
        if any(
            _attribute_changed(change, key)
            for key in ("machine_type", "zone", "can_ip_forward")
        ):
            candidates.append(
                RuleResult(
                    "dangerous",
                    (
                        "Compute Engine instance machine_type, zone, or "
                        "can_ip_forward is changing. Some of these changes "
                        "may force instance restart or replacement."
                    ),
                )
            )
        if _attribute_changed(change, "tags"):
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "Compute Engine instance tags are changing. "
                        "Network firewall rules depend on tag matching."
                    ),
                )
            )
        if not candidates:
            candidates.append(
                RuleResult(
                    "review",
                    (
                        "__TOOL__ will update this Compute Engine instance. "
                        "Review metadata, disk config, and network interface changes."
                    ),
                )
            )

    return candidates




def _gcp_container_cluster_candidates(
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []

    if "delete" in action_set and "create" in action_set:
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    "__TOOL__ will replace this GKE cluster. Expect "
                    "kubeconfig, node pools, and workload disruption "
                    "during the replacement process."
                ),
            )
        )
    elif "delete" in action_set:
        candidates.append(
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete this GKE cluster. All workloads, "
                    "PVs, and cluster-scoped resources are removed. "
                    "Ensure backups and workload migration are complete."
                ),
            )
        )
    elif "update" in action_set:
        candidates.append(
            RuleResult(
                "review",
                (
                    "__TOOL__ will update this GKE cluster. Review "
                    "version upgrades, node pool changes, networking, "
                    "and maintenance window settings."
                ),
            )
        )

    return candidates




def _gcp_sql_database_instance_candidates(
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []

    if "delete" in action_set and "create" in action_set:
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    "__TOOL__ will replace this Cloud SQL instance. "
                    "Connection name, IP addresses, and SSL certs "
                    "will change; applications must reconnect."
                ),
            )
        )
    elif "delete" in action_set:
        candidates.append(
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete this Cloud SQL instance. "
                    "Database contents are lost unless backups or "
                    "point-in-time recovery is configured."
                ),
            )
        )
    elif "update" in action_set:
        candidates.append(
            RuleResult(
                "review",
                (
                    "__TOOL__ will update this Cloud SQL instance. "
                    "Review tier, disk size, backup config, SSL mode, "
                    "and maintenance window changes."
                ),
            )
        )

    if _major_version_changed(change, "database_version"):
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    "Cloud SQL database_version appears to cross a major "
                    "version. Major version upgrades can be disruptive "
                    "and may not be reversible."
                ),
            )
        )

    return candidates




def _gcp_storage_bucket_candidates(
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []

    if "delete" in action_set:
        # GCS buckets can be deleted with force_destroy
        force_destroy = bool(_before_value(change, "force_destroy"))
        if force_destroy:
            candidates.append(
                RuleResult(
                    "irreversible",
                    (
                        "__TOOL__ will delete a GCS bucket with "
                        "force_destroy enabled. All objects in the "
                        "bucket will be irretrievably removed."
                    ),
                )
            )
        else:
            candidates.append(
                RuleResult(
                    "irreversible",
                    (
                        "__TOOL__ will delete a GCS bucket. "
                        "Confirm object versioning, lifecycle rules, "
                        "and replication settings before proceeding."
                    ),
                )
            )
    elif "update" in action_set:
        candidates.append(
            RuleResult(
                "review",
                (
                    "__TOOL__ will update a GCS bucket. Review IAM, "
                    "public access prevention, uniform bucket-level "
                    "access, retention, and encryption settings."
                ),
            )
        )
    elif "create" in action_set:
        candidates.append(
            RuleResult(
                "safe",
                (
                    "__TOOL__ will create a GCS bucket. Confirm "
                    "public access prevention, location, and "
                    "data classification before storing sensitive data."
                ),
            )
        )

    return candidates




def _gcp_compute_firewall_candidates(
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates: list[RuleResult] = []

    if "delete" in action_set and "create" in action_set:
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    "__TOOL__ will replace a Compute Engine firewall "
                    "rule. Traffic matching this rule will be disrupted "
                    "during the transition."
                ),
            )
        )
    elif "delete" in action_set:
        candidates.append(
            RuleResult(
                "irreversible",
                (
                    "__TOOL__ will delete a Compute Engine firewall "
                    "rule. Workloads that depend on this rule may "
                    "lose expected connectivity immediately."
                ),
            )
        )
    elif "update" in action_set or "create" in action_set:
        candidates.append(
            RuleResult(
                "review",
                (
                    "__TOOL__ will change a Compute Engine firewall "
                    "rule. Review source ranges, target tags, "
                    "protocols, and ports before applying."
                ),
            )
        )

    return candidates


# ---------------------------------------------------------------------------
# azurerm_* (Azure) provider rules
# ---------------------------------------------------------------------------


