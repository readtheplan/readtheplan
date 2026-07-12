from __future__ import annotations

from typing import Any

from readtheplan.rules._shared import RuleResult, register_rule


def _desired(change: dict[str, Any]) -> dict[str, Any]:
    after = change.get("after")
    return after if isinstance(after, dict) else {}


def _previous(change: dict[str, Any]) -> dict[str, Any]:
    before = change.get("before")
    return before if isinstance(before, dict) else {}


def _walk(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _walk(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _walk(item)


def _values(value: Any, *keys: str) -> list[Any]:
    expected = set(keys)
    return [item for key, item in _walk(value) if key in expected]


def _any_true(value: Any, *keys: str) -> bool:
    return any(item is True for item in _values(value, *keys))


def _any_false(value: Any, *keys: str) -> bool:
    return any(item is False for item in _values(value, *keys))


def _contains(value: Any, *needles: str) -> bool:
    expected = {needle.lower() for needle in needles}
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str) and item.lower() in expected:
            return True
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, (list, tuple, set)):
            pending.extend(item)
    return False


def _text_contains(value: Any, *needles: str) -> bool:
    expected = tuple(needle.lower() for needle in needles)
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str) and any(needle in item.lower() for needle in expected):
            return True
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, (list, tuple, set)):
            pending.extend(item)
    return False


def _label(resource_type: str) -> str:
    return resource_type.removeprefix("tfe_").replace("_", " ")


def _delete(label: str, action_set: set[str], consequence: str) -> RuleResult | None:
    if "delete" not in action_set:
        return None
    if "create" in action_set:
        return RuleResult(
            "dangerous",
            f"__TOOL__ will replace this HCP Terraform/TFE {label}. {consequence} Review stable "
            "identity, dependent runs/clients, migration order, rollback, and recovery.",
        )
    return RuleResult(
        "irreversible",
        f"__TOOL__ will delete this HCP Terraform/TFE {label}. {consequence} State, run history, "
        "tokens, registry artifacts, policy evidence, or access may not be recoverable.",
    )


_TFE_RESOURCES = (
    "tfe_admin_organization_settings",
    "tfe_admin_smtp_settings",
    "tfe_agent_pool",
    "tfe_agent_pool_allowed_projects",
    "tfe_agent_pool_allowed_workspaces",
    "tfe_agent_pool_excluded_workspaces",
    "tfe_agent_token",
    "tfe_audit_trail_token",
    "tfe_aws_oidc_configuration",
    "tfe_azure_oidc_configuration",
    "tfe_data_retention_policy",
    "tfe_gcp_oidc_configuration",
    "tfe_hyok_configuration",
    "tfe_no_code_module",
    "tfe_notification_configuration",
    "tfe_oauth_client",
    "tfe_opa_version",
    "tfe_org_max_token_ttl_policy",
    "tfe_organization",
    "tfe_organization_default_settings",
    "tfe_organization_membership",
    "tfe_organization_module_sharing",
    "tfe_organization_run_task",
    "tfe_organization_run_task_global_settings",
    "tfe_organization_token",
    "tfe_policy",
    "tfe_policy_set",
    "tfe_policy_set_parameter",
    "tfe_project",
    "tfe_project_notification_configuration",
    "tfe_project_oauth_client",
    "tfe_project_policy_set",
    "tfe_project_policy_set_exclusion",
    "tfe_project_settings",
    "tfe_project_variable_set",
    "tfe_provider_set",
    "tfe_registry_gpg_key",
    "tfe_registry_module",
    "tfe_registry_provider",
    "tfe_registry_provider_version",
    "tfe_registry_provider_version_platform",
    "tfe_run_trigger",
    "tfe_saml_settings",
    "tfe_scim_group_mapping",
    "tfe_scim_settings",
    "tfe_scim_token",
    "tfe_sentinel_policy",
    "tfe_sentinel_version",
    "tfe_ssh_key",
    "tfe_stack",
    "tfe_stack_variable_set",
    "tfe_team",
    "tfe_team_access",
    "tfe_team_member",
    "tfe_team_members",
    "tfe_team_notification_configuration",
    "tfe_team_organization_member",
    "tfe_team_organization_members",
    "tfe_team_project_access",
    "tfe_team_token",
    "tfe_terraform_version",
    "tfe_tfe_test_variable",
    "tfe_variable",
    "tfe_variable_set",
    "tfe_vault_oidc_configuration",
    "tfe_workspace",
    "tfe_workspace_policy_set",
    "tfe_workspace_policy_set_exclusion",
    "tfe_workspace_run",
    "tfe_workspace_run_task",
    "tfe_workspace_settings",
    "tfe_workspace_variable_set",
)


_TOKEN_RESOURCES = {
    "tfe_agent_token",
    "tfe_audit_trail_token",
    "tfe_organization_token",
    "tfe_scim_token",
    "tfe_team_token",
}

_VARIABLE_RESOURCES = {
    "tfe_policy_set_parameter",
    "tfe_stack_variable_set",
    "tfe_tfe_test_variable",
    "tfe_variable",
    "tfe_variable_set",
    "tfe_workspace_variable_set",
    "tfe_project_variable_set",
}

_IDENTITY_RESOURCES = {
    "tfe_organization_membership",
    "tfe_saml_settings",
    "tfe_scim_group_mapping",
    "tfe_scim_settings",
    "tfe_team",
    "tfe_team_access",
    "tfe_team_member",
    "tfe_team_members",
    "tfe_team_organization_member",
    "tfe_team_organization_members",
    "tfe_team_project_access",
}

_POLICY_RESOURCES = {
    "tfe_data_retention_policy",
    "tfe_opa_version",
    "tfe_org_max_token_ttl_policy",
    "tfe_policy",
    "tfe_policy_set",
    "tfe_project_policy_set",
    "tfe_project_policy_set_exclusion",
    "tfe_sentinel_policy",
    "tfe_sentinel_version",
    "tfe_workspace_policy_set",
    "tfe_workspace_policy_set_exclusion",
}

_WORKSPACE_RESOURCES = {
    "tfe_organization",
    "tfe_organization_default_settings",
    "tfe_project",
    "tfe_project_settings",
    "tfe_stack",
    "tfe_workspace",
    "tfe_workspace_settings",
}

_AGENT_RUN_RESOURCES = {
    "tfe_agent_pool",
    "tfe_agent_pool_allowed_projects",
    "tfe_agent_pool_allowed_workspaces",
    "tfe_agent_pool_excluded_workspaces",
    "tfe_organization_run_task",
    "tfe_organization_run_task_global_settings",
    "tfe_run_trigger",
    "tfe_workspace_run",
    "tfe_workspace_run_task",
}

_TRUST_RESOURCES = {
    "tfe_aws_oidc_configuration",
    "tfe_azure_oidc_configuration",
    "tfe_gcp_oidc_configuration",
    "tfe_oauth_client",
    "tfe_project_oauth_client",
    "tfe_ssh_key",
    "tfe_vault_oidc_configuration",
}

_REGISTRY_RESOURCES = {
    "tfe_no_code_module",
    "tfe_organization_module_sharing",
    "tfe_provider_set",
    "tfe_registry_gpg_key",
    "tfe_registry_module",
    "tfe_registry_provider",
    "tfe_registry_provider_version",
    "tfe_registry_provider_version_platform",
    "tfe_terraform_version",
}

_NOTIFICATION_RESOURCES = {
    "tfe_notification_configuration",
    "tfe_project_notification_configuration",
    "tfe_team_notification_configuration",
}

_ADMIN_RESOURCES = {
    "tfe_admin_organization_settings",
    "tfe_admin_smtp_settings",
    "tfe_hyok_configuration",
}


@register_rule(*_TFE_RESOURCES)
def _tfe_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = _label(resource_type)
    before = _previous(change)
    after = _desired(change)
    deleted = _delete(label, action_set, _delete_consequence(resource_type))
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []

    if resource_type in _TOKEN_RESOURCES:
        return [_token_result(label, resource_type, after)]
    if resource_type in _VARIABLE_RESOURCES:
        return [_variable_result(label, resource_type, after)]
    if resource_type in _IDENTITY_RESOURCES:
        return [_identity_result(label, resource_type, after)]
    if resource_type in _POLICY_RESOURCES:
        return [_policy_result(label, resource_type, after)]
    if resource_type in _WORKSPACE_RESOURCES:
        return [_workspace_result(label, resource_type, before, after)]
    if resource_type in _AGENT_RUN_RESOURCES:
        return [_agent_run_result(label, resource_type, after)]
    if resource_type in _TRUST_RESOURCES:
        return [_trust_result(label, resource_type, after)]
    if resource_type in _REGISTRY_RESOURCES:
        return [_registry_result(label, resource_type, after)]
    if resource_type in _NOTIFICATION_RESOURCES:
        return [_notification_result(label, resource_type, after)]
    if resource_type in _ADMIN_RESOURCES:
        return [_admin_result(label, resource_type, after)]
    return [
        RuleResult(
            "review",
            f"This HCP Terraform/TFE {label} change affects infrastructure governance. Review "
            "organization/project/workspace scope, identities, secrets in state, policy and run "
            "behavior, external trust, audit evidence, compatibility, and rollback.",
        )
    ]


def _delete_consequence(resource_type: str) -> str:
    if resource_type in _TOKEN_RESOURCES:
        return (
            "Credential revocation can immediately stop agents, automation, audit export, "
            "or API clients."
        )
    if resource_type in _VARIABLE_RESOURCES:
        return "Workspace, project, stack, policy, or variable-set inputs may disappear."
    if resource_type in _WORKSPACE_RESOURCES:
        return (
            "Remote state, runs, outputs, stack deployment state, or organization settings "
            "may be removed."
        )
    if resource_type in _POLICY_RESOURCES:
        return "Policy enforcement or historical governance evidence may be removed."
    return "The managed governance, execution, access, or supply-chain capability will be removed."


def _token_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses = ["persist a bearer credential in Terraform plan/state"]
    expiry = after.get("expired_at", after.get("expires_at"))
    if expiry in {None, ""}:
        weaknesses.append("create a token without a visible finite lifetime")
    return RuleResult(
        "dangerous",
        f"This HCP Terraform/TFE {label} change can {'; '.join(weaknesses)}. Treat state, saved "
        "plans, CI artifacts, logs, and backups as secret-bearing; review principal scope, expiry, "
        "rotation overlap, consumers, revocation order, and recovery.",
    )


def _variable_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    if after.get("value_wo") is not None and after.get("value") is None:
        weaknesses = ["send a write-only input value without persisting it to plan/state"]
    else:
        weaknesses = ["persist an input value in Terraform state"]
    key = str(after.get("key", after.get("name", ""))).lower()
    secret_key = any(
        token in key
        for token in ("secret", "token", "password", "private_key", "credential", "api_key")
    )
    if secret_key and after.get("sensitive") is not True:
        weaknesses.append("store a secret-like value without the sensitive flag")
    if after.get("sensitive") is True and after.get("value_wo") is None:
        weaknesses.append("handle a sensitive value whose plaintext remains in Terraform state")
    if _any_true(after, "hcl"):
        weaknesses.append("evaluate the value as HCL rather than a literal string")
    return RuleResult(
        "dangerous",
        f"This HCP Terraform/TFE {label} change can {'; '.join(weaknesses)}. Review variable "
        "precedence and scope, category, sensitivity, state/backend access, speculative-run "
        "exposure, HCL evaluation, rotation, consumers, and removal behavior.",
    )


def _identity_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if _contains(after, "owners", "admin", "*"):
        weaknesses.append("grant owner, administrative, or wildcard access")
    if _any_true(after, "manage_workspaces", "manage_policies", "manage_vcs_settings"):
        weaknesses.append("grant organization-level management capabilities")
    if _any_false(after, "enabled", "enforce", "two_factor_conformant"):
        weaknesses.append("disable an identity or federation guardrail")
    if resource_type in {"tfe_team_access", "tfe_team_project_access"}:
        weaknesses.append("change plan/apply/state/variable permissions for infrastructure")
    return RuleResult(
        "dangerous" if weaknesses else "review",
        f"This HCP Terraform/TFE {label} change affects organization identity, teams, SAML/SCIM, "
        "project/workspace access, or owner delegation"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review principal lifecycle, least privilege, two-factor/federation enforcement, "
        "owners-team access, workspace/project scope, break-glass access, and deprovisioning.",
    )


def _policy_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if _contains(after, "advisory", "soft-mandatory", "override", "*"):
        weaknesses.append("weaken enforcement or apply wildcard scope")
    if _any_true(after, "overridable", "global"):
        weaknesses.append("allow policy override or organization-wide attachment")
    if "exclusion" in resource_type:
        weaknesses.append("exclude a project or workspace from policy enforcement")
    if resource_type == "tfe_data_retention_policy":
        weaknesses.append("change retention or deletion of state, runs, and audit-relevant data")
    return RuleResult(
        "dangerous",
        f"This HCP Terraform/TFE {label} change affects Sentinel/OPA policy, policy-set "
        "attachment/exclusion, enforcement level, token TTL, or data retention"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review policy source and checksum, enforcement, overrides, global/project/workspace "
        "scope, exclusions, retention, test evidence, and rollback.",
    )


def _workspace_result(
    label: str,
    resource_type: str,
    before: dict[str, Any],
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if _any_true(
        after,
        "auto_apply",
        "auto_apply_run_trigger",
        "allow_destroy_plan",
        "global_remote_state",
        "force_delete",
    ):
        weaknesses.append("enable automatic apply, destroy, force deletion, or global state access")
    if _any_false(
        after,
        "speculative_enabled",
        "file_triggers_enabled",
        "structured_run_output_enabled",
    ):
        weaknesses.append("disable speculative validation, file triggers, or structured run output")
    if _contains(after, "local"):
        weaknesses.append("move execution outside managed remote/agent controls")
    if resource_type == "tfe_stack":
        weaknesses.append("change a beta multi-deployment stack and orchestration boundary")
    old_mode = before.get("execution_mode")
    new_mode = after.get("execution_mode")
    if old_mode not in {None, new_mode}:
        weaknesses.append(f"change execution mode from {old_mode} to {new_mode}")
    return RuleResult(
        "dangerous" if weaknesses else "review",
        f"This HCP Terraform/TFE {label} change affects an organization, project, workspace, "
        "stack, state, VCS trigger, or execution boundary"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review remote-state consumers, execution mode/agent pool, auto-apply and destroy, "
        "VCS branch/path triggers, Terraform version, queueing, state recovery, and cost.",
    )


def _agent_run_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if _contains(after, "*", "all", "mandatory"):
        weaknesses.append("grant wildcard execution scope or mandatory run-task control")
    if _any_true(after, "global", "apply", "auto_apply"):
        weaknesses.append("run globally or execute/apply infrastructure automatically")
    if resource_type in {
        "tfe_agent_pool_allowed_projects",
        "tfe_agent_pool_allowed_workspaces",
        "tfe_agent_pool_excluded_workspaces",
    }:
        weaknesses.append("change which infrastructure can execute on an agent pool")
    if resource_type in {"tfe_workspace_run", "tfe_run_trigger"}:
        weaknesses.append("initiate or chain infrastructure runs")
    if resource_type == "tfe_workspace_run" and _any_false(
        after, "manual_confirm", "wait_for_run"
    ):
        weaknesses.append("apply without human confirmation or return before run completion")
    if "run_task" in resource_type:
        weaknesses.append("send run data to an external enforcement/integration endpoint")
        if _text_contains(after, "http://"):
            weaknesses.append("send sensitive run data over plaintext HTTP")
        if not _values(after, "hmac_key", "hmac_key_wo"):
            weaknesses.append("send run data without a visible HMAC verification key")
    return RuleResult(
        "dangerous" if weaknesses else "review",
        f"This HCP Terraform/TFE {label} change affects agents, execution scope, run initiation, "
        "run triggers, or external run tasks"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review pool/workspace/project scope, agent trust, network and credentials, task "
        "endpoint/TLS, enforcement stage, payload exposure, run chaining, and rollback.",
    )


def _trust_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if _contains(after, "*", "all", "owners"):
        weaknesses.append("trust a wildcard audience, claim, repository, or owner scope")
    if _any_true(after, "service_account_email", "use_oidc"):
        weaknesses.append("enable workload identity federation")
    if _any_true(after, "ssl_skip_verify"):
        weaknesses.append("disable TLS verification")
    if _text_contains(after, "http://"):
        weaknesses.append("send VCS or federation traffic over plaintext HTTP")
    if _values(after, "oauth_token", "secret", "private_key"):
        weaknesses.append("persist VCS credentials in Terraform state")
    if resource_type == "tfe_ssh_key":
        if after.get("key_wo") is not None and after.get("key") is None:
            weaknesses.append("send a write-only VCS private key through Terraform")
        else:
            weaknesses.append("store a VCS private key in Terraform state")
    return RuleResult(
        "dangerous",
        f"This HCP Terraform/TFE {label} change affects VCS OAuth/SSH or AWS, Azure, GCP, Vault "
        "OIDC federation"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review issuer/audience/subject claims, cloud role and Vault policy, repository/org "
        "scope, private-key and client-secret state exposure, TLS, rotation, and revocation.",
    )


def _registry_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if _text_contains(after, "http://"):
        weaknesses.append("download executable infrastructure tooling over plaintext HTTP")
    if resource_type == "tfe_terraform_version" and not after.get("sha"):
        weaknesses.append("install a Terraform binary without a visible checksum")
    if resource_type == "tfe_cloud_plugin_installation":
        weaknesses.append("install executable plugin code")
    if _contains(after, "public", "latest", "*"):
        weaknesses.append("use public, latest, or wildcard supply-chain scope")
    return RuleResult(
        "dangerous" if weaknesses else "review",
        f"This HCP Terraform/TFE {label} change affects the module/provider registry, GPG trust, "
        "provider platforms, no-code modules, provider sets, or executable Terraform versions"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review source ownership, VCS trust, signatures/checksums, immutable versions, "
        "platform hashes, sharing scope, test configuration, provenance, and rollback.",
    )


def _notification_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if _text_contains(after, "http://"):
        weaknesses.append("send run or team events over plaintext HTTP")
    if _any_false(after, "enabled"):
        weaknesses.append("disable notification delivery")
    return RuleResult(
        "dangerous" if weaknesses else "review",
        f"This HCP Terraform/TFE {label} change sends organization, project, workspace, or team "
        "events to an external destination"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review destination ownership, signing/auth secret, TLS, event scope, sensitive run "
        "metadata, delivery tests, rate/noise, and rollback.",
    )


def _admin_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if _any_false(after, "enabled", "tls", "verify"):
        weaknesses.append("disable a platform-wide control or TLS verification")
    if resource_type == "tfe_hyok_configuration":
        weaknesses.append("change hold-your-own-key encryption and recovery trust")
    if resource_type == "tfe_admin_smtp_settings":
        weaknesses.append("change platform-wide mail delivery and credentials")
    return RuleResult(
        "dangerous",
        f"This HCP Terraform/TFE {label} change affects platform-wide organization, SMTP, or "
        "encryption administration"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review administrator ownership, TLS and credentials, encryption keys and recovery, "
        "default permissions, user impact, audit evidence, and rollback.",
    )
