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


def _values(value: Any, key: str) -> list[Any]:
    return [item for candidate, item in _walk(value) if candidate == key]


def _contains_value(value: Any, *needles: str) -> bool:
    expected = {needle.lower() for needle in needles}
    for _key, item in _walk(value):
        if isinstance(item, str) and item.lower() in expected:
            return True
        if isinstance(item, (list, tuple, set)) and any(
            isinstance(entry, str) and entry.lower() in expected for entry in item
        ):
            return True
    return False


def _any_true(value: Any, *keys: str) -> bool:
    return any(item is True for key in keys for item in _values(value, key))


def _any_false(value: Any, *keys: str) -> bool:
    return any(item is False for key in keys for item in _values(value, key))


def _delete(label: str, action_set: set[str], consequence: str) -> RuleResult | None:
    if "delete" not in action_set:
        return None
    if "create" in action_set:
        return RuleResult(
            "dangerous",
            f"__TOOL__ will replace this GitLab {label}. {consequence} Review identity, "
            "dependencies, migration order, rollback, and recovery before applying.",
        )
    return RuleResult(
        "irreversible",
        f"__TOOL__ will delete this GitLab {label}. {consequence} Confirm ownership, "
        "exports or recovery, dependent automation, and an explicit rollback path.",
    )


_LIFECYCLE_RESOURCES = (
    "gitlab_project",
    "gitlab_group",
)


@register_rule(*_LIFECYCLE_RESOURCES)
def _gitlab_lifecycle_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = "project" if resource_type == "gitlab_project" else "group"
    before = _previous(change)
    after = _desired(change)
    if "delete" in action_set:
        archive = before.get("archive_on_destroy") is True
        permanently_delete = before.get("permanently_delete_on_destroy") is True or before.get(
            "permanently_remove_on_delete"
        ) is True
        consequence = (
            "The namespace is configured for immediate permanent removal, including source, "
            "artifacts, issues, packages, settings, and automation."
            if permanently_delete
            else "Source, artifacts, issues, packages, settings, and automation may be lost."
        )
        deleted = _delete(label, action_set, consequence)
        if archive and deleted and "create" not in action_set:
            return [
                RuleResult(
                    "irreversible",
                    f"__TOOL__ will remove this GitLab {label} from Terraform and archive it "
                    "instead of deleting it. Verify clone/export recovery, namespace ownership, "
                    "and dependent automation before applying.",
                )
            ]
        return [deleted] if deleted else []
    if not ({"create", "update"} & action_set):
        return []

    weaknesses: list[str] = []
    visibility = str(after.get("visibility_level", "")).lower()
    if visibility == "public":
        weaknesses.append(f"publish the {label} to the public Internet")
    if before.get("visibility_level") not in {None, visibility}:
        weaknesses.append("change the namespace visibility boundary")
    if after.get("archived") is True:
        weaknesses.append(f"archive the {label}")
    if after.get("permanently_delete_on_destroy") is True or after.get(
        "permanently_remove_on_delete"
    ) is True:
        weaknesses.append("enable permanent deletion on destroy")
    if after.get("prevent_forking_outside_group") is False and resource_type == "gitlab_group":
        weaknesses.append("allow projects to be forked outside the group")
    if (
        after.get("prevent_sharing_groups_outside_hierarchy") is False
        and resource_type == "gitlab_group"
    ):
        weaknesses.append("allow sharing outside the group hierarchy")
    if after.get("require_two_factor_authentication") is False and resource_type == "gitlab_group":
        weaknesses.append("disable group two-factor authentication enforcement")
    if resource_type == "gitlab_group" and str(
        after.get("shared_runners_setting", "")
    ).lower() in {"enabled", "disabled_with_override", "disabled_and_overridable"}:
        weaknesses.append("allow shared runners or subgroup overrides")
    if resource_type == "gitlab_project":
        if after.get("allow_merge_on_skipped_pipeline") is True:
            weaknesses.append("treat skipped pipelines as successful for merge")
        if after.get("allow_pipeline_trigger_approve_deployment") is True:
            weaknesses.append("allow a pipeline triggerer to approve deployments")
        if after.get("only_allow_merge_if_pipeline_succeeds") is False:
            weaknesses.append("allow merge without a successful pipeline")
        if after.get("only_allow_merge_if_all_discussions_are_resolved") is False:
            weaknesses.append("allow merge with unresolved discussions")
        if after.get("merge_trains_skip_train_allowed") is True:
            weaknesses.append("allow bypassing merge trains")
        if after.get("protect_merge_request_pipelines") is True:
            weaknesses.append("expose protected variables to merge-request pipelines")
        if after.get("ci_push_repository_for_job_token_allowed") is True:
            weaknesses.append("allow CI job tokens to push repository changes")
        if (
            after.get("shared_runners_enabled") is True
            or after.get("group_runners_enabled") is True
        ):
            weaknesses.append("enable shared or group runners")
        if after.get("skip_wait_for_default_branch_protection") is True:
            weaknesses.append("skip waiting for default branch protection")
        if str(after.get("ci_pipeline_variables_minimum_override_role", "")).lower() in {
            "developer",
            "maintainer",
        }:
            weaknesses.append("allow non-owners to override pipeline variables")
        if after.get("public_jobs") is True or after.get("public_builds") is True:
            weaknesses.append("make CI job details public")
        for key in (
            "pre_receive_secret_detection_enabled",
            "ci_separated_caches",
        ):
            if after.get(key) is False:
                weaknesses.append(f"disable {key.replace('_', ' ')}")
    risk = "dangerous" if weaknesses else "review"
    return [
        RuleResult(
            risk,
            f"This GitLab {label} change affects source, identity, CI/CD, registries, Pages, "
            "security, and namespace ownership"
            + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
            + ". Review visibility, merge and push controls, runner/token trust, security "
            "features, retention, imports/templates, and recovery.",
        )
    ]


_INSTANCE_RESOURCES = (
    "gitlab_application",
    "gitlab_application_appearance",
    "gitlab_application_settings",
)


@register_rule(*_INSTANCE_RESOURCES)
def _gitlab_instance_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("gitlab_").replace("_", " ")
    deleted = _delete(
        label,
        action_set,
        "Instance-wide authentication, defaults, integrations, or client credentials may change.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    weaknesses: list[str] = []
    if _contains_value(after, "public"):
        weaknesses.append("set a public default visibility")
    if after.get("default_branch_protection") == 0:
        weaknesses.append("disable default branch protection")
    if _any_true(
        after,
        "allow_local_requests_from_system_hooks",
        "allow_local_requests_from_web_hooks_and_services",
        "allow_project_creation_for_guest_and_below",
        "allow_runner_registration_token",
        "signup_enabled",
    ):
        weaknesses.append("broaden network, signup, project, or runner registration access")
    if _any_false(
        after,
        "admin_mode",
        "dns_rebinding_protection_enabled",
        "enforce_namespace_storage_limit",
        "password_authentication_enabled_for_web",
        "require_admin_approval_after_user_signup",
    ):
        weaknesses.append("disable an instance authentication or security guardrail")
    return [
        RuleResult(
            (
                "dangerous"
                if weaknesses or "update" in action_set or resource_type == "gitlab_application"
                else "review"
            ),
            f"This GitLab {label} change alters instance-wide authentication, OAuth, network "
            "egress, signup, repository/branch defaults, CI limits, storage, or integrations"
            + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
            + ". Review blast radius, secrets in Terraform state, SSO/admin access, SSRF "
            "boundaries, defaults for new namespaces, and rollback.",
        )
    ]


_PROTECTION_RESOURCES = (
    "gitlab_branch",
    "gitlab_branch_protection",
    "gitlab_group_branch_protection",
    "gitlab_tag_protection",
    "gitlab_project_tag",
    "gitlab_group_protected_environment",
    "gitlab_project_protected_environment",
    "gitlab_project_target_branch_rule",
    "gitlab_project_push_rules",
    "gitlab_project_freeze_period",
    "gitlab_project_approval_rule",
    "gitlab_group_level_mr_approvals",
    "gitlab_project_level_mr_approvals",
    "gitlab_project_external_status_check",
)


@register_rule(*_PROTECTION_RESOURCES)
def _gitlab_protection_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("gitlab_").replace("_", " ")
    deleted = _delete(
        label,
        action_set,
        "Protected refs, deployments, reviews, freeze windows, or status gates may disappear.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    weaknesses: list[str] = []
    if _any_true(after, "allow_force_push"):
        weaknesses.append("allow force pushes")
    if _contains_value(after, "developer", "developer + maintainer", "developer_maintainer"):
        weaknesses.append("grant developer-level push, merge, deploy, or approval access")
    if _contains_value(after, "no one", "no_one") and "approval" in resource_type:
        weaknesses.append("remove required approvers")
    if after.get("approvals_required") == 0 or after.get("required_approvals") == 0:
        weaknesses.append("require zero approvals")
    if after.get("disable_overriding_approvers_per_merge_request") is False:
        weaknesses.append("allow per-merge-request approval overrides")
    if after.get("merge_requests_author_approval") is True:
        weaknesses.append("allow merge-request author approval")
    if after.get("merge_requests_disable_committers_approval") is False:
        weaknesses.append("allow committers to approve their own changes")
    if after.get("prevent_secrets") is False or after.get("reject_unsigned_commits") is False:
        weaknesses.append("disable secret or signed-commit push controls")
    if resource_type.endswith("protected_environment") and not _values(after, "approval_rules"):
        weaknesses.append("define no deployment approval rule")
    return [
        RuleResult(
            "dangerous" if weaknesses or "update" in action_set else "review",
            f"This GitLab {label} change controls protected refs, merge approvals, push rules, "
            "deployment access, freeze windows, or required external checks"
            + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
            + ". Review wildcard scope, force push, access levels, code owners, approval "
            "independence, status-check fail-open behavior, and rollback.",
        )
    ]


_IDENTITY_RESOURCES = (
    "gitlab_group_membership",
    "gitlab_project_membership",
    "gitlab_member_role",
    "gitlab_group_ldap_link",
    "gitlab_group_saml_link",
    "gitlab_group_share_group",
    "gitlab_project_share_group",
    "gitlab_group_service_account",
    "gitlab_project_service_account",
    "gitlab_instance_service_account",
    "gitlab_user",
    "gitlab_user_identity",
)


@register_rule(*_IDENTITY_RESOURCES)
def _gitlab_identity_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("gitlab_").replace("_", " ")
    deleted = _delete(
        label,
        action_set,
        "Removing identity, membership, federation, or sharing can lock out responders or "
        "automation.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    privileged = _contains_value(
        after,
        "owner",
        "maintainer",
        "administrator",
        "admin",
        "developer",
    )
    return [
        RuleResult(
            "dangerous" if privileged or "update" in action_set else "review",
            f"This GitLab {label} change alters user, service-account, group/project, SAML/LDAP, "
            "custom-role, or cross-group access. Review identity proofing, least privilege, "
            "expiry, inherited membership, federation lifecycle, and emergency access.",
        )
    ]


_CREDENTIAL_RESOURCES = (
    "gitlab_personal_access_token",
    "gitlab_user_impersonation_token",
    "gitlab_group_access_token",
    "gitlab_project_access_token",
    "gitlab_group_service_account_access_token",
    "gitlab_group_deploy_token",
    "gitlab_project_deploy_token",
    "gitlab_deploy_key",
    "gitlab_deploy_key_enable",
    "gitlab_user_sshkey",
    "gitlab_user_gpgkey",
    "gitlab_cluster_agent_token",
    "gitlab_runner_controller_token",
    "gitlab_project_error_tracking_client_key",
    "gitlab_group_variable",
    "gitlab_project_variable",
    "gitlab_instance_variable",
    "gitlab_pipeline_schedule_variable",
    "gitlab_project_secure_file",
)


@register_rule(*_CREDENTIAL_RESOURCES)
def _gitlab_credential_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("gitlab_").replace("_", " ")
    deleted = _delete(
        label,
        action_set,
        "Credential revocation or variable/file removal can break builds, access, and deployments.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    weaknesses: list[str] = []
    if after.get("masked") is False:
        weaknesses.append("leave a CI/CD value unmasked")
    if after.get("protected") is False:
        weaknesses.append("expose a CI/CD value to unprotected refs")
    if _contains_value(after, "api", "sudo", "write_repository", "write_registry", "admin_mode"):
        weaknesses.append("grant a high-privilege token scope")
    if after.get("can_push") is True:
        weaknesses.append("grant deploy-key write access")
    return [
        RuleResult(
            "dangerous",
            f"This GitLab {label} change creates, rotates, redistributes, or revokes a credential "
            "or sensitive CI input"
            + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
            + ". Review plaintext and Terraform-state exposure, token scopes/role/expiry, "
            "protected and masked settings, environment scope, key custody, and rotation order.",
        )
    ]


_RUNNER_CLUSTER_RESOURCES = (
    "gitlab_cluster_agent",
    "gitlab_group_cluster",
    "gitlab_project_cluster",
    "gitlab_instance_cluster",
    "gitlab_user_runner",
    "gitlab_project_runner_enablement",
    "gitlab_runner_controller",
    "gitlab_runner_controller_instance_scope",
    "gitlab_runner_controller_runner_scope",
)


@register_rule(*_RUNNER_CLUSTER_RESOURCES)
def _gitlab_runner_cluster_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("gitlab_").replace("_", " ")
    deleted = _delete(
        label,
        action_set,
        "Trusted execution capacity or cluster connectivity can disappear and block delivery.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    weaknesses: list[str] = []
    if _contains_value(after, "instance_type", "not_protected"):
        weaknesses.append("allow broad or unprotected runner execution")
    if after.get("untagged") is True:
        weaknesses.append("accept untagged jobs")
    if after.get("locked") is False:
        weaknesses.append("allow runner reassignment beyond one project")
    if _contains_value(after, "enabled") and resource_type == "gitlab_runner_controller":
        weaknesses.append("activate runner-controller reconciliation")
    return [
        RuleResult(
            "dangerous" if weaknesses or "update" in action_set else "review",
            f"This GitLab {label} change alters the CI compute or Kubernetes trust boundary"
            + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
            + ". Review runner scope/tags/protection, untrusted merge requests, secret exposure, "
            "cluster-agent permissions, network egress, token custody, and teardown order.",
        )
    ]


_HOOK_INTEGRATION_RESOURCES = (
    "gitlab_project_hook",
    "gitlab_group_hook",
    "gitlab_system_hook",
    "gitlab_integration_slack",
    "gitlab_group_integration_harbor",
    "gitlab_group_integration_mattermost",
    "gitlab_group_integration_microsoft_teams",
    "gitlab_project_integration_custom_issue_tracker",
    "gitlab_project_integration_datadog",
    "gitlab_project_integration_emails_on_push",
    "gitlab_project_integration_external_wiki",
    "gitlab_project_integration_github",
    "gitlab_project_integration_google_chat",
    "gitlab_project_integration_harbor",
    "gitlab_project_integration_jenkins",
    "gitlab_project_integration_jira",
    "gitlab_project_integration_matrix",
    "gitlab_project_integration_mattermost",
    "gitlab_project_integration_microsoft_teams",
    "gitlab_project_integration_pipelines_email",
    "gitlab_project_integration_redmine",
    "gitlab_project_integration_telegram",
    "gitlab_project_integration_youtrack",
    "gitlab_project_error_tracking_settings",
)


@register_rule(*_HOOK_INTEGRATION_RESOURCES)
def _gitlab_hook_integration_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("gitlab_").replace("_", " ")
    deleted = _delete(
        label,
        action_set,
        "Event delivery, security automation, notifications, or deployment triggers can stop.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    insecure = after.get("enable_ssl_verification") is False
    missing_secret = resource_type.endswith("hook") and not any(
        bool(item) for key in ("signing_token", "token") for item in _values(after, key)
    )
    return [
        RuleResult(
            "dangerous" if insecure or missing_secret or "update" in action_set else "review",
            f"This GitLab {label} changes outbound events or a third-party service boundary"
            + (" without TLS verification" if insecure else "")
            + (" and without a configured signing or validation token" if missing_secret else "")
            + ". Review destination ownership, credentials in Terraform state, event/data scope, "
            "TLS, replay handling, notification volume, and decommission order.",
        )
    ]


_MIRROR_DELIVERY_RESOURCES = (
    "gitlab_project_pull_mirror",
    "gitlab_project_push_mirror",
    "gitlab_group_dependency_proxy",
    "gitlab_project_package_dependency_proxy",
    "gitlab_pages_domain",
    "gitlab_project_pages_settings",
    "gitlab_project_environment",
)


@register_rule(*_MIRROR_DELIVERY_RESOURCES)
def _gitlab_mirror_delivery_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("gitlab_").replace("_", " ")
    deleted = _delete(
        label,
        action_set,
        "Mirrored source, packages, Pages routing, or environment state can become unavailable.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    weaknesses: list[str] = []
    if after.get("mirror_overwrites_diverged_branches") is True:
        weaknesses.append("overwrite diverged branches from the mirror")
    if after.get("only_mirror_protected_branches") is False or after.get(
        "only_protected_branches"
    ) is False:
        weaknesses.append("mirror unprotected branches")
    if after.get("mirror_trigger_builds") is True:
        weaknesses.append("trigger pipelines from mirrored changes")
    return [
        RuleResult(
            (
                "dangerous"
                if weaknesses or "mirror" in resource_type or "pages" in resource_type
                else "review"
            ),
            f"This GitLab {label} change alters source/package replication, published Pages, or "
            "deployment-environment state"
            + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
            + ". Review remote/DNS ownership, credentials and host keys, protected-ref scope, "
            "divergence behavior, pipeline triggers, TLS, and rollback.",
        )
    ]


_CI_AUTOMATION_RESOURCES = (
    "gitlab_pipeline_schedule",
    "gitlab_pipeline_trigger",
    "gitlab_project_job_token_scope",
    "gitlab_project_job_token_scopes",
    "gitlab_project_cicd_catalog",
    "gitlab_group_project_file_template",
    "gitlab_repository_file",
)


@register_rule(*_CI_AUTOMATION_RESOURCES)
def _gitlab_ci_automation_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("gitlab_").replace("_", " ")
    deleted = _delete(
        label,
        action_set,
        "Scheduled execution, trigger access, job-token trust, templates, or managed files "
        "can disappear.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    weaknesses: list[str] = []
    if resource_type == "gitlab_project_job_token_scopes" and after.get("enabled") is False:
        weaknesses.append("disable the job-token inbound allowlist")
    if resource_type == "gitlab_repository_file":
        path = str(after.get("file_path", after.get("file", ""))).lower()
        if path in {".gitlab-ci.yml", "codeowners"} or path.startswith(".gitlab/"):
            weaknesses.append("mutate a CI, ownership, or policy file through the API")
    if after.get("active") is True and resource_type == "gitlab_pipeline_schedule":
        weaknesses.append("activate recurring pipeline execution")
    return [
        RuleResult(
            (
                "dangerous"
                if weaknesses
                or resource_type
                in {
                    "gitlab_pipeline_trigger",
                    "gitlab_project_cicd_catalog",
                    "gitlab_project_job_token_scope",
                    "gitlab_project_job_token_scopes",
                }
                else "review"
            ),
            f"This GitLab {label} change alters automated pipeline execution, job-token inbound "
            "trust, CI catalog/templates, or repository content"
            + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
            + ". Review owner identity, ref and variable scope, token distribution, target "
            "projects/groups, file provenance, protected refs, and rollback.",
        )
    ]


_SUPPLY_CHAIN_RESOURCES = (
    "gitlab_release",
    "gitlab_release_link",
    "gitlab_project_container_repository_protection",
    "gitlab_project_container_tag_protection",
    "gitlab_project_package_protection_rule",
)


@register_rule(*_SUPPLY_CHAIN_RESOURCES)
def _gitlab_supply_chain_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("gitlab_").replace("_", " ")
    deleted = _delete(
        label,
        action_set,
        "Published releases/artifacts or registry protection can disappear.",
    )
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                f"This GitLab {label} change alters a software supply-chain publication or "
                "registry protection boundary. Review tag/commit provenance, artifact digest "
                "and signatures, access levels, wildcard patterns, immutability, retention, "
                "and rollback or revocation communications.",
            )
        ]
    return []


_SECURITY_COMPLIANCE_RESOURCES = (
    "gitlab_compliance_framework",
    "gitlab_project_compliance_frameworks",
    "gitlab_group_security_policy_attachment",
    "gitlab_project_security_policy_attachment",
    "gitlab_project_secret_detection_validity_checks",
)


@register_rule(*_SECURITY_COMPLIANCE_RESOURCES)
def _gitlab_security_compliance_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("gitlab_").replace("_", " ")
    deleted = _delete(
        label,
        action_set,
        "Security policy, compliance classification, or secret-validity coverage can be removed.",
    )
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        after = _desired(change)
        disabled = after.get("enabled") is False
        return [
            RuleResult(
                "dangerous" if disabled or "update" in action_set else "review",
                f"This GitLab {label} change alters compliance pipeline selection, project "
                "classification, security-policy attachment, or secret detection"
                + (" and appears to disable coverage" if disabled else "")
                + ". Review policy-project provenance, namespace/project scope, default framework, "
                "pipeline path/ref immutability, license behavior, and rollback.",
            )
        ]
    return []


_COLLABORATION_RESOURCES = (
    "gitlab_global_level_notifications",
    "gitlab_group_badge",
    "gitlab_group_custom_attribute",
    "gitlab_group_epic_board",
    "gitlab_group_issue_board",
    "gitlab_group_label",
    "gitlab_group_saved_reply",
    "gitlab_project_badge",
    "gitlab_project_custom_attribute",
    "gitlab_project_issue",
    "gitlab_project_issue_board",
    "gitlab_project_issue_link",
    "gitlab_project_label",
    "gitlab_project_level_notifications",
    "gitlab_project_merge_request_note",
    "gitlab_project_milestone",
    "gitlab_project_saved_reply",
    "gitlab_project_wiki_page",
    "gitlab_topic",
    "gitlab_user_avatar",
    "gitlab_user_custom_attribute",
    "gitlab_user_saved_reply",
    "gitlab_value_stream_analytics",
)


@register_rule(*_COLLABORATION_RESOURCES)
def _gitlab_collaboration_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("gitlab_").replace("_", " ")
    deleted = _delete(
        label,
        action_set,
        "Workflow metadata, audit context, notification, or discovery information can be lost.",
    )
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "review",
                f"This GitLab {label} change alters collaboration, planning, notification, "
                "analytics, or discovery metadata. Review automation triggers, confidentiality, "
                "audit references, permissions, notification volume, and downstream reporting.",
            )
        ]
    return []
