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


def _setting_is(value: Any, expected: Any) -> bool:
    if value is expected:
        return True
    return str(value).lower() == str(expected).lower()


def _any_setting(value: Any, key: str, expected: Any) -> bool:
    return any(_setting_is(item, expected) for item in _values(value, key))


def _delete(label: str, action_set: set[str], consequence: str) -> RuleResult | None:
    if "delete" not in action_set:
        return None
    if "create" in action_set:
        return RuleResult(
            "dangerous",
            f"__TOOL__ will replace this GitHub {label}. {consequence} Review identity, "
            "dependencies, migration order, rollback, and recovery before applying.",
        )
    return RuleResult(
        "irreversible",
        f"__TOOL__ will delete this GitHub {label}. {consequence} Confirm ownership, "
        "exports or recovery, dependent automation, and an explicit rollback path.",
    )


def _status_disabled(value: Any) -> bool:
    return value is False or str(value).lower() in {"disabled", "false", "off", "none"}


@register_rule("github_repository")
def _github_repository_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    before = _previous(change)
    after = _desired(change)
    if "delete" in action_set:
        archive = before.get("archive_on_destroy") is True
        if archive and "create" not in action_set:
            return [
                RuleResult(
                    "irreversible",
                    "__TOOL__ will remove this GitHub repository from Terraform and archive "
                    "it instead of deleting it. GitHub currently cannot unarchive it through "
                    "this provider; verify clone/export recovery and dependent automation.",
                )
            ]
        deleted = _delete(
            "repository",
            action_set,
            "Repository contents, issues, releases, settings, and automation may be lost.",
        )
        return [deleted] if deleted else []
    if not ({"create", "update"} & action_set):
        return []

    findings: list[str] = []
    visibility = str(after.get("visibility", "")).lower()
    defaults_to_public = (
        "create" in action_set and "visibility" not in after and "private" not in after
    )
    if (
        visibility == "public"
        or (not visibility and after.get("private") is False)
        or defaults_to_public
    ):
        findings.append("publish repository contents and metadata to the public Internet")
    before_visibility = before.get("visibility", before.get("private"))
    after_visibility = after.get("visibility", after.get("private"))
    if before_visibility is not None and before_visibility != after_visibility:
        findings.append("change the repository visibility boundary")
    if after.get("archived") is True:
        findings.append("archive the repository, which the API does not currently unarchive")
    if after.get("allow_forking") is True:
        findings.append("allow forks of a private or internal repository")
    if after.get("archive_on_destroy") is False and before.get("archive_on_destroy") is True:
        findings.append("replace archive-on-destroy with destructive deletion")
    for key in (
        "advanced_security",
        "code_security",
        "secret_scanning",
        "secret_scanning_push_protection",
        "secret_scanning_ai_detection",
        "secret_scanning_non_provider_patterns",
    ):
        feature_blocks = _values(after.get("security_and_analysis", {}), key)
        if any(_contains_value(block, "disabled") for block in feature_blocks):
            findings.append(f"disable {key.replace('_', ' ')}")
    if after.get("vulnerability_alerts") is False:
        findings.append("disable vulnerability alerts")

    if findings:
        return [
            RuleResult(
                "dangerous",
                f"This GitHub repository change can {'; '.join(findings)}. Review data "
                "classification, fork/Pages exposure, security analysis, branch governance, "
                "integrations, archival/recovery, and visibility before applying.",
            )
        ]
    return [
        RuleResult(
            "review",
            "This GitHub repository lifecycle or settings change affects source, collaboration, "
            "merge behavior, and automation. Review ownership, visibility, security features, "
            "default branch, Pages, and downstream integrations.",
        )
    ]


@register_rule(
    "github_branch",
    "github_branch_default",
    "github_repository_pages",
)
def _github_repository_routing_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("github_").replace("_", " ")
    deleted = _delete(
        label,
        action_set,
        "Git refs, the default merge target, or published Pages routing can change immediately.",
    )
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        after = _desired(change)
        return [
            RuleResult(
                "dangerous" if resource_type != "github_branch" else "review",
                f"This GitHub {label} change can move a release/merge target or published site "
                f"(branch={after.get('branch', after.get('source_branch'))!r}). Review commit "
                "provenance, branch protection, deployment consumers, DNS/TLS, and rollback.",
            )
        ]
    return []


@register_rule(
    "github_branch_protection",
    "github_branch_protection_v3",
    "github_repository_ruleset",
    "github_organization_ruleset",
)
def _github_governance_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete(
        "branch protection or ruleset",
        action_set,
        "Protected refs may immediately accept unreviewed, unsigned, unchecked, or "
        "destructive changes.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    weaknesses: list[str] = []
    if _setting_is(after.get("enforcement"), "disabled"):
        weaknesses.append("disable ruleset enforcement")
    if after.get("enforce_admins") is False:
        weaknesses.append("allow administrators to bypass protection")
    if after.get("allows_deletions") is True:
        weaknesses.append("allow protected branch deletion")
    if after.get("allows_force_pushes") is True:
        weaknesses.append("allow force pushes")
    if _values(after, "force_push_bypassers"):
        weaknesses.append("grant force-push bypasses")
    if _values(after, "pull_request_bypassers"):
        weaknesses.append("grant pull-request bypasses")
    if any(
        str(item).lower() in {"always", "exempt"}
        for item in _values(after, "bypass_mode")
    ):
        weaknesses.append("grant persistent ruleset bypasses")
    if _any_setting(after, "required_approving_review_count", 0):
        weaknesses.append("allow zero approving reviews")
    if _any_setting(after, "strict", False) or _any_setting(
        after, "strict_required_status_checks_policy", False
    ):
        weaknesses.append("permit checks against stale base-branch code")
    risk = "dangerous" if weaknesses or "update" in action_set else "review"
    detail = f" It can {'; '.join(weaknesses)}." if weaknesses else ""
    return [
        RuleResult(
            risk,
            f"This GitHub branch-governance change controls who may update protected refs and "
            f"which reviews, checks, signatures, deployments, or workflows are required.{detail} "
            "Review ref scope, bypass actors, force-push/deletion settings, required checks, "
            "approval counts, code owners, and administrator enforcement.",
        )
    ]


@register_rule(
    "github_membership",
    "github_emu_group_mapping",
    "github_team",
    "github_team_members",
    "github_team_membership",
    "github_team_repository",
    "github_team_settings",
    "github_team_sync_group_mapping",
    "github_repository_collaborator",
    "github_repository_collaborators",
    "github_organization_security_manager",
    "github_organization_custom_role",
    "github_organization_repository_role",
    "github_organization_role",
    "github_organization_role_team",
    "github_organization_role_team_assignment",
    "github_organization_role_user",
    "github_user_invitation_accepter",
)
def _github_identity_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("github_").replace("_", " ")
    deleted = _delete(
        label,
        action_set,
        "Removing access or role bindings can lock out responders and break deployments.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    privileged = _contains_value(after, "admin", "maintain", "write", "push", "member")
    return [
        RuleResult(
            "dangerous" if privileged else "review",
            f"This GitHub {label} change alters organization, team, repository, or security "
            "management access. Review identity lifecycle, least privilege, external/EMU group "
            "sync, base/custom role permissions, repository scope, and emergency access.",
        )
    ]


@register_rule("github_organization_settings", "github_enterprise_organization")
def _github_organization_settings_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete(
        "organization or enterprise organization",
        action_set,
        "Organization-wide ownership, policy, and repository defaults can be removed.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    weaknesses: list[str] = []
    if str(after.get("default_repository_permission", "read")).lower() in {"write", "admin"}:
        weaknesses.append("grant broad default repository permissions")
    for key in (
        "members_can_create_public_repositories",
        "members_can_create_public_pages",
        "members_can_fork_private_repositories",
    ):
        if after.get(key) is True:
            weaknesses.append(key.replace("_", " "))
    for key in (
        "advanced_security_enabled_for_new_repositories",
        "dependabot_alerts_enabled_for_new_repositories",
        "dependabot_security_updates_enabled_for_new_repositories",
        "dependency_graph_enabled_for_new_repositories",
        "secret_scanning_enabled_for_new_repositories",
        "secret_scanning_push_protection_enabled_for_new_repositories",
    ):
        if after.get(key) is False:
            setting = key.removesuffix("_enabled_for_new_repositories").replace("_", " ")
            weaknesses.append(f"disable {setting} defaults")
    return [
        RuleResult(
            "dangerous" if weaknesses else "review",
            "This GitHub organization setting changes repository creation, default access, "
            "private forking, Pages, commit signoff, or security defaults"
            + (f" and can {'; '.join(weaknesses)}" if weaknesses else "")
            + ". Review enterprise inheritance, least privilege, data exposure, security "
            "baseline, and existing-repository exceptions.",
        )
    ]


@register_rule(
    "github_actions_repository_permissions",
    "github_actions_organization_permissions",
    "github_enterprise_actions_permissions",
    "github_actions_repository_access_level",
    "github_workflow_repository_permissions",
)
def _github_actions_policy_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete(
        "Actions execution or reusable-workflow policy",
        action_set,
        "The effective Actions policy may reset, disable workflows, or broaden execution trust.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    weaknesses: list[str] = []
    if _contains_value(after, "all"):
        weaknesses.append("allow all actions, repositories, or reusable-workflow consumers")
    if after.get("sha_pinning_required") is False:
        weaknesses.append("permit unpinned actions and reusable workflows")
    if _any_setting(after, "verified_allowed", True):
        weaknesses.append("trust every verified Marketplace publisher")
    patterns = _values(after, "patterns_allowed")
    flattened_patterns = [
        pattern
        for group in patterns
        for pattern in (group if isinstance(group, list) else [group])
    ]
    if any("*" in str(pattern) for pattern in flattened_patterns):
        weaknesses.append("use wildcard action allow patterns")
    return [
        RuleResult(
            "dangerous" if weaknesses or "update" in action_set else "review",
            "This GitHub Actions policy changes which repositories can execute workflows and "
            "which actions or reusable workflows they may trust"
            + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
            + ". Review SHA pinning, allowed publishers/patterns, repository selection, fork "
            "behavior, reusable-workflow consumers, and enterprise inheritance.",
        )
    ]


@register_rule(
    "github_actions_organization_workflow_permissions",
    "github_enterprise_actions_workflow_permissions",
)
def _github_workflow_token_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete(
        "default workflow-token policy",
        action_set,
        "Destroy resets policy and can change the permissions granted to every workflow token.",
    )
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        after = _desired(change)
        permissive = _setting_is(after.get("default_workflow_permissions"), "write") or after.get(
            "can_approve_pull_request_reviews"
        ) is True
        return [
            RuleResult(
                "dangerous" if permissive else "review",
                "This GitHub Actions default token policy changes GITHUB_TOKEN privileges and "
                "whether workflows can approve pull requests. Review write scopes, forked pull "
                "requests, branch protections, self-approval paths, and explicit job permissions.",
            )
        ]
    return []


@register_rule("github_enterprise_ip_allow_list_entry")
def _github_enterprise_network_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete(
        "enterprise IP allow-list entry",
        action_set,
        "Administrators, automation, or incident responders may lose enterprise access.",
    )
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        after = _desired(change)
        return [
            RuleResult(
                "dangerous",
                "This GitHub enterprise IP allow-list change alters the network locations "
                f"trusted to access the enterprise (CIDR={after.get('value')!r}). Review CIDR "
                "breadth, owner, VPN/NAT egress, GitHub Apps and Actions compatibility, "
                "break-glass access, and rollout order.",
            )
        ]
    return []


@register_rule("github_organization_block")
def _github_organization_block_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete(
        "organization user block",
        action_set,
        "Removing the block restores interaction and repository access paths for the user.",
    )
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                "This GitHub organization block changes a user's ability to interact with the "
                "organization and can remove existing collaboration access. Review identity, "
                "offboarding or abuse evidence, support impact, and reversal ownership.",
            )
        ]
    return []


@register_rule(
    "github_organization_custom_properties",
    "github_repository_custom_property",
)
def _github_custom_property_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete(
        "custom property definition or value",
        action_set,
        "Rulesets, policy reporting, and repository targeting may lose governance metadata.",
    )
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "review",
                "This GitHub custom-property change alters repository governance metadata that "
                "can drive ruleset targeting, inventory, and compliance reporting. Review schema "
                "choices, allowed values, required/default behavior, repository scope, and "
                "downstream policy consumers.",
            )
        ]
    return []


@register_rule("github_release")
def _github_release_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete(
        "release",
        action_set,
        "Published artifacts, release notes, and downstream installation references can disappear.",
    )
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        after = _desired(change)
        return [
            RuleResult(
                "dangerous",
                "This GitHub release change publishes or mutates a software supply-chain "
                f"boundary (tag={after.get('tag_name')!r}, draft={after.get('draft')!r}, "
                f"prerelease={after.get('prerelease')!r}). Review tag/commit provenance, "
                "artifact checksums and signatures, immutability expectations, permissions, "
                "and rollback or revocation communications.",
            )
        ]
    return []


@register_rule(
    "github_issue",
    "github_issue_label",
    "github_issue_labels",
    "github_organization_project",
    "github_project_card",
    "github_project_column",
    "github_repository_autolink_reference",
    "github_repository_milestone",
    "github_repository_project",
    "github_repository_pull_request",
    "github_repository_topics",
)
def _github_collaboration_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("github_").replace("_", " ")
    deleted = _delete(
        label,
        action_set,
        "Workflow metadata, audit context, or repository discovery information can be lost.",
    )
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "review",
                f"This GitHub {label} change alters collaboration, planning, linking, or "
                "repository-discovery metadata. Review automation triggers, audit references, "
                "permissions, notification volume, and downstream reporting.",
            )
        ]
    return []


@register_rule(
    "github_actions_secret",
    "github_actions_environment_secret",
    "github_actions_organization_secret",
    "github_actions_organization_secret_repositories",
    "github_actions_organization_secret_repository",
    "github_codespaces_secret",
    "github_codespaces_organization_secret",
    "github_codespaces_organization_secret_repositories",
    "github_codespaces_user_secret",
    "github_dependabot_secret",
    "github_dependabot_organization_secret",
    "github_dependabot_organization_secret_repositories",
    "github_dependabot_organization_secret_repository",
)
def _github_secret_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("github_").replace("_", " ")
    deleted = _delete(
        label,
        action_set,
        "Credential revocation or repository-scope removal can break builds, updates, "
        "and deployments.",
    )
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        after = _desired(change)
        return [
            RuleResult(
                "dangerous",
                f"This GitHub {label} change creates, rotates, or redistributes a credential. "
                "Review plaintext/encrypted value handling and Terraform state exposure, "
                f"visibility={after.get('visibility')!r}, selected repositories/environments, "
                "fork behavior, least privilege, rotation order, and revocation ownership.",
            )
        ]
    return []


@register_rule(
    "github_actions_variable",
    "github_actions_environment_variable",
    "github_actions_organization_variable",
    "github_actions_organization_variable_repositories",
    "github_actions_organization_variable_repository",
)
def _github_actions_variable_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete(
        "Actions variable or repository binding",
        action_set,
        "Workflow inputs and deployment behavior can change or fail when this value disappears.",
    )
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "review",
                "This GitHub Actions variable change alters non-secret workflow input or its "
                "repository/environment distribution. Review whether the value is actually "
                "sensitive, repository scope, deployment behavior, and rollback.",
            )
        ]
    return []


@register_rule(
    "github_repository_environment",
    "github_repository_deployment_branch_policy",
    "github_repository_environment_deployment_policy",
)
def _github_environment_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete(
        "deployment environment or branch policy",
        action_set,
        "Deployment approvals, environment secrets, and allowed release refs can be removed.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    weaknesses: list[str] = []
    if after.get("can_admins_bypass") is True:
        weaknesses.append("allow administrators to bypass deployment protection")
    if after.get("prevent_self_review") is False:
        weaknesses.append("allow deployment self-review")
    if _any_setting(after, "protected_branches", False) and _any_setting(
        after, "custom_branch_policies", False
    ):
        weaknesses.append("allow deployments from unrestricted branches")
    if resource_type == "github_repository_environment" and not _values(after, "reviewers"):
        weaknesses.append("define no required deployment reviewer")
    return [
        RuleResult(
            "dangerous" if weaknesses or "update" in action_set else "review",
            "This GitHub deployment-environment change controls who can approve releases, "
            "which refs may deploy, wait timers, and access to environment secrets"
            + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
            + ". Review production naming, reviewer independence, admin bypass, branch/tag "
            "patterns, and rollback.",
        )
    ]


@register_rule(
    "github_repository_deploy_key",
    "github_user_ssh_key",
    "github_user_gpg_key",
)
def _github_key_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("github_").replace("_", " ")
    deleted = _delete(
        label,
        action_set,
        "Key revocation can interrupt repository access, signing, or deployment automation.",
    )
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        after = _desired(change)
        writable = (
            resource_type == "github_repository_deploy_key"
            and after.get("read_only") is False
        )
        return [
            RuleResult(
                "dangerous",
                f"This GitHub {label} change grants cryptographic repository access or signing "
                + ("with write capability. " if writable else ". ")
                + "Review key provenance and fingerprint, private-key custody, least privilege, "
                "rotation, repository scope, and revocation ownership.",
            )
        ]
    return []


@register_rule("github_repository_webhook", "github_organization_webhook")
def _github_webhook_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete(
        "webhook",
        action_set,
        "Event delivery, security automation, or deployment triggers can stop immediately.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    insecure = _any_setting(after, "insecure_ssl", True)
    missing_secret = not any(bool(item) for item in _values(after, "secret"))
    active = after.get("active", True) is not False
    return [
        RuleResult(
            "dangerous" if active and (insecure or missing_secret) else "review",
            "This GitHub webhook changes outbound delivery of repository or organization events"
            + (" without TLS verification" if insecure else "")
            + (" and without a configured signing secret" if missing_secret else "")
            + ". Review destination ownership, secret rotation, TLS, event scope, sensitive "
            "payloads, availability, replay handling, and decommission order.",
        )
    ]


@register_rule(
    "github_actions_runner_group",
    "github_enterprise_actions_runner_group",
    "github_actions_hosted_runner",
)
def _github_runner_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("github_").replace("_", " ")
    deleted = _delete(
        label,
        action_set,
        "Runner capacity or trusted execution placement can disappear and block workflows.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    weaknesses: list[str] = []
    if _setting_is(after.get("visibility"), "all"):
        weaknesses.append("make the runner group available to all repositories")
    if after.get("allows_public_repositories") is True:
        weaknesses.append("allow public repositories to use the runner group")
    if after.get("restricted_to_workflows") is False:
        weaknesses.append("allow unrestricted workflows")
    if after.get("public_ip_enabled") is True:
        weaknesses.append("enable a public runner IP")
    if _contains_value(after.get("image", {}), "custom", "partner"):
        weaknesses.append("use a non-GitHub runner image")
    return [
        RuleResult(
            "dangerous" if weaknesses else "review",
            f"This GitHub {label} change alters the compute trust boundary, repository/workflow "
            "scope, network exposure, image provenance, or scaling cost"
            + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
            + ". Review untrusted pull requests, secret exposure, image lifecycle, network "
            "egress, maximum runners, billing, and teardown order.",
        )
    ]


@register_rule(
    "github_actions_repository_oidc_subject_claim_customization_template",
    "github_actions_organization_oidc_subject_claim_customization_template",
)
def _github_oidc_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete(
        "Actions OIDC subject-claim template",
        action_set,
        "Cloud trust policies may stop matching or may fall back to a broader default subject.",
    )
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                "This GitHub Actions OIDC subject-template change alters the identity asserted "
                "to cloud providers. Review included claim keys, repository opt-in/defaults, "
                "audience and subject matching, fork/environment boundaries, cloud trust-policy "
                "deployment order, and rollback.",
            )
        ]
    return []


@register_rule(
    "github_app_installation_repository",
    "github_app_installation_repositories",
)
def _github_app_installation_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete(
        "App installation repository grant",
        action_set,
        "The GitHub App can lose repository access and dependent automation can fail.",
    )
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                "This GitHub App installation change grants or changes an integration's "
                "repository access. Review the App owner and permissions, repository/data "
                "scope, webhook behavior, credential custody, and revocation plan.",
            )
        ]
    return []


@register_rule("github_repository_file")
def _github_repository_file_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    before = _previous(change)
    after = _desired(change)
    path = str(after.get("file", before.get("file", "")))
    deleted = _delete(
        f"repository file {path!r}",
        action_set,
        "The managed file and its policy, workflow, ownership, or configuration can disappear.",
    )
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    normalized = path.lower().replace("\\", "/")
    sensitive = normalized.startswith(".github/workflows/") or normalized in {
        ".github/codeowners",
        "codeowners",
        ".github/dependabot.yml",
        ".github/dependency-review-config.yml",
        ".github/renovate.json",
        "security.md",
    }
    if after.get("overwrite_on_create") is True:
        sensitive = True
    return [
        RuleResult(
            "dangerous" if sensitive else "review",
            f"This GitHub repository-file change commits {path!r} through the API and may "
            "bypass the normal pull-request path. Review target branch protection, content "
            "provenance, CODEOWNERS/workflow security, overwrite behavior, commit identity, "
            "and rollback.",
        )
    ]


@register_rule(
    "github_repository_vulnerability_alerts",
    "github_repository_dependabot_security_updates",
    "github_enterprise_security_analysis_settings",
)
def _github_security_feature_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete(
        "security analysis or remediation setting",
        action_set,
        "Vulnerability detection, secret scanning, or automated remediation coverage may stop.",
    )
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        after = _desired(change)
        disabled = (
            after.get("enabled") is False
            or any(_status_disabled(item) for item in _values(after, "status"))
            or _contains_value(after, "disabled")
        )
        return [
            RuleResult(
                "dangerous" if disabled else "review",
                "This GitHub security-feature change alters vulnerability alerts, Dependabot "
                "security updates, Advanced Security, code security, or secret scanning"
                + (" and appears to disable coverage" if disabled else "")
                + ". Review license/visibility prerequisites, organization inheritance, alert "
                "owners, remediation workflow, and existing-repository coverage.",
            )
        ]
    return []
