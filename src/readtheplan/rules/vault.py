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
    for _key, item in _walk(value):
        if isinstance(item, str) and item.lower() in expected:
            return True
        if isinstance(item, (list, tuple, set)) and any(
            isinstance(entry, str) and entry.lower() in expected for entry in item
        ):
            return True
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
    return resource_type.removeprefix("vault_").replace("_", " ")


def _delete(
    label: str,
    action_set: set[str],
    consequence: str,
) -> RuleResult | None:
    if "delete" not in action_set:
        return None
    if "create" in action_set:
        return RuleResult(
            "dangerous",
            f"__TOOL__ will replace this Vault {label}. {consequence} Review namespace and "
            "mount identity, dependent clients, migration order, rollback, and recovery.",
        )
    return RuleResult(
        "irreversible",
        f"__TOOL__ will delete this Vault {label}. {consequence} Revocation, lost access, "
        "or destroyed cryptographic material may not be recoverable from Terraform state.",
    )


_VAULT_RESOURCES = (
    "vault_activation_flags",
    "vault_ad_secret_backend",
    "vault_ad_secret_backend_library",
    "vault_ad_secret_role",
    "vault_agent_registration",
    "vault_alicloud_auth_backend_role",
    "vault_alicloud_secret_backend",
    "vault_alicloud_secret_backend_role",
    "vault_approle_auth_backend_login",
    "vault_approle_auth_backend_role",
    "vault_approle_auth_backend_role_secret_id",
    "vault_audit",
    "vault_audit_request_header",
    "vault_auth_backend",
    "vault_aws_auth_backend_cert",
    "vault_aws_auth_backend_client",
    "vault_aws_auth_backend_config_identity",
    "vault_aws_auth_backend_identity_whitelist",
    "vault_aws_auth_backend_login",
    "vault_aws_auth_backend_role",
    "vault_aws_auth_backend_role_tag",
    "vault_aws_auth_backend_roletag_blacklist",
    "vault_aws_auth_backend_sts_role",
    "vault_aws_secret_backend",
    "vault_aws_secret_backend_role",
    "vault_aws_secret_backend_static_role",
    "vault_azure_auth_backend_config",
    "vault_azure_auth_backend_role",
    "vault_azure_secret_backend",
    "vault_azure_secret_backend_role",
    "vault_azure_secret_backend_static_role",
    "vault_cert_auth_backend_role",
    "vault_cf_auth_backend_config",
    "vault_cf_auth_backend_role",
    "vault_config_control_group",
    "vault_config_group_policy_application",
    "vault_config_ui_custom_messages",
    "vault_config_ui_default_auth",
    "vault_config_ui_header",
    "vault_consul_secret_backend",
    "vault_consul_secret_backend_role",
    "vault_database_secret_backend_connection",
    "vault_database_secret_backend_role",
    "vault_database_secret_backend_static_role",
    "vault_database_secrets_mount",
    "vault_egp_policy",
    "vault_gcp_auth_backend",
    "vault_gcp_auth_backend_role",
    "vault_gcp_secret_backend",
    "vault_gcp_secret_impersonated_account",
    "vault_gcp_secret_roleset",
    "vault_gcp_secret_static_account",
    "vault_generic_endpoint",
    "vault_generic_secret",
    "vault_github_auth_backend",
    "vault_github_team",
    "vault_github_user",
    "vault_identity_entity",
    "vault_identity_entity_alias",
    "vault_identity_entity_policies",
    "vault_identity_group",
    "vault_identity_group_alias",
    "vault_identity_group_member_entity_ids",
    "vault_identity_group_member_group_ids",
    "vault_identity_group_policies",
    "vault_identity_mfa_duo",
    "vault_identity_mfa_login_enforcement",
    "vault_identity_mfa_okta",
    "vault_identity_mfa_pingid",
    "vault_identity_mfa_totp",
    "vault_identity_oidc",
    "vault_identity_oidc_assignment",
    "vault_identity_oidc_client",
    "vault_identity_oidc_key",
    "vault_identity_oidc_key_allowed_client_id",
    "vault_identity_oidc_provider",
    "vault_identity_oidc_role",
    "vault_identity_oidc_scope",
    "vault_jwt_auth_backend",
    "vault_jwt_auth_backend_role",
    "vault_keymgmt_aws_kms",
    "vault_keymgmt_azure_kms",
    "vault_keymgmt_distribute_key",
    "vault_keymgmt_gcp_kms",
    "vault_keymgmt_key",
    "vault_keymgmt_key_rotate",
    "vault_keymgmt_replicate_key",
    "vault_kmip_secret_backend",
    "vault_kmip_secret_ca_generated",
    "vault_kmip_secret_ca_imported",
    "vault_kmip_secret_listener",
    "vault_kmip_secret_role",
    "vault_kmip_secret_scope",
    "vault_kubernetes_auth_backend_config",
    "vault_kubernetes_auth_backend_role",
    "vault_kubernetes_secret_backend",
    "vault_kubernetes_secret_backend_role",
    "vault_kv_secret",
    "vault_kv_secret_backend_v2",
    "vault_kv_secret_v2",
    "vault_ldap_auth_backend",
    "vault_ldap_auth_backend_group",
    "vault_ldap_auth_backend_user",
    "vault_ldap_secret_backend",
    "vault_ldap_secret_backend_dynamic_role",
    "vault_ldap_secret_backend_library_set",
    "vault_ldap_secret_backend_static_role",
    "vault_managed_keys",
    "vault_mfa_duo",
    "vault_mfa_okta",
    "vault_mfa_pingid",
    "vault_mfa_totp",
    "vault_mongodbatlas_secret_backend",
    "vault_mongodbatlas_secret_role",
    "vault_mount",
    "vault_namespace",
    "vault_nomad_secret_backend",
    "vault_nomad_secret_role",
    "vault_oauth_resource_server_config_profile",
    "vault_oci_auth_backend",
    "vault_oci_auth_backend_role",
    "vault_okta_auth_backend",
    "vault_okta_auth_backend_group",
    "vault_okta_auth_backend_user",
    "vault_os_secret_backend",
    "vault_os_secret_backend_account",
    "vault_os_secret_backend_host",
    "vault_password_policy",
    "vault_pki_external_ca_secret_backend_acme_account",
    "vault_pki_external_ca_secret_backend_order",
    "vault_pki_external_ca_secret_backend_order_certificate",
    "vault_pki_external_ca_secret_backend_order_challenge_fulfilled",
    "vault_pki_external_ca_secret_backend_role",
    "vault_pki_secret_backend_acme_eab",
    "vault_pki_secret_backend_cert",
    "vault_pki_secret_backend_config_acme",
    "vault_pki_secret_backend_config_auto_tidy",
    "vault_pki_secret_backend_config_ca",
    "vault_pki_secret_backend_config_cluster",
    "vault_pki_secret_backend_config_cmpv2",
    "vault_pki_secret_backend_config_est",
    "vault_pki_secret_backend_config_issuers",
    "vault_pki_secret_backend_config_scep",
    "vault_pki_secret_backend_config_urls",
    "vault_pki_secret_backend_crl_config",
    "vault_pki_secret_backend_intermediate_cert_request",
    "vault_pki_secret_backend_intermediate_set_signed",
    "vault_pki_secret_backend_issuer",
    "vault_pki_secret_backend_key",
    "vault_pki_secret_backend_role",
    "vault_pki_secret_backend_root_cert",
    "vault_pki_secret_backend_root_sign_intermediate",
    "vault_pki_secret_backend_sign",
    "vault_plugin",
    "vault_plugin_pinned_version",
    "vault_plugin_runtime",
    "vault_policy",
    "vault_quota_config",
    "vault_quota_lease_count",
    "vault_quota_rate_limit",
    "vault_rabbitmq_secret_backend",
    "vault_rabbitmq_secret_backend_role",
    "vault_radius_auth_backend",
    "vault_radius_auth_backend_user",
    "vault_raft_autopilot",
    "vault_raft_snapshot_agent_config",
    "vault_rgp_policy",
    "vault_rotation_policy",
    "vault_saml_auth_backend",
    "vault_saml_auth_backend_role",
    "vault_scep_auth_backend_role",
    "vault_secrets_sync_association",
    "vault_secrets_sync_aws_destination",
    "vault_secrets_sync_azure_destination",
    "vault_secrets_sync_config",
    "vault_secrets_sync_gcp_destination",
    "vault_secrets_sync_gh_destination",
    "vault_secrets_sync_github_apps",
    "vault_secrets_sync_vercel_destination",
    "vault_spiffe_auth_backend_config",
    "vault_spiffe_auth_backend_role",
    "vault_spiffe_secret_backend_config",
    "vault_spiffe_secret_backend_role",
    "vault_ssh_secret_backend_ca",
    "vault_ssh_secret_backend_role",
    "vault_sys_config_cors",
    "vault_terraform_cloud_secret_backend",
    "vault_terraform_cloud_secret_creds",
    "vault_terraform_cloud_secret_role",
    "vault_token",
    "vault_token_auth_backend_role",
    "vault_transform_alphabet",
    "vault_transform_role",
    "vault_transform_template",
    "vault_transform_transformation",
    "vault_transit_secret_backend_cache_config",
    "vault_transit_secret_backend_key",
    "vault_userpass_auth_backend_user",
)


_SECRET_STATE_RESOURCES = {
    "vault_approle_auth_backend_login",
    "vault_approle_auth_backend_role_secret_id",
    "vault_aws_auth_backend_login",
    "vault_generic_secret",
    "vault_kv_secret",
    "vault_kv_secret_v2",
    "vault_pki_secret_backend_cert",
    "vault_pki_secret_backend_sign",
    "vault_terraform_cloud_secret_creds",
    "vault_token",
}

_POLICY_RESOURCES = {
    "vault_config_control_group",
    "vault_config_group_policy_application",
    "vault_egp_policy",
    "vault_password_policy",
    "vault_policy",
    "vault_quota_config",
    "vault_quota_lease_count",
    "vault_quota_rate_limit",
    "vault_restriction_policy",
    "vault_rgp_policy",
}

_PLATFORM_RESOURCES = {
    "vault_activation_flags",
    "vault_agent_registration",
    "vault_config_ui_custom_messages",
    "vault_config_ui_default_auth",
    "vault_config_ui_header",
    "vault_mount",
    "vault_namespace",
    "vault_raft_autopilot",
    "vault_raft_snapshot_agent_config",
    "vault_rotation_policy",
    "vault_sys_config_cors",
}


@register_rule(*_VAULT_RESOURCES)
def _vault_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = _label(resource_type)
    after = _desired(change)
    before = _previous(change)

    consequence = (
        "Secret material or a credential lease can be revoked, overwritten, or exposed."
        if _is_secret_state(resource_type)
        else "Authentication, authorization, encryption, audit, or secrets delivery can change."
    )
    deleted = _delete(label, action_set, consequence)
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []

    if _is_secret_state(resource_type):
        return [_secret_state_result(label, resource_type, after)]
    if _is_policy(resource_type):
        return [_policy_result(label, resource_type, after)]
    if _is_auth_identity(resource_type):
        return [_auth_identity_result(label, resource_type, after)]
    if _is_crypto_pki(resource_type):
        return [_crypto_result(label, resource_type, after)]
    if _is_secret_engine(resource_type):
        return [_secret_engine_result(label, resource_type, after)]
    if _is_audit(resource_type):
        return [_audit_result(label, after)]
    if _is_external_delivery(resource_type):
        return [_external_result(label, resource_type, after)]
    if _is_plugin(resource_type):
        return [_plugin_result(label, after)]
    if resource_type in _PLATFORM_RESOURCES:
        return [_platform_result(label, resource_type, before, after)]
    return [
        RuleResult(
            "review",
            f"This Vault {label} change affects a security control-plane resource. Review "
            "namespace and mount scope, policies, identity, state exposure, dependent clients, "
            "lease/revocation behavior, audit evidence, and rollback.",
        )
    ]


def _is_secret_state(resource_type: str) -> bool:
    return resource_type in _SECRET_STATE_RESOURCES


def _is_policy(resource_type: str) -> bool:
    return resource_type in _POLICY_RESOURCES or resource_type.endswith("_policies")


def _is_auth_identity(resource_type: str) -> bool:
    return any(
        token in resource_type
        for token in (
            "_auth_backend",
            "identity_",
            "_auth_backend_",
            "mfa_",
            "github_team",
            "github_user",
            "token_auth_backend_role",
            "userpass_auth_backend_user",
        )
    )


def _is_crypto_pki(resource_type: str) -> bool:
    return any(
        token in resource_type
        for token in (
            "pki_",
            "keymgmt_",
            "kmip_",
            "transit_",
            "ssh_secret_backend_ca",
            "managed_keys",
        )
    )


def _is_secret_engine(resource_type: str) -> bool:
    if resource_type in {"vault_mount", "vault_generic_endpoint"}:
        return True
    return any(
        token in resource_type
        for token in (
            "_secret_backend",
            "_secret_role",
            "_secrets_mount",
            "mongodbatlas_secret_",
            "nomad_secret_",
            "os_secret_",
            "terraform_cloud_secret_",
        )
    )


def _is_audit(resource_type: str) -> bool:
    return resource_type in {"vault_audit", "vault_audit_request_header"}


def _is_external_delivery(resource_type: str) -> bool:
    return resource_type.startswith("vault_secrets_sync_")


def _is_plugin(resource_type: str) -> bool:
    return resource_type in {
        "vault_plugin",
        "vault_plugin_pinned_version",
        "vault_plugin_runtime",
    }


def _secret_state_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    details: list[str] = [
        "persist secret material, generated credentials, or tokens in Terraform plan/state"
    ]
    if _contains(after, "root", "sudo", "*"):
        details.append("grant root, sudo, or wildcard capability")
    if resource_type == "vault_token":
        if _any_false(after, "renewable"):
            details.append("create a non-renewable token")
        if _any_true(after, "no_parent"):
            details.append("create an orphan token outside normal parent revocation")
    return RuleResult(
        "dangerous",
        f"This Vault {label} change can {'; '.join(details)}. Treat state, saved plans, CI "
        "artifacts, logs, and backups as secret-bearing; review least privilege, TTL, wrapping, "
        "rotation, revocation, and downstream rollout.",
    )


def _policy_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if _contains(after, "*", "root", "sudo") or _text_contains(
        after, 'path "*"', "capabilities = [\"sudo\"]", "capabilities=[\"sudo\"]"
    ):
        weaknesses.append("grant wildcard, root, or sudo capability")
    if _any_true(after, "enforcement_level", "unauthenticated_metrics_access"):
        weaknesses.append("change enforcement or unauthenticated access")
    if "quota" in resource_type and _any_true(after, "block_interval"):
        weaknesses.append("change request blocking behavior")
    return RuleResult(
        "dangerous",
        f"This Vault {label} change alters authorization, governance, password, control-group, "
        "or quota policy"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review path matching, capabilities, Sentinel/RGP enforcement, exceptions, identity "
        "attachments, denial behavior, break-glass access, and policy recovery.",
    )


def _auth_identity_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if _contains(after, "*", "0.0.0.0/0", "::/0", "root"):
        weaknesses.append("allow wildcard identity, network, audience, or root-policy scope")
    if _any_false(
        after,
        "disable_local_ca_jwt",
        "token_bound_cidrs",
        "use_token_groups",
        "verbose_oidc_logging",
    ):
        weaknesses.append("weaken an authentication binding or expose authentication details")
    if _any_true(
        after,
        "bypass_approval",
        "disable_bound_claims_parsing",
        "allow_token_display_name",
    ):
        weaknesses.append("bypass an authentication or approval guardrail")
    if resource_type.endswith("_login"):
        weaknesses.append("mint a Vault token during Terraform evaluation")
    return RuleResult(
        "dangerous",
        f"This Vault {label} change affects authentication, token issuance, MFA, identity aliases, "
        "groups, OIDC, or principal-policy attachment"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review issuer and audience, bound claims/CIDRs, TTL and use limits, alias uniqueness, "
        "MFA enforcement, token policies, state exposure, and revocation.",
    )


def _crypto_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if _any_true(
        after,
        "allow_any_name",
        "allow_bare_domains",
        "allow_glob_domains",
        "allow_ip_sans",
        "exportable",
        "deletion_allowed",
        "allow_plaintext_backup",
    ):
        weaknesses.append("broaden issuance or permit key export/deletion/plaintext backup")
    if _any_false(after, "require_cn", "enforce_hostnames", "key_usage"):
        weaknesses.append("weaken certificate-name or key-usage constraints")
    if "root_cert" in resource_type or "root_sign" in resource_type:
        weaknesses.append("create or sign with a certificate-authority trust anchor")
    if "rotate" in resource_type:
        weaknesses.append("rotate cryptographic key material used by dependent clients")
    return RuleResult(
        "dangerous",
        f"This Vault {label} change affects PKI, SSH CA, KMIP, managed keys, or transit "
        "cryptography"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review trust hierarchy, algorithms and key size, permitted names/usages, export and "
        "deletion controls, issuer/key rotation, CRL/OCSP behavior, backups, and client migration.",
    )


def _secret_engine_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if resource_type == "vault_generic_endpoint":
        weaknesses.append("write an arbitrary Vault API path with provider-defined semantics")
    if _contains(after, "*", "root", "admin", "owner") or _text_contains(
        after, "administratoraccess", "owner", "root"
    ):
        weaknesses.append("grant wildcard or administrative backend scope")
    if _any_false(after, "verify_connection", "tls", "seal_wrap"):
        weaknesses.append("disable connection verification, transport protection, or seal wrapping")
    if _any_true(after, "skip_static_role_import_rotation", "skip_import_rotation"):
        weaknesses.append("skip managed credential rotation")
    return RuleResult(
        "dangerous",
        f"This Vault {label} change configures a secrets engine, credential role, mount, or "
        "arbitrary endpoint"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review upstream administrative permissions, generated credential scope and TTL, "
        "rotation, revocation, connection TLS, namespace/mount path, state exposure, and recovery.",
    )


def _audit_result(label: str, after: dict[str, Any]) -> RuleResult:
    weaknesses: list[str] = []
    if _any_true(after, "log_raw", "log_raw_request", "log_raw_response"):
        weaknesses.append("record raw request or response data that may contain secrets")
    if _any_false(after, "hmac_accessor", "elide_list_responses", "exclude"):
        weaknesses.append("weaken audit HMAC or event coverage")
    return RuleResult(
        "dangerous" if weaknesses else "review",
        f"This Vault {label} change affects the security audit trail"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review device availability, raw-secret exposure, HMAC/accessor handling, request "
        "headers, event coverage, retention, integrity, failure behavior, and recovery.",
    )


def _external_result(
    label: str,
    resource_type: str,
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if _contains(after, "*", "all"):
        weaknesses.append("synchronize a wildcard secret scope")
    if _any_false(after, "enabled"):
        weaknesses.append("disable synchronization or delivery")
    if _any_true(after, "disable_strict_networking"):
        weaknesses.append("disable strict destination networking controls")
    return RuleResult(
        "dangerous",
        f"This Vault {label} change sends secrets across an external cloud, GitHub, or Vercel "
        "trust boundary"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review destination ownership, credentials in state, selected secret paths, conflict "
        "behavior, encryption, regional residency, rotation/revocation, and rollback.",
    )


def _plugin_result(label: str, after: dict[str, Any]) -> RuleResult:
    weaknesses: list[str] = []
    if not any(after.get(key) for key in ("sha256", "sha_256", "oci_image")):
        weaknesses.append("load plugin code without a visible digest or immutable image reference")
    return RuleResult(
        "dangerous",
        f"This Vault {label} change alters executable plugin code or its runtime"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review source provenance, digest/signature, command and arguments, runtime isolation, "
        "upgrade compatibility, privileges, rollout, and rollback.",
    )


def _platform_result(
    label: str,
    resource_type: str,
    before: dict[str, Any],
    after: dict[str, Any],
) -> RuleResult:
    weaknesses: list[str] = []
    if resource_type == "vault_sys_config_cors" and _contains(after, "*"):
        weaknesses.append("allow browser requests from any origin")
    if resource_type == "vault_mount":
        weaknesses.append("change a mount path, engine type, or lease boundary")
    if resource_type == "vault_namespace":
        weaknesses.append("change an enterprise isolation and administrative boundary")
    if resource_type == "vault_raft_snapshot_agent_config":
        weaknesses.append("send full Vault snapshots and credentials to external storage")
    if resource_type == "vault_rotation_policy":
        weaknesses.append("change automatic rotation of security-critical credentials")
    before_ttl = before.get("max_lease_ttl_seconds")
    after_ttl = after.get("max_lease_ttl_seconds")
    if isinstance(before_ttl, (int, float)) and isinstance(after_ttl, (int, float)):
        if after_ttl > before_ttl:
            weaknesses.append("increase the maximum credential lease lifetime")
    return RuleResult(
        "dangerous" if weaknesses else "review",
        f"This Vault {label} change affects namespaces, mounts, Raft recovery, rotation, UI, CORS, "
        "or platform behavior"
        + (f"; it can {'; '.join(weaknesses)}" if weaknesses else "")
        + ". Review isolation, lease/rotation behavior, administrative access, snapshot secrecy, "
        "browser origins, operational dependencies, recovery evidence, and rollback.",
    )
