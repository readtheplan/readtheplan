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
            yield key
            yield from _walk(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _walk(item)
    else:
        yield value


def _contains(value: Any, *needles: str) -> bool:
    expected = {needle.lower() for needle in needles}
    return any(isinstance(item, str) and item.lower() in expected for item in _walk(value))


def _is_disabled(value: Any) -> bool:
    return value is False or str(value).lower() in {
        "0",
        "disabled",
        "essentially_off",
        "false",
        "flexible",
        "off",
    }


def _delete(label: str, action_set: set[str], *, irreversible: bool = False) -> RuleResult | None:
    if "delete" not in action_set:
        return None
    replacing = "create" in action_set
    risk = "dangerous" if replacing else "irreversible"
    if replacing:
        consequence = "Resource identity and dependent bindings can change during replacement."
    elif irreversible:
        consequence = "Stored data or queued work may be permanently lost."
    else:
        consequence = "The removed configuration may cause an immediate outage or trust gap."
    return RuleResult(
        risk,
        f"__TOOL__ will delete this Cloudflare {label}. {consequence} Verify exports, "
        "dependencies, rollback, and recovery before applying.",
    )


@register_rule("cloudflare_zone")
def _cloudflare_zone_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete("zone", action_set)
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    findings = ["change authoritative DNS, proxy, security, and certificate scope for a domain"]
    if after.get("paused") is True:
        findings.append("pause Cloudflare proxying and its security/performance protections")
    before_type = _previous(change).get("type")
    after_type = after.get("type")
    if before_type and after_type and before_type != after_type:
        findings.append("change full/partial/secondary/internal zone ownership mode")
    return [
        RuleResult(
            "dangerous" if len(findings) > 1 else "review",
            f"This Cloudflare zone can {'; '.join(findings)}. Review ownership validation, "
            "nameserver delegation, DNS continuity, proxy coverage, plan features, and rollback.",
        )
    ]


@register_rule("cloudflare_dns_record", "cloudflare_record", "cloudflare_zone_dnssec")
def _cloudflare_dns_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = "DNSSEC configuration" if resource_type.endswith("dnssec") else "DNS record"
    deleted = _delete(label, action_set)
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    findings = ["change public name resolution or domain routing"]
    record_type = str(after.get("type", "")).upper()
    if record_type in {"MX", "NS", "DS", "DNSKEY", "CAA"}:
        findings.append(f"change a high-impact {record_type} control record")
    if record_type in {"A", "AAAA", "CNAME"} and after.get("proxied") is False:
        findings.append("publish a DNS-only origin that bypasses Cloudflare proxy protections")
    if str(after.get("name", "")).startswith("*"):
        findings.append("affect wildcard hostnames")
    if resource_type.endswith("dnssec"):
        findings.append("change the chain of trust coordinated with the registrar")
    return [
        RuleResult(
            "dangerous" if len(findings) > 1 else "review",
            f"This Cloudflare {label} can {'; '.join(findings)}. Review TTL, record content, "
            "proxy/origin exposure, DNSSEC/registrar coordination, and dependent services.",
        )
    ]


@register_rule(
    "cloudflare_ruleset",
    "cloudflare_page_rule",
    "cloudflare_list",
    "cloudflare_list_item",
)
def _cloudflare_edge_policy_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete("edge policy or policy input", action_set)
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        after = _desired(change)
        actions = sorted(
            {
                str(item).lower()
                for item in _walk(after)
                if isinstance(item, str)
                and item.lower()
                in {
                    "block",
                    "challenge",
                    "execute",
                    "js_challenge",
                    "redirect",
                    "rewrite",
                    "route",
                    "skip",
                }
            }
        )
        detail = f" using actions {', '.join(actions)}" if actions else ""
        return [
            RuleResult(
                "dangerous",
                f"This Cloudflare edge policy changes WAF, routing, redirects, cache, or "
                f"request/response behavior{detail}. Review phase and scope, expressions, "
                "rule ordering, bypass/skip behavior, managed-rule references, and rollback.",
            )
        ]
    return []


@register_rule("cloudflare_zone_setting", "cloudflare_zone_settings_override")
def _cloudflare_zone_setting_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete("zone setting", action_set)
    if deleted is not None:
        return [deleted]
    if not ({"create", "update"} & action_set):
        return []
    after = _desired(change)
    setting_id = str(after.get("setting_id", "multiple settings"))
    value = after.get("value", after.get("enabled"))
    unsafe = False
    if setting_id in {
        "always_use_https",
        "browser_check",
        "hotlink_protection",
        "tls_1_3",
        "waf",
    }:
        unsafe = _is_disabled(value)
    elif setting_id in {"security_level", "ssl"}:
        unsafe = _is_disabled(value)
    elif setting_id == "min_tls_version":
        try:
            unsafe = float(str(value)) < 1.2
        except ValueError:
            unsafe = True
    return [
        RuleResult(
            "dangerous" if unsafe else "review",
            f"This Cloudflare zone-setting change sets {setting_id!r} to {value!r}. Review "
            "TLS/HTTPS enforcement, WAF and bot protections, cache behavior, compatibility, "
            "and the provider-v5 per-setting default that applies if it is removed.",
        )
    ]


@register_rule("cloudflare_workers_script", "cloudflare_worker_script")
def _cloudflare_worker_script_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete("Workers script", action_set)
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        after = _desired(change)
        findings = ["deploy executable code to Cloudflare's edge"]
        if _contains(after, "secret_text", "secret_key", "secrets_store_secret"):
            findings.append("bind secrets or secret-store values into the Worker")
        observability = after.get("observability")
        if isinstance(observability, dict) and observability.get("enabled") is False:
            findings.append("disable Worker observability")
        if after.get("compatibility_flags"):
            findings.append("enable runtime compatibility flags")
        return [
            RuleResult(
                "dangerous",
                f"This Cloudflare Worker can {'; '.join(findings)}. Review code provenance, "
                "module/runtime compatibility, bindings and secret scope, Durable Object "
                "migrations, egress, placement, observability, and rollback/version retention.",
            )
        ]
    return []


@register_rule("cloudflare_workers_route", "cloudflare_worker_route")
def _cloudflare_worker_route_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete("Workers route", action_set)
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        after = _desired(change)
        return [
            RuleResult(
                "dangerous",
                "This Cloudflare Workers route changes which production requests execute "
                f"edge code (pattern={after.get('pattern')!r}). Review wildcard scope, "
                "script binding, fail-open behavior, route precedence, and rollback.",
            )
        ]
    return []


@register_rule(
    "cloudflare_zero_trust_access_application",
    "cloudflare_access_application",
    "cloudflare_zero_trust_access_policy",
    "cloudflare_access_policy",
    "cloudflare_zero_trust_access_group",
    "cloudflare_zero_trust_gateway_policy",
    "cloudflare_teams_rules",
)
def _cloudflare_zero_trust_policy_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete("Zero Trust application, group, or policy", action_set)
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        after = _desired(change)
        findings = ["change who can reach protected applications, networks, or SaaS resources"]
        if _contains(after, "bypass", "everyone") or _contains(after, "*"):
            findings.append("include a bypass, everyone, or wildcard selector")
        if after.get("session_duration"):
            findings.append("change authenticated session lifetime")
        return [
            RuleResult(
                "dangerous",
                f"This Cloudflare Zero Trust change can {'; '.join(findings)}. Review policy "
                "order and action, include/exclude/require logic, identity-provider groups, "
                "service tokens, device posture, session duration, and emergency access.",
            )
        ]
    return []


@register_rule(
    "cloudflare_zero_trust_tunnel_cloudflared",
    "cloudflare_tunnel",
    "cloudflare_zero_trust_tunnel_cloudflared_config",
    "cloudflare_tunnel_config",
    "cloudflare_zero_trust_tunnel_cloudflared_route",
)
def _cloudflare_tunnel_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete("Tunnel or Tunnel route/configuration", action_set)
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                "This Cloudflare Tunnel change alters private-origin reachability and ingress "
                "routing. Review tunnel credentials, connector redundancy, hostname/service "
                "routes, origin TLS, catch-all behavior, private CIDRs, and rollback.",
            )
        ]
    return []


@register_rule(
    "cloudflare_r2_bucket",
    "cloudflare_d1_database",
    "cloudflare_workers_kv_namespace",
    "cloudflare_workers_kv",
    "cloudflare_queue",
)
def _cloudflare_data_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("cloudflare_").replace("_", " ")
    deleted = _delete(label, action_set, irreversible=True)
    if deleted is not None:
        return [deleted]
    if "update" in action_set:
        return [
            RuleResult(
                "dangerous",
                f"This Cloudflare {label} update can change data location, jurisdiction, "
                "retention, schema, or producer/consumer behavior. Review backups/exports, "
                "migration compatibility, binding consumers, and rollback.",
            )
        ]
    if "create" in action_set:
        return [
            RuleResult(
                "review",
                f"__TOOL__ will create Cloudflare {label} storage or messaging state. Review "
                "location/jurisdiction, retention, encryption, access bindings, and recovery.",
            )
        ]
    return []


@register_rule(
    "cloudflare_load_balancer",
    "cloudflare_load_balancer_pool",
    "cloudflare_healthcheck",
)
def _cloudflare_traffic_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    label = resource_type.removeprefix("cloudflare_").replace("_", " ")
    deleted = _delete(label, action_set)
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                f"This Cloudflare {label} change can redirect or withdraw production traffic. "
                "Review origin addresses and weights, health monitors, steering/fallback, "
                "session affinity, enabled state, regional behavior, and rollback.",
            )
        ]
    return []


@register_rule(
    "cloudflare_custom_ssl",
    "cloudflare_origin_ca_certificate",
    "cloudflare_authenticated_origin_pulls_certificate",
    "cloudflare_hostname_tls_setting",
    "cloudflare_api_shield_mtls_certificate",
)
def _cloudflare_tls_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete("TLS, origin, or mTLS certificate/configuration", action_set)
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        after = _desired(change)
        disabled = _is_disabled(after.get("setting", after.get("value", after.get("enabled"))))
        return [
            RuleResult(
                "dangerous",
                "This Cloudflare TLS change can alter browser-to-edge or edge-to-origin trust"
                + (" and appears to disable TLS enforcement" if disabled else "")
                + ". Review hostname coverage, key custody, expiry/rotation, validation mode, "
                "origin deployment order, mTLS clients, and rollback.",
            )
        ]
    return []


@register_rule("cloudflare_api_token", "cloudflare_account_member")
def _cloudflare_identity_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete("API token or account membership", action_set)
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                "This Cloudflare identity change grants or changes API/account permissions. "
                "Review least-privilege permission groups, account/zone resources, conditions, "
                "token lifetime, member roles, secret delivery, and revocation ownership.",
            )
        ]
    return []


@register_rule("cloudflare_logpush_job")
def _cloudflare_logpush_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete("Logpush job", action_set)
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        after = _desired(change)
        disabled = after.get("enabled") is False
        destination_changed = _previous(change).get("destination_conf") not in {
            None,
            after.get("destination_conf"),
        }
        return [
            RuleResult(
                "dangerous" if disabled or destination_changed else "review",
                "This Cloudflare Logpush change alters security/traffic evidence delivery"
                + (" and disables or redirects the job" if disabled or destination_changed else "")
                + ". Review dataset, filters/fields, destination credentials, encryption, "
                "retention, duplicate/gap handling, and downstream alerting.",
            )
        ]
    return []


@register_rule("cloudflare_pages_project", "cloudflare_pages_domain")
def _cloudflare_pages_candidates(
    resource_type: str,
    action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    deleted = _delete("Pages project or custom domain", action_set)
    if deleted is not None:
        return [deleted]
    if {"create", "update"} & action_set:
        return [
            RuleResult(
                "dangerous",
                "This Cloudflare Pages change can alter production builds, environment "
                "variables, deployment branches, Functions execution, or custom-domain "
                "routing. Review repository/build trust, secret scope, preview exposure, "
                "DNS/TLS activation order, and rollback.",
            )
        ]
    return []
