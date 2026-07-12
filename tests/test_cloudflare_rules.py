from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from readtheplan.plan import analyze_plan_file

FIXTURES = Path(__file__).parent / "fixtures"


def _summary_for(*changes: dict):
    return analyze_plan_file(
        {
            "format_version": "1.2",
            "terraform_version": "1.11.4",
            "resource_changes": list(changes),
        }
    )


def _change(
    resource_type: str,
    actions: list[str],
    *,
    before=None,
    after=None,
) -> dict:
    return {
        "address": f"{resource_type}.example",
        "type": resource_type,
        "name": "example",
        "change": {"actions": actions, "before": before, "after": after},
    }


def test_cloudflare_provider_v5_fixture_receives_resource_aware_rules() -> None:
    plan = json.loads((FIXTURES / "cloudflare_plan_risky.json").read_text())
    changes = analyze_plan_file(plan).resource_changes
    by_address = {change.address: change for change in changes}

    assert len(changes) == 24
    assert Counter(change.risk for change in changes) == {
        "dangerous": 13,
        "irreversible": 5,
        "review": 6,
    }
    assert "pause Cloudflare proxying" in by_address["cloudflare_zone.production"].explanation
    assert "bypasses Cloudflare proxy" in by_address["cloudflare_dns_record.origin"].explanation
    assert "high-impact MX" in by_address["cloudflare_dns_record.mail"].explanation
    assert "DNSSEC configuration" in by_address["cloudflare_zone_dnssec.production"].explanation
    assert "actions skip" in by_address["cloudflare_ruleset.waf"].explanation
    assert "'min_tls_version' to '1.0'" in by_address["cloudflare_zone_setting.min_tls"].explanation
    assert "bind secrets" in by_address["cloudflare_workers_script.api"].explanation
    assert (
        "everyone, or wildcard"
        in by_address["cloudflare_zero_trust_access_policy.everyone"].explanation
    )
    assert by_address["cloudflare_r2_bucket.backups"].risk == "irreversible"
    assert by_address["cloudflare_d1_database.production"].risk == "irreversible"
    assert by_address["cloudflare_queue.deployments"].risk == "irreversible"
    assert "TLS, origin, or mTLS" in by_address["cloudflare_custom_ssl.production"].explanation
    assert "redirect or withdraw" in by_address["cloudflare_load_balancer.www"].explanation
    assert "disables or redirects" in by_address["cloudflare_logpush_job.security"].explanation
    assert by_address["cloudflare_zone_setting.cache_ttl"].risk == "review"
    assert by_address["cloudflare_dns_record.verification"].risk == "review"


@pytest.mark.parametrize(
    ("resource_type", "after", "phrase"),
    [
        ("cloudflare_record", {"type": "A", "proxied": False}, "DNS-only origin"),
        ("cloudflare_page_rule", {"actions": {"forwarding_url": {}}}, "edge policy"),
        ("cloudflare_worker_script", {"content": "addEventListener()"}, "executable code"),
        ("cloudflare_worker_route", {"pattern": "*/*"}, "production requests"),
        ("cloudflare_access_policy", {"decision": "bypass"}, "Zero Trust"),
        ("cloudflare_tunnel_config", {"ingress_rule": []}, "private-origin"),
    ],
)
def test_cloudflare_v4_aliases_keep_first_party_semantics(
    resource_type: str, after: dict, phrase: str
) -> None:
    change = _summary_for(_change(resource_type, ["create"], after=after)).resource_changes[0]
    assert change.risk in {"dangerous", "review"}
    assert phrase in change.explanation


def test_cloudflare_pinned_proxied_dns_record_is_review_not_false_safe() -> None:
    change = _summary_for(
        _change(
            "cloudflare_dns_record",
            ["create"],
            after={"name": "www.example.com", "type": "A", "proxied": True},
        )
    ).resource_changes[0]
    assert change.risk == "review"
    assert "name resolution" in change.explanation


def test_cloudflare_templated_minimum_tls_value_fails_conservatively() -> None:
    change = _summary_for(
        _change(
            "cloudflare_zone_setting",
            ["update"],
            before={"setting_id": "min_tls_version", "value": "1.2"},
            after={"setting_id": "min_tls_version", "value": "${var.minimum_tls}"},
        )
    ).resource_changes[0]
    assert change.risk == "dangerous"


@pytest.mark.parametrize(
    "resource_type",
    [
        "cloudflare_workers_kv",
        "cloudflare_workers_kv_namespace",
        "cloudflare_r2_bucket",
        "cloudflare_d1_database",
        "cloudflare_queue",
    ],
)
def test_cloudflare_data_deletions_are_irreversible(resource_type: str) -> None:
    change = _summary_for(
        _change(resource_type, ["delete"], before={"name": "production"})
    ).resource_changes[0]
    assert change.risk == "irreversible"
    assert "permanently lost" in change.explanation


def test_cloudflare_unrelated_provider_resource_keeps_generic_baseline() -> None:
    change = _summary_for(
        _change("example_dns_record", ["create"], after={"proxied": False})
    ).resource_changes[0]
    assert change.risk == "safe"
    assert "Cloudflare" not in change.explanation
