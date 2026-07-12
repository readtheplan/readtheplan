from __future__ import annotations

import configparser
import json
import re
from pathlib import Path
from typing import Any

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class GrafanaInputError(ValueError):
    """Raised when Grafana configuration is invalid or unrecognizable."""


_INI_SECTIONS = {
    "analytics",
    "auth",
    "auth.anonymous",
    "auth.basic",
    "auth.generic_oauth",
    "auth.github",
    "auth.gitlab",
    "auth.google",
    "auth.jwt",
    "auth.proxy",
    "database",
    "dataproxy",
    "live",
    "plugins",
    "remote_cache",
    "security",
    "server",
    "smtp",
    "users",
}
_PROVISIONING_KEYS = {
    "apps",
    "contactPoints",
    "datasources",
    "deleteContactPoints",
    "deleteDatasources",
    "deleteMuteTimes",
    "deleteRules",
    "groups",
    "muteTimes",
    "policies",
    "providers",
    "roles",
    "teams",
    "templates",
}
_SECRET_KEY = re.compile(
    r"(?:password|passwd|secret|token|api_?key|client_?secret|private_?key|credentials?)",
    re.IGNORECASE,
)


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _enabled(value: Any) -> bool:
    return value is True or str(value).strip().lower() in {"1", "true", "yes", "on"}


def _disabled(value: Any) -> bool:
    return value is False or str(value).strip().lower() in {"0", "false", "no", "off"}


def parse_grafana_config(source: str) -> dict[str, Any]:
    """Parse Grafana INI or provisioning YAML/JSON without resolving secrets."""
    if not source.strip():
        raise GrafanaInputError("input is empty")

    document: Any = None
    try:
        document = json.loads(source)
    except json.JSONDecodeError:
        try:
            document = yaml.safe_load(source)
        except yaml.YAMLError:
            document = None
    if isinstance(document, dict) and _PROVISIONING_KEYS & set(document):
        return {"grafana_config": {"artifact_type": "provisioning", "document": document}}

    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str  # preserve Grafana option spelling for useful addresses
    try:
        parser.read_string(source)
    except configparser.Error as exc:
        raise GrafanaInputError(str(exc)) from exc
    sections = set(parser.sections())
    if not sections & _INI_SECTIONS:
        raise GrafanaInputError("input is not recognizable as Grafana configuration")
    ini = {section: dict(parser.items(section)) for section in parser.sections()}
    return {"grafana_config": {"artifact_type": "ini", "document": ini}}


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


class GrafanaAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "grafana"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        config = input_data.get("grafana_config")
        return (
            isinstance(config, dict)
            and config.get("artifact_type") in {"ini", "provisioning"}
            and isinstance(config.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        config = input_data["grafana_config"]
        document = config["document"]
        changes = (
            self._ini(document)
            if config["artifact_type"] == "ini"
            else self._provisioning(document)
        )
        changes.append(
            _change(
                "grafana.effective_configuration",
                "effective_configuration",
                "review",
                "Effective Grafana behavior also depends on environment overrides, command-line "
                "flags, provisioned files, plugins, database state, reverse proxies, and network "
                "policy.",
            )
        )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"grafana_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )

    def _ini(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        server = _mapping(document.get("server"))
        protocol = str(server.get("protocol", "http")).lower()
        if protocol == "http":
            changes.append(
                _change(
                    "server.protocol",
                    "plaintext_server",
                    "dangerous",
                    "Grafana serves plaintext HTTP unless a trusted reverse proxy terminates TLS.",
                )
            )
        if str(server.get("http_addr", "")).strip() in {"0.0.0.0", "::"}:
            changes.append(
                _change(
                    "server.http_addr",
                    "public_listener",
                    "dangerous",
                    "Grafana listens on every network interface.",
                )
            )
        if server.get("root_url") is not None or _enabled(server.get("serve_from_sub_path")):
            changes.append(
                _change(
                    "server.root_url",
                    "external_url",
                    "review",
                    "Grafana external URL and sub-path settings affect redirects, cookies, and "
                    "reverse-proxy routing.",
                )
            )

        security = _mapping(document.get("security"))
        for key, explanation in (
            (
                "admin_password",
                "Grafana configuration contains or references the initial admin credential.",
            ),
            (
                "secret_key",
                "Grafana configuration contains or references its signing and encryption secret.",
            ),
        ):
            if security.get(key) is not None:
                changes.append(
                    _change(f"security.{key}", "secret_material", "dangerous", explanation)
                )
        if _enabled(security.get("allow_embedding")):
            changes.append(
                _change(
                    "security.allow_embedding",
                    "browser_security",
                    "dangerous",
                    "Grafana permits embedding, increasing clickjacking and cross-origin exposure.",
                )
            )
        if _disabled(security.get("cookie_secure")):
            changes.append(
                _change(
                    "security.cookie_secure",
                    "insecure_cookie",
                    "dangerous",
                    "Grafana authentication cookies are allowed over non-HTTPS connections.",
                )
            )
        if (
            _disabled(security.get("cookie_samesite"))
            or str(security.get("cookie_samesite", "")).lower() == "none"
        ):
            changes.append(
                _change(
                    "security.cookie_samesite",
                    "insecure_cookie",
                    "dangerous",
                    "Grafana authentication cookies lack normal cross-site request protection.",
                )
            )
        if _enabled(security.get("disable_brute_force_login_protection")):
            changes.append(
                _change(
                    "security.disable_brute_force_login_protection",
                    "authentication_hardening",
                    "dangerous",
                    "Grafana brute-force login protection is disabled.",
                )
            )

        anonymous = _mapping(document.get("auth.anonymous"))
        if _enabled(anonymous.get("enabled")):
            role = str(anonymous.get("org_role", "Viewer"))
            changes.append(
                _change(
                    "auth.anonymous",
                    "anonymous_access",
                    "dangerous",
                    f"Unauthenticated visitors receive the Grafana {role} role and can query "
                    "accessible data sources.",
                )
            )
        auth_proxy = _mapping(document.get("auth.proxy"))
        if _enabled(auth_proxy.get("enabled")):
            changes.append(
                _change(
                    "auth.proxy",
                    "trusted_auth_proxy",
                    "dangerous",
                    "Grafana trusts identity supplied by an upstream proxy.",
                )
            )
            if not str(auth_proxy.get("whitelist", "")).strip():
                changes.append(
                    _change(
                        "auth.proxy.whitelist",
                        "unrestricted_auth_proxy",
                        "dangerous",
                        "Auth proxy mode has no source-IP whitelist, so direct header spoofing "
                        "may create authenticated sessions.",
                    )
                )
        for section in (
            "auth.jwt",
            "auth.generic_oauth",
            "auth.github",
            "auth.gitlab",
            "auth.google",
        ):
            auth = _mapping(document.get(section))
            if _enabled(auth.get("enabled")):
                changes.append(
                    _change(
                        section,
                        "external_authentication",
                        "review",
                        f"Grafana {section} delegates authentication and may map "
                        "organization roles.",
                    )
                )
                changes.extend(self._secret_fields(auth, section))
                if _enabled(auth.get("allow_assign_grafana_admin")):
                    changes.append(
                        _change(
                            f"{section}.allow_assign_grafana_admin",
                            "admin_role_mapping",
                            "dangerous",
                            "External identity claims can grant Grafana server "
                            "administrator access.",
                        )
                    )

        users = _mapping(document.get("users"))
        if _enabled(users.get("allow_sign_up")):
            changes.append(
                _change(
                    "users.allow_sign_up",
                    "self_registration",
                    "dangerous",
                    "Grafana permits users to create their own local accounts.",
                )
            )
        if str(users.get("auto_assign_org_role", "Viewer")).lower() in {"editor", "admin"}:
            changes.append(
                _change(
                    "users.auto_assign_org_role",
                    "privileged_default_role",
                    "dangerous",
                    "New users automatically receive a privileged organization role.",
                )
            )

        database = _mapping(document.get("database"))
        if database:
            changes.append(
                _change(
                    "database",
                    "database",
                    "review",
                    "Grafana database settings control persistent users, dashboards, "
                    "alerts, and secrets.",
                )
            )
            changes.extend(self._secret_fields(database, "database"))
            if str(database.get("ssl_mode", "")).lower() in {"disable", "false"}:
                changes.append(
                    _change(
                        "database.ssl_mode",
                        "plaintext_database",
                        "dangerous",
                        "Grafana permits an unencrypted connection to its external database.",
                    )
                )
        smtp = _mapping(document.get("smtp"))
        if _enabled(smtp.get("enabled")):
            changes.append(
                _change(
                    "smtp",
                    "notification_egress",
                    "review",
                    "Grafana sends email through an external SMTP service.",
                )
            )
            changes.extend(self._secret_fields(smtp, "smtp"))
            if str(smtp.get("startTLS_policy", "")).lower() in {
                "nostarttls",
                "no_starttls",
                "false",
            }:
                changes.append(
                    _change(
                        "smtp.startTLS_policy",
                        "plaintext_smtp",
                        "dangerous",
                        "Grafana SMTP delivery does not require STARTTLS.",
                    )
                )
        plugins = _mapping(document.get("plugins"))
        if str(plugins.get("allow_loading_unsigned_plugins", "")).strip():
            changes.append(
                _change(
                    "plugins.allow_loading_unsigned_plugins",
                    "unsigned_plugin",
                    "dangerous",
                    "Grafana is allowed to execute unsigned server or frontend plugin code.",
                )
            )
        live = _mapping(document.get("live"))
        if "*" in str(live.get("allowed_origins", "")):
            changes.append(
                _change(
                    "live.allowed_origins",
                    "wildcard_origin",
                    "dangerous",
                    "Grafana Live accepts WebSocket connections from arbitrary browser origins.",
                )
            )
        dataproxy = _mapping(document.get("dataproxy"))
        if dataproxy:
            changes.append(
                _change(
                    "dataproxy",
                    "data_proxy",
                    "review",
                    "Grafana data proxy settings govern outbound queries to configured backends.",
                )
            )
        return changes

    def _provisioning(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if _enabled(document.get("prune")) or document.get("deleteDatasources") is not None:
            changes.append(
                _change(
                    "datasources.deletion",
                    "resource_deletion",
                    "dangerous",
                    "Grafana provisioning can delete data sources and break dashboards, "
                    "alerts, or queries.",
                )
            )
        for index, datasource in enumerate(_items(document.get("datasources"))):
            address = f"datasources[{index}]"
            if not isinstance(datasource, dict):
                changes.append(
                    _change(
                        address, "unresolved", "review", "Grafana data source is not an object."
                    )
                )
                continue
            changes.append(
                _change(
                    address,
                    "datasource",
                    "review",
                    "Grafana provisions a backend that users and alerts can query "
                    "through the server.",
                )
            )
            url = str(datasource.get("url", ""))
            if url.lower().startswith("http://"):
                changes.append(
                    _change(
                        f"{address}.url",
                        "plaintext_datasource",
                        "dangerous",
                        "Grafana connects to this data source over plaintext HTTP.",
                    )
                )
            if str(datasource.get("access", "proxy")).lower() in {"direct", "browser"}:
                changes.append(
                    _change(
                        f"{address}.access",
                        "browser_datasource",
                        "dangerous",
                        "Browser-direct access exposes the data-source endpoint to users "
                        "and bypasses server-side controls.",
                    )
                )
            json_data = _mapping(datasource.get("jsonData"))
            if _enabled(json_data.get("tlsSkipVerify")):
                changes.append(
                    _change(
                        f"{address}.jsonData.tlsSkipVerify",
                        "insecure_tls",
                        "dangerous",
                        "Grafana does not verify the data source TLS certificate.",
                    )
                )
            for key in ("oauthPassThru", "forwardOauthIdentity", "forwardCookies"):
                if _enabled(json_data.get(key)) or (key == "forwardCookies" and json_data.get(key)):
                    changes.append(
                        _change(
                            f"{address}.jsonData.{key}",
                            "identity_forwarding",
                            "dangerous",
                            "Grafana forwards user identity or browser credentials to the "
                            "data source.",
                        )
                    )
            if (
                _enabled(datasource.get("basicAuth"))
                or datasource.get("secureJsonData") is not None
            ):
                changes.append(
                    _change(
                        f"{address}.credentials",
                        "secret_material",
                        "dangerous",
                        "Grafana stores credentials for server-side data-source access.",
                    )
                )
            if _enabled(datasource.get("editable")):
                changes.append(
                    _change(
                        f"{address}.editable",
                        "mutable_provisioning",
                        "review",
                        "Grafana users may modify this provisioned data source through the UI.",
                    )
                )

        for index, provider in enumerate(_items(document.get("providers"))):
            address = f"providers[{index}]"
            if not isinstance(provider, dict):
                changes.append(
                    _change(address, "unresolved", "review", "Dashboard provider is not an object.")
                )
                continue
            changes.append(
                _change(
                    address,
                    "dashboard_provider",
                    "review",
                    "Grafana imports dashboards from an external provisioning source.",
                )
            )
            if _disabled(provider.get("disableDeletion")) or "disableDeletion" not in provider:
                changes.append(
                    _change(
                        f"{address}.disableDeletion",
                        "resource_deletion",
                        "dangerous",
                        "Removing provisioned dashboard files can delete dashboards from Grafana.",
                    )
                )
            if _enabled(provider.get("allowUiUpdates")):
                changes.append(
                    _change(
                        f"{address}.allowUiUpdates",
                        "mutable_provisioning",
                        "review",
                        "UI edits can diverge from and later be overwritten by the "
                        "dashboard source.",
                    )
                )
            options = _mapping(provider.get("options"))
            if options.get("path") is not None:
                changes.append(
                    _change(
                        f"{address}.options.path",
                        "filesystem_import",
                        "review",
                        "Grafana reads dashboard definitions from the local filesystem.",
                    )
                )

        for key, kind, risk, explanation in (
            (
                "groups",
                "alert_rules",
                "review",
                "Grafana provisions alert rule groups that execute queries and evaluate "
                "operational conditions.",
            ),
            (
                "contactPoints",
                "notification_egress",
                "dangerous",
                "Grafana provisions contact points that send alert data to external systems.",
            ),
            (
                "policies",
                "notification_policy",
                "review",
                "Grafana provisioning changes alert routing, grouping, and delivery policy.",
            ),
            (
                "muteTimes",
                "alert_suppression",
                "dangerous",
                "Grafana provisioning can suppress alerts during configured time intervals.",
            ),
            (
                "templates",
                "notification_template",
                "review",
                "Grafana provisions notification templates used in outbound alerts.",
            ),
            (
                "apps",
                "plugin",
                "dangerous",
                "Grafana provisioning configures an application plugin that can extend "
                "server and UI behavior.",
            ),
        ):
            if document.get(key) is not None:
                changes.append(_change(key, kind, risk, explanation))
        for key in ("deleteRules", "deleteContactPoints", "deleteMuteTimes"):
            if document.get(key) is not None:
                changes.append(
                    _change(
                        key,
                        "resource_deletion",
                        "dangerous",
                        f"Grafana provisioning deletes resources listed in {key}.",
                    )
                )

        for index, role in enumerate(_items(document.get("roles"))):
            address = f"roles[{index}]"
            changes.append(
                _change(
                    address,
                    "access_control",
                    "dangerous",
                    "Grafana provisioning creates or changes a custom authorization role.",
                )
            )
            if isinstance(role, dict):
                permissions = _items(role.get("permissions"))
                if any("*" in str(permission) for permission in permissions):
                    changes.append(
                        _change(
                            f"{address}.permissions",
                            "wildcard_permission",
                            "dangerous",
                            "Grafana custom role contains wildcard actions or scopes.",
                        )
                    )
        if document.get("teams") is not None:
            changes.append(
                _change(
                    "teams",
                    "role_assignment",
                    "dangerous",
                    "Grafana provisioning assigns authorization roles to teams or users.",
                )
            )
        changes.extend(self._secret_fields(document, "provisioning"))
        return changes

    def _secret_fields(self, value: Any, address: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if not isinstance(value, dict):
            return changes
        for key, child in value.items():
            field_address = f"{address}.{key}"
            if key in {"secureJsonData", "secure_settings"} or _SECRET_KEY.search(str(key)):
                changes.append(
                    _change(
                        field_address,
                        "secret_material",
                        "dangerous",
                        "Grafana configuration contains or references credential material.",
                    )
                )
            elif isinstance(child, dict):
                changes.extend(self._secret_fields(child, field_address))
            elif isinstance(child, list):
                for index, item in enumerate(child):
                    if isinstance(item, dict):
                        changes.extend(self._secret_fields(item, f"{field_address}[{index}]"))
        return changes


def analyze_grafana(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    adapter = GrafanaAdapter()
    changes = adapter.analyze(data, tool_name="grafana")
    summary = PlanSummary(
        path=Path("grafana://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="grafana")
    gate["adapter"] = "grafana"
    gate["total_changes"] = len(changes)
    return gate
