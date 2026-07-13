from __future__ import annotations

import fnmatch
import io
import json
import os
import re
from collections import Counter
from collections.abc import Sequence
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from readtheplan.rules import RISK_ORDER

PROJECT_SCAN_SCHEMA = "rtp-agent-gate-v1"
PROJECT_SCAN_ADAPTER = "project-scan"

DEFAULT_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".next",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".terraform",
        ".terragrunt-cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "site-packages",
        "vendor",
        "venv",
    }
)

_SYSTEMD_SUFFIXES = (
    ".service",
    ".socket",
    ".timer",
    ".mount",
    ".automount",
    ".path",
    ".slice",
    ".target",
    ".swap",
)
_YAML_SUFFIXES = (".yaml", ".yml")
_CONFIG_BASENAME_SOURCE_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".go",
        ".h",
        ".hpp",
        ".java",
        ".js",
        ".json",
        ".md",
        ".py",
        ".pyi",
        ".rb",
        ".rs",
        ".sh",
        ".toml",
        ".ts",
        ".txt",
        ".yaml",
        ".yml",
    }
)
_KUBERNETES_HINT = re.compile(r"(?ms)^\s*apiVersion\s*:\s*[^\s#]+.*?^\s*kind\s*:\s*[^\s#]+")
_ANSIBLE_HINT = re.compile(r"(?ms)^\s*-?\s*hosts\s*:.*?^\s*(?:tasks|roles)\s*:")


class ProjectScanError(ValueError):
    """Raised when a project scan cannot be performed safely."""


@dataclass(frozen=True)
class DiscoveredInput:
    path: Path
    relative_path: str
    tool: str
    size: int


def discover_project_inputs(
    root: Path,
    *,
    excludes: Sequence[str] = (),
    max_files: int = 500,
) -> list[DiscoveredInput]:
    """Find high-confidence infrastructure inputs without following symlinks."""
    if max_files < 1:
        raise ProjectScanError("max_files must be at least 1")
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise ProjectScanError(f"scan path cannot be resolved: {exc}") from exc

    if resolved.is_file():
        candidates = [resolved]
        scan_root = resolved.parent
    elif resolved.is_dir():
        candidates = _walk_files(resolved, excludes)
        scan_root = resolved
    else:
        raise ProjectScanError("scan path must be a regular file or directory")

    discovered: list[DiscoveredInput] = []
    for path in candidates:
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(scan_root).as_posix()
        if _excluded(relative, excludes):
            continue
        tool = identify_project_input(path, relative)
        if tool is None:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            size = -1
        discovered.append(
            DiscoveredInput(
                path=path,
                relative_path=relative,
                tool=tool,
                size=size,
            )
        )
        if len(discovered) > max_files:
            raise ProjectScanError(
                f"scan discovered more than {max_files} supported inputs; narrow the path, "
                "add --exclude patterns, or raise --max-files explicitly"
            )
    return sorted(discovered, key=lambda item: (item.relative_path.casefold(), item.tool))


def _walk_files(root: Path, excludes: Sequence[str]) -> list[Path]:
    paths: list[Path] = []
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        kept: list[str] = []
        for directory in sorted(directories, key=str.casefold):
            candidate = current_path / directory
            relative = candidate.relative_to(root).as_posix()
            if directory in DEFAULT_EXCLUDED_DIRECTORIES:
                continue
            if candidate.is_symlink() or _excluded(relative, excludes, directory=True):
                continue
            kept.append(directory)
        directories[:] = kept
        for filename in sorted(files, key=str.casefold):
            paths.append(current_path / filename)
    return paths


def _excluded(relative: str, patterns: Sequence[str], *, directory: bool = False) -> bool:
    normalized = relative.replace("\\", "/")
    candidates = (normalized, f"{normalized}/" if directory else normalized)
    return any(
        fnmatch.fnmatchcase(candidate, pattern.replace("\\", "/"))
        for pattern in patterns
        for candidate in candidates
    )


def identify_project_input(path: Path, relative_path: str) -> str | None:
    """Return the adapter command for one high-confidence path/content pair."""
    relative = PurePosixPath(relative_path)
    lowered = relative_path.casefold()
    name = relative.name.casefold()
    suffix = path.suffix.casefold()
    parts = tuple(part.casefold() for part in relative.parts)

    if name == ".terraform.lock.hcl":
        return "terraform-lock"
    if name == "terragrunt.hcl" or name.endswith(".terragrunt.hcl"):
        return "terragrunt"
    if name.endswith((".tm.hcl", ".tm.json", ".tmgen")) or name == "terramate.tm.hcl":
        return "terramate"
    if lowered.endswith(".spacelift/config.yml") or lowered.endswith(".spacelift/config.yaml"):
        return "spacelift"
    if "cdk.out" in parts and (name == "manifest.json" or name.endswith(".assets.json")):
        return "cdk"
    if name in {"pulumi.yaml", "pulumi.yml", "pulumipolicy.yaml", "pulumipolicy.yml"}:
        return "pulumi-project"
    if name.startswith("pulumi.") and suffix in _YAML_SUFFIXES:
        return "pulumi-project"

    if name == "ansible.cfg":
        return "ansible-project"
    if name in {"playbook.yml", "playbook.yaml"} or (
        name.startswith("playbook-") and suffix in _YAML_SUFFIXES
    ):
        return "ansible"
    if _named_config_variant(name, suffix, "jenkinsfile"):
        return "jenkins"
    if name in {"jenkins.yaml", "jenkins.yml"} and any(
        part in {"jenkins", "jcasc", "casc_configs"} for part in parts[:-1]
    ):
        return "jenkins-jcasc"
    if name in {"policyfile.rb", "policyfile.lock.json"}:
        return "chef-project"
    if suffix == ".rb" and "recipes" in parts:
        return "chef"
    if name in {"puppetfile", "hiera.yaml", "hiera.yml"}:
        return "puppet-project"
    if suffix == ".pp":
        return "puppet"
    if suffix == ".sls":
        return "salt"
    if name in {"master", "minion", "roster"} and any(
        part in {"salt", "saltstack"} for part in parts[:-1]
    ):
        return "salt-project"
    if suffix == ".nix" or name == "flake.lock":
        return "nix"
    if name.endswith((".dsc.yaml", ".dsc.yml", ".dsc.json")):
        return "dsc"
    if suffix == ".ps1" and "dsc" in name:
        return "dsc"
    if suffix == ".cf":
        return "cfengine"
    if suffix == ".rego" or name == "conftest.toml":
        return "opa"
    if suffix == ".sentinel" or name in {"sentinel.hcl", "sentinel.json"}:
        return "sentinel"

    if _named_config_variant(name, suffix, "vagrantfile"):
        return "vagrant"
    if _named_config_variant(name, suffix, "dockerfile", "containerfile"):
        return "dockerfile"
    if name in {
        "compose.yaml",
        "compose.yml",
        "docker-compose.yaml",
        "docker-compose.yml",
    }:
        return "docker-compose"
    if name == ".gitlab-ci.yml" or name == ".gitlab-ci.yaml":
        return "gitlab-ci"
    if lowered.startswith(".github/workflows/") and suffix in _YAML_SUFFIXES:
        return "github-actions"
    if lowered in {".circleci/config.yml", ".circleci/config.yaml"}:
        return "circleci"
    if name in {"azure-pipelines.yml", "azure-pipelines.yaml"}:
        return "azure-pipelines"
    if name in {"bitbucket-pipelines.yml", "bitbucket-pipelines.yaml"}:
        return "bitbucket-pipelines"
    if ".buildkite" in parts and name in {"pipeline.yml", "pipeline.yaml"}:
        return "buildkite"
    if name in {"atlantis.yaml", "atlantis.yml"} or (
        name in {"repos.yaml", "repos.yml"}
        and any(part in {".atlantis", "atlantis"} for part in parts[:-1])
    ):
        return "atlantis"

    if name in {"chart.yaml", "chart.yml"} or ("templates" in parts and suffix in _YAML_SUFFIXES):
        return "helm"
    if name in {"kustomization.yaml", "kustomization.yml"}:
        return "kustomize"
    if name.startswith("helmfile") and (
        suffix in _YAML_SUFFIXES or name.endswith((".gotmpl", ".lock"))
    ):
        return "helmfile"
    if name.startswith("skaffold") and suffix in _YAML_SUFFIXES:
        return "skaffold"
    if name.startswith("devspace") and suffix in _YAML_SUFFIXES:
        return "devspace"
    if _named_config_variant(name, suffix, "tiltfile"):
        return "tilt"
    if suffix == ".cue" or lowered.endswith("cue.mod/module.cue"):
        return "cue"
    if name in {"spec.json", "main.jsonnet"} and "environments" in parts:
        return "tanka"
    if suffix == ".jsonnet" or name in {"jsonnetfile.json", "jsonnetfile.lock.json"}:
        return "jsonnet"
    if name in {"vendir.yml", "vendir.yaml", "vendir.lock.yml", "vendir.lock.yaml"}:
        return "vendir"
    if name in {"kbld.yml", "kbld.yaml"}:
        return "kbld"
    if name in {"kapp-config.yml", "kapp-config.yaml"}:
        return "kapp"
    if name in {"serverless.yml", "serverless.yaml"}:
        return "serverless"

    if name.endswith((".nomad.hcl", ".nomad.json")):
        return "nomad"
    if name.endswith((".pkr.hcl", ".pkr.json")):
        return "packer"
    if suffix == ".bicep":
        return "bicep"
    if suffix in _SYSTEMD_SUFFIXES:
        return "systemd"
    if name in {"cloud-init.yml", "cloud-init.yaml", "user-data.yml", "user-data.yaml"}:
        return "cloud-init"
    if name == "nginx.conf":
        return "nginx"
    if name in {"haproxy.cfg", "haproxy.conf"}:
        return "haproxy"
    if name in {"envoy.yaml", "envoy.yml", "envoy.json"}:
        return "envoy"
    if name in {"traefik.yaml", "traefik.yml", "traefik.toml"}:
        return "traefik"
    if relative.name == "Caddyfile" or name == "caddy.json":
        return "caddy"
    if name == "grafana.ini" or (
        "provisioning" in parts
        and any(
            part in {"alerting", "dashboards", "datasources", "notifiers", "plugins"}
            for part in parts
        )
        and suffix in (*_YAML_SUFFIXES, ".json")
    ):
        return "grafana"
    if name in {"loki.yaml", "loki.yml"}:
        return "loki"
    if name in {"vault.hcl", "vault.json"}:
        return "vault"
    if name in {"consul.hcl", "consul.json"}:
        return "consul"
    if name in {"prometheus.yml", "prometheus.yaml"}:
        return "prometheus"
    if name in {"alertmanager.yml", "alertmanager.yaml"}:
        return "alertmanager"
    if name in {"otel-collector.yml", "otel-collector.yaml", "otelcol.yml", "otelcol.yaml"}:
        return "otel-collector"

    if suffix == ".tf" or name.endswith(".tf.json"):
        return "terraform-config"

    return _identify_from_content(path, suffix)


def _named_config_variant(name: str, suffix: str, *basenames: str) -> bool:
    """Recognize extensionless config basenames without matching similarly named source code."""
    for basename in basenames:
        if name == basename:
            return True
        if name.startswith((f"{basename}.", f"{basename}-")) and suffix not in (
            _CONFIG_BASENAME_SOURCE_SUFFIXES
        ):
            return True
    return False


def _identify_from_content(path: Path, suffix: str) -> str | None:
    if suffix not in (*_YAML_SUFFIXES, ".json"):
        return None
    try:
        raw = path.read_bytes()[: 256 * 1024]
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    if suffix in _YAML_SUFFIXES:
        if _KUBERNETES_HINT.search(text):
            return "kubernetes"
        if _ANSIBLE_HINT.search(text):
            return "ansible"
        return None
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(document, dict):
        return None
    if "format_version" in document and (
        "resource_changes" in document or "planned_values" in document
    ):
        return "terraform"
    if isinstance(document.get("Changes"), list):
        return "cloudformation"
    if "properties" in document and "changeType" in document:
        return "azure"
    return None


def scan_project(
    root: Path,
    *,
    display_root: str,
    framework: str | None = None,
    excludes: Sequence[str] = (),
    max_files: int = 500,
    max_file_bytes: int = 10 * 1024 * 1024,
) -> dict[str, Any]:
    """Discover, analyze, and aggregate supported infrastructure inputs."""
    if max_file_bytes < 1:
        raise ProjectScanError("max_file_bytes must be at least 1")
    discovered = discover_project_inputs(root, excludes=excludes, max_files=max_files)
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for item in discovered:
        if item.size < 0:
            errors.append(_scan_error(item, "unreadable"))
            continue
        if item.size > max_file_bytes:
            errors.append(_scan_error(item, "file-too-large"))
            continue
        payload = _analyze_input(item, framework=framework)
        if payload is None:
            errors.append(_scan_error(item, "analysis-failed"))
            continue
        results.append(_file_result(item, payload))
    return aggregate_project_scan(
        display_root=display_root,
        discovered=discovered,
        results=results,
        errors=errors,
        framework=framework,
    )


def _analyze_input(item: DiscoveredInput, *, framework: str | None) -> dict[str, Any] | None:
    from readtheplan.cli import main

    command = "agent-gate" if item.tool == "terraform" else item.tool
    arguments = [command]
    if framework:
        arguments.extend(("--framework", framework))
    arguments.append(str(item.path))
    stdout = io.StringIO()
    stderr = io.StringIO()
    try:
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(arguments)
    except (SystemExit, OSError, UnicodeError, ValueError):
        return None
    if status not in {0, 1, 2}:
        return None
    try:
        payload = json.loads(stdout.getvalue())
    except (json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("risk_counts"), dict):
        return None
    return payload


def _scan_error(item: DiscoveredInput, code: str) -> dict[str, str]:
    return {"path": item.relative_path, "tool": item.tool, "code": code}


def _file_result(item: DiscoveredInput, payload: dict[str, Any]) -> dict[str, Any]:
    counts = _normalized_counts(payload.get("risk_counts"))
    total_changes = payload.get("total_changes")
    if not isinstance(total_changes, int):
        total_changes = sum(counts.values())
    required = payload.get("required_checks")
    return {
        "path": item.relative_path,
        "tool": item.tool,
        "adapter": str(payload.get("adapter") or item.tool),
        "decision": str(payload.get("decision") or "warn"),
        "risk": str(payload.get("risk") or "review"),
        "risk_counts": counts,
        "total_changes": total_changes,
        "required_checks": sorted(str(check) for check in required)
        if isinstance(required, list)
        else [],
        "reason": str(payload.get("reason") or "Analysis completed without a reason."),
    }


def aggregate_project_scan(
    *,
    display_root: str,
    discovered: Sequence[DiscoveredInput],
    results: Sequence[dict[str, Any]],
    errors: Sequence[dict[str, str]],
    framework: str | None,
) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    required_checks: set[str] = set()
    total_changes = 0
    for result in results:
        counts.update(_normalized_counts(result.get("risk_counts")))
        total_changes += int(result.get("total_changes") or 0)
        required_checks.update(str(check) for check in result.get("required_checks", []))
    if errors:
        counts["review"] += len(errors)
        total_changes += len(errors)
        required_checks.add("rtp.check.input_validation")
    normalized_counts = {risk: counts.get(risk, 0) for risk in RISK_ORDER}
    risk = _maximum_risk(normalized_counts)
    if not discovered:
        decision = "warn"
        risk = "review"
        reason = (
            "No supported infrastructure inputs were discovered; narrow or verify the scan path."
        )
    else:
        decision = _decision_for_risk(risk)
        reason = _aggregate_reason(
            decision=decision,
            risk=risk,
            file_count=len(results),
            error_count=len(errors),
            total_changes=total_changes,
        )
    score = max(
        0.0,
        min(
            100.0,
            100.0
            - normalized_counts["review"] * 5
            - normalized_counts["dangerous"] * 15
            - normalized_counts["irreversible"] * 30,
        ),
    )
    return {
        "schema": PROJECT_SCAN_SCHEMA,
        "adapter": PROJECT_SCAN_ADAPTER,
        "root": display_root,
        "decision": decision,
        "risk": risk,
        "compliance_score": score,
        "required_checks": sorted(required_checks),
        "allowed_next_actions": _allowed_actions(decision),
        "prohibited_next_actions": _prohibited_actions(decision),
        "reason": reason,
        "pr_comment": _project_pr_comment(
            decision=decision,
            risk=risk,
            reason=reason,
            results=results,
            errors=errors,
            required_checks=sorted(required_checks),
        ),
        "evidence_checklist": [
            "Record the scanned repository revision and readtheplan version.",
            "Attach this aggregate gate and the per-file analyzer summaries to the change record.",
            "Review every unanalysed input and confirm excluded paths are intentional.",
            "Record reviewer identity, approval decision, and recovery notes before apply.",
        ],
        "auditor_summary": (
            f"readtheplan scanned {len(results)} supported infrastructure file(s), found "
            f"{total_changes} change or validation item(s), and could not analyze "
            f"{len(errors)} discovered file(s). The aggregate decision is {decision} with "
            f"maximum risk {risk}."
        ),
        "risk_counts": normalized_counts,
        "mode": "kernel",
        "framework": framework,
        "discovered_file_count": len(discovered),
        "scanned_file_count": len(results),
        "error_count": len(errors),
        "total_changes": total_changes,
        "files": list(results),
        "errors": list(errors),
    }


def _normalized_counts(value: Any) -> dict[str, int]:
    source = value if isinstance(value, dict) else {}
    return {
        risk: int(source.get(risk, 0)) if isinstance(source.get(risk, 0), int) else 0
        for risk in RISK_ORDER
    }


def _maximum_risk(counts: dict[str, int]) -> str:
    present = [risk for risk, rank in RISK_ORDER.items() if counts.get(risk, 0) > 0]
    if not present:
        return "safe"
    return max(present, key=RISK_ORDER.__getitem__)


def _decision_for_risk(risk: str) -> str:
    if risk in {"dangerous", "irreversible"}:
        return "block"
    if risk == "review":
        return "warn"
    return "proceed"


def _aggregate_reason(
    *, decision: str, risk: str, file_count: int, error_count: int, total_changes: int
) -> str:
    suffix = f" {error_count} discovered file(s) require input validation." if error_count else ""
    return (
        f"{decision.capitalize()} because {file_count} infrastructure file(s) produced "
        f"{total_changes} change or validation item(s) with maximum risk {risk}.{suffix}"
    )


def _allowed_actions(decision: str) -> list[str]:
    if decision == "block":
        return ["post_pr_comment", "request_human_review", "collect_evidence", "open_change_record"]
    if decision == "warn":
        return ["request_review", "post_pr_comment", "collect_evidence", "open_change_record"]
    return ["continue", "post_pr_comment", "collect_evidence"]


def _prohibited_actions(decision: str) -> list[str]:
    if decision == "block":
        return ["merge", "apply", "auto_approve", "auto_apply"]
    if decision == "warn":
        return ["merge_without_review", "apply_without_review", "auto_approve"]
    return ["auto_apply_without_policy"]


def _project_pr_comment(
    *,
    decision: str,
    risk: str,
    reason: str,
    results: Sequence[dict[str, Any]],
    errors: Sequence[dict[str, str]],
    required_checks: Sequence[str],
) -> str:
    lines = [
        f"**readtheplan project gate:** {decision.upper()}",
        "",
        reason,
        "",
        f"- Highest risk: `{risk}`",
        f"- Analyzed files: `{len(results)}`",
        f"- Unanalysed files: `{len(errors)}`",
        "- Required checks: " + (", ".join(required_checks) or "none"),
    ]
    if results:
        lines.extend(("", "- File gates:"))
        for result in results[:10]:
            lines.append(
                f"  - `{result['path']}` ({result['tool']}): "
                f"`{result['decision']}` / `{result['risk']}`"
            )
        if len(results) > 10:
            lines.append(f"  - ...and {len(results) - 10} more")
    if errors:
        lines.extend(("", "- Inputs requiring validation:"))
        for error in errors[:10]:
            lines.append(f"  - `{error['path']}` ({error['tool']}): `{error['code']}`")
        if len(errors) > 10:
            lines.append(f"  - ...and {len(errors) - 10} more")
    return "\n".join(lines)
