# User-facing explanations remain complete sentences.
# ruff: noqa: E501

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import hcl2
from hcl2.utils import SerializationOptions

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class TerramateInputError(ValueError):
    """Raised when input is not recognizable Terramate configuration."""


_KEYS = {
    "apply",
    "define",
    "generate_file",
    "generate_hcl",
    "globals",
    "import",
    "input",
    "output",
    "script",
    "sharing_backend",
    "stack",
    "terramate",
    "vendor",
}
_SECRET = re.compile(
    r"(?:password|passwd|token|secret|private.?key|access.?key|credential|api.?key|auth)", re.I
)
_REMOTE = re.compile(r"^(?:https?|git|ssh|s3|oci)://|^[^/@\s]+@[^:\s]+:", re.I)
_EXACT_VERSION = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_SHELL = {"bash", "cmd", "fish", "nu", "powershell", "pwsh", "sh", "zsh"}
_MUTATING = {
    "apply",
    "destroy",
    "force-unlock",
    "import",
    "refresh",
    "state",
    "taint",
    "untaint",
}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TerramateInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strip_internal(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_internal(child) for key, child in value.items() if key != "__is_block__"
        }
    if isinstance(value, list):
        return [_strip_internal(child) for child in value]
    return value


def _text(value: Any) -> str:
    text = str(value).strip().strip("\"'")
    if text.startswith("${") and text.endswith("}"):
        return text[2:-1]
    return text


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
        return value[0]
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _blocks(value: Any, max_labels: int = 2) -> list[tuple[tuple[str, ...], dict[str, Any]]]:
    results: list[tuple[tuple[str, ...], dict[str, Any]]] = []
    for item in _items(value):
        if not isinstance(item, dict):
            continue
        current: Any = item
        labels: list[str] = []
        for _ in range(max_labels):
            if not isinstance(current, dict) or len(current) != 1:
                break
            label, child = next(iter(current.items()))
            if not isinstance(child, dict):
                break
            labels.append(_text(label))
            current = child
        if isinstance(current, dict):
            results.append((tuple(labels), current))
    return results


def _enabled(value: Any) -> bool:
    return value is True or _text(value).lower() in {"1", "true", "yes", "on"}


def _disabled(value: Any) -> bool:
    return value is False or _text(value).lower() in {"0", "false", "no", "off"}


def _outside_project(value: str) -> bool:
    normalized = _text(value).replace("\\", "/")
    path = PurePosixPath(normalized)
    return (
        bool(_REMOTE.match(normalized))
        or ".." in path.parts
        or bool(re.match(r"^[A-Za-z]:/", normalized))
    )


def _embedded_credential(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return bool(parsed.password or (parsed.username and parsed.scheme in {"http", "https"}))


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def parse_terramate(source: str, filename: str = "terramate.tm.hcl") -> dict[str, Any]:
    """Parse one Terramate HCL/JSON configuration without evaluation or traversal."""
    if not source.strip():
        raise TerramateInputError("input is empty")
    name = Path(filename).name.lower()
    if not (name.endswith((".tm.hcl", ".tm", ".tmgen")) or name.endswith(".tm.json")):
        raise TerramateInputError(
            "Terramate filename must end in .tm.hcl, .tm, .tmgen, or .tm.json"
        )
    representation = "json" if source.lstrip().startswith(("{", "[")) else "hcl"
    if representation == "json":
        try:
            document: Any = json.loads(source, object_pairs_hook=_unique_object)
        except TerramateInputError:
            raise
        except json.JSONDecodeError as exc:
            raise TerramateInputError(f"invalid Terramate JSON: {exc}") from exc
    else:
        try:
            document = hcl2.loads(
                source,
                serialization_options=SerializationOptions(
                    explicit_blocks=False,
                    strip_string_quotes=True,
                ),
            )
        except Exception as exc:
            raise TerramateInputError(f"invalid Terramate HCL: {exc}") from exc
    document = _strip_internal(document)
    if not isinstance(document, dict):
        raise TerramateInputError("Terramate configuration must be an HCL or JSON object")
    tmgen = name.endswith(".tmgen")
    if not tmgen and not (_KEYS & set(document)):
        raise TerramateInputError("no recognizable Terramate configuration blocks were found")
    return {
        "terramate": {
            "artifact_type": "tmgen" if tmgen else "configuration",
            "filename": Path(filename).name,
            "representation": representation,
            "document": document,
            "source": source,
        }
    }


def _secret_changes(value: Any, address: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_address = f"{address}.{key}"
            if _SECRET.search(str(key)) and child not in (None, "", False, [], {}):
                text = _text(child)
                reference = bool(re.search(r"\b(?:env|global|terramate|outputs)\.", text))
                changes.append(
                    _change(
                        child_address,
                        "secret_reference" if reference else "literal_secret",
                        "review" if reference else "dangerous",
                        "Terramate references credential-like data from evaluated project, stack, environment, or output context."
                        if reference
                        else "Terramate embeds credential-like material; the value is omitted from analysis output.",
                    )
                )
            changes.extend(_secret_changes(child, child_address))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            changes.extend(_secret_changes(child, f"{address}[{index}]"))
    return changes


def _project_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for index, (_, block) in enumerate(_blocks(document.get("terramate"), 0)):
        address = f"terramate[{index}]"
        required = _text(block.get("required_version", ""))
        changes.append(
            _change(
                address,
                "project_configuration",
                "review",
                "Terramate project configuration controls version compatibility, safeguards, execution environment, change detection, cloud synchronization, telemetry, and experiments.",
            )
        )
        if not required or not re.search(r"\d+\.\d+", required):
            changes.append(
                _change(
                    f"{address}.required_version",
                    "unconstrained_cli_version",
                    "dangerous",
                    "Terramate project does not visibly constrain the CLI version, so parsing, generation, orchestration, and safeguard behavior can drift.",
                )
            )
        for config_index, (_, config) in enumerate(_blocks(block.get("config"), 0)):
            config_address = f"{address}.config[{config_index}]"
            safeguards = _items(config.get("disable_safeguards"))
            if safeguards:
                changes.append(
                    _change(
                        f"{config_address}.disable_safeguards",
                        "disabled_orchestration_safeguards",
                        "dangerous",
                        "Terramate disables Git or generated-code safeguards; commands may run with uncommitted, untracked, out-of-sync, or stale generated configuration.",
                    )
                )
            for _, run in _blocks(config.get("run"), 0):
                for _, env in _blocks(run.get("env"), 0):
                    if env:
                        changes.append(
                            _change(
                                f"{config_address}.run.env",
                                "run_environment",
                                "review",
                                "Terramate injects environment variables into every orchestrated command; review PATH precedence, credentials, Terraform/OpenTofu behavior, and stack isolation.",
                            )
                        )
                    if "PATH" in env:
                        changes.append(
                            _change(
                                f"{config_address}.run.env.PATH",
                                "executable_path_override",
                                "dangerous",
                                "Terramate overrides PATH for orchestrated commands, which can substitute project or attacker-controlled executables.",
                            )
                        )
            for _, cloud in _blocks(config.get("cloud"), 0):
                if cloud:
                    changes.append(
                        _change(
                            f"{config_address}.cloud",
                            "cloud_integration",
                            "review",
                            "Terramate Cloud configuration can synchronize stack metadata, plans, deployments, previews, drift status, and outputs; verify organization, region, authentication, data residency, and disclosure scope.",
                        )
                    )
            for _, detection in _blocks(config.get("change_detection"), 0):
                if "off" in str(detection).lower() or any(
                    _disabled(value)
                    for value in detection.values()
                    if not isinstance(value, (dict, list))
                ):
                    changes.append(
                        _change(
                            f"{config_address}.change_detection",
                            "weakened_change_detection",
                            "dangerous",
                            "Terramate change detection is partly disabled, so affected stacks or local changes may be omitted from orchestration.",
                        )
                    )
            if config.get("experiments"):
                changes.append(
                    _change(
                        f"{config_address}.experiments",
                        "experimental_features",
                        "review",
                        "Terramate enables experimental behavior whose configuration or execution semantics may change between releases.",
                    )
                )
    return changes


def _stack_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for index, (_, stack) in enumerate(_blocks(document.get("stack"), 0)):
        address = f"stack[{index}]"
        name = _text(stack.get("name", ""))
        stack_id = _text(stack.get("id", ""))
        changes.append(
            _change(
                address,
                "stack",
                "dangerous"
                if re.search(r"(?:^|[-_])(prod|production)(?:$|[-_])", name, re.I)
                else "review",
                "Terramate stack is an independently orchestrated Terraform, OpenTofu, or Terragrunt unit; verify identity, environment, state backend, credentials, dependency graph, and blast radius.",
            )
        )
        if not stack_id:
            changes.append(
                _change(
                    f"{address}.id",
                    "missing_stack_identity",
                    "review",
                    "Terramate stack has no stable ID, limiting cloud tracking and output-sharing identity across refactors.",
                )
            )
        for key in ("before", "after", "wants", "wanted_by"):
            if stack.get(key):
                changes.append(
                    _change(
                        f"{address}.{key}",
                        "stack_orchestration_edge",
                        "review",
                        "Terramate modifies stack selection or execution order; forced-execution edges do not necessarily establish data dependency ordering, so verify concurrency, reverse ordering, scope, and failure propagation.",
                    )
                )
        for watch in _items(stack.get("watch")):
            path = _text(watch)
            if path:
                changes.append(
                    _change(
                        f"{address}.watch",
                        "external_change_trigger",
                        "dangerous" if _outside_project(path) else "review",
                        "Terramate marks the stack changed from watched paths; verify project confinement, glob breadth, generated files, and whether all material dependencies are covered.",
                    )
                )
    return changes


def _import_vendor_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for index, (_, block) in enumerate(_blocks(document.get("import"), 0)):
        source = _text(block.get("source", ""))
        changes.append(
            _change(
                f"import[{index}]",
                "configuration_import",
                "dangerous" if not source or _outside_project(source) else "review",
                "Terramate imports and merges additional configuration; review project confinement, globs, cycles, inherited globals/scripts/generation, and effective hierarchy.",
            )
        )
    for index, (_, block) in enumerate(_blocks(document.get("vendor"), 0)):
        directory = _text(block.get("dir", ""))
        changes.append(
            _change(
                f"vendor[{index}]",
                "vendor_configuration",
                "dangerous" if not directory or _outside_project(directory) else "review",
                "Terramate downloads module sources into a vendor directory; review path confinement, source pinning, transport, credentials, manifest filters, overwrite behavior, and generated module provenance.",
            )
        )
    return changes


def _generation_changes(document: dict[str, Any], source: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for block_name, kind in (
        ("generate_file", "generated_file"),
        ("generate_hcl", "generated_hcl"),
    ):
        for index, (labels, block) in enumerate(_blocks(document.get(block_name), 1)):
            target = labels[0] if labels else ""
            address = f"{block_name}[{index}]"
            root_context = _text(block.get("context", "stack")) == "root"
            dangerous = not target or _outside_project(target) or root_context
            changes.append(
                _change(
                    address,
                    kind,
                    "dangerous" if dangerous else "review",
                    "Terramate evaluates hierarchical globals, metadata, functions, filters, assertions, and partial HCL to generate infrastructure configuration; review target confinement, inheritance, root/stack scope, overwrites, secrets, and generated semantics.",
                )
            )
            if block.get("condition") is not None or block.get("stack_filter") is not None:
                changes.append(
                    _change(
                        f"{address}.selection",
                        "conditional_generation",
                        "review",
                        "Terramate conditionally selects stacks or project paths for generation; verify all intended stacks receive current configuration and excluded stacks remain safe.",
                    )
                )
            for _, assertion in _blocks(block.get("assert"), 0):
                if _enabled(assertion.get("warning")):
                    changes.append(
                        _change(
                            f"{address}.assert",
                            "fail_open_generation_assertion",
                            "dangerous",
                            "Terramate generation assertion emits only a warning, allowing generation to continue when a stated precondition fails.",
                        )
                    )
    function_probes = (
        (
            r"\btm_(?:file|filebase64|templatefile)\s*\(",
            "generation_file_read",
            "dangerous",
            "Terramate evaluation reads or templates host filesystem content; review confinement, symlinks, sensitive data, encoding, and generated destinations.",
        ),
        (
            r"\btm_vendor\s*\(",
            "module_vendoring",
            "dangerous",
            "Terramate downloads and rewrites a module source during generation; verify immutable revision, transport, credentials, checksums, cache, and transitive provenance.",
        ),
        (
            r"\b(?:env|global|terramate)\.",
            "dynamic_generation_input",
            "review",
            "Terramate generation depends on environment, hierarchical globals, or project/stack metadata resolved only in effective context.",
        ),
    )
    for pattern, kind, risk, explanation in function_probes:
        if re.search(pattern, source):
            changes.append(_change(f"generation.{kind}", kind, risk, explanation))
    return changes


def _command_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for index, (labels, script) in enumerate(_blocks(document.get("script"), 2)):
        address = f"script[{index}]"
        changes.append(
            _change(
                address,
                "script",
                "dangerous",
                "Terramate script orchestrates ordered commands across every selected or inheriting stack; review labels, scope, selection, working directories, concurrency, credentials, approvals, and failure behavior.",
            )
        )
        jobs = _blocks(script.get("job"), 0)
        for job_index, (_, job) in enumerate(jobs):
            for command_index, command in enumerate(_items(job.get("commands"))):
                if not isinstance(command, list) or not command:
                    continue
                argv = [_text(arg) for arg in command if not isinstance(arg, dict)]
                options = next((arg for arg in command if isinstance(arg, dict)), {})
                executable = Path(argv[0]).name.lower() if argv else ""
                subcommand = next((arg.lower() for arg in argv[1:] if not arg.startswith("-")), "")
                shell = executable in _SHELL
                mutating = subcommand in _MUTATING or any(
                    arg in {"-auto-approve", "--auto-approve"} for arg in argv
                )
                risk = "dangerous" if shell or mutating else "review"
                changes.append(
                    _change(
                        f"{address}.job[{job_index}].commands[{command_index}]",
                        "mutating_command" if risk == "dangerous" else "command",
                        risk,
                        "Terramate executes a shell or infrastructure-mutating command across selected stacks; review interpolation, auto-approval, state locks, credentials, network/filesystem access, blast radius, and rollback."
                        if risk == "dangerous"
                        else "Terramate executes an external command across selected stacks; review executable provenance, arguments, environment, outputs, failures, and side effects.",
                    )
                )
                if any(
                    _enabled(options.get(key))
                    for key in (
                        "cloud_sync_deployment",
                        "cloud_sync_drift_status",
                        "cloud_sync_preview",
                        "sync_deployment",
                        "sync_drift_status",
                        "sync_preview",
                    )
                ):
                    changes.append(
                        _change(
                            f"{address}.job[{job_index}].commands[{command_index}].cloud_sync",
                            "cloud_result_sync",
                            "review",
                            "Terramate synchronizes command results or plan data to Terramate Cloud; verify organization, data classification, credentials, retention, and PR/deployment identity.",
                        )
                    )
                if _enabled(options.get("mock_on_fail")):
                    changes.append(
                        _change(
                            f"{address}.job[{job_index}].commands[{command_index}].mock_on_fail",
                            "mocked_dependency_fail_open",
                            "dangerous",
                            "Terramate permits mocked output-sharing values when dependencies fail, which can produce a misleading or unsafe downstream plan.",
                        )
                    )
    return changes


def _sharing_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for index, (labels, backend) in enumerate(_blocks(document.get("sharing_backend"), 1)):
        address = f"sharing_backend[{index}]"
        changes.append(
            _change(
                address,
                "output_sharing_backend",
                "dangerous",
                "Terramate executes a backend command to collect stack outputs and inject dependent values as Terraform variables; review command provenance, sensitive outputs, generated filename, credentials, stack trust, and failure behavior.",
            )
        )
        filename = _text(backend.get("filename", ""))
        if not filename or _outside_project(filename):
            changes.append(
                _change(
                    f"{address}.filename",
                    "unsafe_sharing_destination",
                    "dangerous",
                    "Terramate output-sharing generated file target is missing or escapes the project boundary.",
                )
            )
    for block_name in ("input", "output"):
        for index, (labels, block) in enumerate(_blocks(document.get(block_name), 1)):
            address = f"{block_name}[{index}]"
            sensitive = block.get("sensitive")
            changes.append(
                _change(
                    address,
                    f"shared_stack_{block_name}",
                    "dangerous"
                    if sensitive is False or block_name == "input" and block.get("mock") is not None
                    else "review",
                    "Terramate shares a stack value across execution boundaries; verify producing stack identity, backend, sensitivity, mock safety, generated Terraform variable/output, and cloud/log disclosure.",
                )
            )
    return changes


def _bundle_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    if document.get("define") is not None or document.get("apply") is not None:
        changes.append(
            _change(
                "bundle",
                "bundle_scaffolding",
                "dangerous",
                "Terramate bundle definitions or applications can scaffold stacks, components, files, and infrastructure configuration; review source/version, inputs, prompts, target directories, generated content, secrets, and overwrite scope.",
            )
        )
    return changes


def _configuration_changes(document: dict[str, Any], source: str) -> list[dict[str, str]]:
    changes = _project_changes(document)
    changes.extend(_stack_changes(document))
    changes.extend(_import_vendor_changes(document))
    changes.extend(_generation_changes(document, source))
    changes.extend(_command_changes(document))
    changes.extend(_sharing_changes(document))
    changes.extend(_bundle_changes(document))
    changes.extend(_secret_changes(document, "terramate"))
    changes.append(
        _change(
            "terramate.effective_configuration",
            "evaluation_boundary",
            "review",
            "Static analysis does not traverse or merge the Terramate project hierarchy, resolve imports/globals/metadata/functions/filters, read files or environment variables, vendor modules, generate or overwrite files, discover stack state/backends, calculate changed stacks or dependency order, execute scripts/run commands, collect/share outputs, authenticate or synchronize with Terramate Cloud, or invoke Terraform, OpenTofu, Terragrunt, Git, or infrastructure APIs.",
        )
    )
    return changes


def _tmgen_changes(source: str) -> list[dict[str, str]]:
    changes = [
        _change(
            "tmgen",
            "hcl_blueprint",
            "dangerous",
            "Terramate .tmgen blueprint is evaluated in stack context and can generate Terraform, OpenTofu, provider, backend, module, and resource configuration across selected stacks.",
        )
    ]
    changes.extend(_generation_changes({}, source))
    changes.append(
        _change(
            "tmgen.effective_configuration",
            "evaluation_boundary",
            "review",
            "Static analysis does not evaluate .tmgen expressions, globals, metadata, functions, or partial HCL; select stacks; generate files; resolve modules/providers; or invoke Terraform/OpenTofu.",
        )
    )
    return changes


class TerramateAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "terramate"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        payload = input_data.get("terramate")
        return (
            isinstance(payload, dict)
            and payload.get("artifact_type")
            in {
                "configuration",
                "tmgen",
            }
            and isinstance(payload.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        payload = input_data["terramate"]
        if payload["artifact_type"] == "tmgen":
            return _tmgen_changes(payload["source"])
        return _configuration_changes(payload["document"], payload["source"])

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"terramate_{raw['Kind']}",
            actions=("execute",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_terramate(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = TerramateAdapter().analyze(data, tool_name="Terramate")
    summary = PlanSummary(
        path=Path("terramate://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Terramate")
    gate["adapter"] = "terramate"
    gate["artifact_type"] = data["terramate"]["artifact_type"]
    gate["total_changes"] = len(changes)
    return gate
