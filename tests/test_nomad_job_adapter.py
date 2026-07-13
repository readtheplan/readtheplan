from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.nomad_job import NomadJobInputError, parse_nomad_job
from readtheplan.adapters.workloads import NomadPlanAdapter, parse_nomad
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes(name: str):
    path = FIXTURES / name
    data = parse_nomad(path.read_text(encoding="utf-8"))
    adapter = detect_adapter(data)
    assert isinstance(adapter, NomadPlanAdapter)
    return data, adapter.analyze(data, use_rules=False)


def test_hcl_jobspec_detects_execution_identity_network_storage_and_supply_chain() -> None:
    data, changes = _changes("nomad_job_risky.nomad.hcl")
    assert data["nomad_job"]["representation"] == "hcl"
    kinds = {change.resource_type for change in changes}
    assert {
        "nomad_cluster_wide_job",
        "nomad_global_placement",
        "nomad_unattended_execution",
        "nomad_host_network",
        "nomad_static_port",
        "nomad_host_volume",
        "nomad_rollout_strategy",
        "nomad_service_mesh",
        "nomad_task_driver",
        "nomad_privileged_identity",
        "nomad_command",
        "nomad_network_mode",
        "nomad_devices",
        "nomad_artifact",
        "nomad_template_remote_data",
        "nomad_absolute_template_destination",
        "nomad_template_environment",
        "nomad_template_change_action",
        "nomad_vault_access",
        "nomad_consul_access",
        "nomad_workload_identity",
        "nomad_lifecycle_task",
        "nomad_image",
        "nomad_privileged",
        "nomad_cap_add",
        "nomad_volumes",
        "nomad_literal_secret",
        "nomad_source_boundary",
    } <= kinds
    assert sum(change.risk == "dangerous" for change in changes) >= 20


def test_json_jobspec_is_supported() -> None:
    data = parse_nomad_job(
        json.dumps(
            {
                "Job": {
                    "Name": "api",
                    "Type": "service",
                    "Datacenters": ["dc1"],
                    "TaskGroups": [
                        {
                            "Name": "web",
                            "Tasks": [
                                {
                                    "Name": "app",
                                    "Driver": "docker",
                                    "User": "65532",
                                    "Config": {
                                        "image": "app@sha256:" + "a" * 64,
                                    },
                                }
                            ],
                        }
                    ],
                }
            }
        )
    )
    changes = NomadPlanAdapter().analyze(data, use_rules=False)
    image = next(change for change in changes if change.resource_type == "nomad_image")
    assert image.risk == "review"


def test_plan_autodetection_remains_backward_compatible() -> None:
    data = parse_nomad((FIXTURES / "nomad_plan_risky.json").read_text(encoding="utf-8"))
    assert "nomad_plan" in data


def test_jobspec_gate_redacts_secret_values(capsys) -> None:
    path = FIXTURES / "nomad_job_risky.nomad.hcl"
    assert main(["nomad", str(path)]) == 2
    assert "literal-example" not in capsys.readouterr().out


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("", "empty"),
        ("[]", "object"),
        ("unrelated = true", "not recognized"),
        ('job "a" {}\njob "b" {}', "exactly one"),
        ('job "broken" {', "invalid Nomad"),
        ('{"Job": {"Name": "x"}, "Job": {}}', "duplicate JSON key"),
    ],
)
def test_jobspec_rejects_malformed_or_ambiguous_input(source: str, message: str) -> None:
    with pytest.raises(NomadJobInputError, match=message):
        parse_nomad_job(source)


def test_jobspec_never_executes_nomad_or_downloads(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("Nomad execution is forbidden")

    monkeypatch.setattr("subprocess.run", fail)
    _, changes = _changes("nomad_job_risky.nomad.hcl")
    assert changes


def test_jobspec_cli_emits_artifact_type_and_framework(capsys) -> None:
    path = FIXTURES / "nomad_job_risky.nomad.hcl"
    assert main(["nomad", "--framework", "soc2", str(path)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "nomad"
    assert payload["artifact_type"] == "jobspec"
    assert payload["decision"] == "block"
    assert "literal-example" not in json.dumps(payload)
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
