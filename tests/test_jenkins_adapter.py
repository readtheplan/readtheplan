from __future__ import annotations

import json

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.jenkins import JenkinsAdapter, analyze_jenkins
from readtheplan.cli import main


def test_detects_and_classifies_jenkins_steps() -> None:
    source = """
pipeline {
  stages {
    stage('Build') {
      steps {
        echo 'building'
        sh './deploy.sh'
        archiveArtifacts artifacts: 'dist/**'
      }
    }
  }
}
"""
    data = {"jenkinsfile": source}
    adapter = detect_adapter(data)
    assert isinstance(adapter, JenkinsAdapter)

    changes = adapter.analyze(data, tool_name="Jenkins")
    assert [change.resource_type for change in changes] == [
        "jenkins_echo",
        "jenkins_shell",
        "jenkins_archive",
    ]
    assert [change.risk for change in changes] == ["safe", "dangerous", "safe"]


def test_jenkins_credentials_and_unparsed_pipeline_require_attention() -> None:
    credentials = JenkinsAdapter().analyze(
        {"jenkinsfile": "node('linux') { withCredentials([]) { echo 'x' } }"},
        use_rules=False,
    )
    assert credentials[0].risk == "dangerous"

    unparsed = JenkinsAdapter().analyze(
        {"jenkinsfile": "pipeline { agent any; stages { } }"},
        use_rules=False,
    )
    assert unparsed[0].resource_type == "jenkins_unparsed_pipeline"
    assert unparsed[0].risk == "review"


def test_jenkins_gate_uses_shared_contract() -> None:
    gate = analyze_jenkins({"jenkinsfile": "pipeline { stages { sh 'deploy' } }"})
    assert gate["decision"] == "block"
    assert "Jenkins" in gate["reason"]


def test_jenkins_cli_reads_jenkinsfile(tmp_path, capsys) -> None:
    source = tmp_path / "Jenkinsfile"
    source.write_text("pipeline {\n  stages {\n    echo 'ok'\n  }\n}\n", encoding="utf-8")
    assert main(["jenkins", str(source)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision"] == "proceed"


def test_jenkins_cli_rejects_unrecognized_text(tmp_path, capsys) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("deploy this somehow\n", encoding="utf-8")
    assert main(["jenkins", str(source)]) == 1
    assert "not recognized" in capsys.readouterr().err
