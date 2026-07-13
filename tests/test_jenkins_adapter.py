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
    assert gate["adapter"] == "jenkins"
    assert gate["credential_binding_count"] == 0
    assert gate["secret_interpolation_count"] == 0
    assert gate["credential_exposure_capabilities"] == []


def test_jenkins_detects_bound_secret_gstrings_without_exposing_identifiers() -> None:
    source = r'''pipeline {
  agent any
  environment {
    API_TOKEN = credentials('fixture-helper-credential-do-not-leak')
  }
  stages {
    stage('Deploy') {
      steps {
        withCredentials([
          usernamePassword(credentialsId: 'fixture-pair-do-not-leak',
            usernameVariable: 'SERVICE_USER', passwordVariable: 'SERVICE_PASSWORD'),
          string(credentialsId: 'fixture-log-do-not-leak', variable: 'LOG_TOKEN')
        ]) {
          sh(returnStdout: true, script: """curl -H "Token: ${env.API_TOKEN}" /deploy""")
          echo "$LOG_TOKEN"
          writeFile file: 'result.txt', text: "${SERVICE_PASSWORD}"
          sh 'curl -H "Token: $API_TOKEN" /safe'
        }
      }
    }
  }
}'''

    changes = JenkinsAdapter().analyze({"jenkinsfile": source}, use_rules=False)
    interpolation = [
        change for change in changes if change.resource_type == "jenkins_credential_interpolation"
    ]
    assert len(interpolation) == 3
    assert all(change.risk == "dangerous" for change in interpolation)

    gate = analyze_jenkins({"jenkinsfile": source})
    assert gate["credential_binding_count"] == 4
    assert gate["secret_interpolation_count"] == 3
    assert gate["credential_exposure_capabilities"] == ["command", "file", "log"]
    encoded = json.dumps(gate)
    for sensitive in (
        "fixture-helper-credential-do-not-leak",
        "fixture-pair-do-not-leak",
        "fixture-log-do-not-leak",
        "API_TOKEN",
        "SERVICE_PASSWORD",
        "LOG_TOKEN",
    ):
        assert sensitive not in encoded


def test_jenkins_ignores_step_text_and_non_interpolating_secret_references() -> None:
    source = r"""pipeline {
  stages {
    stage('Build') {
      steps {
        withCredentials([string(credentialsId: 'example', variable: 'TOKEN')]) {
          echo "literal sh('not-a-step')"
          sh 'curl $TOKEN'
          sh '''curl $TOKEN'''
          sh "echo \$TOKEN"
          // powershell "Write-Host $TOKEN"
          scriptText = "pipeline { bat('also-not-a-step') }"
        }
      }
    }
  }
}"""

    changes = JenkinsAdapter().analyze({"jenkinsfile": source}, use_rules=False)
    kinds = [change.resource_type for change in changes]
    assert kinds.count("jenkins_shell") == 3
    assert "jenkins_batch" not in kinds
    assert "jenkins_powershell" not in kinds
    assert "jenkins_credential_interpolation" not in kinds


def test_jenkins_detects_declarative_username_password_derived_variable() -> None:
    source = """
pipeline {
  environment { SERVICE = credentials('pair') }
  stages { stage('x') { steps { bat \"deploy %SERVICE_PSW% ${SERVICE_PSW}\" } } }
}
"""
    gate = analyze_jenkins({"jenkinsfile": source})
    assert gate["credential_binding_count"] == 1
    assert gate["secret_interpolation_count"] == 1
    assert gate["credential_exposure_capabilities"] == ["command"]


def test_jenkins_with_credentials_variables_are_scoped_to_the_binding_block() -> None:
    source = """
node {
  withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) {
    sh "deploy $TOKEN"
  }
  sh "unrelated $TOKEN"
}
"""
    gate = analyze_jenkins({"jenkinsfile": source})
    assert gate["credential_binding_count"] == 1
    assert gate["secret_interpolation_count"] == 1


def test_jenkins_parser_ignores_pipeline_markers_in_comments_and_strings() -> None:
    source = 'def sample = "pipeline { stages { sh(\\\"deploy\\\") } }"\n// node("agent")\n'
    assert JenkinsAdapter().can_handle({"jenkinsfile": source}) is False


def test_jenkins_mutable_image_explanation_redacts_the_image_reference() -> None:
    source = """
pipeline {
  agent { docker { image 'registry-user:registry-password@registry.invalid/app:latest' } }
  stages { stage('x') { steps { echo 'ok' } } }
}
"""
    changes = JenkinsAdapter().analyze({"jenkinsfile": source}, use_rules=False)
    image = next(change for change in changes if change.resource_type == "jenkins_container_image")
    assert image.risk == "dangerous"
    assert "not pinned by digest" in image.explanation
    assert "registry-user" not in image.explanation
    assert "registry-password" not in image.explanation


def test_jenkins_cli_reads_jenkinsfile(tmp_path, capsys) -> None:
    source = tmp_path / "Jenkinsfile"
    source.write_text("pipeline {\n  stages {\n    echo 'ok'\n  }\n}\n", encoding="utf-8")
    assert main(["jenkins", "--framework", "soc2", str(source)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision"] == "proceed"
    assert payload["adapter"] == "jenkins"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


def test_jenkins_cli_rejects_unrecognized_text(tmp_path, capsys) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("deploy this somehow\n", encoding="utf-8")
    assert main(["jenkins", str(source)]) == 1
    assert "not recognized" in capsys.readouterr().err
