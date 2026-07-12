from __future__ import annotations

import json

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.puppet import PuppetAdapter, analyze_puppet
from readtheplan.cli import main


def test_puppet_manifest_classification() -> None:
    source = """
package { 'nginx':
  ensure => installed,
}
service { 'nginx':
  ensure => 'stopped',
}
exec { 'database migration':
  command => '/srv/migrate',
}
"""
    data = {"puppet_manifest": source}
    assert isinstance(detect_adapter(data), PuppetAdapter)
    changes = PuppetAdapter().analyze(data, use_rules=False)
    assert [change.risk for change in changes] == ["review", "dangerous", "dangerous"]


def test_puppet_gate_and_cli(tmp_path, capsys) -> None:
    gate = analyze_puppet({"puppet_manifest": "exec { 'deploy':\n command => '/deploy',\n}\n"})
    assert gate["decision"] == "block"
    assert "Puppet" in gate["reason"]
    assert "Puppet input path" in gate["evidence_checklist"][0]
    assert "plan JSON" not in gate["evidence_checklist"][0]

    manifest = tmp_path / "site.pp"
    manifest.write_text("package { 'curl':\n ensure => installed,\n}\n", encoding="utf-8")
    assert main(["puppet", "--framework", "soc2", str(manifest)]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision"] == "warn"
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


def test_puppet_cli_rejects_plain_text(tmp_path, capsys) -> None:
    source = tmp_path / "notes.pp"
    source.write_text("this is not a manifest\n", encoding="utf-8")
    assert main(["puppet", str(source)]) == 1
    assert "not recognized" in capsys.readouterr().err
