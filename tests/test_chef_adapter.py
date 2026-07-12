from __future__ import annotations

import json

from readtheplan.adapters import detect_adapter
from readtheplan.adapters.chef import ChefAdapter, analyze_chef
from readtheplan.cli import main


def test_chef_recipe_classification() -> None:
    source = """
log 'starting'

package 'nginx' do
  action :install
end

service 'nginx' do
  action [:enable, :restart]
end

execute 'migrate database' do
  command './migrate'
end
"""
    data = {"chef_recipe": source}
    assert isinstance(detect_adapter(data), ChefAdapter)
    changes = ChefAdapter().analyze(data, use_rules=False)
    assert [change.risk for change in changes] == ["safe", "review", "dangerous", "dangerous"]


def test_chef_gate_and_cli(tmp_path, capsys) -> None:
    gate = analyze_chef({"chef_recipe": "execute 'deploy' do\n command './deploy'\nend\n"})
    assert gate["decision"] == "block"
    assert "Chef" in gate["reason"]

    recipe = tmp_path / "default.rb"
    recipe.write_text("log 'hello'\n", encoding="utf-8")
    assert main(["chef", str(recipe)]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "proceed"


def test_chef_cli_rejects_plain_ruby(tmp_path, capsys) -> None:
    source = tmp_path / "script.rb"
    source.write_text("puts 'hello'\n", encoding="utf-8")
    assert main(["chef", str(source)]) == 1
    assert "not recognized" in capsys.readouterr().err
