"""Red tests for install-safety and side effects (Codex review 2026-07-10, findings 4-5).

These tests encode REQUIRED behavior. They are expected to FAIL on
main@c84c9c0 and must pass once ``fix/install-safety`` lands.

Findings covered:

4. Self-improving mode must be install-safe: candidate verification must not
   spawn subprocesses or require pytest at runtime, and evolution diagnostics
   must never corrupt the CLI's JSON stdout.
5. No misleading side effects: importing the CLI or evolution module must not
   create ``~/.readtheplan``, and ``analyze --mode self-improving`` must
   actually record the run.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from readtheplan.cli import main
from readtheplan.evolution import EvolutionEngine

FIXTURES = Path(__file__).parent / "fixtures"


def _isolated_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


# ---------------------------------------------------------------------------
# Finding 5 — import side effects
# ---------------------------------------------------------------------------


def _import_in_clean_interpreter(module: str, home: Path) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    return subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_importing_evolution_module_creates_no_home_state(tmp_path) -> None:
    """``import readtheplan.evolution`` must not create ~/.readtheplan.

    On main, the module-level ``evolution = EvolutionEngine()`` singleton
    creates the data dir, ``briefs/``, and ``evolution.db`` at import time.
    """
    home = tmp_path / "home"
    home.mkdir()
    proc = _import_in_clean_interpreter("readtheplan.evolution", home)
    assert proc.returncode == 0, proc.stderr
    assert not (home / ".readtheplan").exists(), (
        "importing readtheplan.evolution created ~/.readtheplan"
    )


def test_importing_cli_creates_no_home_state(tmp_path) -> None:
    """``import readtheplan.cli`` must not create ~/.readtheplan."""
    home = tmp_path / "home"
    home.mkdir()
    proc = _import_in_clean_interpreter("readtheplan.cli", home)
    assert proc.returncode == 0, proc.stderr
    assert not (home / ".readtheplan").exists(), (
        "importing readtheplan.cli created ~/.readtheplan"
    )


# ---------------------------------------------------------------------------
# Finding 5 — analyze --mode self-improving must not be a no-op
# ---------------------------------------------------------------------------


def test_analyze_self_improving_records_run(monkeypatch, tmp_path, capsys) -> None:
    """``analyze --mode self-improving`` must record the run in the engine.

    On main the flag is accepted and silently ignored: ``_analyze`` never
    constructs an :class:`EvolutionEngine`.
    """
    home = _isolated_home(monkeypatch, tmp_path)
    rc = main(["analyze", "--mode", "self-improving", str(FIXTURES / "valid_plan.json")])
    assert rc in (0, 1, 2)
    capsys.readouterr()

    data_dir = home / ".readtheplan"
    assert data_dir.exists(), "self-improving analyze recorded nothing"
    engine = EvolutionEngine(data_dir=data_dir)
    assert engine.get_recent_runs(limit=1), "no run was recorded in evolution.db"


# ---------------------------------------------------------------------------
# Finding 4 — install-safe verification (no subprocess, no pytest dependency)
# ---------------------------------------------------------------------------

_PATTERN = {
    "resource_type": "aws_s3_bucket",
    "risk": "dangerous",
    "incident_count": 12,
    "pattern_hash": "feedfacefeedface",
}


def test_candidate_verification_runs_in_process(monkeypatch, tmp_path) -> None:
    """Candidate verification must not spawn subprocesses.

    pytest is not a runtime dependency, and ``PYTHONPATH=src`` only exists in
    a source checkout, so shelling out breaks on installed wheels. Raised
    ``AssertionError`` exceptions from either standard subprocess entry point
    prove verification remains in-process.
    """
    import shutil

    def _no_subprocess(*args, **kwargs):
        raise AssertionError("candidate verification must not spawn subprocesses")

    monkeypatch.setattr(shutil, "which", lambda _command: "external-tool")
    monkeypatch.setattr(subprocess, "run", _no_subprocess)
    monkeypatch.setattr(subprocess, "Popen", _no_subprocess)

    engine = EvolutionEngine(data_dir=tmp_path / "data")
    evolved = engine.analyze_with_agents([dict(_PATTERN)])

    assert evolved, "expected a candidate to be produced"
    assert evolved[0]["rule_status"] == "pr-ready", (
        "verification must succeed in-process without pytest or subprocesses"
    )


# ---------------------------------------------------------------------------
# Finding 4 — diagnostics must never reach stdout
# ---------------------------------------------------------------------------


def test_rule_generation_prints_nothing_to_stdout(tmp_path, capsys) -> None:
    """All evolution diagnostics (including the PR template) go to stderr.

    Machine-readable CLI output owns stdout; a high-scoring candidate on main
    prints its PR template there.
    """
    engine = EvolutionEngine(data_dir=tmp_path / "data")
    engine.analyze_with_agents([dict(_PATTERN)])

    captured = capsys.readouterr()
    assert captured.out == "", (
        f"evolution diagnostics leaked to stdout: {captured.out[:200]!r}"
    )


def test_agent_gate_self_improving_stdout_stays_valid_json(
    monkeypatch, tmp_path, capsys
) -> None:
    """Repeated self-improving gate runs must keep emitting parseable JSON.

    The clean-wheel probe in the 2026-07-10 review reproduced invalid JSON on
    the third run, when accumulated incidents first trigger rule suggestion
    and its diagnostics interleave with the JSON document on stdout.
    """
    _isolated_home(monkeypatch, tmp_path)
    plan = str(FIXTURES / "valid_plan.json")

    for run_number in range(1, 5):
        rc = main(["agent-gate", "--mode", "self-improving", plan])
        assert rc in (0, 1, 2)
        out = capsys.readouterr().out
        try:
            json.loads(out)
        except json.JSONDecodeError as exc:
            pytest.fail(
                f"run {run_number} produced invalid JSON on stdout: {exc}\n"
                f"first 300 chars: {out[:300]!r}"
            )
