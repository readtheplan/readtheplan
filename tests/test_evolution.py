"""Tests for the self-improving evolution engine."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.evolution import EvolutionEngine, _sanitize_for_codegen
from readtheplan.plan import analyze_plan_file

# ── Helpers ───────────────────────────────────────────────────────


def _make_engine(tmp_path: Path) -> EvolutionEngine:
    """Create an engine with a temp data dir so tests don't collide."""
    data_dir = tmp_path / ".readtheplan"
    return EvolutionEngine(data_dir)


def _write_plan(tmp_path: Path, actions: list[str], resource_type: str = "aws_s3_bucket") -> Path:
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps({
            "resource_changes": [
                {
                    "address": f"{resource_type}.example",
                    "type": resource_type,
                    "change": {"actions": actions},
                }
            ]
        }),
        encoding="utf-8",
    )
    return plan


# ── Engine tests ──────────────────────────────────────────────────


def test_engine_creates_db(tmp_path: Path):
    engine = _make_engine(tmp_path)
    assert engine.db_path.exists()
    assert engine.data_dir.exists()


def test_record_run(tmp_path: Path):
    engine = _make_engine(tmp_path)
    run_id = engine.record_run(
        plan_hash="abc123",
        decision="block",
        compliance_score=45.0,
        mode="self-improving",
        incident_flag=True,
    )
    assert run_id is not None and run_id > 0

    stats = engine.get_stats()
    assert stats["total_runs"] == 1
    assert stats["blocked"] == 1


def test_record_and_detect_patterns(tmp_path: Path):
    engine = _make_engine(tmp_path)

    # Run 3 incidents of the same type to trigger pattern detection
    for i in range(3):
        run_id = engine.record_run(
            plan_hash=f"plan-{i}",
            decision="block",
            compliance_score=30.0,
            mode="self-improving",
            incident_flag=True,
        )
        engine.record_incident(
            run_id=run_id,
            resource_type="aws_s3_bucket",
            risk="irreversible",
            address=f"aws_s3_bucket.deleteme-{i}",
            actions=["delete"],
        )

    patterns = engine.analyze_incidents(min_incidents=3)
    assert len(patterns) == 1
    assert patterns[0]["resource_type"] == "aws_s3_bucket"
    assert patterns[0]["incident_count"] == 3


def test_pattern_below_threshold_not_detected(tmp_path: Path):
    engine = _make_engine(tmp_path)

    # Only 2 incidents — should be below the threshold of 3
    for i in range(2):
        run_id = engine.record_run(
            plan_hash=f"plan-{i}",
            decision="block",
            compliance_score=30.0,
            mode="self-improving",
            incident_flag=True,
        )
        engine.record_incident(
            run_id=run_id,
            resource_type="aws_lambda_function",
            risk="dangerous",
            address=f"aws_lambda_function.fn-{i}",
            actions=["update"],
        )

    patterns = engine.analyze_incidents(min_incidents=3)
    assert len(patterns) == 0


def test_analyze_with_agents_generates_rule(tmp_path: Path):
    engine = _make_engine(tmp_path)

    # Set up a pattern manually
    for i in range(3):
        run_id = engine.record_run(
            plan_hash=f"plan-{i}",
            decision="block",
            compliance_score=30.0,
            mode="self-improving",
            incident_flag=True,
        )
        engine.record_incident(
            run_id=run_id,
            resource_type="aws_iam_role",
            risk="irreversible",
            address=f"aws_iam_role.admin-{i}",
            actions=["delete"],
        )

    patterns = engine.analyze_incidents(min_incidents=3)
    evolved = engine.analyze_with_agents(patterns)

    assert len(evolved) == 1
    assert evolved[0]["suggested_rule"] is not None
    assert "aws_iam_role" in evolved[0]["suggested_rule"]
    assert evolved[0]["rule_score"] > 0
    # Irreversible + 3 incidents = score >= 70, so should be at least "pr-ready"
    assert evolved[0]["rule_status"] in ("pr-ready", "auto-merge", "disabled")

    # Cleanup permanently generated files from tests
    auto_rule = Path("src/readtheplan/rules/auto/rule_aws_iam_role_irreversible.py")
    auto_test = Path("tests/test_rules_auto/test_rule_aws_iam_role_irreversible.py")
    if auto_rule.exists():
        auto_rule.unlink()
    if auto_test.exists():
        auto_test.unlink()


def test_full_evolution_loop(tmp_path: Path):
    engine = _make_engine(tmp_path)

    result = engine.run_full_evolution_loop(
        plan_hash="full-loop-test",
        decision="block",
        compliance_score=30.0,
        mode="self-improving",
        plan_summary={"path": "test.json", "terraform_version": "1.5", "change_count": 1},
        resource_changes=[
            {"address": "aws_s3_bucket.data", "resource_type": "aws_s3_bucket",
             "actions": ["delete"], "risk": "irreversible", "explanation": "Bucket deletion"}
        ],
    )

    assert result["run_id"] > 0
    assert result["decision"] == "block"
    assert result["compliance_score"] == 30.0

    # Should have recorded the incident
    stats = engine.get_stats()
    assert stats["total_runs"] == 1
    assert stats["total_incidents"] == 1


def test_full_loop_triggers_pattern_after_3_runs(tmp_path: Path):
    engine = _make_engine(tmp_path)

    change = {
        "address": "aws_s3_bucket.data",
        "resource_type": "aws_s3_bucket",
        "actions": ["delete"],
        "risk": "irreversible",
        "explanation": "Bucket deletion",
    }

    # Run 3 times with same resource type
    for i in range(3):
        result = engine.run_full_evolution_loop(
            plan_hash=f"loop-{i}",
            decision="block",
            compliance_score=30.0,
            mode="self-improving",
            resource_changes=[change],
        )
        if i < 2:
            assert result["patterns_detected"] == 0
        else:
            # On the 3rd run, pattern should be detected
            assert result["patterns_detected"] >= 1


def test_get_stats_empty(tmp_path: Path):
    engine = _make_engine(tmp_path)
    stats = engine.get_stats()
    assert stats["total_runs"] == 0
    assert stats["blocked"] == 0
    assert stats["avg_compliance_score"] == 0.0


def test_get_stats_with_data(tmp_path: Path):
    engine = _make_engine(tmp_path)
    engine.record_run(plan_hash="a", decision="proceed", compliance_score=90.0)
    engine.record_run(plan_hash="b", decision="warn", compliance_score=60.0)
    engine.record_run(plan_hash="c", decision="block", compliance_score=25.0)

    stats = engine.get_stats()
    assert stats["total_runs"] == 3
    assert stats["blocked"] == 1
    assert stats["warned"] == 1
    # (90 + 60 + 25) / 3 = 58.3
    assert stats["avg_compliance_score"] == 58.3


def test_generate_html_dashboard(tmp_path: Path):
    engine = _make_engine(tmp_path)
    engine.record_run(plan_hash="a", decision="proceed", compliance_score=90.0)
    engine.record_run(plan_hash="b", decision="warn", compliance_score=60.0)

    path = engine.generate_html_dashboard()
    assert Path(path).exists()
    html = Path(path).read_text(encoding="utf-8")
    assert "Self-Improving Kernel Gate" in html
    assert "chart.js" in html.lower() or "Chart.js" in html


def test_get_recent_runs(tmp_path: Path):
    engine = _make_engine(tmp_path)
    for i in range(5):
        engine.record_run(
            plan_hash=f"plan-{i}",
            decision="proceed",
            compliance_score=80.0 + i,
        )

    runs = engine.get_recent_runs(limit=3)
    assert len(runs) == 3
    # Most recent first
    assert runs[0]["compliance_score"] == 84.0


def test_get_all_patterns(tmp_path: Path):
    engine = _make_engine(tmp_path)

    # Create a pattern
    for i in range(3):
        run_id = engine.record_run(
            plan_hash=f"p-{i}",
            decision="block",
            compliance_score=30.0,
            mode="self-improving",
            incident_flag=True,
        )
        engine.record_incident(
            run_id=run_id,
            resource_type="aws_ec2_instance",
            risk="dangerous",
            address=f"aws_ec2_instance.web-{i}",
            actions=["delete", "create"],
        )

    engine.analyze_incidents(min_incidents=3)
    patterns = engine.get_all_patterns()
    assert len(patterns) >= 1
    assert patterns[0]["resource_type"] == "aws_ec2_instance"
    assert patterns[0]["rule_status"] == "pending"


def test_generate_voice_brief(tmp_path: Path):
    engine = _make_engine(tmp_path)
    for i in range(3):
        engine.record_run(
            plan_hash=f"v-{i}",
            decision="proceed",
            compliance_score=75.0 + i * 5,
        )

    text = engine.generate_voice_brief(style="concise")
    assert "3 runs" in text or "3" in text

    text_narrative = engine.generate_voice_brief(style="narrative")
    assert len(text_narrative) > len(text)


def test_compliance_score_in_agent_gate(tmp_path: Path):
    """Verify that agent_gate_to_dict includes compliance_score."""
    plan = _write_plan(tmp_path, ["delete"])  # irreversible
    summary = analyze_plan_file(plan)
    gate = agent_gate_to_dict(summary, mode="kernel")
    assert "compliance_score" in gate
    # One irreversible change = 100 - 30 = 70
    assert gate["compliance_score"] == 70.0


def test_self_improving_mode_creates_evolution_block(tmp_path: Path):
    """Verify that self-improving mode adds evolution data to gate output."""
    engine = _make_engine(tmp_path)
    plan = _write_plan(tmp_path, ["delete"])
    summary = analyze_plan_file(plan)

    gate = agent_gate_to_dict(summary, mode="self-improving", evolution_engine=engine)
    assert "evolution" in gate
    assert gate["evolution"]["run_id"] > 0
    assert gate["schema"] == "rtp-kernel-v1"

    # Should have recorded the incident
    stats = engine.get_stats()
    assert stats["total_runs"] == 1


def test_kernel_mode_no_evolution(tmp_path: Path):
    """Verify that kernel mode does NOT add evolution data."""
    plan = _write_plan(tmp_path, ["create"])
    summary = analyze_plan_file(plan)

    gate = agent_gate_to_dict(summary, mode="kernel")
    assert "evolution" not in gate
    assert gate["schema"] == "rtp-agent-gate-v1"
    assert gate["mode"] == "kernel"


def test_different_risk_profiles_different_scores(tmp_path: Path):
    """Verify different plan compositions produce different compliance scores."""
    engine = _make_engine(tmp_path)

    # Safe plan
    safe_plan = _write_plan(tmp_path, ["create"])
    safe_summary = analyze_plan_file(safe_plan)
    safe_gate = agent_gate_to_dict(safe_summary, mode="self-improving", evolution_engine=engine)

    # Irreversible plan
    bad_plan = _write_plan(tmp_path, ["delete"], resource_type="aws_iam_role")
    bad_summary = analyze_plan_file(bad_plan)
    bad_gate = agent_gate_to_dict(bad_summary, mode="self-improving", evolution_engine=engine)

    assert safe_gate["compliance_score"] > bad_gate["compliance_score"]
    assert safe_gate["decision"] == "proceed"
    assert bad_gate["decision"] == "block"


def test_evolution_real_multi_agent_pipeline(tmp_path: Path):
    """Test the real multi-agent pipeline verification loop and code generation."""
    engine = _make_engine(tmp_path)
    
    patterns = [{
        "pattern_hash": "aws_s3_bucket::irreversible",
        "resource_type": "aws_s3_bucket",
        "risk": "irreversible",
        "incident_count": 10,
    }]
    
    evolved = engine.analyze_with_agents(patterns)
    assert len(evolved) == 1
    assert evolved[0]["rule_score"] == 100.0
    assert evolved[0]["rule_status"] == "pr-ready"
    
    handoffs_dir = engine.data_dir / "handoffs"
    assert handoffs_dir.exists()
    handoff_files = list(handoffs_dir.glob("*.json"))
    assert len(handoff_files) == 1
    
    handoff_data = json.loads(handoff_files[0].read_text(encoding="utf-8"))
    assert handoff_data["resource_type"] == "aws_s3_bucket"
    assert handoff_data["risk"] == "irreversible"
    
    import os
    temp_handoff_root = tmp_path / "shared_handoffs"
    os.environ["AGENT_HANDOFF_ROOT"] = str(temp_handoff_root)
    
    dispatched = engine.dispatch_handoffs()
    assert len(dispatched) == 1
    assert not handoff_files[0].exists()
    
    assert temp_handoff_root.exists()
    mcp_json_files = list(temp_handoff_root.glob("*.json"))
    mcp_md_files = list(temp_handoff_root.glob("*.md"))
    assert len(mcp_json_files) == 1
    assert len(mcp_md_files) == 1
    
    from pathlib import Path
    auto_rule = Path("src/readtheplan/rules/auto/rule_aws_s3_bucket_irreversible.py")
    auto_test = Path("tests/test_rules_auto/test_rule_aws_s3_bucket_irreversible.py")
    if auto_rule.exists():
        auto_rule.unlink()
    if auto_test.exists():
        auto_test.unlink()
        
    del os.environ["AGENT_HANDOFF_ROOT"]


def test_cli_evolution_console(capsys):
    """Test evolution console subcommand output."""
    import sys

    from readtheplan.cli import main
    
    sys.argv = ["readtheplan", "evolution", "console"]
    try:
        main()
    except SystemExit as e:
        assert e.code == 0
        
    captured = capsys.readouterr()
    assert "READTHEPLAN EVOLUTION CONSOLE DASHBOARD" in captured.out
    assert "DETECTED PATTERNS" in captured.out
    assert "RECENT RUNS" in captured.out


def test_cli_evolution_dispatch(capsys):
    """Test evolution dispatch subcommand."""
    import sys

    from readtheplan.cli import main

    sys.argv = ["readtheplan", "evolution", "dispatch"]
    try:
        main()
    except SystemExit as e:
        assert e.code == 0

    captured = capsys.readouterr()
    assert "No pending handoffs" in captured.out or "Successfully dispatched" in captured.out


# ── Security regression tests ─────────────────────────────────────


def test_sanitize_rejects_shell_metacharacters():
    """resource_type containing shell/Python metacharacters must be rejected."""
    with pytest.raises(ValueError, match="not a safe Python identifier"):
        _sanitize_for_codegen("aws_s3_bucket\npass\nimport os", "irreversible")


def test_sanitize_rejects_unknown_risk():
    """An unrecognised risk level must be rejected before code generation."""
    with pytest.raises(ValueError, match="not a known risk level"):
        _sanitize_for_codegen("aws_s3_bucket", "critical_unknown")


def test_sanitize_rejects_trailing_newline():
    """A trailing newline on an otherwise-valid name must NOT bypass the regex."""
    # re.match() with $ allows trailing \n to pass; .fullmatch() blocks it.
    with pytest.raises(ValueError, match="not a safe Python identifier"):
        _sanitize_for_codegen("aws_s3_bucket\n", "irreversible")


def test_html_dashboard_escapes_plan_derived_fields(tmp_path: Path):
    """HTML-injectable patterns must be escaped in the generated dashboard."""
    engine = _make_engine(tmp_path)

    # Seed 3 incidents so analyze_incidents() writes a row to the patterns table.
    for i in range(3):
        run_id = engine.record_run(
            plan_hash=f"xss-{i}",
            decision="block",
            compliance_score=20.0,
            mode="self-improving",
            incident_flag=True,
        )
        engine.record_incident(
            run_id=run_id,
            resource_type="aws_s3_bucket",
            risk="irreversible",
            address=f"aws_s3_bucket.xss-{i}",
            actions=["delete"],
        )
    engine.analyze_incidents(min_incidents=3)  # materialises the patterns table row

    # Tamper: overwrite resource_type with an XSS payload directly in the DB,
    # simulating a crafted plan.json that bypassed earlier validation.
    xss_payload = '<script>alert("xss")</script>'
    with sqlite3.connect(engine.db_path) as conn:
        conn.execute("UPDATE patterns SET resource_type = ?", (xss_payload,))

    html = Path(engine.generate_html_dashboard()).read_text(encoding="utf-8")
    assert xss_payload not in html, "Raw XSS payload must not appear in dashboard HTML"
    assert "&lt;script&gt;" in html, "XSS payload must be HTML-escaped in the dashboard"


def test_standalone_report_escapes_plan_derived_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """The standalone generate-report tool must also escape DB-sourced data."""
    import importlib.util
    repo_root = Path(__file__).parent.parent
    spec = importlib.util.spec_from_file_location(
        "generate_evolution_report",
        repo_root / "tools" / "generate-evolution-report.py",
    )
    report_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(report_mod)

    # Redirect report tool output: monkeypatch home() so it writes to tmp_path
    readtheplan_dir = tmp_path / ".readtheplan"
    readtheplan_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    # Make the engine write to .readtheplan/ so the standalone tool finds the DB
    # _make_engine creates data_dir = tmp_path / ".readtheplan" internally
    engine = _make_engine(tmp_path)

    # Seed 3 incidents to produce a patterns row.
    for i in range(3):
        run_id = engine.record_run(
            plan_hash=f"xss-{i}", decision="block",
            compliance_score=20.0, mode="self-improving", incident_flag=True,
        )
        engine.record_incident(
            run_id=run_id, resource_type="aws_s3_bucket",
            risk="irreversible", address=f"aws_s3_bucket.xss-{i}",
            actions=["delete"],
        )
    engine.analyze_incidents(min_incidents=3)

    # Tamper: inject XSS into resource_type directly in the report DB.
    xss_payload = '<script>alert("xss")</script>'
    with sqlite3.connect(readtheplan_dir / "evolution.db") as conn:
        conn.execute("UPDATE patterns SET resource_type = ?", (xss_payload,))

    report_file = readtheplan_dir / "evolution-report.html"
    report_mod.generate_report()

    html = report_file.read_text(encoding="utf-8")
    assert xss_payload not in html, "Raw XSS must NOT appear in standalone report"
    assert "&lt;script&gt;" in html, "XSS must be HTML-escaped in standalone report"

