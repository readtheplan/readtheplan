"""Tests for the self-improving evolution engine."""

from __future__ import annotations

import hashlib
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


def _generate_candidate(
    engine: EvolutionEngine,
    monkeypatch: pytest.MonkeyPatch,
    resource_type: str,
) -> dict:
    """Generate one verified candidate without invoking an optional provider CLI."""
    monkeypatch.setattr("readtheplan.evolution.shutil.which", lambda _command: None)
    [candidate] = engine.analyze_with_agents(
        [
            {
                "pattern_hash": f"{resource_type}::dangerous",
                "resource_type": resource_type,
                "risk": "dangerous",
                "incident_count": 12,
            }
        ]
    )
    return candidate


def _write_approved_rule_store(
    data_dir: Path,
    rule_id: str,
    source: bytes,
) -> Path:
    approved_dir = data_dir / "approved-rules"
    approved_dir.mkdir(parents=True, exist_ok=True)
    rule_file = approved_dir / f"{rule_id}.py"
    rule_file.write_bytes(source)
    (approved_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "readtheplan-approved-rules-v1",
                "rules": {
                    rule_id: {
                        "file": rule_file.name,
                        "sha256": hashlib.sha256(source).hexdigest(),
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return rule_file


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
    # Irreversible + 3 incidents = score >= 70, so it is ready for human approval.
    assert evolved[0]["rule_status"] == "pr-ready"
    assert Path(evolved[0]["candidate_dir"]).is_relative_to(engine.data_dir)


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
    
    del os.environ["AGENT_HANDOFF_ROOT"]


def test_candidate_artifacts_are_confined_and_validate_counterexamples(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    engine = _make_engine(tmp_path)
    candidate = _generate_candidate(engine, monkeypatch, "custom_widget_confinement")

    candidate_dir = Path(candidate["candidate_dir"]).resolve()
    assert candidate_dir.parent == engine.candidates_dir.resolve()
    assert {path.name for path in candidate_dir.iterdir()} == {
        "candidate.json",
        "rule.py",
        "test_rule.py",
    }

    metadata = json.loads((candidate_dir / "candidate.json").read_text(encoding="utf-8"))
    assert metadata["rule_id"] == candidate["rule_id"]
    assert metadata["verified"] is True
    validation = (candidate_dir / "test_rule.py").read_text(encoding="utf-8")
    assert "spec_from_file_location" in validation
    assert 'Path(__file__).with_name("rule.py")' in validation
    assert '{"no-op"}' in validation
    assert '{"read"}' in validation
    assert "== []" in validation


def test_candidate_runtime_verification_restores_registry_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    import sys

    import readtheplan.rules._shared as shared
    from readtheplan.rules import RuleResult, apply_resource_rules

    resource_type = "custom_widget_runtime_isolation"
    registry_object = shared._RULE_REGISTRY
    cross_cutting_object = shared._CROSS_CUTTING
    registry_snapshot = {
        registered_type: (id(bucket), tuple(bucket))
        for registered_type, bucket in registry_object.items()
    }
    cross_cutting_snapshot = tuple(cross_cutting_object)
    source_snapshot = shared._current_source

    engine = _make_engine(tmp_path)
    candidate = _generate_candidate(engine, monkeypatch, resource_type)

    assert candidate["rule_status"] == "pr-ready"
    assert shared._RULE_REGISTRY is registry_object
    assert shared._CROSS_CUTTING is cross_cutting_object
    assert set(registry_object) == set(registry_snapshot)
    for registered_type, (bucket_id, functions) in registry_snapshot.items():
        assert id(registry_object[registered_type]) == bucket_id
        assert tuple(registry_object[registered_type]) == functions
    assert tuple(cross_cutting_object) == cross_cutting_snapshot
    assert shared._current_source == source_snapshot
    assert not any(
        module_name.startswith("_readtheplan_candidate_verify_")
        for module_name in sys.modules
    )

    result = apply_resource_rules(
        resource_type=resource_type,
        actions=("delete",),
        change={"actions": ["delete"]},
        baseline=RuleResult("safe", "baseline"),
    )
    assert result == RuleResult("safe", "baseline")


def test_failed_candidate_verification_is_disabled_with_zero_score(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    import readtheplan.evolution as evolution_module

    monkeypatch.setattr(
        evolution_module,
        "_verify_candidate_rule",
        lambda *args, **kwargs: (False, "counterexample failed"),
    )
    engine = _make_engine(tmp_path)
    candidate = _generate_candidate(
        engine,
        monkeypatch,
        "custom_widget_failed_verification",
    )
    metadata = json.loads(
        (Path(candidate["candidate_dir"]) / "candidate.json").read_text(encoding="utf-8")
    )

    assert candidate["rule_score"] == 0
    assert candidate["rule_status"] == "disabled"
    assert metadata["verified"] is False
    assert metadata["score"] == 0


def test_candidate_system_exit_is_a_verification_failure_with_rollback(
    tmp_path: Path,
):
    import sys

    import readtheplan.rules._shared as shared
    from readtheplan.evolution import _verify_candidate_rule

    resource_type = "custom_widget_system_exit"
    module_name = "_readtheplan_candidate_verify_system_exit"
    candidate_file = tmp_path / "rule.py"
    candidate_source = f'''from readtheplan.rules._shared import register_rule

@register_rule("{resource_type}")
def _rule_system_exit(resource_type, action_set, change):
    raise SystemExit(17)
'''.encode()

    success, error = _verify_candidate_rule(
        candidate_source,
        source_path=candidate_file,
        module_name=module_name,
        function_name="_rule_system_exit",
        resource_type=resource_type,
        risk="dangerous",
    )

    assert success is False
    assert error == "SystemExit: 17"
    assert resource_type not in shared._RULE_REGISTRY
    assert module_name not in sys.modules


def test_generation_rejects_symlinked_candidate_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    engine = _make_engine(tmp_path)
    resource_type = "custom_widget_symlink_generation"
    rule_id = f"rule_{resource_type}_dangerous"
    candidate_dir = engine.candidates_dir / rule_id
    candidate_dir.mkdir(parents=True)
    outside = tmp_path / "outside-rule.py"
    outside.write_text("sentinel", encoding="utf-8")
    try:
        (candidate_dir / "rule.py").symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"file symlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="symlinked output"):
        _generate_candidate(engine, monkeypatch, resource_type)
    assert outside.read_text(encoding="utf-8") == "sentinel"


def test_approve_rule_hash_allowlists_and_loads_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    from readtheplan.rules import RuleResult, apply_resource_rules
    from readtheplan.rules._shared import _RULE_REGISTRY

    engine = _make_engine(tmp_path)
    resource_type = "custom_widget_approval"
    candidate = _generate_candidate(engine, monkeypatch, resource_type)
    rule_id = candidate["rule_id"]

    # Loading an approved rule mutates the process-global registry by design.
    # Restore the original bucket after this test so provider-coverage tests
    # remain order-independent when suites are combined.
    monkeypatch.setitem(
        _RULE_REGISTRY,
        resource_type,
        list(_RULE_REGISTRY.get(resource_type, [])),
    )

    with pytest.raises(ValueError, match="invalid rule ID"):
        engine.approve_rule("../rule_escape")

    before = len(_RULE_REGISTRY.get(resource_type, []))
    approved = engine.approve_rule(rule_id)
    assert approved["rule_id"] == rule_id
    manifest = json.loads(
        (engine.approved_rules_dir / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["schema"] == "readtheplan-approved-rules-v1"
    assert manifest["rules"][rule_id]["sha256"] == approved["sha256"]
    assert len(_RULE_REGISTRY.get(resource_type, [])) == before

    assert engine.load_approved_rules() == [rule_id]
    assert len(_RULE_REGISTRY[resource_type]) == before + 1
    result = apply_resource_rules(
        resource_type=resource_type,
        actions=("delete",),
        change={"actions": ["delete"]},
        baseline=RuleResult("safe", "baseline"),
    )
    assert result.risk == "dangerous"
    assert result.source == f"approved:{rule_id}"

    # Re-loading the same manifest record is idempotent.
    assert engine.load_approved_rules() == [rule_id]
    assert len(_RULE_REGISTRY[resource_type]) == before + 1


def test_approval_rejects_symlinked_approved_rule_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    engine = _make_engine(tmp_path)
    candidate = _generate_candidate(engine, monkeypatch, "custom_widget_symlink_approval")
    engine.approved_rules_dir.mkdir()
    outside = tmp_path / "outside-approved-rule.py"
    outside.write_text("sentinel", encoding="utf-8")
    approved_file = engine.approved_rules_dir / f"{candidate['rule_id']}.py"
    try:
        approved_file.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"file symlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="symlinked output"):
        engine.approve_rule(candidate["rule_id"])
    assert outside.read_text(encoding="utf-8") == "sentinel"
    assert not (engine.approved_rules_dir / "manifest.json").exists()


def test_unapproved_or_hash_mismatched_rule_file_is_not_loaded(tmp_path: Path):
    from readtheplan.rules._shared import _RULE_REGISTRY, _load_auto_rules

    engine = _make_engine(tmp_path)
    resource_type = "custom_widget_unapproved"
    rule_id = f"rule_{resource_type}_dangerous"
    engine.approved_rules_dir.mkdir()
    loose_rule = engine.approved_rules_dir / f"{rule_id}.py"
    loose_rule.write_text(
        "from readtheplan.rules import RuleResult, register_rule\n"
        f"@register_rule({resource_type!r})\n"
        "def loose_rule(resource_type, action_set, change):\n"
        "    return [RuleResult('dangerous', 'must not load')]\n",
        encoding="utf-8",
    )
    before = len(_RULE_REGISTRY.get(resource_type, []))

    assert _load_auto_rules(engine.data_dir) == []
    assert len(_RULE_REGISTRY.get(resource_type, [])) == before

    (engine.approved_rules_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "readtheplan-approved-rules-v1",
                "rules": {
                    rule_id: {
                        "file": loose_rule.name,
                        "sha256": "0" * 64,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    assert _load_auto_rules(engine.data_dir) == []
    assert len(_RULE_REGISTRY.get(resource_type, [])) == before


def test_approved_loader_executes_verified_source_not_timestamp_valid_bytecode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    import importlib.util
    import os
    import py_compile

    from readtheplan.rules._shared import _RULE_REGISTRY, _load_auto_rules

    data_dir = tmp_path / ".readtheplan"
    rule_id = "rule_custom_widget_bytecode_dangerous"
    good_resource = "custom_widget_bytecode_good"
    evil_resource = "custom_widget_bytecode_evil"
    template = (
        "from readtheplan.rules._shared import RuleResult, register_rule\n\n"
        '@register_rule("custom_widget_bytecode_{token}")\n'
        "def approved_rule(resource_type, action_set, change):\n"
        '    return [RuleResult("dangerous", "{token}")]\n'
    )
    benign_source = template.format(token="good").encode()
    malicious_source = template.format(token="evil").encode()
    assert len(benign_source) == len(malicious_source)

    rule_file = _write_approved_rule_store(data_dir, rule_id, malicious_source)
    fixed_timestamp = 1_700_000_000
    os.utime(rule_file, (fixed_timestamp, fixed_timestamp))
    cached_file = Path(importlib.util.cache_from_source(str(rule_file)))
    cached_file.parent.mkdir(exist_ok=True)
    py_compile.compile(
        str(rule_file),
        cfile=str(cached_file),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
    )

    # Keep the timestamp and size accepted by the malicious pyc while the
    # manifest hashes the benign source now present at the same pathname.
    _write_approved_rule_store(data_dir, rule_id, benign_source)
    os.utime(rule_file, (fixed_timestamp, fixed_timestamp))
    assert cached_file.is_file()

    monkeypatch.setitem(
        _RULE_REGISTRY,
        good_resource,
        list(_RULE_REGISTRY.get(good_resource, [])),
    )
    monkeypatch.setitem(
        _RULE_REGISTRY,
        evil_resource,
        list(_RULE_REGISTRY.get(evil_resource, [])),
    )
    good_before = len(_RULE_REGISTRY[good_resource])
    evil_before = len(_RULE_REGISTRY[evil_resource])

    assert _load_auto_rules(data_dir) == [rule_id]
    assert len(_RULE_REGISTRY[good_resource]) == good_before + 1
    assert len(_RULE_REGISTRY[evil_resource]) == evil_before


def test_approved_loader_rolls_back_partial_registry_mutations(tmp_path: Path):
    import sys

    import readtheplan.rules._shared as shared

    data_dir = tmp_path / ".readtheplan"
    rule_id = "rule_custom_widget_failed_load_dangerous"
    failed_resource = "custom_widget_failed_load"
    failing_source = (
        "import readtheplan.rules._shared as shared\n"
        "from readtheplan.rules._shared import (\n"
        "    RuleResult, register_cross_cutting, register_rule,\n"
        ")\n\n"
        f"@register_rule({failed_resource!r})\n"
        "def failed_rule(resource_type, action_set, change):\n"
        "    return [RuleResult('dangerous', 'must roll back')]\n\n"
        "@register_cross_cutting\n"
        "def failed_cross_cutting(resource_type, action_set, change):\n"
        "    return []\n\n"
        "shared._current_source = 'corrupted-during-load'\n"
        "raise RuntimeError('approved module failed after registration')\n"
    ).encode()
    _write_approved_rule_store(data_dir, rule_id, failing_source)

    registry_object = shared._RULE_REGISTRY
    cross_cutting_object = shared._CROSS_CUTTING
    registry_before = {
        resource_type: tuple(bucket)
        for resource_type, bucket in registry_object.items()
    }
    bucket_ids_before = {
        resource_type: id(bucket)
        for resource_type, bucket in registry_object.items()
    }
    cross_cutting_before = tuple(cross_cutting_object)
    source_before = shared._current_source

    assert shared._load_auto_rules(data_dir) == []
    assert shared._RULE_REGISTRY is registry_object
    assert shared._CROSS_CUTTING is cross_cutting_object
    assert set(registry_object) == set(registry_before)
    for resource_type, before in registry_before.items():
        assert tuple(registry_object[resource_type]) == before
        assert id(registry_object[resource_type]) == bucket_ids_before[resource_type]
    assert tuple(cross_cutting_object) == cross_cutting_before
    assert failed_resource not in registry_object
    assert shared._current_source == source_before
    assert not any(rule_id in module_name for module_name in sys.modules)


def test_approval_rejects_disabled_or_unverified_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    engine = _make_engine(tmp_path)
    candidate = _generate_candidate(engine, monkeypatch, "custom_widget_unverified")
    metadata_file = Path(candidate["candidate_dir"]) / "candidate.json"
    metadata = json.loads(metadata_file.read_text(encoding="utf-8"))

    metadata["status"] = "disabled"
    metadata_file.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(ValueError, match="not verified and pr-ready"):
        engine.approve_rule(candidate["rule_id"])

    metadata["status"] = "pr-ready"
    metadata["verified"] = False
    metadata_file.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(ValueError, match="not verified and pr-ready"):
        engine.approve_rule(candidate["rule_id"])
    assert not engine.approved_rules_dir.exists()


def test_cli_evolve_approve_uses_exact_top_level_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    import readtheplan.cli as cli

    engine = _make_engine(tmp_path)
    candidate = _generate_candidate(engine, monkeypatch, "custom_widget_cli")
    monkeypatch.setattr(cli, "get_engine", lambda: engine)

    assert cli.main(["evolve", "approve", candidate["rule_id"]]) == 0
    captured = capsys.readouterr()
    assert f"Approved {candidate['rule_id']}" in captured.out
    assert (engine.approved_rules_dir / "manifest.json").is_file()


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
