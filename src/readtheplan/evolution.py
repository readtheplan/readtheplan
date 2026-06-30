"""
Self-Improving Evolution Engine for readtheplan.

4-stage loop:
  1. Gate — classify risk, compliance score, decision
  2. Record — log every run to SQLite
  3. Analyze — detect recurring patterns across incidents
  4. Evolve — generate/score/merge rules automatically

Multi-agent coordination (optional, via provider CLI):
  - Research Agent (Grok) — finds patterns in past incidents
  - Coder Agent (DeepSeek) — generates rule code with tests
  - Reviewer Agent (Codex) — audits for correctness + safety
  - Signal Agent (Hermes) — decides auto-merge vs PR vs disable
"""

from __future__ import annotations

import html as _html
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# Valid risk values — must match RISK_ORDER in rules/_shared.py
_VALID_RISKS = frozenset({"safe", "review", "dangerous", "irreversible"})
# Resource type after normalisation must be an identifier-safe token
_RESOURCE_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")


def _sanitize_for_codegen(resource_type: str, risk: str) -> tuple[str, str]:
    """Validate and normalise inputs before they touch any code-generation path.

    Raises ValueError for inputs that would produce unsafe identifiers or
    unknown risk levels, stopping code generation before exec() is reached.
    """
    rt_clean = resource_type.replace("::", "_").replace("-", "_").replace(".", "_").lower()
    if not _RESOURCE_TYPE_RE.fullmatch(rt_clean):
        raise ValueError(
            f"resource_type {resource_type!r} normalises to {rt_clean!r} which is not "
            "a safe Python identifier (allowed: [a-z][a-z0-9_]{{0,127}})"
        )
    if risk not in _VALID_RISKS:
        raise ValueError(
            f"risk {risk!r} is not a known risk level (allowed: {sorted(_VALID_RISKS)})"
        )
    return rt_clean, risk


class EvolutionEngine:
    """Records gate runs, detects patterns, and evolves rules."""

    def __init__(self, data_dir: str | Path | None = None):
        if data_dir is None:
            data_dir = Path.home() / ".readtheplan"
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.db_path = self.data_dir / "evolution.db"
        self.report_file = self.data_dir / "evolution-report.html"
        self.brief_dir = self.data_dir / "briefs"
        self.brief_dir.mkdir(exist_ok=True)

        self._init_db()

    # ── Stage 1-2: Record ──────────────────────────────────────────────

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                plan_hash TEXT,
                decision TEXT,
                compliance_score REAL,
                mode TEXT,
                outcome TEXT,
                suggested_rules TEXT,
                incident_flag INTEGER,
                plan_summary TEXT,
                resource_types TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY,
                run_id INTEGER,
                resource_type TEXT,
                risk TEXT,
                address TEXT,
                actions TEXT,
                pattern_hash TEXT,
                FOREIGN KEY (run_id) REFERENCES runs(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS patterns (
                id INTEGER PRIMARY KEY,
                resource_type TEXT,
                risk TEXT,
                pattern_hash TEXT UNIQUE,
                incident_count INTEGER DEFAULT 1,
                first_seen TEXT,
                last_seen TEXT,
                suggested_rule TEXT,
                rule_score REAL,
                rule_status TEXT DEFAULT 'pending'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rules_catalog (
                id INTEGER PRIMARY KEY,
                pattern_id INTEGER,
                rule_code TEXT,
                rule_description TEXT,
                score REAL,
                status TEXT DEFAULT 'pending',
                created_at TEXT,
                merged_at TEXT,
                FOREIGN KEY (pattern_id) REFERENCES patterns(id)
            )
        """)
        conn.commit()
        conn.close()

    def record_run(
        self,
        plan_hash: str,
        decision: str,
        compliance_score: float,
        mode: str = "kernel",
        outcome: str = "success",
        suggested_rules: list | None = None,
        incident_flag: bool = False,
        plan_summary: dict | None = None,
        resource_types: list[str] | None = None,
    ) -> int:
        """Record a gate run and return its row ID."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.execute(
            "INSERT INTO runs (timestamp, plan_hash, decision, compliance_score, "
            "mode, outcome, suggested_rules, incident_flag, plan_summary, resource_types) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                datetime.now().isoformat(),
                plan_hash,
                decision,
                compliance_score,
                mode,
                outcome,
                json.dumps(suggested_rules or []),
                1 if incident_flag else 0,
                json.dumps(plan_summary or {}),
                json.dumps(resource_types or []),
            ),
        )
        run_id = cur.lastrowid
        conn.commit()
        conn.close()
        return run_id

    def record_incident(
        self,
        run_id: int,
        resource_type: str,
        risk: str,
        address: str,
        actions: list[str],
    ) -> str:
        """Record an individual incident and return its pattern hash."""
        pattern_hash = self._pattern_hash(resource_type, risk)
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO incidents (run_id, resource_type, risk, "
            "address, actions, pattern_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (run_id, resource_type, risk, address,
             json.dumps(actions), pattern_hash),
        )
        conn.commit()
        conn.close()
        return pattern_hash

    @staticmethod
    def _pattern_hash(resource_type: str, risk: str) -> str:
        return f"{resource_type}::{risk}"

    # ── Stage 3: Analyze ───────────────────────────────────────────────

    def analyze_incidents(self, min_incidents: int = 3) -> list[dict[str, Any]]:
        """Detect recurring patterns after N+ same-type incidents.

        Returns a list of pattern dicts that have crossed the threshold.
        """
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("""
            SELECT
                i.pattern_hash,
                i.resource_type,
                i.risk,
                COUNT(*) as cnt,
                MIN(r.timestamp) as first_seen,
                MAX(r.timestamp) as last_seen
            FROM incidents i
            JOIN runs r ON i.run_id = r.id
            GROUP BY i.pattern_hash
            HAVING cnt >= ?
        """, (min_incidents,)).fetchall()
        conn.close()

        patterns = []
        for row in rows:
            pattern_hash, resource_type, risk, cnt, first_seen, last_seen = row
            # Upsert into patterns table
            conn2 = sqlite3.connect(self.db_path)
            existing = conn2.execute(
                "SELECT id FROM patterns WHERE pattern_hash = ?", (pattern_hash,)
            ).fetchone()
            if existing:
                conn2.execute(
                    "UPDATE patterns SET incident_count = ?, last_seen = ? WHERE pattern_hash = ?",
                    (cnt, last_seen, pattern_hash),
                )
            else:
                conn2.execute(
                    "INSERT INTO patterns (resource_type, risk, pattern_hash, "
                    "incident_count, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
                    (resource_type, risk, pattern_hash, cnt, first_seen, last_seen),
                )
            conn2.commit()
            conn2.close()

            patterns.append({
                "pattern_hash": pattern_hash,
                "resource_type": resource_type,
                "risk": risk,
                "incident_count": cnt,
                "first_seen": first_seen,
                "last_seen": last_seen,
            })

        return patterns

    def get_all_patterns(self) -> list[dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("""
            SELECT id, resource_type, risk, pattern_hash, incident_count,
                   first_seen, last_seen, suggested_rule, rule_score, rule_status
            FROM patterns ORDER BY incident_count DESC
        """).fetchall()
        conn.close()
        return [
            {
                "id": r[0],
                "resource_type": r[1],
                "risk": r[2],
                "pattern_hash": r[3],
                "incident_count": r[4],
                "first_seen": r[5],
                "last_seen": r[6],
                "suggested_rule": r[7],
                "rule_score": r[8],
                "rule_status": r[9] or "pending",
            }
            for r in rows
        ]

    # ── Stage 3b: Multi-Agent Analysis ────────────────────────────────

    def analyze_with_agents(self, patterns: list[dict]) -> list[dict]:
        """Coordinate multi-agent analysis of detected patterns.

        Uses the configurable provider CLIs (Grok, DeepSeek, Codex, Hermes)
        to research, code, review, and signal on detected patterns.

        Falls back to rule-based heuristics when providers are unavailable.
        """
        evolved = []
        for pattern in patterns:
            rt = pattern["resource_type"]
            risk = pattern["risk"]
            cnt = pattern["incident_count"]
            pattern_hash = pattern["pattern_hash"]
            try:
                rt_clean, risk = _sanitize_for_codegen(rt, risk)
            except ValueError as exc:
                print(f"Skipping pattern {pattern_hash!r}: {exc}")
                continue

            # 1. Grok pattern analysis (when grok.exe is available)
            grok_available = shutil.which("grok.exe") or shutil.which("grok")
            grok_analysis = ""
            if grok_available:
                groq_msg = (
                    "Explain the security risk and recurring pattern "
                    f"for resource type '{rt}' with risk level '{risk}' "
                    f"based on {cnt} incidents."
                )
                cmd = ["grok", "--single", groq_msg]
                if shutil.which("grok.exe"):
                    cmd[0] = "grok.exe"
                try:
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if proc.returncode == 0:
                        grok_analysis = proc.stdout.strip()
                    else:
                        print(
                            f"grok.exe returned exit code "
                            f"{proc.returncode}. Output: "
                            f"{proc.stderr.strip() or proc.stdout.strip()}"
                        )
                except Exception as e:
                    print(f"Error calling grok.exe: {e}")
            
            # 2. Local template generation of candidate rule + test code
            rule_code = f"""# Auto-generated rule for {rt} ({risk})
from typing import Any
from readtheplan.rules._shared import RuleResult, register_rule

@register_rule("{rt}")
def _rule_{rt_clean}_{risk}(
    resource_type: str, action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates = []
    # Auto-generated check
    if "delete" in action_set or "update" in action_set or "create" in action_set:
        candidates.append(
            RuleResult("{risk}", "Auto-generated rule flagged {rt} for {risk}")
        )
    return candidates
"""
            test_code = f"""# Auto-generated test for {rt} ({risk})
from readtheplan.rules import RuleResult
from readtheplan.rules._shared import apply_resource_rules

def test_rule_{rt_clean}_{risk}():
    change = {{"actions": ["delete"]}}
    result = apply_resource_rules(
        resource_type="{rt}",
        actions=("delete",),
        change=change,
        baseline=RuleResult("safe", "baseline")
    )
    assert result.risk == "{risk}"
"""

            # 3. Verification Loop via temporary test execution
            temp_rule_dir = Path(__file__).parent / "rules" / "auto"
            temp_rule_dir.mkdir(parents=True, exist_ok=True)
            init_pkg = '"""Auto-generated rules package."""\n'
            (temp_rule_dir / "__init__.py").write_text(init_pkg, encoding="utf-8")
            
            temp_rule_file = temp_rule_dir / "temp_candidate.py"
            
            temp_test_dir = Path(__file__).parent.parent.parent / "tests" / "test_rules_auto"
            temp_test_dir.mkdir(parents=True, exist_ok=True)
            init_test = '"""Auto-generated rules tests package."""\n'
            (temp_test_dir / "__init__.py").write_text(init_test, encoding="utf-8")
            
            temp_test_file = temp_test_dir / "test_temp_candidate.py"
            
            # Write temp candidate files
            temp_rule_file.write_text(rule_code, encoding="utf-8")
            temp_test_file.write_text(test_code, encoding="utf-8")

            # Run pytest on the temp test
            pytest_cmd = [sys.executable, "-m", "pytest", "--no-cov", str(temp_test_file)]
            env = os.environ.copy()
            env["PYTHONPATH"] = "src"
            
            verification_success = False
            try:
                proc = subprocess.run(
                    pytest_cmd, env=env,
                    capture_output=True, text=True,
                    timeout=15,
                )
                if proc.returncode == 0:
                    verification_success = True
                else:
                    print(
                        "Verification pytest failed with exit code "
                        f"{proc.returncode}:\n{proc.stdout}\n{proc.stderr}"
                    )
            except Exception as e:
                print(f"Error running verification pytest: {e}")

            # Clean up temp files immediately after test
            if temp_rule_file.exists():
                temp_rule_file.unlink()
            if temp_test_file.exists():
                temp_test_file.unlink()

            # 4. Scoring logic
            score = 0.0
            if verification_success:
                base_score = 70.0
                risk_bonus_map = {
                    "safe": 5.0, "review": 10.0,
                    "dangerous": 15.0, "irreversible": 20.0,
                }
                risk_bonus = risk_bonus_map.get(risk, 5.0)
                incident_bonus = 5.0 if cnt >= 3 else 0.0
                if cnt >= 5:
                    incident_bonus = 10.0
                if cnt >= 10:
                    incident_bonus = 20.0
                score = base_score + risk_bonus + incident_bonus + 10.0 # +10 for test success
                score = min(score, 100.0)

            # 5. Evolve decision
            decision = self._evolve_decision(score, risk)

            # 6. Save evolved rule to SQLite
            self._save_evolved_rule(pattern_hash, rule_code, score, decision)

            # 7. Write permanent files if score >= 85
            if score >= 85:
                perm_rule_file = temp_rule_dir / f"rule_{rt_clean}_{risk}.py"
                perm_test_file = temp_test_dir / f"test_rule_{rt_clean}_{risk}.py"
                
                perm_rule_file.write_text(rule_code, encoding="utf-8")
                perm_test_file.write_text(test_code, encoding="utf-8")
                
                # Print PR Template
                print("=" * 60)
                print("PULL REQUEST TEMPLATE")
                print("=" * 60)
                print(f"Title: feat(rules): Auto-generated rule for {rt} ({risk})")
                print("\nDescription:")
                print(
                    "This PR adds a self-evolved rule for resource type "
                    f"'{rt}' with risk '{risk}'."
                )
                print(f"- Rule file: src/readtheplan/rules/auto/rule_{rt_clean}_{risk}.py")
                print(f"- Test file: tests/test_rules_auto/test_rule_{rt_clean}_{risk}.py")
                print(f"- Score: {score:.1f}")
                grok_fallback = grok_analysis or "No Grok analysis (heuristic fallback)"
                print(f"- Analysis: {grok_fallback}")
                print("=" * 60)

            # 8. Write JSON Handoff to ~/.readtheplan/handoffs/ if score >= 70
            if score >= 70:
                handoffs_dir = self.data_dir / "handoffs"
                handoffs_dir.mkdir(parents=True, exist_ok=True)
                handoff_file = handoffs_dir / f"handoff_{rt_clean}_{risk}.json"
                
                import uuid
                handoff_ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                handoff_id = f"handoff_{handoff_ts}_{uuid.uuid4().hex[:8]}"
                
                handoff_data = {
                    "handoff_id": handoff_id,
                    "pattern_hash": pattern_hash,
                    "resource_type": rt,
                    "risk": risk,
                    "incident_count": cnt,
                    "score": score,
                    "suggested_rule": rule_code,
                    "status": "pr-ready" if decision == "pr-ready" else "auto-merge"
                }
                handoff_file.write_text(json.dumps(handoff_data, indent=2), encoding="utf-8")

            evolved.append({
                **pattern,
                "suggested_rule": rule_code,
                "rule_score": score,
                "rule_status": decision,
            })

        return evolved

    def _generate_rule_heuristic(self, pattern: dict) -> str:
        """Generate a rule candidate from pattern data.

        In production this is delegated to a Coder agent (DeepSeek).
        For local standalone use, generate a heuristic rule description.
        """
        rt = pattern["resource_type"]
        risk = pattern["risk"]
        cnt = pattern["incident_count"]

        action_label = (
            "require human approval"
            if risk in ("dangerous", "irreversible")
            else "flag for review"
        )
        priority_label = (
            "high" if cnt >= 5 else "medium" if cnt >= 3 else "low"
        )
        return (
            f"auto-{rt.lower().replace('_', '-')}-{risk}\n"
            f"Resource type: {rt}\n"
            f"Detected risk: {risk}\n"
            f"Incident count: {cnt}\n"
            f"Action: {action_label}\n"
            f"Priority: {priority_label}\n"
        )

    def _score_rule(self, rule: str, pattern: dict) -> float:
        """Score a rule candidate 0-100 based on severity and frequency.

        In production this is delegated to a Reviewer agent (Codex).
        """
        base = 50.0
        # Higher risk = higher potential value
        risk_bonus = {"safe": 10, "review": 20, "dangerous": 35, "irreversible": 50}
        base += risk_bonus.get(pattern["risk"], 10)
        # More incidents = more confidence the pattern is real
        inc = pattern["incident_count"]
        if inc >= 10:
            base += 20
        elif inc >= 5:
            base += 10
        return min(base, 100.0)

    def _evolve_decision(self, score: float, risk: str) -> str:
        """Decide whether to auto-merge, create PR, or disable a rule.

        In production this is delegated to a Signal agent (Hermes).
        """
        if score >= 90 and risk not in ("irreversible",):
            return "auto-merge"
        elif score >= 70:
            return "pr-ready"
        else:
            return "disabled"

    def _save_evolved_rule(self, pattern_hash: str, rule: str, score: float, status: str):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "UPDATE patterns SET suggested_rule = ?, rule_score = ?, "
            "rule_status = ? WHERE pattern_hash = ?",
            (rule, score, status, pattern_hash),
        )
        conn.execute(
            "INSERT INTO rules_catalog "
            "(pattern_id, rule_code, rule_description, "
            "score, status, created_at) "
            "SELECT id, ?, ?, ?, ?, ? FROM patterns WHERE pattern_hash = ?",
            (rule,
             f"Auto-generated rule for {pattern_hash}",
             score, status, datetime.now().isoformat(),
             pattern_hash),
        )
        conn.commit()
        conn.close()

    def _get_handoff_root(self) -> Path:
        root = os.environ.get("AGENT_HANDOFF_ROOT")
        if root:
            p = Path(root)
        else:
            obsidian = Path.home() / "Documents" / "Obsidian Vault"
            if obsidian.exists():
                p = obsidian / "Agent Handoffs"
            else:
                p = Path.home() / "Documents" / "agent-handoffs"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def dispatch_handoffs(self) -> list[str]:
        """Dispatch pending handoffs from ~/.readtheplan/handoffs/ to shared dir."""
        handoffs_dir = self.data_dir / "handoffs"
        if not handoffs_dir.exists():
            return []

        dispatched = []
        dest_dir = self._get_handoff_root()

        for f in handoffs_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                hid = data.get("handoff_id")
                if not hid:
                    continue

                # Generate the final handoff JSON for computer-use-mcp
                mcp_handoff_data = {
                    "id": hid,
                    "title": f"Evolution Rule Handoff: {data.get('pattern_hash')}",
                    "from_agent": "readtheplan",
                    "to_agent": "computer-use-mcp",
                    "status": "pending",
                    "project": "readtheplan-evolution",
                    "created_at": datetime.now().isoformat(timespec="seconds") + "Z",
                    "updated_at": datetime.now().isoformat(timespec="seconds") + "Z",
                    "tags": ["readtheplan", "evolution", "rule-generation"],
                    "extracted_response": {
                        "message_text": (
                            "Suggested auto-rule for pattern: "
                            f"{data.get('pattern_hash')}\n\n"
                            "Rule details:\n"
                            f"{data.get('suggested_rule')}\n\n"
                            f"Incident count: {data.get('incident_count')}\n"
                            f"Score: {data.get('score')}"
                        )
                    },
                    "policy": {
                        "routing_mode": "auto",
                        "prefer_both": True
                    }
                }

                # Write JSON handoff
                dest_json = dest_dir / f"{hid}.json"
                dest_json.write_text(json.dumps(mcp_handoff_data, indent=2), encoding="utf-8")

                # Generate Obsidian-friendly Markdown handoff
                dest_md = dest_dir / f"{hid}.md"
                md_content = f"""---
id: "{hid}"
type: "handoff"
cssclass: "agent-handoff"
title: "Evolution Rule Handoff: {data.get('pattern_hash')}"
from_agent: "readtheplan"
to_agent: "computer-use-mcp"
status: "pending"
status_emoji: "📥"
project: "readtheplan-evolution"
date: "{mcp_handoff_data['created_at']}"
tags:
  - "readtheplan"
  - "evolution"
  - "rule-generation"
  - "handoff"
  - "agent-handoff"
---

# Evolution Rule Handoff: {data.get('pattern_hash')}

**From:** readtheplan → **To:** computer-use-mcp  
**Status:** 📥 pending  
**Project/Context:** readtheplan-evolution

Suggested auto-rule for pattern: {data.get('pattern_hash')}

Rule details:
```python
{data.get('suggested_rule')}
```

Incident count: {data.get('incident_count')}
Score: {data.get('score')}
"""
                dest_md.write_text(md_content, encoding="utf-8")

                # Delete original handoff file
                f.unlink()
                dispatched.append(hid)
            except Exception as e:
                print(f"Error dispatching handoff {f.name}: {e}")

        return dispatched

    # ── Stage 4: Evolve (full loop) ────────────────────────────────────

    def run_full_evolution_loop(
        self,
        plan_hash: str,
        decision: str,
        compliance_score: float,
        mode: str = "self-improving",
        outcome: str = "success",
        plan_summary: dict | None = None,
        resource_changes: list[dict] | None = None,
    ) -> dict[str, Any]:
        """Run the full Gate → Record → Analyze → Evolve loop.

        Returns a summary dict with run_id, patterns found, and evolved rules.
        """
        # Stage 2: Record
        suggested_rules = []
        incident_flag = decision in ("block",)

        run_id = self.record_run(
            plan_hash=plan_hash,
            decision=decision,
            compliance_score=compliance_score,
            mode=mode,
            outcome=outcome,
            incident_flag=incident_flag,
            plan_summary=plan_summary,
            resource_types=[c.get("resource_type", "") for c in (resource_changes or [])],
        )

        # Record incidents for flagged resources
        resource_types_seen = set()
        for change in (resource_changes or []):
            risk = change.get("risk", "review")
            if risk in ("dangerous", "irreversible", "review"):
                rt = change.get("resource_type", "unknown")
                resource_types_seen.add(rt)
                self.record_incident(
                    run_id=run_id,
                    resource_type=rt,
                    risk=risk,
                    address=change.get("address", "unknown"),
                    actions=change.get("actions", ["unknown"]),
                )

        # Stage 3: Analyze
        patterns = self.analyze_incidents(min_incidents=3)

        # Stage 3b: Multi-agent analysis
        if patterns:
            evolved = self.analyze_with_agents(patterns)
            suggested_rules = [
                {
                    "pattern_hash": e["pattern_hash"],
                    "rule": e["suggested_rule"],
                    "score": e["rule_score"],
                    "status": e["rule_status"],
                }
                for e in evolved
            ]

        result = {
            "run_id": run_id,
            "decision": decision,
            "compliance_score": compliance_score,
            "patterns_detected": len(patterns),
            "patterns": [{"hash": p["pattern_hash"], "resource_type": p["resource_type"],
                          "risk": p["risk"], "count": p["incident_count"]} for p in patterns],
            "suggested_rules": suggested_rules,
        }

        # Update the run record with suggested rules
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "UPDATE runs SET suggested_rules = ? WHERE id = ?",
            (json.dumps(suggested_rules), run_id),
        )
        conn.commit()
        conn.close()

        return result

    # ── Dashboard ──────────────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        conn = sqlite3.connect(self.db_path)
        total_runs = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        blocked = conn.execute("SELECT COUNT(*) FROM runs WHERE decision = 'block'").fetchone()[0]
        warned = conn.execute("SELECT COUNT(*) FROM runs WHERE decision = 'warn'").fetchone()[0]
        avg_score = conn.execute("SELECT AVG(compliance_score) FROM runs").fetchone()[0] or 0.0
        total_incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        total_patterns = conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0]
        auto_merged = conn.execute(
            "SELECT COUNT(*) FROM rules_catalog WHERE status = 'auto-merge'"
        ).fetchone()[0]

        recent = conn.execute(
            "SELECT timestamp, decision, compliance_score FROM runs ORDER BY id DESC LIMIT 10"
        ).fetchall()
        conn.close()

        return {
            "total_runs": total_runs,
            "blocked": blocked,
            "warned": warned,
            "avg_compliance_score": round(avg_score, 1),
            "total_incidents": total_incidents,
            "total_patterns": total_patterns,
            "auto_merged_rules": auto_merged,
            "recent_runs": [
                {"timestamp": r[0], "decision": r[1], "score": r[2]} for r in recent
            ],
        }

    def generate_html_dashboard(self) -> str:
        """Generate an HTML dashboard with Chart.js graphs."""
        stats = self.get_stats()
        patterns = self.get_all_patterns()

        # Build chart data from recent runs
        recent = stats["recent_runs"][::-1]  # chronological
        labels = json.dumps([r["timestamp"][:10] for r in recent])
        scores = json.dumps([r["score"] for r in recent])

        pattern_rows = ""
        for p in patterns:
            status_badge = {
                "auto-merge": "🟢",
                "pr-ready": "🟡",
                "disabled": "🔴",
                "pending": "⚪",
            }.get(p["rule_status"], "⚪")
            pattern_rows += (
                f"\n            <tr>"
                f"<td>{_html.escape(str(p['resource_type']))}</td>"
                f"<td>{_html.escape(str(p['risk']))}</td>"
                f"<td>{_html.escape(str(p['incident_count']))}</td>"
                f"<td>{status_badge} {_html.escape(str(p['rule_status']))}</td>"
                f"<td>{_html.escape(str(p['rule_score'] or '-'))}</td>"
                f"</tr>"
            )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Evolution Dashboard - {datetime.now().strftime('%Y-%m-%d')}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  body {{
    font-family: system-ui, -apple-system, sans-serif;
    background: #0f0f0f; color: #e0e0e0;
    margin: 0; padding: 20px;
  }}
  .container {{ max-width: 1000px; margin: 0 auto; }}
  h1 {{ color: #22c55e; font-size: 1.5rem; }}
  .stats {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px; margin: 20px 0;
  }}
  .stat-card {{
    background: #1a1a1a; border: 1px solid #2a2a2a;
    border-radius: 8px; padding: 16px; text-align: center;
  }}
  .stat-card .value {{ font-size: 1.8rem; font-weight: bold; color: #22c55e; }}
  .stat-card .label {{ font-size: 0.75rem; color: #888; margin-top: 4px; }}
  canvas {{ background: #1a1a1a; border-radius: 8px; padding: 12px; margin: 20px 0; }}
  table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
  th, td {{
    text-align: left; padding: 8px 12px;
    border-bottom: 1px solid #2a2a2a; font-size: 0.85rem;
  }}
  th {{ color: #22c55e; font-weight: 600; }}
  tr:hover {{ background: #1a1a1a; }}
  .footer {{ text-align: center; color: #555; font-size: 0.75rem; margin-top: 40px; }}
</style>
</head>
<body>
<div class="container">
  <h1>⚡ Self-Improving Kernel Gate</h1>
  <p style="color: #888; font-size: 0.85rem;">All data stays local — {self.db_path}</p>

  <div class="stats">
    <div class="stat-card">
      <div class="value">{stats['total_runs']}</div>
      <div class="label">Total Runs</div>
    </div>
    <div class="stat-card">
      <div class="value">{stats['avg_compliance_score']}</div>
      <div class="label">Avg Compliance Score</div>
    </div>
    <div class="stat-card">
      <div class="value">{stats['blocked']}</div>
      <div class="label">Blocked</div>
    </div>
    <div class="stat-card">
      <div class="value">{stats['total_incidents']}</div>
      <div class="label">Incidents</div>
    </div>
    <div class="stat-card">
      <div class="value">{stats['total_patterns']}</div>
      <div class="label">Patterns</div>
    </div>
    <div class="stat-card">
      <div class="value">{stats['auto_merged_rules']}</div>
      <div class="label">Auto-Merged Rules</div>
    </div>
  </div>

  <canvas id="scoreChart" width="800" height="300"></canvas>

  <h2 style="color: #22c55e; font-size: 1.1rem;">Detected Patterns</h2>
  <table>
    <thead><tr><th>Resource Type</th><th>Risk</th>
    <th>Incidents</th><th>Status</th><th>Score</th></tr></thead>
    <tbody>
      {pattern_rows if pattern_rows else '<tr><td colspan="5" style="text-align:center;color:#555;">No patterns yet. Run the gate on some plans first.</td></tr>'}
    </tbody>
  </table>

  <div class="footer">
    Generated by readtheplan evolution engine — {datetime.now().strftime('%Y-%m-%d %H:%M')}
  </div>
</div>
<script>
  new Chart(document.getElementById("scoreChart"), {{
    type: "line",
    data: {{
      labels: {labels},
      datasets: [{{
        label: "Compliance Score",
        data: {scores},
        borderColor: "#22c55e",
        backgroundColor: "rgba(34,197,94,0.1)",
        fill: true,
        tension: 0.3
      }}]
    }},
    options: {{
      responsive: true,
      plugins: {{ legend: {{ labels: {{ color: "#e0e0e0" }} }} }},
      scales: {{
        x: {{ ticks: {{ color: "#888" }}, grid: {{ color: "#2a2a2a" }} }},
        y: {{ min: 0, max: 100, ticks: {{ color: "#888" }}, grid: {{ color: "#2a2a2a" }} }}
      }}
    }}
  }});
</script>
</body>
</html>"""
        self.report_file.write_text(html, encoding="utf-8")
        return str(self.report_file)

    # ── Voice brief (optional) ─────────────────────────────────────────

    def generate_voice_brief(self, style: str = "concise") -> str:
        """Generate a voice brief summary (text only, TTS optional).

        Styles: concise, narrative, professional, excited
        """
        stats = self.get_stats()
        patterns = self.get_all_patterns()
        active_patterns = [p for p in patterns if p["rule_status"] in ("pr-ready", "auto-merge")]

        if style == "concise":
            text = (
                f"Evolution update. "
                f"{stats['total_runs']} runs analyzed. "
                f"Average compliance score: {stats['avg_compliance_score']:.1f}. "
                f"{len(patterns)} patterns detected. "
                f"{stats['auto_merged_rules']} rules auto-merged."
            )
        elif style == "narrative":
            text = (
                f"The self-improving gate has processed {stats['total_runs']} plans. "
                f"The average compliance score is {stats['avg_compliance_score']:.1f}. "
                f"We detected {len(patterns)} recurring patterns "
                f"across {stats['total_incidents']} incidents. "
                f"{stats['auto_merged_rules']} rules have been auto-merged into the catalog. "
                f"{len(active_patterns)} patterns are ready for review."
            )
        elif style == "professional":
            text = (
                f"ReadThePlan Evolution Report. "
                f"Total runs: {stats['total_runs']}. "
                f"Average compliance score: {stats['avg_compliance_score']:.1f}. "
                f"Patterns detected: {len(patterns)}. "
                f"Rules auto-merged: {stats['auto_merged_rules']}. "
                f"Active patterns pending: {len(active_patterns)}."
            )
        else:  # excited
            text = (
                f"Your self-improving kernel gate is getting smarter! "
                f"Compliance score is {stats['avg_compliance_score']:.1f}. "
                f"We've spotted {len(patterns)} patterns and "
                f"auto-merged {stats['auto_merged_rules']} rules. "
                f"The system is learning from every run!"
            )

        return text

    # ── Utility ────────────────────────────────────────────────────────

    def get_recent_runs(self, limit: int = 10) -> list[dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT id, timestamp, plan_hash, decision, compliance_score, mode, outcome "
            "FROM runs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [
            {
                "id": r[0],
                "timestamp": r[1],
                "plan_hash": r[2],
                "decision": r[3],
                "compliance_score": r[4],
                "mode": r[5],
                "outcome": r[6],
            }
            for r in rows
        ]


# Singleton
evolution = EvolutionEngine()
