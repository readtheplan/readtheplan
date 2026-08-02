"""
Self-Improving Evolution Engine for readtheplan.

4-stage loop:
  1. Gate — classify risk, compliance score, decision
  2. Record — log every run to SQLite
  3. Analyze — detect recurring patterns across incidents
  4. Evolve — generate and score candidates for explicit approval

Evolution analysis is intentionally local and deterministic. External model
review is delegated to tooling outside this library.
"""

from __future__ import annotations

import errno
import hashlib
import html as _html
import json
import os
import re
import sqlite3
import stat
import sys
import tempfile
import threading
import time
from contextlib import contextmanager, redirect_stdout
from datetime import datetime
from importlib.machinery import ModuleSpec
from pathlib import Path
from types import ModuleType
from typing import Any

# Valid risk values — must match RISK_ORDER in rules/_shared.py
_VALID_RISKS = frozenset({"safe", "review", "dangerous", "irreversible"})
# Resource type after normalisation must be an identifier-safe token
_RESOURCE_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_RULE_ID_RE = re.compile(r"^rule_[a-z][a-z0-9_]{0,190}$")
_HANDOFF_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_CODEGEN_ACTIONS = frozenset({"create", "update", "delete"})
_CANDIDATE_SCHEMA = "readtheplan-evolution-candidate-v1"
_APPROVAL_MANIFEST_SCHEMA = "readtheplan-approved-rules-v1"
_APPROVAL_LOCK = threading.RLock()


@contextmanager
def _approval_process_lock(data_dir: Path):
    """Serialize approval publication across processes sharing *data_dir*."""
    data_dir.mkdir(parents=True, exist_ok=True)
    lock_path = data_dir / ".approval.lock"
    if _is_link_or_reparse_point(lock_path):
        raise ValueError("approval lock must be a regular in-store file")
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    locked = False
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("approval lock must be a regular in-store file")
        if os.name == "nt":
            import msvcrt

            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            while True:
                try:
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                    break
                except OSError as exc:
                    if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                        raise
                    time.sleep(0.05)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = True
        yield
    finally:
        if locked:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


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


def _parse_pattern_identity(identity: Any) -> tuple[str, str, tuple[str, ...]] | None:
    """Parse an action-qualified identity without splitting resource types."""
    if not isinstance(identity, str):
        return None
    prefix, separator, tail = identity.rpartition("::")
    if not separator or not prefix:
        return None
    resource_type, separator, risk = prefix.rpartition("::")
    if not separator or not resource_type or risk not in _VALID_RISKS or not tail:
        return None
    actions = tuple(tail.split(","))
    if not all(actions):
        return None
    return resource_type, risk, actions


def _is_legacy_pattern_identity(identity: Any) -> bool:
    if not isinstance(identity, str):
        return False
    resource_type, separator, risk = identity.rpartition("::")
    return bool(separator and resource_type and risk in _VALID_RISKS)


def _actions_from_pattern(pattern: dict[str, Any]) -> tuple[str, ...]:
    supplied = pattern.get("actions")
    if supplied is not None:
        if not isinstance(supplied, list) or not all(isinstance(a, str) for a in supplied):
            return ()
        actions = tuple(supplied)
    else:
        parsed = _parse_pattern_identity(pattern.get("pattern_hash"))
        if parsed is None:
            return ()
        actions = parsed[2]
    if not actions or any(action not in _CODEGEN_ACTIONS for action in actions):
        return ()
    return tuple(sorted(set(actions)))


def _validated_pattern_actions(pattern: dict[str, Any]) -> tuple[str, ...]:
    """Return canonical actions only when all provenance identity fields agree."""
    parsed = _parse_pattern_identity(pattern.get("pattern_hash"))
    if parsed is None:
        return ()
    resource_type, risk, parsed_actions = parsed
    if resource_type != pattern.get("resource_type") or risk != pattern.get("risk"):
        return ()
    canonical_parsed = tuple(sorted(set(parsed_actions)))
    if not canonical_parsed or any(action not in _CODEGEN_ACTIONS for action in canonical_parsed):
        return ()
    if "actions" in pattern:
        supplied = _actions_from_pattern({"actions": pattern["actions"]})
        if supplied != canonical_parsed:
            return ()
    return canonical_parsed


def _atomic_write_in_directory(path: Path, data: bytes, directory: Path) -> None:
    """Atomically write *data* without following an existing output symlink."""
    try:
        resolved_directory = directory.resolve(strict=True)
        if _is_link_or_reparse_point(directory) or (
            path.parent.resolve(strict=True) != resolved_directory
        ):
            raise ValueError(f"output path escapes its data directory: {path}")
        if _is_link_or_reparse_point(path):
            raise ValueError(f"refusing to replace symlinked output: {path}")
        if path.exists():
            resolved_path = path.resolve(strict=True)
            if resolved_path.parent != resolved_directory or not resolved_path.is_file():
                raise ValueError(f"output path is not a confined regular file: {path}")
    except OSError as exc:
        raise ValueError(f"cannot validate output path: {path}") from exc

    descriptor, temporary_name = tempfile.mkstemp(
        dir=resolved_directory,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    try:
        stream = os.fdopen(descriptor, "wb")
        descriptor = -1
        with stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        Path(temporary_name).unlink(missing_ok=True)
        raise


def _atomic_replace_text(path: Path, content: str) -> None:
    """Atomically replace a handoff file without following a destination symlink."""
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def _is_link_or_reparse_point(path: Path) -> bool:
    """Return true for symlinks and Windows junction/reparse-point paths."""
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return path.is_symlink() or bool(attributes & reparse_flag)


def _verify_candidate_rule(
    rule_bytes: bytes,
    *,
    source_path: Path,
    module_name: str,
    function_name: str,
    resource_type: str,
    risk: str,
    actions: tuple[str, ...] = ("delete",),
) -> tuple[bool, str | None]:
    """Execute and verify a generated rule without activating it.

    Candidate modules use the public registration decorators, so executing one
    mutates the process-global rule registry even when its function is called
    directly.  Verification therefore holds the registry lock, snapshots the
    same state protected by the approved-rule loader, and restores it in all
    cases.  Compiling the bytes already written to the candidate directory
    also avoids pathname-loader bytecode substitution.
    """
    import readtheplan.rules._shared as shared

    try:
        code = compile(rule_bytes, str(source_path), "exec", dont_inherit=True)
    except (SyntaxError, TypeError, ValueError) as exc:
        return False, f"candidate could not be compiled: {exc}"

    module = ModuleType(module_name)
    module.__file__ = str(source_path)
    module.__package__ = ""
    module.__loader__ = None
    module.__spec__ = ModuleSpec(module_name, loader=None, origin=str(source_path))
    module.__cached__ = None

    missing_module = object()
    success = False
    error: str | None = None
    with shared._REGISTRY_LOCK:
        registry_object = shared._RULE_REGISTRY
        registry_buckets = dict(registry_object)
        registry_snapshot = {
            registered_type: list(bucket)
            for registered_type, bucket in registry_buckets.items()
        }
        cross_cutting_object = shared._CROSS_CUTTING
        cross_cutting_snapshot = list(cross_cutting_object)
        source_snapshot = shared._current_source
        previous_module = sys.modules.get(module_name, missing_module)
        sys.modules[module_name] = module

        try:
            # Candidate output is diagnostic output and must never share the
            # caller's machine-readable stdout stream.
            with redirect_stdout(sys.stderr):
                exec(code, module.__dict__)
                rule = module.__dict__.get(function_name)
                if not callable(rule):
                    raise ValueError(f"candidate did not define {function_name}")

                action_set = set(actions)
                mutating_results = rule(resource_type, action_set, {"actions": list(actions)})
                if not mutating_results or not any(
                    getattr(result, "risk", None) == risk
                    for result in mutating_results
                ):
                    raise ValueError("candidate did not flag the mutating change")

                for actions in ({"no-op"}, {"read"}):
                    results = rule(
                        resource_type,
                        actions,
                        {"actions": sorted(actions)},
                    )
                    if results != []:
                        raise ValueError(
                            "candidate flagged a no-op or read-only counterexample"
                        )

            if (
                shared._RULE_REGISTRY is not registry_object
                or shared._CROSS_CUTTING is not cross_cutting_object
            ):
                raise RuntimeError("candidate replaced a global rule registry")
            for registered_type, before in registry_snapshot.items():
                current = registry_object.get(registered_type)
                if current is None or current[: len(before)] != before:
                    raise RuntimeError("candidate modified existing registrations")
            if cross_cutting_object[: len(cross_cutting_snapshot)] != cross_cutting_snapshot:
                raise RuntimeError("candidate modified existing cross-cutting rules")
            success = True
        except (Exception, SystemExit) as exc:
            error = f"{type(exc).__name__}: {exc}"
        finally:
            shared._RULE_REGISTRY = registry_object
            registry_object.clear()
            for registered_type, bucket in registry_buckets.items():
                bucket[:] = registry_snapshot[registered_type]
                registry_object[registered_type] = bucket
            shared._CROSS_CUTTING = cross_cutting_object
            cross_cutting_object[:] = cross_cutting_snapshot
            shared._current_source = source_snapshot
            if previous_module is missing_module:
                sys.modules.pop(module_name, None)
            else:
                sys.modules[module_name] = previous_module

    return success, error


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
        self.candidates_dir = self.data_dir / "candidates"
        self.approved_rules_dir = self.data_dir / "approved-rules"
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
        self._migrate_legacy_pattern_hashes(conn)
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
        actions: Any,
    ) -> str:
        """Record an individual incident and return its pattern hash."""
        pattern_hash = self._pattern_hash(resource_type, risk, actions)
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
    def _pattern_hash(
        resource_type: str, risk: str, actions: Any = None,
    ) -> str:
        if actions is None:
            return f"{resource_type}::{risk}"
        if isinstance(actions, list):
            if not actions:
                return f"{resource_type}::{risk}"
            if all(
                isinstance(action, str)
                and "," not in action
                and "::" not in action
                for action in actions
            ):
                action_identity = ",".join(sorted(set(actions)))
            else:
                action_identity = "<malformed-list>"
        else:
            action_identity = f"<malformed-{type(actions).__name__}>"
        return f"{resource_type}::{risk}::{action_identity}"

    def _migrate_legacy_pattern_hashes(self, conn: sqlite3.Connection) -> None:
        for incident_id, resource_type, risk, actions_json, pattern_hash in conn.execute(
            "SELECT id, resource_type, risk, actions, pattern_hash FROM incidents"
        ).fetchall():
            parsed_identity = _parse_pattern_identity(pattern_hash)
            if parsed_identity is not None:
                continue
            try:
                actions = json.loads(actions_json or "[]")
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(actions, list) or not all(isinstance(a, str) for a in actions):
                continue
            migrated = self._pattern_hash(resource_type, risk, actions)
            if migrated != pattern_hash:
                conn.execute(
                    "UPDATE incidents SET pattern_hash = ? WHERE id = ?",
                    (migrated, incident_id),
                )

        legacy_patterns = [row for row in conn.execute(
            "SELECT id, resource_type, risk, pattern_hash, suggested_rule, "
            "rule_score, rule_status FROM patterns"
        ).fetchall() if _is_legacy_pattern_identity(row[3])]
        for legacy in legacy_patterns:
            legacy_id, resource_type, risk, legacy_hash, rule, score, status = legacy
            conn.execute(
                "UPDATE patterns SET rule_status = 'disabled' WHERE id = ?",
                (legacy_id,),
            )
            conn.execute(
                "UPDATE rules_catalog SET status = 'disabled' WHERE pattern_id = ?",
                (legacy_id,),
            )
            groups = conn.execute(
                "SELECT pattern_hash, COUNT(*), MIN(r.timestamp), MAX(r.timestamp) "
                "FROM incidents i JOIN runs r ON r.id = i.run_id "
                "WHERE i.resource_type = ? AND i.risk = ? GROUP BY pattern_hash",
                (resource_type, risk),
            ).fetchall()
            migrated_groups = [group for group in groups if group[0] != legacy_hash]
            if not migrated_groups:
                continue
            target_ids: list[int] = []
            for index, (pattern_hash, count, first_seen, last_seen) in enumerate(migrated_groups):
                existing = conn.execute(
                    "SELECT id FROM patterns WHERE pattern_hash = ?", (pattern_hash,)
                ).fetchone()
                if existing:
                    target_id = existing[0]
                elif index == 0:
                    target_id = legacy_id
                    conn.execute(
                        "UPDATE patterns SET pattern_hash = ?, incident_count = ?, "
                        "first_seen = ?, last_seen = ?, suggested_rule = NULL, "
                        "rule_score = NULL, rule_status = 'pending' WHERE id = ?",
                        (pattern_hash, count, first_seen, last_seen, target_id),
                    )
                else:
                    cursor = conn.execute(
                        "INSERT INTO patterns (resource_type, risk, pattern_hash, incident_count, "
                        "first_seen, last_seen, suggested_rule, rule_score, rule_status) "
                        "VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, 'pending')",
                        (resource_type, risk, pattern_hash, count, first_seen, last_seen),
                    )
                    target_id = cursor.lastrowid
                target_ids.append(target_id)
            if target_ids and target_ids[0] != legacy_id:
                conn.execute(
                    "UPDATE rules_catalog SET pattern_id = ? WHERE pattern_id = ?",
                    (target_ids[0], legacy_id),
                )
                conn.execute("DELETE FROM patterns WHERE id = ?", (legacy_id,))

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

    # ── Stage 3b: Local Candidate Analysis ───────────────────────────

    def analyze_with_agents(self, patterns: list[dict]) -> list[dict]:
        """Generate candidates using the local deterministic evolution rules.

        This library does not spawn external model tooling. Model review, when
        desired, is delegated to tooling outside this library.
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
                print(f"Skipping pattern {pattern_hash!r}: {exc}", file=sys.stderr)
                continue
            actions = _validated_pattern_actions(pattern)
            if not actions:
                print(
                    f"Skipping pattern {pattern_hash!r}: no supported mutation actions",
                    file=sys.stderr,
                )
                continue
            action_slug = "_".join(actions)
            action_set_literal = "{" + ", ".join(f'"{a}"' for a in actions) + "}"
            action_list_literal = "[" + ", ".join(f'"{a}"' for a in actions) + "]"

            # Keep generation local and deterministic. Spawning external model
            # tooling here could open an authentication flow or consume a
            # user's quota; optional model review belongs outside this library.
            analysis_summary = (
                "Local heuristic analysis; external model review is delegated "
                "to tooling outside this library."
            )

            # 1. Local template generation of candidate rule + validation code
            rule_id = self._candidate_rule_id(rt_clean, risk, actions)
            self.candidates_dir.mkdir(parents=True, exist_ok=True)
            candidate_root = self.candidates_dir.resolve()
            if (
                _is_link_or_reparse_point(self.candidates_dir)
                or candidate_root.parent != self.data_dir.resolve()
            ):
                raise ValueError("candidates path escapes the evolution data directory")
            candidate_dir = self.candidates_dir / rule_id
            candidate_dir.mkdir(exist_ok=True)
            if (
                _is_link_or_reparse_point(candidate_dir)
                or candidate_dir.resolve().parent != candidate_root
            ):
                raise ValueError(f"candidate path escapes the data directory: {rule_id!r}")
            candidate_rule_file = candidate_dir / "rule.py"
            candidate_test_file = candidate_dir / "test_rule.py"
            candidate_metadata_file = candidate_dir / "candidate.json"

            rule_code = f"""# Auto-generated rule for {rt} ({risk})
from typing import Any
from readtheplan.rules._shared import RuleResult, register_rule

@register_rule("{rt}")
def _rule_{rt_clean}_{risk}_{action_slug}(
    resource_type: str, action_set: set[str],
    change: dict[str, Any],
) -> list[RuleResult]:
    candidates = []
    # Auto-generated check
    if {action_set_literal}.issubset(action_set):
        candidates.append(
            RuleResult("{risk}", "Auto-generated rule flagged {rt} for {risk}")
        )
    return candidates
"""
            test_code = f"""# Auto-generated validation for {rt} ({risk})
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

_CANDIDATE_FILE = Path(__file__).with_name("rule.py")
_SPEC = spec_from_file_location("_readtheplan_candidate_{rule_id}", _CANDIDATE_FILE)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
_RULE = _MODULE._rule_{rt_clean}_{risk}_{action_slug}


def test_rule_{rt_clean}_{risk}_{action_slug}_flags_mutating_change():
    actions = {action_set_literal}
    results = _RULE("{rt}", actions, {{"actions": {action_list_literal}}})
    assert results
    assert any(result.risk == "{risk}" for result in results)


def test_rule_{rt_clean}_{risk}_{action_slug}_ignores_noop_and_read_only_changes():
    for actions in ({{"no-op"}}, {{"read"}}):
        assert _RULE("{rt}", actions, {{"actions": sorted(actions)}}) == []
"""

            # 2. Confine candidate artifacts to data_dir and validate them there.
            _atomic_write_in_directory(candidate_rule_file, rule_code.encode(), candidate_dir)
            _atomic_write_in_directory(candidate_test_file, test_code.encode(), candidate_dir)

            verification_success, verification_error = _verify_candidate_rule(
                candidate_rule_file.read_bytes(),
                source_path=candidate_rule_file,
                module_name=(
                    f"_readtheplan_candidate_verify_{rule_id}_"
                    f"{hashlib.sha256(rule_code.encode()).hexdigest()[:12]}"
                ),
                function_name=f"_rule_{rt_clean}_{risk}_{action_slug}",
                resource_type=rt,
                risk=risk,
                actions=actions,
            )
            if verification_error is not None:
                print(
                    f"Candidate verification failed for {rule_id}: {verification_error}",
                    file=sys.stderr,
                )

            # 3. Scoring logic
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
                score = base_score + risk_bonus + incident_bonus + 10.0
                score = min(score, 100.0)

            # 4. Evolve decision
            decision = self._evolve_decision(score, risk)

            # 5. Save evolved rule to SQLite
            self._save_evolved_rule(pattern_hash, rule_code, score, decision)

            candidate_metadata = {
                "schema": _CANDIDATE_SCHEMA,
                "rule_id": rule_id,
                "pattern_hash": pattern_hash,
                "resource_type": rt,
                "risk": risk,
                "incident_count": cnt,
                "score": score,
                "status": decision,
                "verified": verification_success,
                "rule_file": candidate_rule_file.name,
                "test_file": candidate_test_file.name,
                "rule_sha256": hashlib.sha256(candidate_rule_file.read_bytes()).hexdigest(),
                "test_sha256": hashlib.sha256(candidate_test_file.read_bytes()).hexdigest(),
                "created_at": datetime.now().isoformat(),
            }
            _atomic_write_in_directory(
                candidate_metadata_file,
                json.dumps(candidate_metadata, indent=2).encode(),
                candidate_dir,
            )

            # 6. Print a review handoff for strong candidates.  Approval is a
            # separate explicit command; this step never activates the code.
            if score >= 85:
                print(
                    "\n".join(
                        [
                            "=" * 60,
                            "PULL REQUEST TEMPLATE",
                            "=" * 60,
                            f"Title: feat(rules): Auto-generated rule for {rt} ({risk})",
                            "",
                            "Description:",
                            (
                                "This PR adds a self-evolved rule for resource type "
                                f"'{rt}' with risk '{risk}'."
                            ),
                            f"- Rule ID: {rule_id}",
                            f"- Rule file: {candidate_rule_file}",
                            f"- Test file: {candidate_test_file}",
                            f"- Score: {score:.1f}",
                            f"- Analysis: {analysis_summary}",
                            f"- Approve: readtheplan evolve approve {rule_id}",
                            "=" * 60,
                        ]
                    ),
                    file=sys.stderr,
                )

            # 7. Write JSON Handoff to ~/.readtheplan/handoffs/ if score >= 70
            if score >= 70:
                handoffs_dir = self.data_dir / "handoffs"
                handoffs_dir.mkdir(parents=True, exist_ok=True)
                if (
                    _is_link_or_reparse_point(handoffs_dir)
                    or handoffs_dir.resolve().parent != self.data_dir.resolve()
                ):
                    raise ValueError("handoffs path escapes the evolution data directory")
                handoff_file = handoffs_dir / f"handoff_{rt_clean}_{risk}_{action_slug}.json"
                
                import uuid
                handoff_ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                handoff_id = f"handoff_{handoff_ts}_{uuid.uuid4().hex[:8]}"
                
                handoff_data = {
                    "handoff_id": handoff_id,
                    "rule_id": rule_id,
                    "pattern_hash": pattern_hash,
                    "resource_type": rt,
                    "risk": risk,
                    "incident_count": cnt,
                    "score": score,
                    "suggested_rule": rule_code,
                    "candidate_dir": str(candidate_dir),
                    "status": decision,
                }
                _atomic_write_in_directory(
                    handoff_file,
                    json.dumps(handoff_data, indent=2).encode(),
                    handoffs_dir,
                )

            evolved.append({
                **pattern,
                "rule_id": rule_id,
                "candidate_dir": str(candidate_dir),
                "suggested_rule": rule_code,
                "rule_score": score,
                "rule_status": decision,
            })

        return evolved

    def _generate_rule_heuristic(self, pattern: dict) -> str:
        """Generate a rule candidate from pattern data.

        The library always generates this deterministic heuristic locally;
        optional model-assisted generation belongs to tooling outside it.
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
        """Score a rule candidate locally based on severity and frequency."""
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
        """Decide whether to propose or disable a generated rule.

        Plan-derived observations can prepare a candidate for review, but only
        :meth:`approve_rule` may make one eligible to load.  ``risk`` remains
        part of this policy hook for compatibility with risk-aware engine
        subclasses; the base policy intentionally uses the verified score
        alone so every risk level has the same explicit-approval boundary.
        """
        if score >= 70:
            return "pr-ready"
        return "disabled"

    @staticmethod
    def _candidate_rule_id(
        resource_type: str, risk: str, actions: tuple[str, ...] = (),
    ) -> str:
        """Return the stable, path-safe ID used by generation and approval."""
        suffix = f"_{'_'.join(actions)}" if actions else ""
        rule_id = f"rule_{resource_type}_{risk}{suffix}"
        if not _RULE_ID_RE.fullmatch(rule_id):
            raise ValueError(f"generated rule ID is not safe: {rule_id!r}")
        return rule_id

    def approve_rule(self, rule_id: str) -> dict[str, Any]:
        """Explicitly approve a verified, ``pr-ready`` candidate.

        Approval copies the exact validated bytes into ``approved-rules`` and
        adds a SHA-256 allowlist record.  The loader ignores all files that are
        absent from this manifest or differ from the approved digest.
        """
        with _APPROVAL_LOCK:
            with _approval_process_lock(self.data_dir):
                return self._approve_rule_locked(rule_id)

    def _approve_rule_locked(self, rule_id: str) -> dict[str, Any]:
        if not _RULE_ID_RE.fullmatch(rule_id):
            raise ValueError(f"invalid rule ID: {rule_id!r}")
        if os.environ.get("READTHEPLAN_ALLOW_ACTIVE_RULE_WRITES") != "1":
            raise PermissionError(
                "active rule writes require READTHEPLAN_ALLOW_ACTIVE_RULE_WRITES=1"
            )

        candidate_root = self.candidates_dir.resolve()
        if (
            _is_link_or_reparse_point(self.candidates_dir)
            or candidate_root.parent != self.data_dir.resolve()
        ):
            raise ValueError("candidates path escapes the evolution data directory")
        candidate_dir = self.candidates_dir / rule_id
        try:
            resolved_candidate_dir = candidate_dir.resolve(strict=True)
        except OSError as exc:
            raise FileNotFoundError(f"candidate not found: {rule_id}") from exc
        if (
            _is_link_or_reparse_point(candidate_dir)
            or resolved_candidate_dir.parent != candidate_root
        ):
            raise ValueError(f"candidate path escapes the data directory: {rule_id!r}")

        metadata_file = resolved_candidate_dir / "candidate.json"
        try:
            resolved_metadata_file = metadata_file.resolve(strict=True)
            if (
                _is_link_or_reparse_point(metadata_file)
                or resolved_metadata_file.parent != resolved_candidate_dir
                or not resolved_metadata_file.is_file()
            ):
                raise ValueError(f"candidate metadata escapes its directory: {rule_id}")
            metadata = json.loads(resolved_metadata_file.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise FileNotFoundError(f"candidate not found: {rule_id}") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"candidate metadata is invalid: {rule_id}") from exc
        if not isinstance(metadata, dict) or metadata.get("schema") != _CANDIDATE_SCHEMA:
            raise ValueError(f"candidate metadata is invalid: {rule_id}")
        if metadata.get("rule_id") != rule_id:
            raise ValueError(f"candidate metadata does not match rule ID: {rule_id}")

        actions = _validated_pattern_actions(metadata)
        if not actions:
            raise ValueError(f"candidate metadata provenance is invalid: {rule_id}")

        try:
            expected_rule_id = self._candidate_rule_id(
                *_sanitize_for_codegen(metadata["resource_type"], metadata["risk"]),
                actions,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"candidate metadata is invalid: {rule_id}") from exc
        if expected_rule_id != rule_id:
            raise ValueError(f"candidate metadata does not match rule ID: {rule_id}")
        score = metadata.get("score")
        if (
            metadata.get("status") != "pr-ready"
            or metadata.get("verified") is not True
            or not isinstance(score, (int, float))
            or isinstance(score, bool)
            or score < 70
        ):
            raise ValueError(f"candidate is not verified and pr-ready: {rule_id}")

        rule_file = resolved_candidate_dir / "rule.py"
        test_file = resolved_candidate_dir / "test_rule.py"
        try:
            resolved_rule_file = rule_file.resolve(strict=True)
            resolved_test_file = test_file.resolve(strict=True)
            if (
                _is_link_or_reparse_point(rule_file)
                or _is_link_or_reparse_point(test_file)
                or resolved_rule_file.parent != resolved_candidate_dir
                or resolved_test_file.parent != resolved_candidate_dir
                or not resolved_rule_file.is_file()
                or not resolved_test_file.is_file()
            ):
                raise ValueError(f"candidate artifacts escape their directory: {rule_id}")
            rule_bytes = resolved_rule_file.read_bytes()
            test_bytes = resolved_test_file.read_bytes()
        except OSError as exc:
            raise ValueError(f"candidate artifacts are missing: {rule_id}") from exc

        rule_hash = hashlib.sha256(rule_bytes).hexdigest()
        test_hash = hashlib.sha256(test_bytes).hexdigest()
        if (
            metadata.get("rule_file") != "rule.py"
            or metadata.get("test_file") != "test_rule.py"
            or metadata.get("rule_sha256") != rule_hash
            or metadata.get("test_sha256") != test_hash
        ):
            raise ValueError(f"candidate artifacts changed after validation: {rule_id}")

        transitioned = False
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            self.approved_rules_dir.mkdir(parents=True, exist_ok=True)
            approved_root = self.approved_rules_dir.resolve()
            if (
                _is_link_or_reparse_point(self.approved_rules_dir)
                or approved_root.parent != self.data_dir.resolve()
            ):
                raise ValueError("approved-rules path escapes the evolution data directory")
            manifest_file = approved_root / "manifest.json"
            if _is_link_or_reparse_point(manifest_file):
                raise ValueError("approved-rules manifest must be a regular in-store file")
            if manifest_file.exists():
                try:
                    resolved_manifest_file = manifest_file.resolve(strict=True)
                    if (
                        resolved_manifest_file.parent != approved_root
                        or not resolved_manifest_file.is_file()
                    ):
                        raise ValueError("approved-rules manifest escapes its directory")
                    manifest = json.loads(resolved_manifest_file.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise ValueError("approved-rules manifest is invalid") from exc
                if (
                    not isinstance(manifest, dict)
                    or manifest.get("schema") != _APPROVAL_MANIFEST_SCHEMA
                    or not isinstance(manifest.get("rules"), dict)
                ):
                    raise ValueError("approved-rules manifest is invalid")
            else:
                manifest = {"schema": _APPROVAL_MANIFEST_SCHEMA, "rules": {}}

            approved_file = approved_root / f"{rule_id}.py"
            existing_record = manifest["rules"].get(rule_id)
            database_row = conn.execute(
                "SELECT p.rule_status, rc.status, p.suggested_rule, p.rule_score, "
                "rc.rule_code, rc.score FROM patterns p "
                "JOIN rules_catalog rc ON rc.id = ("
                "SELECT MAX(latest.id) FROM rules_catalog latest "
                "WHERE latest.pattern_id = p.id) "
                "WHERE p.pattern_hash = ?",
                (metadata["pattern_hash"],),
            ).fetchone()
            if database_row is None:
                raise ValueError(f"candidate database status transition failed: {rule_id}")

            pattern_status, catalog_status = database_row[:2]
            if existing_record is not None:
                expected_record = {
                    "file": approved_file.name,
                    "sha256": rule_hash,
                    "pattern_hash": metadata["pattern_hash"],
                    "resource_type": metadata["resource_type"],
                    "risk": metadata["risk"],
                }
                if (
                    pattern_status != "approved"
                    or catalog_status != "approved"
                    or not isinstance(existing_record, dict)
                    or any(existing_record.get(key) != value
                           for key, value in expected_record.items())
                    or not isinstance(existing_record.get("approved_at"), str)
                ):
                    raise ValueError(f"approved rule record conflicts: {rule_id}")
                try:
                    resolved_approved_file = approved_file.resolve(strict=True)
                    if (
                        _is_link_or_reparse_point(approved_file)
                        or resolved_approved_file.parent != approved_root
                        or not resolved_approved_file.is_file()
                        or resolved_approved_file.read_bytes() != rule_bytes
                    ):
                        raise ValueError(f"approved rule record conflicts: {rule_id}")
                except OSError as exc:
                    raise ValueError(f"approved rule record conflicts: {rule_id}") from exc
                result = {"rule_id": rule_id, **existing_record}
                conn.commit()
                return result

            approved_at = datetime.now().isoformat()
            if pattern_status == "pr-ready" and catalog_status == "pr-ready":
                pattern_update = conn.execute(
                    "UPDATE patterns SET rule_status = 'approved' "
                    "WHERE pattern_hash = ? AND rule_status = 'pr-ready'",
                    (metadata["pattern_hash"],),
                )
                catalog_update = conn.execute(
                    "UPDATE rules_catalog SET status = 'approved', merged_at = ? "
                    "WHERE id = (SELECT MAX(rc.id) FROM rules_catalog rc "
                    "JOIN patterns p ON p.id = rc.pattern_id WHERE p.pattern_hash = ?) "
                    "AND status = 'pr-ready'",
                    (approved_at, metadata["pattern_hash"]),
                )
                if pattern_update.rowcount != 1 or catalog_update.rowcount != 1:
                    raise ValueError(
                        f"candidate database status transition failed: {rule_id}"
                    )
                transitioned = True
            elif pattern_status == "approved" and catalog_status == "approved":
                rule_text = rule_bytes.decode("utf-8")
                if (
                    database_row[2] != rule_text
                    or database_row[3] != score
                    or database_row[4] != rule_text
                    or database_row[5] != score
                ):
                    raise ValueError(f"candidate database provenance mismatch: {rule_id}")
            else:
                raise ValueError(f"candidate database status transition failed: {rule_id}")
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

        record = {
            "file": approved_file.name,
            "sha256": rule_hash,
            "approved_at": approved_at,
            "pattern_hash": metadata["pattern_hash"],
            "resource_type": metadata["resource_type"],
            "risk": metadata["risk"],
        }
        manifest["rules"][rule_id] = record
        manifest_bytes = json.dumps(manifest, indent=2).encode()
        result = {"rule_id": rule_id, **record}
        try:
            _atomic_write_in_directory(approved_file, rule_bytes, self.approved_rules_dir)
            _atomic_write_in_directory(
                manifest_file,
                manifest_bytes,
                self.approved_rules_dir,
            )
        except BaseException:
            if transitioned:
                compensation = None
                try:
                    compensation = sqlite3.connect(self.db_path)
                    compensation.execute("BEGIN IMMEDIATE")
                    compensation.execute(
                        "UPDATE patterns SET rule_status = 'pr-ready' "
                        "WHERE pattern_hash = ? AND rule_status = 'approved'",
                        (metadata["pattern_hash"],),
                    )
                    compensation.execute(
                        "UPDATE rules_catalog SET status = 'pr-ready', merged_at = NULL "
                        "WHERE id = (SELECT MAX(rc.id) FROM rules_catalog rc "
                        "JOIN patterns p ON p.id = rc.pattern_id "
                        "WHERE p.pattern_hash = ?) AND status = 'approved'",
                        (metadata["pattern_hash"],),
                    )
                    compensation.commit()
                except BaseException:
                    if compensation is not None:
                        try:
                            compensation.rollback()
                        except BaseException:
                            pass
                finally:
                    if compensation is not None:
                        try:
                            compensation.close()
                        except BaseException:
                            pass
            raise
        return result

    def load_approved_rules(self) -> list[str]:
        """Load manifest-approved rules from this engine's data directory."""
        from readtheplan.rules._shared import _load_auto_rules

        return _load_auto_rules(self.data_dir)

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
                if (not isinstance(hid, str) or not _HANDOFF_ID_RE.fullmatch(hid)
                        or hid in {".", ".."}):
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
                _atomic_replace_text(dest_json, json.dumps(mcp_handoff_data, indent=2))

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
                _atomic_replace_text(dest_md, md_content)

                # Delete original handoff file
                f.unlink()
                dispatched.append(hid)
            except Exception as e:
                print(f"Error dispatching handoff {f.name}: {e}", file=sys.stderr)

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

        # Stage 3b: Local candidate analysis
        if patterns:
            evolved = self.analyze_with_agents(patterns)
            suggested_rules = [
                {
                    "rule_id": e["rule_id"],
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
        approved = conn.execute(
            "SELECT COUNT(*) FROM rules_catalog WHERE status = 'approved'"
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
            "approved_rules": approved,
            # Retained for dashboards created from databases predating explicit approval.
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
                "approved": "🟢",
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
      <div class="value">{stats['approved_rules']}</div>
      <div class="label">Approved Rules</div>
    </div>
  </div>

  <canvas id="scoreChart" width="800" height="300"></canvas>

  <h2 style="color: #22c55e; font-size: 1.1rem;">Detected Patterns</h2>
  <table>
    <thead><tr><th>Resource Type</th><th>Risk</th>
    <th>Incidents</th><th>Status</th><th>Score</th></tr></thead>
    <tbody>
      {
        pattern_rows
        if pattern_rows
        else '<tr><td colspan="5" style="text-align:center;">No patterns yet.</td></tr>'
      }
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
        active_patterns = [
            p
            for p in patterns
            if p["rule_status"] in ("pr-ready", "approved", "auto-merge")
        ]

        if style == "concise":
            text = (
                f"Evolution update. "
                f"{stats['total_runs']} runs analyzed. "
                f"Average compliance score: {stats['avg_compliance_score']:.1f}. "
                f"{len(patterns)} patterns detected. "
                f"{stats['approved_rules']} rules explicitly approved."
            )
        elif style == "narrative":
            text = (
                f"The self-improving gate has processed {stats['total_runs']} plans. "
                f"The average compliance score is {stats['avg_compliance_score']:.1f}. "
                f"We detected {len(patterns)} recurring patterns "
                f"across {stats['total_incidents']} incidents. "
                f"{stats['approved_rules']} rules have been explicitly approved. "
                f"{len(active_patterns)} patterns are ready for review."
            )
        elif style == "professional":
            text = (
                f"ReadThePlan Evolution Report. "
                f"Total runs: {stats['total_runs']}. "
                f"Average compliance score: {stats['avg_compliance_score']:.1f}. "
                f"Patterns detected: {len(patterns)}. "
                f"Rules approved: {stats['approved_rules']}. "
                f"Active patterns pending: {len(active_patterns)}."
            )
        else:  # excited
            text = (
                f"Your self-improving kernel gate is getting smarter! "
                f"Compliance score is {stats['avg_compliance_score']:.1f}. "
                f"We've spotted {len(patterns)} patterns and "
                f"explicitly approved {stats['approved_rules']} rules. "
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


_ENGINE_CACHE: dict[Path, EvolutionEngine] = {}
_ENGINE_CACHE_LOCK = threading.Lock()


def get_engine(data_dir: str | Path | None = None) -> EvolutionEngine:
    """Return the lazily constructed engine for the current data directory.

    The default path is resolved at call time so importing this module has no
    filesystem side effects and processes that intentionally change HOME use
    the corresponding engine rather than a stale singleton from another home.
    """
    root = Path(data_dir) if data_dir is not None else Path.home() / ".readtheplan"
    cache_key = root.expanduser().resolve(strict=False)
    with _ENGINE_CACHE_LOCK:
        engine = _ENGINE_CACHE.get(cache_key)
        if engine is None:
            engine = EvolutionEngine(cache_key)
            _ENGINE_CACHE[cache_key] = engine
        return engine
