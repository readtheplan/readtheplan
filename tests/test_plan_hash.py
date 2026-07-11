"""Red tests for content-based plan identity (finding 6, ADR 0014).

These tests encode REQUIRED behavior per docs/adr/0014-plan-identity-hash.md.
The collision and path-sensitivity tests FAIL on main@486af4c and must pass
once ``fix/plan-identity-hash`` lands. Three canonicalization tests are
guards that already pass and must stay green.
"""

from __future__ import annotations

import re
from pathlib import Path

from readtheplan.agent_gate import _compute_plan_hash
from readtheplan.plan import PlanSummary, ResourceChange


def _change(
    address: str,
    resource_type: str,
    actions: tuple[str, ...],
    risk: str = "review",
    explanation: str = "test",
) -> ResourceChange:
    return ResourceChange(
        address=address,
        resource_type=resource_type,
        actions=actions,
        risk=risk,
        explanation=explanation,
    )


def _summary(
    changes: tuple[ResourceChange, ...],
    path: str = "plan.json",
    version: str | None = "1.9.0",
) -> PlanSummary:
    return PlanSummary(
        path=Path(path),
        terraform_version=version,
        resource_changes=changes,
    )


# ---------------------------------------------------------------------------
# Collisions the current hash cannot distinguish (red)
# ---------------------------------------------------------------------------


def test_different_changes_hash_differently() -> None:
    """Two materially different plans must not share an identity.

    On main, path + change count + terraform version are the only inputs, so
    these two single-change plans collide.
    """
    delete_db = _summary((_change("aws_db_instance.main", "aws_db_instance", ("delete",)),))
    create_bucket = _summary((_change("aws_s3_bucket.logs", "aws_s3_bucket", ("create",)),))

    assert _compute_plan_hash(delete_db) != _compute_plan_hash(create_bucket)


def test_different_actions_on_same_resource_hash_differently() -> None:
    """Same address, different actions — different plan identity."""
    update = _summary((_change("aws_iam_role.app", "aws_iam_role", ("update",)),))
    delete = _summary((_change("aws_iam_role.app", "aws_iam_role", ("delete",)),))

    assert _compute_plan_hash(update) != _compute_plan_hash(delete)


def test_action_order_is_identity_relevant() -> None:
    """delete-then-create is not create-then-delete (replace semantics)."""
    destroy_first = _summary(
        (_change("aws_db_instance.main", "aws_db_instance", ("delete", "create")),)
    )
    create_first = _summary(
        (_change("aws_db_instance.main", "aws_db_instance", ("create", "delete")),)
    )

    assert _compute_plan_hash(destroy_first) != _compute_plan_hash(create_first)


def test_same_content_at_different_paths_hashes_identically() -> None:
    """Plan identity is content-based; the local file path is noise."""
    changes = (
        _change("aws_s3_bucket.logs", "aws_s3_bucket", ("create",)),
        _change("aws_db_instance.main", "aws_db_instance", ("delete", "create")),
    )
    here = _summary(changes, path="/ci/workspace/plan.json")
    there = _summary(changes, path="C:/Users/dev/plans/plan.json")

    assert _compute_plan_hash(here) == _compute_plan_hash(there)


def test_hash_is_full_sha256_hex() -> None:
    """The identity key is a full 64-char digest, not a 16-char prefix."""
    digest = _compute_plan_hash(
        _summary((_change("aws_s3_bucket.logs", "aws_s3_bucket", ("create",)),))
    )
    assert re.fullmatch(r"[0-9a-f]{64}", digest), digest


# ---------------------------------------------------------------------------
# Canonicalization guards (green now, must stay green)
# ---------------------------------------------------------------------------


def test_change_order_does_not_affect_hash() -> None:
    a = _change("aws_s3_bucket.logs", "aws_s3_bucket", ("create",))
    b = _change("aws_db_instance.main", "aws_db_instance", ("delete",))

    assert _compute_plan_hash(_summary((a, b))) == _compute_plan_hash(_summary((b, a)))


def test_same_address_changes_are_totally_ordered() -> None:
    """Same address+type twice (current + deposed object) must still canonicalize.

    Terraform keys changes by address plus ``deposed``; PlanSummary drops
    ``deposed``, so the sort key must include the actions tuple to keep the
    ordering total — input order must not leak into the digest.
    """
    current = _change("aws_instance.web", "aws_instance", ("create",))
    deposed = _change("aws_instance.web", "aws_instance", ("delete",))

    assert _compute_plan_hash(_summary((current, deposed))) == _compute_plan_hash(
        _summary((deposed, current))
    )


def test_derived_rule_fields_do_not_affect_hash() -> None:
    """risk/explanation come from the rule engine, not the plan."""
    strict = _summary(
        (_change("aws_db_instance.main", "aws_db_instance", ("delete",), risk="irreversible", explanation="will destroy data"),)  # noqa: E501
    )
    lax = _summary(
        (_change("aws_db_instance.main", "aws_db_instance", ("delete",), risk="review", explanation="check this"),)  # noqa: E501
    )

    assert _compute_plan_hash(strict) == _compute_plan_hash(lax)
