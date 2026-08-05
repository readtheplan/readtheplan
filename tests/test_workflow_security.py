from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
USES_PATTERN = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
FULL_COMMIT_PATTERN = re.compile(r"[^@\s]+@[0-9a-f]{40}")
DIGEST_IMAGE_PATTERN = re.compile(r"docker://[^@\s]+@sha256:[0-9a-f]{64}")


def test_external_actions_are_pinned_to_immutable_references() -> None:
    workflow_dir = ROOT / ".github" / "workflows"
    paths = [ROOT / "action.yml"]
    paths.extend(sorted(workflow_dir.glob("*.yml")))
    paths.extend(sorted(workflow_dir.glob("*.yaml")))

    unpinned: list[str] = []
    for path in paths:
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), 1
        ):
            match = USES_PATTERN.match(line)
            if match is None:
                continue
            reference = match.group(1)
            if reference.startswith("./"):
                continue
            if reference.startswith("docker://"):
                immutable = DIGEST_IMAGE_PATTERN.fullmatch(reference) is not None
            else:
                immutable = FULL_COMMIT_PATTERN.fullmatch(reference) is not None
            if not immutable:
                relative = path.relative_to(ROOT).as_posix()
                unpinned.append(f"{relative}:{line_number}: {reference}")

    assert unpinned == []
