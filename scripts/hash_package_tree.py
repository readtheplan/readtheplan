#!/usr/bin/env python3
"""Print a deterministic digest for a readtheplan package tree."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path


def package_tree_digest(root: Path) -> str:
    """Hash package-relative paths and contents, excluding bytecode caches."""
    digest = hashlib.sha256()
    paths = sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".pyo"}
    )
    if not paths:
        raise ValueError(f"package tree contains no files: {root}")
    for path in paths:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def main(arguments: list[str]) -> int:
    if len(arguments) > 1:
        print("usage: hash_package_tree.py [PACKAGE_ROOT]", file=sys.stderr)
        return 2
    if arguments:
        root = Path(arguments[0])
    else:
        import readtheplan

        root = Path(readtheplan.__file__).resolve().parent
    try:
        print(package_tree_digest(root))
    except (OSError, ValueError) as exc:
        print(f"package tree hash failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
