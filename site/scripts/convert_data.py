#!/usr/bin/env python3
"""Convert YAML compliance catalogs to JSON for Pages Functions bundling."""

import json
from pathlib import Path

import yaml

SRC = Path("src/readtheplan/data/controls")
OUT = Path("site/data")
OUT.mkdir(parents=True, exist_ok=True)


def project_version() -> str:
    """Read the package version without requiring tomllib on Python 3.10."""

    in_project = False
    for raw_line in Path("pyproject.toml").read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line == "[project]":
            in_project = True
            continue
        if in_project and line.startswith("["):
            break
        if in_project and line.startswith("version") and "=" in line:
            return line.split("=", 1)[1].strip().strip('"')
    raise RuntimeError("Unable to read [project].version from pyproject.toml")

# Convert each framework.
frameworks = {}
for yf in sorted(SRC.glob("*.yaml")):
    name = yf.stem
    with open(yf, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    out_file = OUT / f"{name}.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(data, f)
    frameworks[name] = {
        "id": name,
        "file": f"{name}.json",
        "control_count": len(data.get("controls", data.get("mappings", []))),
    }
    print(f"  {name}: {frameworks[name]['control_count']} mappings -> {out_file}")

# Write framework index.
index = {
    "version": project_version(),
    "frameworks": frameworks,
    "endpoints": {
        "list": "/api/v1/controls",
        "get": "/api/v1/controls/{framework}",
        "demo": "/api/v1/demo/{plan}",
        "version": "/api/v1/version",
    },
}
with open(OUT / "index.json", "w", encoding="utf-8") as f:
    json.dump(index, f, indent=2)
print(f"\n  index: {len(frameworks)} frameworks -> {OUT / 'index.json'}")

# Copy demo plans from playground.
PLAYGROUND = Path("site/playground")
DEMO_OUT = OUT / "demos"
DEMO_OUT.mkdir(exist_ok=True)
for stale_demo in DEMO_OUT.glob("*.json"):
    stale_demo.unlink()
demos = []
for jf in sorted(PLAYGROUND.glob("*.json")):
    dest = DEMO_OUT / jf.name
    dest.write_text(jf.read_text(encoding="utf-8"), encoding="utf-8")
    demos.append(jf.stem)
    print(f"  demo: {jf.stem} -> {dest}")
with open(DEMO_OUT / "index.json", "w", encoding="utf-8") as f:
    json.dump({"demos": demos}, f)
print(f"  demos: {len(demos)} plans")

print("\nDone - data bundle ready for Pages Functions.")
