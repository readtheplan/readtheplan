#!/usr/bin/env python3
"""Convert YAML compliance catalogs to JSON for Pages Functions bundling."""
import json, yaml, sys
from pathlib import Path

SRC = Path("src/readtheplan/data/controls")
OUT = Path("site/data")
OUT.mkdir(parents=True, exist_ok=True)

# Convert each framework
frameworks = {}
for yf in sorted(SRC.glob("*.yaml")):
    name = yf.stem
    with open(yf) as f:
        data = yaml.safe_load(f)
    out_file = OUT / f"{name}.json"
    with open(out_file, "w") as f:
        json.dump(data, f)
    frameworks[name] = {
        "id": name,
        "file": f"{name}.json",
        "control_count": len(data.get("controls", data.get("mappings", [])))
    }
    print(f"  {name}: {frameworks[name]['control_count']} mappings → {out_file}")

# Write framework index
index = {
    "version": "0.3.0",
    "frameworks": frameworks,
    "endpoints": {
        "list": "/api/v1/controls",
        "get": "/api/v1/controls/{framework}",
        "demo": "/api/v1/demo/{plan}",
        "version": "/api/v1/version"
    }
}
with open(OUT / "index.json", "w") as f:
    json.dump(index, f, indent=2)
print(f"\n  index: {len(frameworks)} frameworks → {OUT / 'index.json'}")

# Copy demo plans from playground
PLAYGROUND = Path("site/playground")
DEMO_OUT = OUT / "demos"
DEMO_OUT.mkdir(exist_ok=True)
demos = []
for jf in sorted(PLAYGROUND.glob("*.json")):
    dest = DEMO_OUT / jf.name
    dest.write_text(jf.read_text())
    demos.append(jf.stem)
    print(f"  demo: {jf.stem} → {dest}")
with open(DEMO_OUT / "index.json", "w") as f:
    json.dump({"demos": demos}, f)
print(f"  demos: {len(demos)} plans")

print("\nDone — data bundle ready for Pages Functions.")
