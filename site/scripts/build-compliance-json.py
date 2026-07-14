#!/usr/bin/env python3
"""Build compliance catalog JSON for the in-browser playground.

Converts src/readtheplan/data/controls/*.yaml into a single 
site/playground/compliance.json file that the JS classifier loads.
"""
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[2]
CONTROLS_DIR = ROOT / "src" / "readtheplan" / "data" / "controls"
OUTPUT = ROOT / "site" / "playground" / "compliance.json"

def main():
    frameworks = {}
    for yaml_path in sorted(CONTROLS_DIR.glob("*.yaml")):
        with open(yaml_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        name = data["framework"]
        frameworks[name] = {
            "framework": name,
            "version": data.get("framework_version", ""),
            "mappings": data.get("mappings", []),
        }
        print(f"  Loaded {name}: {len(frameworks[name]['mappings'])} mappings")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(frameworks, f, indent=2)
    print(f"\nWrote {OUTPUT} ({OUTPUT.stat().st_size:,} bytes)")

if __name__ == "__main__":
    main()
