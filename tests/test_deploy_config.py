from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "site" / "scripts" / "prepare-pages-config.py"
WORKFLOW = ROOT / ".github" / "workflows" / "deploy.yml"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("prepare_pages_config", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pages_config_merge_is_preserving_and_idempotent() -> None:
    module = _load_script()
    original = {
        "name": "readtheplan",
        "pages_build_output_dir": "dist",
        "compatibility_date": "2026-07-14",
        "compatibility_flags": ["nodejs_compat"],
        "vars": {"PUBLIC_SETTING": "preserved"},
        "kv_namespaces": [{"binding": "CACHE", "id": "abc123"}],
        "env": {
            "production": {
                "pages_build_output_dir": "stale-output",
                "compatibility_flags": ["production-flag"],
                "vars": {"PRODUCTION_SETTING": "preserved"},
                "durable_objects": {
                    "bindings": [
                        {
                            "name": "PRODUCTION_DO",
                            "class_name": "Production",
                            "script_name": "production-worker",
                        }
                    ]
                },
            },
            "preview": {
                "pages_build_output_dir": "",
                "limits": {"cpu_ms": 25},
            },
        },
        "durable_objects": {
            "bindings": [
                {"name": "EXISTING_DO", "class_name": "Existing", "script_name": "other"},
                {
                    "name": "CHAT_RATE_LIMITER",
                    "class_name": "StaleClass",
                    "script_name": "stale-worker",
                    "environment": "production",
                },
                {"name": "CHAT_RATE_LIMITER", "class_name": "Duplicate"},
            ],
            "other_setting": "preserved",
        },
    }
    snapshot = copy.deepcopy(original)

    merged = module.merge_pages_config(original)

    assert original == snapshot
    assert merged["pages_build_output_dir"] == "dist"
    assert merged["vars"] == original["vars"]
    assert merged["kv_namespaces"] == original["kv_namespaces"]
    assert merged["durable_objects"]["other_setting"] == "preserved"
    assert merged["compatibility_flags"] == ["nodejs_compat", "enable_request_signal"]
    assert merged["env"]["production"]["compatibility_flags"] == [
        "production-flag",
        "enable_request_signal",
    ]
    assert "pages_build_output_dir" not in merged["env"]["production"]
    assert "pages_build_output_dir" not in merged["env"]["preview"]
    assert merged["env"]["production"]["vars"] == {
        "PRODUCTION_SETTING": "preserved"
    }
    assert merged["env"]["preview"]["durable_objects"]["bindings"] == [
        {
            "name": "CHAT_RATE_LIMITER",
            "class_name": "ChatRateLimiter",
            "script_name": "readtheplan-chat-rate-limiter",
        }
    ]

    bindings = merged["durable_objects"]["bindings"]
    assert bindings[0] == original["durable_objects"]["bindings"][0]
    limiter = [binding for binding in bindings if binding["name"] == "CHAT_RATE_LIMITER"]
    assert limiter == [
        {
            "name": "CHAT_RATE_LIMITER",
            "class_name": "ChatRateLimiter",
            "script_name": "readtheplan-chat-rate-limiter",
        }
    ]
    production_bindings = merged["env"]["production"]["durable_objects"]["bindings"]
    assert production_bindings[0] == original["env"]["production"]["durable_objects"][
        "bindings"
    ][0]
    assert production_bindings[1] == {
        "name": "CHAT_RATE_LIMITER",
        "class_name": "ChatRateLimiter",
        "script_name": "readtheplan-chat-rate-limiter",
    }
    assert module.merge_pages_config(merged) == merged


def test_pages_config_adds_binding_to_environment_without_other_bindings() -> None:
    module = _load_script()

    merged = module.merge_pages_config(
        {
            "name": "readtheplan",
            "env": {"production": {"compatibility_flags": ["nodejs_compat"]}},
        }
    )

    production = merged["env"]["production"]
    assert production["compatibility_flags"] == [
        "nodejs_compat",
        "enable_request_signal",
    ]
    assert production["durable_objects"]["bindings"] == [
        module.RATE_LIMITER_BINDING,
    ]


@pytest.mark.parametrize(
    "config",
    [
        {"name": "readtheplan"},
        {"name": "readtheplan", "pages_build_output_dir": ""},
    ],
)
def test_pages_config_merge_adds_required_build_output_directory(
    config: dict[str, object],
) -> None:
    module = _load_script()

    merged = module.merge_pages_config(config)

    assert merged["pages_build_output_dir"] == "dist"


def test_pages_config_round_trip_writes_wrangler_json(tmp_path: Path) -> None:
    module = _load_script()
    downloaded = tmp_path / "wrangler.toml"
    generated = tmp_path / "wrangler.json"
    downloaded.write_text(
        '\n'.join(
            [
                'name = "readtheplan"',
                'pages_build_output_dir = "dist"',
                'compatibility_date = "2026-07-14"',
                'compatibility_flags = ["nodejs_compat"]',
                '',
                '[[d1_databases]]',
                'binding = "DATABASE"',
                'database_id = "database-id"',
                '',
                '[env.production]',
                'compatibility_flags = ["production-flag"]',
                '',
                '[env.production.vars]',
                'PRODUCTION_SETTING = "preserved"',
            ]
        ),
        encoding="utf-8",
    )

    module.write_json_atomic(generated, module.merge_pages_config(module.load_toml(downloaded)))
    result = json.loads(generated.read_text(encoding="utf-8"))

    assert result["pages_build_output_dir"] == "dist"
    assert result["d1_databases"] == [
        {"binding": "DATABASE", "database_id": "database-id"}
    ]
    assert result["compatibility_flags"] == ["nodejs_compat", "enable_request_signal"]
    assert result["durable_objects"]["bindings"] == [
        {
            "name": "CHAT_RATE_LIMITER",
            "class_name": "ChatRateLimiter",
            "script_name": "readtheplan-chat-rate-limiter",
        }
    ]
    assert result["env"]["production"]["compatibility_flags"] == [
        "production-flag",
        "enable_request_signal",
    ]
    assert result["env"]["production"]["vars"] == {
        "PRODUCTION_SETTING": "preserved"
    }
    assert result["env"]["production"]["durable_objects"]["bindings"] == [
        {
            "name": "CHAT_RATE_LIMITER",
            "class_name": "ChatRateLimiter",
            "script_name": "readtheplan-chat-rate-limiter",
        }
    ]


@pytest.mark.parametrize(
    ("config", "message"),
    [
        ({"name": "another-project"}, "expected Pages project"),
        ({"name": "readtheplan", "compatibility_flags": "not-a-list"}, "list of strings"),
        ({"name": "readtheplan", "durable_objects": []}, "must be a table"),
        (
            {"name": "readtheplan", "durable_objects": {"bindings": ["not-a-table"]}},
            "list of tables",
        ),
    ],
)
def test_pages_config_merge_fails_closed(config: dict[str, object], message: str) -> None:
    module = _load_script()
    with pytest.raises(module.ConfigurationError, match=message):
        module.merge_pages_config(config)


def test_cloudflare_production_workflow_contract() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    build_script = (ROOT / "site" / "scripts" / "build.js").read_text(encoding="utf-8")

    for expected in [
        "contents: read",
        "queue: max",
        "cancel-in-progress: false",
        "if: github.event_name == 'push' && github.ref == 'refs/heads/main'",
        "environment:",
        "name: production",
        "url: https://readtheplan.dev",
        "timeout-minutes: 20",
        "persist-credentials: false",
        "node-version: 22",
        "python-version: '3.13'",
        'python -m pip install "PyYAML>=6,<7"',
        "npm ci --ignore-scripts",
        "npm test",
        "node analysis/classifier-parity.test.js",
        "npm run build",
        "wrangler@4.110.0 deploy",
        "workers/chat-rate-limiter/wrangler.toml",
        "wrangler@4.110.0 pages download config readtheplan --force",
        "scripts/prepare-pages-config.py wrangler.toml wrangler.json",
        "wrangler@4.110.0 pages deploy",
        "--branch=main",
        '--commit-hash="${GITHUB_SHA}"',
        "Record exact deployment commit",
        'printf \'%s\\n\' "$GITHUB_SHA" > dist/_deployment-commit.txt',
        "Verify exact production deployment",
        "https://readtheplan.dev/_deployment-commit.txt",
        "https://readtheplan.dev/modern.css",
        "https://readtheplan.dev/chat/chat.js",
        "curl --fail --silent --show-error --location --compressed",
        "--proto '=https' --proto-redir '=https' --tlsv1.2",
        "--max-filesize 5242880",
        'rm -f -- "$output"',
        "cmp --silent",
    ]:
        assert expected in workflow

    assert "paths:" not in workflow
    assert "workflow_dispatch:" not in workflow
    assert "pull_request:" not in workflow
    assert "src/readtheplan/data/controls/**" not in workflow
    assert "src/readtheplan/plan.py" not in workflow
    assert "src/readtheplan/rules/**" not in workflow
    assert "pyproject.toml" not in workflow.split("jobs:", maxsplit=1)[0]
    assert "Cache-Control: no-store, max-age=0" in build_script
    assert "/_deployment-commit.txt" in build_script
    assert workflow.count("|| return 1") >= 5

    assert workflow.index("npm test") < workflow.index("npm run build")
    assert workflow.index("classifier-parity.test.js") < workflow.index("npm run build")
    assert workflow.index("npm run build") < workflow.index("Record exact deployment commit")
    assert workflow.index("Record exact deployment commit") < workflow.index(
        "wrangler@4.110.0 pages deploy"
    )
    assert workflow.index("wrangler@4.110.0 pages deploy") < workflow.index(
        "Verify exact production deployment"
    )
    assert workflow.index("workers/chat-rate-limiter/wrangler.toml") < workflow.index(
        "pages deploy"
    )
    assert workflow.index("pages download config readtheplan") < workflow.index(
        "prepare-pages-config.py"
    )
    assert "pages deploy dist" not in workflow
