import pytest

from tools.nexus_release_evidence import (
    EvidenceError,
    assert_exact_distribution_assets,
    canonical_inventory,
    parse_repository_url,
    semantic_inventory,
)


def test_parse_repository_url_supports_context_path() -> None:
    assert parse_repository_url("https://nexus.example.test/nexus/repository/pypi-staging/") == (
        "https://nexus.example.test/nexus",
        "pypi-staging",
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://nexus.example.test/repository/pypi",
        "https://user:password@nexus.example.test/repository/pypi",
        "https://nexus.example.test/service/rest/v1/search",
    ],
)
def test_parse_repository_url_rejects_unsafe_or_non_repository_url(url: str) -> None:
    with pytest.raises(EvidenceError):
        parse_repository_url(url)


def test_full_inventory_rejects_extra_nexus_asset() -> None:
    entries = [
        {
            "manifest_path": "dist/readtheplan-1.0-py3-none-any.whl",
            "release_asset": "readtheplan-1.0-py3-none-any.whl",
            "sha256": "a" * 64,
        },
        {
            "manifest_path": "dist/readtheplan-1.0.tar.gz",
            "release_asset": "readtheplan-1.0.tar.gz",
            "sha256": "b" * 64,
        },
    ]
    inventory = [
        {
            "assets": [
                {"path": "a/readtheplan-1.0-py3-none-any.whl", "sha256": "a" * 64},
                {"path": "a/readtheplan-1.0.tar.gz", "sha256": "b" * 64},
                {"path": "a/unexpected.metadata", "sha256": "c" * 64},
            ]
        }
    ]

    with pytest.raises(EvidenceError, match="exact wheel/sdist set"):
        assert_exact_distribution_assets(inventory, entries)


def test_semantic_inventory_ignores_repository_and_component_id() -> None:
    item = {
        "id": "source-id",
        "repository": "pypi-staging",
        "format": "pypi",
        "group": None,
        "name": "readtheplan",
        "version": "1.0",
        "assets": [
            {
                "path": "packages/readtheplan-1.0.tar.gz",
                "checksum": {"sha256": "a" * 64},
                "fileSize": 42,
            }
        ],
    }
    source = canonical_inventory([item], "pypi-staging")
    destination_item = {**item, "id": "destination-id", "repository": "pypi-release"}
    destination = canonical_inventory([destination_item], "pypi-release")

    assert semantic_inventory(source) == semantic_inventory(destination)
