"""Capture and verify immutable Nexus release inventory for CI promotion.

This helper intentionally uses only the Python standard library.  Credentials
come from ``NEXUS_USERNAME`` and ``NEXUS_PASSWORD`` and are never written to
the signed manifest.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

SCHEMA = "https://readtheplan.dev/schemas/nexus-release-manifest-v1"
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9._-]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CHECKSUM_RE = re.compile(r"^([0-9a-f]{64})  (.+)$")


class EvidenceError(RuntimeError):
    """Raised when release evidence is incomplete or inconsistent."""


def fail(message: str) -> NoReturn:
    raise EvidenceError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_repository(value: str, label: str) -> str:
    if not REPOSITORY_RE.fullmatch(value):
        fail(f"{label} must be a Nexus repository name")
    return value


def normalize_base_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.rstrip("/"))
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        fail("Nexus base URL must be HTTPS and must not contain credentials, query, or fragment")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def validate_expected_origin(base_url: str, expected_host: str, expected_path: str) -> None:
    parsed = urllib.parse.urlsplit(normalize_base_url(base_url))
    if not expected_host or "/" in expected_host or "://" in expected_host:
        fail("NEXUS_EXPECTED_HOST must be an exact host[:port] value")
    if parsed.netloc.lower() != expected_host.lower():
        fail("Nexus URL host does not match NEXUS_EXPECTED_HOST")
    if not expected_path.startswith("/") or ".." in PurePosixPath(expected_path).parts:
        fail("NEXUS_EXPECTED_PATH_PREFIX must be an absolute URL path")
    normalized_expected = expected_path.rstrip("/") or "/"
    actual_path = parsed.path.rstrip("/") or "/"
    if actual_path != normalized_expected:
        fail("Nexus base path does not match NEXUS_EXPECTED_PATH_PREFIX")


def parse_repository_url(value: str) -> tuple[str, str]:
    normalized = normalize_base_url(value)
    parsed = urllib.parse.urlsplit(normalized)
    match = re.fullmatch(r"(?P<base>.*)/repository/(?P<repository>[A-Za-z0-9._-]+)", parsed.path)
    if match is None:
        fail("NEXUS_PYPI_REPOSITORY_URL must end in /repository/<repository-name>")
    repository = validate_repository(match.group("repository"), "source repository")
    base_path = match.group("base").rstrip("/")
    base_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, base_path, "", ""))
    return normalize_base_url(base_url), repository


def parse_checksums(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        fail(f"checksum manifest does not exist: {path}")
    entries: list[dict[str, str]] = []
    paths: set[str] = set()
    basenames: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        match = CHECKSUM_RE.fullmatch(line)
        if match is None:
            fail(f"invalid SHA256SUMS line {line_number}")
        digest, relative = match.groups()
        pure_path = PurePosixPath(relative)
        if pure_path.is_absolute() or ".." in pure_path.parts or str(pure_path) != relative:
            fail(f"unsafe path in SHA256SUMS: {relative!r}")
        basename = pure_path.name
        if relative in paths or basename in basenames:
            fail(f"duplicate path or release-asset name in SHA256SUMS: {relative!r}")
        paths.add(relative)
        basenames.add(basename)
        entries.append({"manifest_path": relative, "release_asset": basename, "sha256": digest})
    if not entries:
        fail("SHA256SUMS is empty")
    return entries


def distribution_entries(entries: list[dict[str, str]]) -> list[dict[str, str]]:
    result = [
        entry
        for entry in entries
        if entry["manifest_path"].startswith("dist/")
        and (entry["release_asset"].endswith(".whl") or entry["release_asset"].endswith(".tar.gz"))
    ]
    if not any(entry["release_asset"].endswith(".whl") for entry in result):
        fail("SHA256SUMS does not contain a wheel")
    if not any(entry["release_asset"].endswith(".tar.gz") for entry in result):
        fail("SHA256SUMS does not contain a source distribution")
    return result


def verify_local_evidence(
    checksum_path: Path,
    root: Path,
    expected_entries: list[dict[str, str]] | None = None,
) -> list[dict[str, str]]:
    entries = parse_checksums(checksum_path)
    if expected_entries is not None and entries != expected_entries:
        fail("SHA256SUMS entries do not match the signed release manifest")
    for entry in entries:
        candidate = root / entry["manifest_path"]
        if not candidate.is_file():
            # GitHub Release assets are flat, while the checksum manifest records
            # build-time dist/ and release-evidence/ paths.
            candidate = root / entry["release_asset"]
        if not candidate.is_file():
            fail(f"release evidence is missing {entry['release_asset']!r}")
        actual = sha256_file(candidate)
        if actual != entry["sha256"]:
            fail(f"SHA-256 mismatch for {entry['release_asset']!r}")
    return entries


def package_coordinates(dist_dir: Path, entries: list[dict[str, str]]) -> tuple[str, str]:
    wheel_entries = [entry for entry in entries if entry["release_asset"].endswith(".whl")]
    if len(wheel_entries) != 1:
        fail("release evidence must contain exactly one wheel")
    wheel = dist_dir / wheel_entries[0]["release_asset"]
    if not wheel.is_file():
        fail(f"wheel does not exist: {wheel}")
    with zipfile.ZipFile(wheel) as archive:
        metadata_names = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_names) != 1:
            fail("wheel must contain exactly one .dist-info/METADATA file")
        metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
    name = metadata.get("Name", "").strip()
    version = metadata.get("Version", "").strip()
    if not name or not version or any(character.isspace() for character in name + version):
        fail("wheel metadata contains an invalid package name or version")
    return name, version


def normalized_package_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Do not forward Nexus Basic credentials across redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class NexusClient:
    def __init__(self, base_url: str, username: str, password: str) -> None:
        self.base_url = normalize_base_url(base_url)
        if not username or not password:
            fail("NEXUS_USERNAME and NEXUS_PASSWORD are required")
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {token}", "Accept": "application/json"}
        self.opener = urllib.request.build_opener(RejectRedirects())

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
        expected: tuple[int, ...] = (200, 204),
    ) -> Any:
        url = f"{self.base_url}{path}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"
        data = None
        headers = dict(self.headers)
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=60) as response:  # noqa: S310
                payload = response.read()
                status = response.status
        except urllib.error.HTTPError as exc:
            detail = exc.read(1000).decode("utf-8", errors="replace")
            fail(f"Nexus API {method} {path} failed with HTTP {exc.code}: {detail}")
        except urllib.error.URLError as exc:
            fail(f"Nexus API {method} {path} failed: {exc.reason}")
        if status not in expected:
            fail(f"Nexus API {method} {path} returned unexpected HTTP {status}")
        if not payload:
            return None
        try:
            return json.loads(payload)
        except json.JSONDecodeError as exc:
            fail(f"Nexus API {method} {path} returned invalid JSON: {exc}")

    def search(self, **criteria: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        token: str | None = None
        while True:
            query = dict(criteria)
            if token:
                query["continuationToken"] = token
            payload = self.request("GET", "/service/rest/v1/search", query=query)
            if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
                fail("Nexus search response does not contain an items list")
            items.extend(payload["items"])
            token = payload.get("continuationToken")
            if token is None:
                return items
            if not isinstance(token, str) or not token:
                fail("Nexus search returned an invalid continuation token")

    def create_tag(self, tag: str, repository: str, release_tag: str, git_sha: str) -> None:
        self.request(
            "POST",
            "/service/rest/v1/tags",
            body={
                "name": tag,
                "attributes": {
                    "readtheplan.repository": repository,
                    "readtheplan.release_tag": release_tag,
                    "readtheplan.git_sha": git_sha,
                },
            },
            expected=(200, 201, 204),
        )

    def associate_tag(self, tag: str, repository: str, sha256: str) -> None:
        encoded = urllib.parse.quote(tag, safe="")
        self.request(
            "POST",
            f"/service/rest/v1/tags/associate/{encoded}",
            query={"repository": repository, "sha256": sha256},
            expected=(200, 204),
        )

    def move_tag(self, tag: str, source: str, destination: str) -> None:
        encoded = urllib.parse.quote(destination, safe="")
        self.request(
            "POST",
            f"/service/rest/v1/staging/move/{encoded}",
            query={"repository": source, "tag": tag},
            expected=(200, 202, 204),
        )


def exact_coordinate_items(
    client: NexusClient, repository: str, name: str, version: str
) -> list[dict[str, Any]]:
    items = client.search(repository=repository, name=name, version=version)
    normalized_name = normalized_package_name(name)
    return [
        item
        for item in items
        if item.get("repository") == repository
        and normalized_package_name(str(item.get("name", ""))) == normalized_name
        and str(item.get("version", "")) == version
    ]


def canonical_inventory(items: list[dict[str, Any]], repository: str) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    component_ids: set[str] = set()
    for item in items:
        component_id = item.get("id")
        if not isinstance(component_id, str) or not component_id or component_id in component_ids:
            fail("Nexus returned a missing or duplicate component ID")
        component_ids.add(component_id)
        if item.get("repository") != repository or item.get("format") != "pypi":
            fail("Nexus returned a component outside the expected PyPI repository")
        assets = item.get("assets")
        if not isinstance(assets, list) or not assets:
            fail(f"Nexus component {component_id!r} has no assets")
        canonical_assets: list[dict[str, Any]] = []
        asset_paths: set[str] = set()
        for asset in assets:
            path = asset.get("path")
            checksum = asset.get("checksum")
            size = asset.get("fileSize")
            if (
                not isinstance(path, str)
                or not path
                or path in asset_paths
                or not isinstance(checksum, dict)
                or not isinstance(checksum.get("sha256"), str)
                or not SHA256_RE.fullmatch(checksum["sha256"])
                or not isinstance(size, int)
                or size < 0
            ):
                fail(f"Nexus component {component_id!r} has incomplete asset evidence")
            asset_paths.add(path)
            canonical_assets.append({"path": path, "sha256": checksum["sha256"], "size": size})
        inventory.append(
            {
                "id": component_id,
                "repository": repository,
                "format": "pypi",
                "group": item.get("group"),
                "name": item.get("name"),
                "version": item.get("version"),
                "assets": sorted(canonical_assets, key=lambda value: value["path"]),
            }
        )
    return sorted(inventory, key=lambda value: value["id"])


def inventory_for_tag(client: NexusClient, repository: str, tag: str) -> list[dict[str, Any]]:
    items = [
        item
        for item in client.search(repository=repository, tag=tag)
        if item.get("repository") == repository
    ]
    return canonical_inventory(items, repository)


def assert_exact_distribution_assets(
    inventory: list[dict[str, Any]], entries: list[dict[str, str]]
) -> None:
    expected = {entry["release_asset"]: entry["sha256"] for entry in distribution_entries(entries)}
    actual: dict[str, str] = {}
    for component in inventory:
        for asset in component["assets"]:
            basename = PurePosixPath(asset["path"]).name
            if basename in actual:
                fail(f"Nexus inventory contains duplicate asset basename {basename!r}")
            actual[basename] = asset["sha256"]
    if actual != expected:
        fail(
            "Nexus component inventory is not the exact wheel/sdist set in SHA256SUMS "
            f"(expected {sorted(expected)}, received {sorted(actual)})"
        )


def semantic_inventory(inventory: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = [
        {
            "format": component["format"],
            "group": component["group"],
            "name": component["name"],
            "version": component["version"],
            "assets": component["assets"],
        }
        for component in inventory
    ]
    return sorted(result, key=lambda value: json.dumps(value, sort_keys=True))


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read signed Nexus release manifest: {exc}")
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        fail("unsupported Nexus release manifest schema")
    return manifest


def credentials() -> tuple[str, str]:
    return os.environ.get("NEXUS_USERNAME", ""), os.environ.get("NEXUS_PASSWORD", "")


def resolve_configuration(args: argparse.Namespace) -> tuple[str, str]:
    base_url, repository = parse_repository_url(args.repository_url)
    validate_expected_origin(base_url, args.expected_host, args.expected_path_prefix)
    if args.expected_base_url and normalize_base_url(args.expected_base_url) != base_url:
        fail("NEXUS_STAGING_BASE_URL does not match NEXUS_PYPI_REPOSITORY_URL")
    if args.expected_source_repository:
        expected_source = validate_repository(
            args.expected_source_repository, "NEXUS_STAGING_SOURCE_REPOSITORY"
        )
        if expected_source != repository:
            fail("NEXUS_STAGING_SOURCE_REPOSITORY does not match NEXUS_PYPI_REPOSITORY_URL")
    return base_url, repository


def command_preflight(args: argparse.Namespace) -> None:
    base_url, repository = resolve_configuration(args)
    entries = verify_local_evidence(args.checksums, args.root)
    name, version = package_coordinates(args.dist_dir, distribution_entries(entries))
    client = NexusClient(base_url, *credentials())
    existing = exact_coordinate_items(client, repository, name, version)
    if existing:
        fail(
            f"immutable preflight failed: {repository!r} already contains "
            f"{name} {version} ({len(existing)} component(s))"
        )
    print(f"Immutable preflight passed for {repository}/{name}/{version}")


def command_capture(args: argparse.Namespace) -> None:
    base_url, repository = resolve_configuration(args)
    entries = verify_local_evidence(args.checksums, args.root)
    dist_entries = distribution_entries(entries)
    name, version = package_coordinates(args.dist_dir, dist_entries)
    client = NexusClient(base_url, *credentials())
    inventory = canonical_inventory(
        exact_coordinate_items(client, repository, name, version), repository
    )
    if not inventory:
        fail("Nexus upload completed but no exact package coordinates were found")
    assert_exact_distribution_assets(inventory, entries)

    destination = None
    component_tag = None
    mode = "reference-only"
    if args.destination_repository:
        destination = validate_repository(
            args.destination_repository, "NEXUS_STAGING_PROMOTION_TARGET"
        )
        if destination == repository:
            fail("Nexus source and destination repositories must differ")
        safe_tag = re.sub(r"[^A-Za-z0-9._:+-]", "-", args.github_tag)
        component_tag = f"readtheplan-{safe_tag}-{args.github_sha[:12]}"
        client.create_tag(component_tag, args.github_repository, args.github_tag, args.github_sha)
        for component in inventory:
            # Associating each exact component by an asset digest avoids the broad
            # name/version selector that could tag an unintended component.
            client.associate_tag(component_tag, repository, component["assets"][0]["sha256"])
        tagged = inventory_for_tag(client, repository, component_tag)
        if tagged != inventory:
            fail("Nexus tag does not select the exact captured component inventory")
        mode = "pro-tag-move"

    checksum_signature = None
    if args.checksum_bundle:
        if not args.checksum_bundle.is_file():
            fail("checksum signature bundle was required but not found")
        checksum_signature = {
            "asset": args.checksum_bundle.name,
            "sha256": sha256_file(args.checksum_bundle),
        }

    workflow_ref = (
        f"{args.github_repository}/.github/workflows/publish.yml@refs/tags/{args.github_tag}"
    )
    if args.github_workflow_ref != workflow_ref:
        fail("GITHUB_WORKFLOW_REF is not the expected tag-triggered publish workflow identity")
    manifest = {
        "schema": SCHEMA,
        "release": {
            "repository": args.github_repository,
            "tag": args.github_tag,
            "git_sha": args.github_sha,
            "run_id": args.github_run_id,
            "workflow_ref": workflow_ref,
            "package": {"name": name, "version": version},
        },
        "release_evidence": {
            "checksum_manifest": {
                "asset": args.checksums.name,
                "sha256": sha256_file(args.checksums),
            },
            "checksum_signature": checksum_signature,
            "files": entries,
        },
        "nexus": {
            "base_url": base_url,
            "source_repository": repository,
            "destination_repository": destination,
            "promotion_mode": mode,
            "component_tag": component_tag,
            "source_inventory": inventory,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"Captured {len(inventory)} exact Nexus component(s) with "
        f"{sum(len(component['assets']) for component in inventory)} asset(s)"
    )


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"signed manifest field {label} must be an object")
    return value


def command_promote(args: argparse.Namespace) -> None:
    manifest = load_manifest(args.manifest)
    release = require_mapping(manifest.get("release"), "release")
    evidence = require_mapping(manifest.get("release_evidence"), "release_evidence")
    nexus = require_mapping(manifest.get("nexus"), "nexus")

    expected_workflow_ref = (
        f"{args.expected_repository}/.github/workflows/publish.yml@refs/tags/{args.expected_tag}"
    )
    if (
        release.get("repository") != args.expected_repository
        or release.get("tag") != args.expected_tag
        or release.get("workflow_ref") != expected_workflow_ref
    ):
        fail("signed release identity does not match the requested protected release tag")

    expected_base_url = normalize_base_url(args.expected_base_url)
    validate_expected_origin(
        expected_base_url, args.expected_host, args.expected_path_prefix
    )
    expected_source = validate_repository(
        args.expected_source_repository, "NEXUS_STAGING_SOURCE_REPOSITORY"
    )
    expected_destination = args.expected_destination_repository or None
    if expected_destination is not None:
        expected_destination = validate_repository(
            expected_destination, "NEXUS_STAGING_PROMOTION_TARGET"
        )
    if (
        nexus.get("base_url") != expected_base_url
        or nexus.get("source_repository") != expected_source
        or nexus.get("destination_repository") != expected_destination
    ):
        fail("current Nexus configuration does not match the signed release authority")

    checksum = require_mapping(evidence.get("checksum_manifest"), "checksum_manifest")
    checksum_path = args.release_assets_dir / str(checksum.get("asset", ""))
    if not checksum_path.is_file() or sha256_file(checksum_path) != checksum.get("sha256"):
        fail("durable GitHub Release checksum manifest does not match signed Nexus evidence")
    files = evidence.get("files")
    if not isinstance(files, list):
        fail("signed release evidence files must be a list")
    verify_local_evidence(checksum_path, args.release_assets_dir, files)
    checksum_signature = evidence.get("checksum_signature")
    if checksum_signature is not None:
        signature = require_mapping(checksum_signature, "checksum_signature")
        signature_path = args.release_assets_dir / str(signature.get("asset", ""))
        if not signature_path.is_file() or sha256_file(signature_path) != signature.get("sha256"):
            fail("durable checksum signature bundle does not match signed Nexus evidence")

    package = require_mapping(release.get("package"), "release.package")
    name = package.get("name")
    version = package.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        fail("signed package coordinates are incomplete")
    signed_inventory = nexus.get("source_inventory")
    if not isinstance(signed_inventory, list) or not signed_inventory:
        fail("signed Nexus source inventory is empty")

    client = NexusClient(expected_base_url, *credentials())
    current_inventory = canonical_inventory(
        exact_coordinate_items(client, expected_source, name, version), expected_source
    )
    if current_inventory != signed_inventory:
        fail("current Nexus source inventory differs from the signed full inventory")
    assert_exact_distribution_assets(current_inventory, files)

    mode = nexus.get("promotion_mode")
    tag = nexus.get("component_tag")
    if expected_destination is None:
        if mode != "reference-only" or tag is not None:
            fail("signed reference-only release contains unexpected Pro promotion authority")
        print("Verified durable signed Nexus CE reference; no artifact was copied or rebuilt")
        return

    if mode != "pro-tag-move" or not isinstance(tag, str) or not tag:
        fail("signed manifest does not authorize a Nexus Pro tag move")
    tagged_source = inventory_for_tag(client, expected_source, tag)
    if tagged_source != signed_inventory:
        fail("Nexus tag no longer selects the exact signed source component inventory")

    client.move_tag(tag, expected_source, expected_destination)
    destination_inventory = inventory_for_tag(client, expected_destination, tag)
    if semantic_inventory(destination_inventory) != semantic_inventory(signed_inventory):
        fail("destination full asset inventory differs after Nexus promotion")
    if inventory_for_tag(client, expected_source, tag):
        fail("Nexus source still contains tagged components after the staging move")
    assert_exact_distribution_assets(destination_inventory, files)
    print(
        f"Promoted and verified {len(destination_inventory)} component(s); "
        "the complete destination asset inventory is byte-identical"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_repository_arguments(command: argparse.ArgumentParser) -> None:
        command.add_argument("--repository-url", required=True)
        command.add_argument("--expected-base-url", default="")
        command.add_argument("--expected-host", required=True)
        command.add_argument("--expected-path-prefix", required=True)
        command.add_argument("--expected-source-repository", default="")
        command.add_argument("--checksums", type=Path, required=True)
        command.add_argument("--root", type=Path, required=True)
        command.add_argument("--dist-dir", type=Path, required=True)

    preflight = subparsers.add_parser("preflight")
    add_repository_arguments(preflight)
    preflight.set_defaults(handler=command_preflight)

    capture = subparsers.add_parser("capture")
    add_repository_arguments(capture)
    capture.add_argument("--destination-repository", default="")
    capture.add_argument("--checksum-bundle", type=Path)
    capture.add_argument("--github-repository", required=True)
    capture.add_argument("--github-tag", required=True)
    capture.add_argument("--github-sha", required=True)
    capture.add_argument("--github-run-id", required=True)
    capture.add_argument("--github-workflow-ref", required=True)
    capture.add_argument("--output", type=Path, required=True)
    capture.set_defaults(handler=command_capture)

    promote = subparsers.add_parser("promote")
    promote.add_argument("--manifest", type=Path, required=True)
    promote.add_argument("--release-assets-dir", type=Path, required=True)
    promote.add_argument("--expected-repository", required=True)
    promote.add_argument("--expected-tag", required=True)
    promote.add_argument("--expected-base-url", required=True)
    promote.add_argument("--expected-host", required=True)
    promote.add_argument("--expected-path-prefix", required=True)
    promote.add_argument("--expected-source-repository", required=True)
    promote.add_argument("--expected-destination-repository", default="")
    promote.set_defaults(handler=command_promote)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        args.handler(args)
    except EvidenceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
