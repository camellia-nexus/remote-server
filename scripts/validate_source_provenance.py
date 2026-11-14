#!/usr/bin/env python3
"""Validate and enforce semantic constraints on SOURCE_PROVENANCE.json."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


PROTOCOL_PATH = Path("libs/camellia_remote_protocol")
PROTOCOL_SUBMODULE = "submodule.libs/camellia_remote_protocol.url"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
GITHUB_REPO_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SIBLING_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")

KNOWN_COMPONENTS = {
    "camellia-remote-client",
    "camellia-remote-server",
    "camellia-remote-protocol",
    "camellia-remote-management-server",
}

ALLOWED_HISTORY_POLICIES = {"fresh-root-snapshot"}
ALLOWED_LICENSES = {"AGPL-3.0-only"}

REQUIRED_BASE_FIELDS = {
    "schema_version",
    "component",
    "source_repository",
    "source_commit",
    "history_policy",
    "license",
}

CONSUMER_COMPONENTS = {
    "camellia-remote-client",
    "camellia-remote-server",
}


class ProvenanceError(ValueError):
    """Raised when source provenance is missing, malformed, or stale."""


def validate_document(
    document: object,
    *,
    expected_component: str | None = None,
    actual_protocol_commit: str | None = None,
    actual_protocol_repository: str | None = None,
) -> None:
    if not isinstance(document, dict):
        raise ProvenanceError("SOURCE_PROVENANCE.json must be a JSON object")

    if document.get("schema_version") != 1:
        raise ProvenanceError("SOURCE_PROVENANCE.json must use schema_version 1")

    # Validate required base fields
    for field in REQUIRED_BASE_FIELDS:
        if field not in document:
            raise ProvenanceError(f"missing required provenance field: {field}")

    # Validate component
    component = document.get("component")
    if not isinstance(component, str) or component not in KNOWN_COMPONENTS:
        raise ProvenanceError(f"component must be one of {sorted(KNOWN_COMPONENTS)}, got: {component!r}")
    if expected_component is not None and component != expected_component:
        raise ProvenanceError(f"component mismatch: expected {expected_component!r}, got {component!r}")

    # Validate source_repository
    source_repo = document.get("source_repository")
    if not isinstance(source_repo, str) or GITHUB_REPO_RE.fullmatch(source_repo) is None:
        raise ProvenanceError("source_repository must be a canonical https://github.com/owner/repo URL")

    # Validate source_commit
    source_commit = document.get("source_commit")
    if not isinstance(source_commit, str) or SHA_RE.fullmatch(source_commit) is None:
        raise ProvenanceError("source_commit must be a 40-character lowercase hex SHA")

    # Validate upstream_repository if present
    if "upstream_repository" in document:
        upstream_repo = document["upstream_repository"]
        if not isinstance(upstream_repo, str) or GITHUB_REPO_RE.fullmatch(upstream_repo) is None:
            raise ProvenanceError("upstream_repository must be a canonical https://github.com/owner/repo URL")

    # Validate history_policy
    history_policy = document.get("history_policy")
    if not isinstance(history_policy, str) or history_policy not in ALLOWED_HISTORY_POLICIES:
        raise ProvenanceError(f"history_policy must be one of {sorted(ALLOWED_HISTORY_POLICIES)}, got: {history_policy!r}")

    # Validate license
    lic = document.get("license")
    if not isinstance(lic, str) or lic not in ALLOWED_LICENSES:
        raise ProvenanceError(f"license must be one of {sorted(ALLOWED_LICENSES)}, got: {lic!r}")

    # Check allowed extra fields
    allowed_fields = set(REQUIRED_BASE_FIELDS)
    allowed_fields.add("upstream_repository")
    if component in CONSUMER_COMPONENTS:
        allowed_fields.update({"protocol_repository", "protocol_source_commit"})
    if component == "camellia-remote-management-server":
        allowed_fields.add("production_database")
        prod_db = document.get("production_database")
        if not isinstance(prod_db, str) or not prod_db:
            raise ProvenanceError("production_database must be a non-empty string")

    unknown_fields = set(document.keys()) - allowed_fields
    if unknown_fields:
        raise ProvenanceError(f"unknown provenance field(s): {sorted(unknown_fields)}")

    # Protocol submodule validation for consumer components
    if component in CONSUMER_COMPONENTS:
        if "protocol_repository" not in document:
            raise ProvenanceError(f"{component} provenance must specify protocol_repository")
        if "protocol_source_commit" not in document:
            raise ProvenanceError(f"{component} provenance must specify protocol_source_commit")

        proto_repo = document["protocol_repository"]
        if not isinstance(proto_repo, str):
            raise ProvenanceError("protocol_repository must be a string")

        proto_commit = document["protocol_source_commit"]
        if not isinstance(proto_commit, str) or SHA_RE.fullmatch(proto_commit) is None:
            raise ProvenanceError("protocol_source_commit must be a 40-character lowercase hex SHA")

        if actual_protocol_repository is not None:
            sibling_name = actual_protocol_repository.removeprefix("../").removesuffix(".git")
            if (
                not actual_protocol_repository.startswith("../")
                or not actual_protocol_repository.endswith(".git")
                or SIBLING_REPO_RE.fullmatch(sibling_name) is None
                or sibling_name in {".", ".."}
            ):
                raise ProvenanceError("protocol submodule must use one portable relative sibling repository")
            if proto_repo != actual_protocol_repository:
                raise ProvenanceError(
                    f"protocol_repository mismatch: recorded={proto_repo!r}, actual={actual_protocol_repository!r}"
                )

        if actual_protocol_commit is not None:
            if SHA_RE.fullmatch(actual_protocol_commit) is None:
                raise ProvenanceError("protocol submodule does not resolve to a full Git SHA")
            if proto_commit != actual_protocol_commit:
                raise ProvenanceError(
                    f"protocol provenance mismatch: recorded={proto_commit}, actual={actual_protocol_commit}"
                )


def _run_git(root: Path, arguments: list[str]) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown Git error"
        raise ProvenanceError(f"cannot resolve protocol submodule: {detail}")
    return result.stdout.strip()


def resolve_protocol_commit(root: Path) -> str:
    submodule = root / PROTOCOL_PATH
    if (submodule / ".git").exists():
        return _run_git(submodule, ["rev-parse", "HEAD"])

    entry = _run_git(root, ["ls-tree", "HEAD", "--", PROTOCOL_PATH.as_posix()])
    fields = entry.split(maxsplit=3)
    if len(fields) != 4 or fields[0] != "160000" or fields[1] != "commit":
        raise ProvenanceError("release source does not contain the protocol Git submodule")
    return fields[2]


def resolve_protocol_repository(root: Path) -> str:
    repository = _run_git(
        root,
        ["config", "-f", ".gitmodules", "--get", PROTOCOL_SUBMODULE],
    )
    if not repository:
        raise ProvenanceError("release source does not define the protocol Git submodule")
    return repository


def default_repository_root() -> Path:
    root = Path(__file__).resolve().parent.parent
    if root.name == ".github":
        root = root.parent
    return root


def validate_repository(root: Path, *, expected_component: str | None = None) -> None:
    root = root.resolve()
    provenance_path = root / "SOURCE_PROVENANCE.json"
    try:
        document = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProvenanceError(f"cannot read SOURCE_PROVENANCE.json: {error}") from error

    actual_protocol_commit = None
    actual_protocol_repository = None
    component = document.get("component") if isinstance(document, dict) else None
    if component in CONSUMER_COMPONENTS or (root / PROTOCOL_PATH).exists():
        actual_protocol_commit = resolve_protocol_commit(root)
        actual_protocol_repository = resolve_protocol_repository(root)

    validate_document(
        document,
        expected_component=expected_component,
        actual_protocol_commit=actual_protocol_commit,
        actual_protocol_repository=actual_protocol_repository,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=default_repository_root(),
        help="repository root",
    )
    parser.add_argument(
        "--component",
        type=str,
        default=None,
        help="expected component name",
    )
    args = parser.parse_args(argv)

    try:
        validate_repository(args.root, expected_component=args.component)
    except ProvenanceError as error:
        print(f"source provenance error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
