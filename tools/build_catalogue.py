#!/usr/bin/env python3
"""Validate, package, sign, and publish the Lanius plugin catalogue."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import shutil
import sys
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASE_URL = "https://mirusu400.github.io/Lanius-plugins/"
PACKAGE_KEY_ID = "lanius-package-2026-01"
CATALOGUE_KEY_ID = "lanius-catalogue-2026-01"
PLUGIN_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


class BuildError(ValueError):
    """A source plugin or signing input is invalid."""


@dataclass(frozen=True, slots=True)
class PluginRelease:
    root: Path
    manifest: dict[str, Any]
    files: dict[str, str]

    @property
    def plugin_id(self) -> str:
        return str(self.manifest["id"])

    @property
    def version(self) -> str:
        return str(self.manifest["version"])


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BuildError(f"{label} must be an object")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BuildError(f"{label} must be a non-empty string")
    return value


def _safe_relative(value: Any, label: str) -> str:
    text = _string(value, label)
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or "\\" in text:
        raise BuildError(f"{label} must stay inside the plugin directory")
    return path.as_posix()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_files(root: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for candidate in sorted(root.rglob("*")):
        if candidate.is_symlink():
            raise BuildError(f"plugin source contains a symlink: {candidate}")
        if not candidate.is_file() or candidate.name == "plugin.json":
            continue
        relative = candidate.relative_to(root)
        # Tests and local development may generate bytecode next to the source.
        # It is never integrity-listed or copied into a release archive.
        if "__pycache__" in relative.parts or candidate.suffix == ".pyc":
            continue
        files[relative.as_posix()] = _sha256(candidate)
    return files


def _validate_release(root: Path, manifest: dict[str, Any]) -> PluginRelease:
    if manifest.get("schema") != 1:
        raise BuildError(f"{root}: manifest schema must be 1")
    if "signature" in manifest:
        raise BuildError(f"{root}: source manifests must not contain signatures")

    plugin_id = _string(manifest.get("id"), "plugin id")
    if not PLUGIN_ID.fullmatch(plugin_id) or plugin_id != root.parent.name:
        raise BuildError(f"{root}: plugin id must match its parent directory")
    version = _string(manifest.get("version"), "plugin version")
    try:
        Version(version)
    except InvalidVersion as exc:
        raise BuildError(f"{root}: invalid plugin version {version!r}") from exc
    if version != root.name:
        raise BuildError(f"{root}: plugin version must match its directory")

    _string(manifest.get("name"), "plugin name")
    _string(manifest.get("description"), "plugin description")
    _string(manifest.get("published_at"), "published_at")
    author = manifest.get("author")
    if isinstance(author, dict):
        _string(author.get("name"), "author name")
    else:
        _string(author, "author")

    categories = manifest.get("categories")
    if not isinstance(categories, list) or not categories or not all(
        isinstance(item, str) and item for item in categories
    ):
        raise BuildError(f"{root}: categories must be a non-empty string list")
    permissions = manifest.get("permissions")
    if not isinstance(permissions, list) or not all(
        isinstance(item, str) and item for item in permissions
    ):
        raise BuildError(f"{root}: permissions must be a string list")

    compatibility = _object(manifest.get("compatibility"), "compatibility")
    for key in ("lanius", "sdk"):
        specifier = _string(compatibility.get(key), f"compatibility.{key}")
        try:
            SpecifierSet(specifier)
        except InvalidSpecifier as exc:
            raise BuildError(f"{root}: invalid compatibility.{key}") from exc

    backend = _object(manifest.get("backend"), "backend")
    if backend.get("runtime", "trusted") != "trusted":
        raise BuildError(f"{root}: schema 1 only supports the trusted runtime")
    entrypoint = _safe_relative(backend.get("entrypoint"), "backend.entrypoint")
    if not entrypoint.endswith(".py"):
        raise BuildError(f"{root}: backend entrypoint must be Python")

    files = _regular_files(root)
    if entrypoint not in files:
        raise BuildError(f"{root}: backend entrypoint does not exist")
    integrity = _object(manifest.get("integrity"), "integrity")
    declared = _object(integrity.get("files"), "integrity.files")
    if declared != files:
        raise BuildError(
            f"{root}: integrity.files is stale; run tools/update_integrity.py"
        )
    if not all(isinstance(value, str) and SHA256.fullmatch(value) for value in declared.values()):
        raise BuildError(f"{root}: integrity values must be lowercase SHA-256")
    return PluginRelease(root, manifest, files)


def load_plugins(directory: Path) -> list[PluginRelease]:
    releases: list[PluginRelease] = []
    seen: set[tuple[str, str]] = set()
    for path in sorted(directory.glob("*/*/plugin.json")):
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError) as exc:
            raise BuildError(f"cannot read {path}: {exc}") from exc
        release = _validate_release(path.parent, _object(manifest, "manifest"))
        identity = (release.plugin_id, release.version)
        if identity in seen:
            raise BuildError(f"duplicate plugin release: {identity[0]} {identity[1]}")
        seen.add(identity)
        releases.append(release)
    if not releases:
        raise BuildError(f"no plugin releases found under {directory}")
    return releases


def load_revocations(path: Path, releases: list[PluginRelease]) -> list[dict[str, str]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise BuildError(f"cannot read {path}: {exc}") from exc
    entries = value.get("entries") if isinstance(value, dict) else None
    if not isinstance(entries, list):
        raise BuildError("registry/revoked.json must contain an entries list")
    known = {(release.plugin_id, release.version) for release in releases}
    result: list[dict[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise BuildError("every revocation must be an object")
        plugin_id = _string(entry.get("plugin"), "revoked plugin")
        version = _string(entry.get("version"), "revoked version")
        reason = _string(entry.get("reason"), "revocation reason")
        if (plugin_id, version) not in known:
            raise BuildError(f"revocation references unknown release: {plugin_id} {version}")
        result.append({"plugin": plugin_id, "version": version, "reason": reason})
    return result


def _private_key(variable: str) -> Ed25519PrivateKey:
    encoded = os.environ.get(variable)
    if not encoded:
        raise BuildError(f"{variable} is required for a signed build")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise BuildError(f"{variable} must be valid base64") from exc
    if len(raw) != 32:
        raise BuildError(f"{variable} must contain a raw 32-byte Ed25519 key")
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_key_base64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def verify_published_keys(
    path: Path,
    package_key: Ed25519PrivateKey,
    catalogue_key: Ed25519PrivateKey,
) -> None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise BuildError(f"cannot read {path}: {exc}") from exc
    expected = {
        "catalogue": {
            "key_id": CATALOGUE_KEY_ID,
            "public_key": public_key_base64(catalogue_key),
        },
        "packages": {PACKAGE_KEY_ID: public_key_base64(package_key)},
    }
    if value != expected:
        raise BuildError(
            "signing secrets do not match registry/public-keys.json; "
            "rotate the public keys and secrets together"
        )


def _signed(value: dict[str, Any], key: Ed25519PrivateKey, key_id: str) -> dict[str, Any]:
    result = dict(value)
    result.pop("signature", None)
    result["signature"] = {
        "algorithm": "ed25519",
        "key_id": key_id,
        "value": base64.b64encode(key.sign(canonical(result))).decode("ascii"),
    }
    return result


def _zip_entry(name: str, data: bytes) -> zipfile.ZipInfo:
    entry = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
    entry.compress_type = zipfile.ZIP_DEFLATED
    entry.external_attr = 0o100644 << 16
    entry.file_size = len(data)
    return entry


def package_release(release: PluginRelease, key: Ed25519PrivateKey) -> bytes:
    manifest = _signed(release.manifest, key, PACKAGE_KEY_ID)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        manifest_bytes = (
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        archive.writestr(_zip_entry("plugin.json", manifest_bytes), manifest_bytes)
        for relative in sorted(release.files):
            data = (release.root / relative).read_bytes()
            archive.writestr(_zip_entry(relative, data), data)
    return output.getvalue()


def _author_name(manifest: dict[str, Any]) -> str:
    author = manifest["author"]
    return str(author["name"] if isinstance(author, dict) else author)


def _prepare_output(output: Path) -> None:
    resolved = output.resolve()
    if resolved in {Path("/").resolve(), ROOT.resolve()}:
        raise BuildError(f"refusing to replace unsafe output directory: {resolved}")
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)


def build(
    releases: list[PluginRelease],
    revocations: list[dict[str, str]],
    output: Path,
    site_directory: Path,
    base_url: str,
    package_key: Ed25519PrivateKey,
    catalogue_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    _prepare_output(output)
    package_records: dict[tuple[str, str], dict[str, Any]] = {}
    for release in releases:
        archive = package_release(release, package_key)
        filename = f"{release.plugin_id}-{release.version}.lanius-plugin"
        relative = Path("packages") / release.plugin_id / release.version / filename
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(archive)
        package_records[(release.plugin_id, release.version)] = {
            "version": release.version,
            "url": relative.as_posix(),
            "sha256": hashlib.sha256(archive).hexdigest(),
            "package_key_id": PACKAGE_KEY_ID,
            "compatibility": dict(release.manifest["compatibility"]),
            "published_at": release.manifest["published_at"],
        }

    grouped: dict[str, list[PluginRelease]] = {}
    for release in releases:
        grouped.setdefault(release.plugin_id, []).append(release)
    plugins: list[dict[str, Any]] = []
    for plugin_id, versions in sorted(grouped.items()):
        versions.sort(key=lambda item: Version(item.version), reverse=True)
        latest = versions[0].manifest
        plugins.append(
            {
                "id": plugin_id,
                "name": latest["name"],
                "description": latest["description"],
                "author": _author_name(latest),
                "categories": latest["categories"],
                "releases": [
                    package_records[(item.plugin_id, item.version)] for item in versions
                ],
            }
        )

    catalogue = _signed(
        {
            "schema": 1,
            "generated_at": datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "plugins": plugins,
            "revoked": revocations,
        },
        catalogue_key,
        CATALOGUE_KEY_ID,
    )
    (output / "index.json").write_text(
        json.dumps(catalogue, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    bootstrap = {
        "schema": 1,
        "source": {
            "id": "official",
            "title": "Lanius Official Plugins",
            "url": base_url.rstrip("/") + "/index.json",
            "public_key": public_key_base64(catalogue_key),
            "key_id": CATALOGUE_KEY_ID,
            "enabled": True,
        },
        "trusted_package_keys": {
            PACKAGE_KEY_ID: public_key_base64(package_key),
        },
    }
    (output / "bootstrap.json").write_text(
        json.dumps(bootstrap, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / ".nojekyll").write_text("", encoding="utf-8")
    for candidate in site_directory.rglob("*"):
        if candidate.is_file():
            target = output / candidate.relative_to(site_directory)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(candidate, target)
    return catalogue


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate without building")
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        releases = load_plugins(ROOT / "plugins")
        revocations = load_revocations(ROOT / "registry" / "revoked.json", releases)
        if args.check:
            print(f"validated {len(releases)} plugin release(s)")
            return 0
        package_key = _private_key("LANIUS_PACKAGE_SIGNING_KEY")
        catalogue_key = _private_key("LANIUS_CATALOGUE_SIGNING_KEY")
        verify_published_keys(
            ROOT / "registry" / "public-keys.json", package_key, catalogue_key
        )
        catalogue = build(
            releases,
            revocations,
            args.output,
            ROOT / "site",
            args.base_url,
            package_key,
            catalogue_key,
        )
        print(
            f"built {len(catalogue['plugins'])} plugin(s) in {args.output.resolve()}"
        )
        return 0
    except BuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
