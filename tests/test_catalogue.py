from __future__ import annotations

import base64
import json
from pathlib import Path

from app.plugin_catalogue import CatalogueSource, verify_catalogue
from app.plugin_packages import PluginPackageManager
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools import build_catalogue

ROOT = Path(__file__).resolve().parents[1]


def test_source_manifests_and_signed_build_are_accepted_by_lanius(tmp_path) -> None:
    releases = build_catalogue.load_plugins(ROOT / "plugins")
    revoked = build_catalogue.load_revocations(
        ROOT / "registry" / "revoked.json", releases
    )
    package_key = Ed25519PrivateKey.generate()
    catalogue_key = Ed25519PrivateKey.generate()
    output = tmp_path / "site"
    catalogue = build_catalogue.build(
        releases,
        revoked,
        output,
        ROOT / "site",
        build_catalogue.DEFAULT_BASE_URL,
        package_key,
        catalogue_key,
    )

    source = CatalogueSource(
        id="official",
        title="Lanius Official Plugins",
        url=build_catalogue.DEFAULT_BASE_URL + "index.json",
        public_key=build_catalogue.public_key_base64(catalogue_key),
        key_id=build_catalogue.CATALOGUE_KEY_ID,
    )
    verified = verify_catalogue(catalogue, source)
    assert {plugin["id"] for plugin in verified["plugins"]} == {
        "lanius.request-randomizer",
        "lanius.security-headers",
    }

    trusted = tmp_path / "trusted.json"
    trusted.write_text(
        json.dumps(
            {
                build_catalogue.PACKAGE_KEY_ID: build_catalogue.public_key_base64(
                    package_key
                )
            }
        ),
        encoding="utf-8",
    )
    packages = PluginPackageManager(
        tmp_path / "installed", trusted_keys_path=trusted
    )
    for plugin in verified["plugins"]:
        release = plugin["releases"][0]
        archive = (output / release["url"]).read_bytes()
        installed = packages.install(
            archive,
            allow_unsigned=False,
            expected_id=plugin["id"],
            expected_version=release["version"],
            expected_key_id=build_catalogue.PACKAGE_KEY_ID,
        )
        assert installed["trust"] == "trusted"


def test_signed_archives_are_reproducible() -> None:
    release = build_catalogue.load_plugins(ROOT / "plugins")[0]
    raw = bytes(range(32))
    key = Ed25519PrivateKey.from_private_bytes(raw)
    first = build_catalogue.package_release(release, key)
    second = build_catalogue.package_release(release, key)
    assert first == second
    assert base64.b64decode(build_catalogue.public_key_base64(key), validate=True)

