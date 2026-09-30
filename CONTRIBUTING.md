# Contributing

Every published version is immutable. Add a new version directory instead of
editing or removing an existing release.

1. Copy the latest `plugins/<plugin-id>/<version>/` directory to a new version.
2. Update `plugin.json` and the implementation.
3. Run `python tools/update_integrity.py`.
4. Run `python tools/build_catalogue.py --check` and `pytest` with the Lanius
   engine directory on `PYTHONPATH`.
5. Open a pull request describing behavior, permissions, and security impact.

Plugins must not perform hidden network requests, collect telemetry, or bundle
compiled bytecode. Any product-owned outbound path must document how it is
enforced by Lanius Lockdown Mode before it can be accepted.

