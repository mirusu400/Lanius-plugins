#!/usr/bin/env python3
"""Print an apply-ready summary of integrity changes for source manifests."""

from __future__ import annotations

import json
from pathlib import Path

from build_catalogue import ROOT, _regular_files


def main() -> None:
    changed = 0
    for path in sorted((ROOT / "plugins").glob("*/*/plugin.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        files = _regular_files(path.parent)
        if manifest.get("integrity", {}).get("files") == files:
            continue
        manifest["integrity"] = {"files": files}
        path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(path.relative_to(ROOT))
        changed += 1
    print(f"updated {changed} manifest(s)")


if __name__ == "__main__":
    main()

