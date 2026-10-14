#!/usr/bin/env python3
"""Copy registries.json from a checkout of the spec repository into this package.

Usage: python tools/sync_registries.py ../spec
"""

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "src" / "burgee" / "data" / "registries.json"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    src = Path(sys.argv[1]) / "registries" / "registries.json"
    if not src.exists():
        print(f"not found: {src}", file=sys.stderr)
        return 1
    data = json.loads(src.read_text(encoding="utf-8"))
    shutil.copyfile(src, DEST)
    print(f"copied registries {data['version']} to {DEST.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
