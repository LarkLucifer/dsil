"""Minimal smoke test for DSIL CLI wiring."""

from __future__ import annotations

import subprocess
import sys


def main() -> int:
    cmd = [sys.executable, "-m", "dsil.cli", "--help"]
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        return result.returncode
    print("DSIL smoke test: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
