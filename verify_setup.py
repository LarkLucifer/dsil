"""Verify pyproject.toml is valid TOML."""

from __future__ import annotations

import sys
from pathlib import Path


def load_toml(text: str) -> dict:
    try:
        import tomllib  # py3.11+

        return tomllib.loads(text)
    except ModuleNotFoundError:
        import tomli

        return tomli.loads(text)


def main() -> int:
    path = Path(__file__).parent / "pyproject.toml"
    data = path.read_bytes()

    if data.startswith(b"\xef\xbb\xbf"):
        print("ERROR: UTF-8 BOM detected in pyproject.toml", file=sys.stderr)
        return 2

    text = data.decode("utf-8")
    try:
        obj = load_toml(text)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: TOML parse failed: {exc}", file=sys.stderr)
        return 1

    if "project" not in obj:
        print("ERROR: Missing [project] table", file=sys.stderr)
        return 3

    print("OK: pyproject.toml parsed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
