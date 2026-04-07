"""
Check that tiers 0-3 and SAST analyzer are registered and importable.
"""

from __future__ import annotations

from dsil.scanner import registry as registry
from dsil.sast.analyzers import JSStaticAnalyzer

# Ensure tier modules are imported to register scanners
from dsil.scanner.tiers import tier0, tier1, tier2, tier3  # noqa: F401


def main() -> int:
    # Alias internal registry for audit output
    SCANNER_REGISTRY = registry._REGISTRY  # noqa: N806

    for tier in range(0, 4):
        scanners = SCANNER_REGISTRY.get(tier, [])
        names = [cls.__name__ for cls in scanners]
        print(f"Tier {tier}: {', '.join(names) if names else 'NONE'}")

    # Ensure SAST analyzer class is importable
    _ = JSStaticAnalyzer  # noqa: F841
    print("SAST: JSStaticAnalyzer importable")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
