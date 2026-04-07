"""
Scanner registry for DSIL tiers.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Callable, Iterable

from .base import BaseScanner

RegistryType = dict[int, list[type[BaseScanner]]]

_REGISTRY: RegistryType = defaultdict(list)


def register_scanner(tier: int) -> Callable[[type[BaseScanner]], type[BaseScanner]]:
    """
    Decorator to register a scanner class to a tier.
    """
    if tier < 0:
        raise ValueError("tier must be >= 0")

    def decorator(cls: type[BaseScanner]) -> type[BaseScanner]:
        if not issubclass(cls, BaseScanner):
            raise TypeError("registered scanner must extend BaseScanner")
        _REGISTRY[tier].append(cls)
        return cls

    return decorator


def get_scanners(tier: int) -> list[type[BaseScanner]]:
    """
    Return scanner classes for a given tier.
    """
    return list(_REGISTRY.get(tier, []))


def list_tiers() -> list[int]:
    """
    Return all tiers that have registered scanners.
    """
    return sorted(_REGISTRY.keys())
