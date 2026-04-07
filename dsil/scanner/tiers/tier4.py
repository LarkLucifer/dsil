"""
Tier 4 scanners: Parameter sensitivity discovery.
"""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qsl, urlsplit

from ..base import BaseScanner, Vulnerability
from ..registry import register_scanner
from ...core.context import ScanContext

SENSITIVE_KEYS = {
    "redirect",
    "url",
    "file",
    "path",
    "dest",
    "proxy",
    "document",
    "callback",
    "api",
}


@register_scanner(4)
class ParameterSensitivityScanner(BaseScanner):
    """
    Flags URLs containing high-impact parameter names.
    """

    id = "PARAM-001"
    name = "Potential High-Impact Entry Point"
    severity = "medium"

    async def scan(self, url: str, context: ScanContext) -> list[Vulnerability]:
        parts = urlsplit(url)
        if not parts.query:
            return []

        params = parse_qsl(parts.query, keep_blank_values=True)
        hits = [k for k, _ in params if k.lower() in SENSITIVE_KEYS]
        if not hits:
            return []

        evidence = {
            "matched_params": sorted(set(hits)),
            "url": url,
        }
        return [self._vuln(url, evidence)]
