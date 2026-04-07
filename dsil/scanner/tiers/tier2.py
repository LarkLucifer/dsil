"""
Tier 2 scanners: Prototype Pollution checks.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

import aiohttp

from ..base import BaseScanner, Vulnerability
from ..registry import register_scanner
from ...core.context import ScanContext


@register_scanner(2)
class PrototypePollutionScanner(BaseScanner):
    """
    Basic reflection-based prototype pollution check.

    This is a lightweight heuristic that looks for reflection of __proto__ keys.
    """

    id = "PP-001"
    name = "Prototype Pollution Reflection"
    severity = "medium"

    async def scan(self, url: str, context: ScanContext) -> list[Vulnerability]:
        token = "dsilpp"
        probe_key = "__proto__[dsil]"

        probed_url = self._with_param(url, probe_key, token)
        timeout = aiohttp.ClientTimeout(total=10)
        headers = {"User-Agent": "DSIL/0.1.0"}

        try:
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.get(probed_url, allow_redirects=True) as resp:
                    text = await resp.text()

            if token in text or "__proto__" in text:
                evidence = {
                    "probe": probe_key,
                    "token": token,
                    "reflected": True,
                    "url": probed_url,
                }
                return [self._vuln(url, evidence)]
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return []

        return []

    def _with_param(self, url: str, key: str, value: str) -> str:
        parts = urlsplit(url)
        query = parse_qsl(parts.query, keep_blank_values=True)
        query.append((key, value))
        new_query = urlencode(query, doseq=True)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
