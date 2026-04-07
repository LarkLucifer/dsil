"""
Tier 3 scanners: Smart reflection checks.
"""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import aiohttp

from ..base import BaseScanner, Vulnerability
from ..registry import register_scanner
from ...core.context import ScanContext


@register_scanner(3)
class SmartReflectionScanner(BaseScanner):
    """
    Injects a canary into query parameters and checks for raw reflection.
    """

    id = "REFLECT-001"
    name = "Unencoded Reflection"
    severity = "low"

    async def scan(self, url: str, context: ScanContext) -> list[Vulnerability]:
        canary = "dsilxss7a1"
        probe_url = self._with_canary(url, canary)

        timeout = aiohttp.ClientTimeout(total=10)
        headers = {"User-Agent": "DSIL/0.1.0"}

        try:
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.get(probe_url, allow_redirects=True) as resp:
                    text = await resp.text()

            if self._is_raw_reflected(text, canary):
                evidence = {
                    "canary": canary,
                    "url": probe_url,
                    "raw_reflection": True,
                }
                return [self._vuln(url, evidence)]
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return []

        return []

    def _with_canary(self, url: str, canary: str) -> str:
        parts = urlsplit(url)
        query = parse_qsl(parts.query, keep_blank_values=True)
        if not query:
            query = [("q", canary)]
        else:
            query = [(k, f"{v}{canary}") for k, v in query]
        new_query = urlencode(query, doseq=True)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))

    def _is_raw_reflected(self, text: str, canary: str) -> bool:
        if canary not in text:
            return False
        idx = text.find(canary)
        if idx == -1:
            return False
        window = text[max(0, idx - 20) : idx + len(canary) + 20]
        return ("<" in window) or (">" in window)
