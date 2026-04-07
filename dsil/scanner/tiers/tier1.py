"""
Tier 1 scanners: standard web vulnerability checks (XSS, SSRF).
"""

from __future__ import annotations

import asyncio
import aiohttp
from typing import Sequence

from ..base import BaseScanner, Vulnerability
from ..registry import register_scanner
from ...core.context import ScanContext
from ...core.evasion import HeaderFactory


@register_scanner(1)
class ReflectedXSSScanner(BaseScanner):
    """
    Checks for reflected XSS in URL parameters.
    """

    id = "XSS-001"
    name = "Reflected Cross-Site Scripting (XSS)"
    severity = "medium"

    payloads = [
        "<script>alert(1)</script>",
        "\"-alert(1)-\"",
        "<img src=x onerror=alert(1)>",
    ]

    async def scan(self, url: str, context: ScanContext) -> list[Vulnerability]:
        if "?" not in url:
            return []

        findings = []
        headers = HeaderFactory.get_headers()
        timeout = aiohttp.ClientTimeout(total=10)

        # Basic reflected check for each payload
        for payload in self.payloads:
            # Simple heuristic: inject into all parameters (pseudo-code)
            # In real tool, use a proper URL parser and inject into each param
            injected_url = f"{url}&dsil_xss={payload}" 
            
            try:
                async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                    async with session.get(injected_url) as resp:
                        context.record_status(resp.status)
                        if resp.status == 200:
                            text = await resp.text()
                            if payload in text:
                                findings.append(self._vuln(
                                    url=url,
                                    evidence={"payload": payload, "reflected": True},
                                    confidence=0.8
                                ))
                                break # Found one, move on
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
        
        return findings


@register_scanner(1)
class BlindSSRFScanner(BaseScanner):
    """
    Checks for SSRF using Out-of-Band (OOB) techniques.
    """

    id = "SSRF-001"
    name = "Blind Server-Side Request Forgery (SSRF)"
    severity = "high"

    async def scan(self, url: str, context: ScanContext) -> list[Vulnerability]:
        if not context.oob_session:
            return []

        # Generate a unique interaction URL
        interact_url = context.oob_session.get_url()
        injected_url = f"{url}&url=http://{interact_url}"

        headers = HeaderFactory.get_headers()
        timeout = aiohttp.ClientTimeout(total=10)

        try:
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.get(injected_url) as resp:
                    context.record_status(resp.status)
                    # We don't check for reflection here, we wait for OOB callback
                    # Usually OOB checks are async, but for DSIL we might poll later
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
            
        return [] # Findings will be populated via OOB polling in the pipeline
