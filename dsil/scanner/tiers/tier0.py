"""
Tier 0 scanners: low-impact, high-signal checks.
"""

from __future__ import annotations

import asyncio
import aiohttp

from ..base import BaseScanner, Vulnerability
from ..registry import register_scanner
from ...core.context import ScanContext
from ...core.evasion import HeaderFactory

REQUIRED_HEADERS = (
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
)


@register_scanner(0)
class BasicHeadersScanner(BaseScanner):
    """
    Checks for common missing security headers.
    """

    id = "HDR-001"
    name = "Missing Security Headers"
    severity = "low"

    async def scan(self, url: str, context: ScanContext) -> list[Vulnerability]:
        timeout = aiohttp.ClientTimeout(total=10)
        headers = HeaderFactory.get_headers()

        try:
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.get(url, allow_redirects=True) as resp:
                    context.record_status(resp.status)
                    missing = [h for h in REQUIRED_HEADERS if h not in resp.headers]
                    if not missing:
                        return []

                    # If X-Frame-Options missing, check for sensitive forms
                    severity = self.severity
                    if "X-Frame-Options" in missing:
                        try:
                            text = await resp.text()
                            lowered = text.lower()
                            if "<form" in lowered or "type=\"password\"" in lowered:
                                severity = "medium"
                        except Exception:
                            pass

                    evidence = {
                        "status": resp.status,
                        "missing_headers": missing,
                    }
                    return [
                        Vulnerability(
                            id=self.id,
                            name=self.name,
                            severity=severity,
                            url=url,
                            evidence=evidence,
                            confidence=0.5,
                            verified=False,
                        )
                    ]
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return []
