"""
SAST analyzers for DSIL.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Iterable, Sequence

import aiohttp

from ..core.context import ScanContext
from ..scanner.base import Vulnerability

logger = logging.getLogger("dsil.sast.analyzers")


SENSITIVE_PATTERNS: list[tuple[str, str]] = [
    ("API Key", r"(?i)api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{16,}['\"]?"),
    ("Secret Token", r"(?i)secret\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{16,}['\"]?"),
    ("Firebase URL", r"https?://[a-z0-9-]+\.firebaseio\.com"),
    ("Cloudinary Key", r"cloudinary\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{16,}['\"]?"),
]


@dataclass(slots=True)
class JSStaticAnalyzer:
    """
    Simple JS static analyzer using regex heuristics.
    """

    context: ScanContext
    concurrency: int = 8
    timeout: int = 10

    async def analyze(self, js_urls: Sequence[str]) -> list[Vulnerability]:
        if not js_urls:
            return []

        sem = asyncio.Semaphore(max(1, self.concurrency))
        findings: list[Vulnerability] = []

        async def scan_one(url: str) -> list[Vulnerability]:
            async with sem:
                return await self._scan_url(url)

        tasks = [asyncio.create_task(scan_one(u)) for u in js_urls]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        for batch in results:
            findings.extend(batch)

        return findings

    async def _scan_url(self, url: str) -> list[Vulnerability]:
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        headers = {"User-Agent": "DSIL/0.1.0"}

        try:
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.get(url, allow_redirects=True) as resp:
                    if resp.status >= 400:
                        return []
                    text = await resp.text()
        except (aiohttp.ClientError, asyncio.TimeoutError):
            logger.debug("SAST fetch failed: %s", url, exc_info=True)
            return []

        findings: list[Vulnerability] = []
        for name, pattern in SENSITIVE_PATTERNS:
            match = re.search(pattern, text)
            if not match:
                continue
            evidence = {
                "pattern": name,
                "match": match.group(0)[:200],
            }
            findings.append(
                Vulnerability(
                    id="SAST-JS-001",
                    name=f"Potential {name} in JS",
                    severity="medium",
                    url=url,
                    evidence=evidence,
                    confidence=0.4,
                    verified=False,
                )
            )

        return findings
