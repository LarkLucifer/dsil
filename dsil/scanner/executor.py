"""
Tier executor for DSIL scanners.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Sequence

from ..core.context import ScanContext
from .base import BaseScanner, Vulnerability
from .registry import get_scanners

logger = logging.getLogger("dsil.scanner.executor")


@dataclass(slots=True)
class TierExecutor:
    """
    Executes scanners tier-by-tier in order.
    """

    context: ScanContext
    urls: Sequence[str]
    tiers: Sequence[int] = tuple(range(0, 9))
    concurrency: int = 20

    async def run(self) -> list[Vulnerability]:
        """
        Execute all tiers and aggregate findings.
        """
        findings: list[Vulnerability] = []

        for tier in sorted(self.tiers):
            scanners = get_scanners(tier)
            if not scanners:
                continue

            logger.info("Executing tier %d with %d scanners", tier, len(scanners))
            tier_findings = await self._run_tier(scanners)
            findings.extend(tier_findings)

        return findings

    async def _run_tier(self, scanners: Sequence[type[BaseScanner]]) -> list[Vulnerability]:
        if not self.urls:
            return []

        sem = asyncio.Semaphore(max(1, self.concurrency))

        async def run_one(scanner_cls: type[BaseScanner], url: str) -> list[Vulnerability]:
            async with sem:
                try:
                    scanner = scanner_cls()
                    return await scanner.scan(url, self.context)
                except asyncio.TimeoutError:
                    logger.warning("Scanner timeout: %s on %s", scanner_cls.__name__, url)
                    return []
                except Exception:
                    logger.exception("Scanner failed: %s on %s", scanner_cls.__name__, url)
                    return []

        tasks = [
            asyncio.create_task(run_one(scanner_cls, url))
            for url in self.urls
            for scanner_cls in scanners
        ]

        results = await asyncio.gather(*tasks, return_exceptions=False)

        aggregated: list[Vulnerability] = []
        for batch in results:
            aggregated.extend(batch)

        return aggregated
