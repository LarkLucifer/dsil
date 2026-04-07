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

        # Worker pool pattern to prevent memory explosion with millions of tasks
        queue: asyncio.Queue[tuple[type[BaseScanner], str]] = asyncio.Queue()
        for scanner_cls in scanners:
            for url in self.urls:
                queue.put_nowait((scanner_cls, url))

        results: list[Vulnerability] = []
        results_lock = asyncio.Lock()

        async def worker():
            while True:
                try:
                    try:
                        scanner_cls, url = queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break

                    try:
                        scanner = scanner_cls()
                        findings = await scanner.scan(url, self.context)
                        async with results_lock:
                            results.extend(findings)
                    except asyncio.TimeoutError:
                        logger.warning("Scanner timeout: %s on %s", scanner_cls.__name__, url)
                    except Exception:
                        logger.exception("Scanner failed: %s on %s", scanner_cls.__name__, url)
                    finally:
                        queue.task_done()
                except Exception:
                    logger.exception("Worker error")
                    break

        # Create workers up to concurrency limit
        total_tasks = len(scanners) * len(self.urls)
        worker_count = min(total_tasks, self.concurrency)
        
        workers = [
            asyncio.create_task(worker())
            for _ in range(max(1, worker_count))
        ]

        if workers:
            await asyncio.gather(*workers)
        
        return results

