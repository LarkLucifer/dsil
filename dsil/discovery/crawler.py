"""
Asynchronous crawler for DSIL discovery.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Sequence
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from ..core.context import ScanContext
from ..core.scope import ScopeManager
from ..core.evasion import HeaderFactory, random_delay
from .dedup import DedupStore

logger = logging.getLogger("dsil.discovery.crawler")


@dataclass(slots=True)
class CrawlResult:
    url: str
    status: int | None
    content_type: str | None


class AsyncCrawler:
    """
    Async crawler that discovers in-scope links.
    """

    def __init__(
        self,
        context: ScanContext,
        scope: ScopeManager,
        dedup: DedupStore,
        *,
        concurrency: int = 10,
        max_pages: int = 200,
        request_timeout: int = 10,
    ) -> None:
        self.context = context
        self.scope = scope
        self.dedup = dedup
        self.concurrency = max(1, concurrency)
        self.max_pages = max_pages
        self.request_timeout = request_timeout
        self._counter_lock = asyncio.Lock()
        self._fetched_count = 0

    async def crawl(self, seeds: Sequence[str]) -> list[CrawlResult]:
        """
        Crawl starting from seed URLs.
        """
        queue: asyncio.Queue[str] = asyncio.Queue()
        results: list[CrawlResult] = []

        for seed in seeds:
            await self._enqueue_if_valid(queue, seed)

        timeout = aiohttp.ClientTimeout(total=self.request_timeout)
        headers = {"User-Agent": "DSIL/0.1.0"}

        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            workers = [
                asyncio.create_task(self._worker(queue, session, results))
                for _ in range(self.concurrency)
            ]

            await queue.join()

            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

        return results

    async def _worker(
        self,
        queue: asyncio.Queue[str],
        session: aiohttp.ClientSession,
        results: list[CrawlResult],
    ) -> None:
        while True:
            url = await queue.get()
            try:
                if await self._max_reached():
                    continue

                result, html = await self._fetch(session, url)
                results.append(result)

                if not html:
                    continue

                for link in self._extract_links(html, url):
                    await self._enqueue_if_valid(queue, link)
            finally:
                queue.task_done()

    async def _max_reached(self) -> bool:
        async with self._counter_lock:
            if self._fetched_count >= self.max_pages:
                return True
            self._fetched_count += 1
            return False

    async def _fetch(
        self, session: aiohttp.ClientSession, url: str
    ) -> tuple[CrawlResult, str | None]:
        try:
            # True rotation: generate headers per request
            headers = HeaderFactory.get_headers()
            await random_delay()
            
            async with session.get(url, allow_redirects=True, headers=headers) as resp:
                self.context.record_status(resp.status)
                
                content_type = resp.headers.get("Content-Type", "")
                status = resp.status

                if "text/html" not in content_type and "application/xhtml" not in content_type:
                    return (CrawlResult(url=url, status=status, content_type=content_type), None)

                text = await resp.text()
                return (CrawlResult(url=url, status=status, content_type=content_type), text)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            logger.debug("Fetch failed: %s", url, exc_info=True)
            return (CrawlResult(url=url, status=None, content_type=None), None)

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        soup = BeautifulSoup(html, "html.parser")
        links: list[str] = []

        for tag in soup.find_all("a", href=True):
            href = (tag.get("href") or "").strip()
            if not href:
                continue

            if href.startswith("mailto:") or href.startswith("javascript:"):
                continue

            absolute = urljoin(base_url, href)
            links.append(absolute)

        return links

    async def _enqueue_if_valid(self, queue: asyncio.Queue[str], url: str) -> None:
        # Prevent memory exhaustion by capping total discovered URLs
        if self.dedup.count >= self.context.url_mem_cap:
            return

        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"}:
            return

        if not self.scope.is_allowed(url):
            return

        if self.context.agent is not None:
            try:
                score = await self.context.agent.score_url(url, self.context)
                if score <= 0.0:
                    return
            except Exception:
                logger.debug("Agent scoring failed for %s", url, exc_info=True)

        added = await self.dedup.add(url)
        if not added:
            return

        await queue.put(url)
