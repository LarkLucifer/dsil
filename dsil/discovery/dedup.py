"""
Deduplication store for discovered URLs.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


@dataclass(slots=True)
class DedupStore:
    """
    Tracks and normalizes URLs to avoid redundant crawling.
    """

    _seen: set[str] = field(default_factory=set)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @staticmethod
    def canonicalize(url: str) -> str:
        """
        Normalize a URL by:
          - Lowercasing scheme/host
          - Removing fragments
          - Sorting query parameters
          - Normalizing empty paths to '/'
        """
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        netloc = parts.netloc.lower()

        # Strip default ports
        if netloc.endswith(":80") and scheme == "http":
            netloc = netloc[:-3]
        elif netloc.endswith(":443") and scheme == "https":
            netloc = netloc[:-4]

        path = parts.path or "/"

        query_pairs = parse_qsl(parts.query, keep_blank_values=True)
        query_pairs.sort()
        query = urlencode(query_pairs, doseq=True)

        return urlunsplit((scheme, netloc, path, query, ""))

    async def add(self, url: str) -> bool:
        """
        Add a URL to the store if unseen. Returns True if added.
        """
        normalized = self.canonicalize(url)
        async with self._lock:
            if normalized in self._seen:
                return False
            self._seen.add(normalized)
        return True

    async def is_seen(self, url: str) -> bool:
        """
        Check if a URL has already been seen.
        """
        normalized = self.canonicalize(url)
        async with self._lock:
            return normalized in self._seen

    @property
    def count(self) -> int:
        return len(self._seen)
