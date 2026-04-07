"""
Scope management for DSIL crawling and scanning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence
from urllib.parse import urlparse

DEFAULT_BLOCKED_EXTENSIONS: tuple[str, ...] = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4",
    ".webm", ".mp3", ".wav", ".avi", ".mov",
)

@dataclass
class ScopeManager:
    """
    Enforces crawl scope rules.
    """

    target_url: str
    allowed_domains: Sequence[str] | None = None
    blocked_extensions: Sequence[str] = field(default_factory=lambda: DEFAULT_BLOCKED_EXTENSIONS)

    def __post_init__(self) -> None:
        # Ambil hostname dari target_url sebagai domain utama
        target_host = (urlparse(self.target_url).hostname or "").lower()
        if not target_host:
            raise ValueError("target_url must include a valid host")

        # Set daftar domain yang diperbolehkan
        if self.allowed_domains is None:
            self.actual_allowed_domains = (target_host,)
        else:
            self.actual_allowed_domains = tuple(d.lower() for d in self.allowed_domains if d)

    def is_allowed(self, url: str) -> bool:
        """
        Cek apakah URL berada dalam scope.
        """
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False

        host = (parsed.hostname or "").lower()
        if not host:
            return False

        # Cek domain
        if not self._is_domain_allowed(host):
            return False

        # Cek ekstensi file (abaikan gambar/css/video)
        path = parsed.path.lower()
        if any(path.endswith(ext) for ext in self.blocked_extensions):
            return False

        return True

    def _is_domain_allowed(self, host: str) -> bool:
        for domain in self.actual_allowed_domains:
            # Cocokkan domain utama atau sub-domainnya
            if host == domain or host.endswith("." + domain):
                return True
        return False