"""
Runtime context for DSIL scans.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Literal, Optional, TYPE_CHECKING

from .ai import AgentInterface

if TYPE_CHECKING:
    from ..oob.interactsh import InteractSession

ScanMode = Literal["poc", "scan", "sast"]
ScanProfile = Literal["local", "vps"]

@dataclass(slots=True)
class ScanContext:
    """
    Shared scan context passed through the DSIL pipeline.

    Attributes:
        target: Target URL or scope root for the scan.
        mode: Execution mode ("poc", "scan", or "sast").
        profile: Execution profile ("local" or "vps").
        verbosity: Verbosity level (0 = quiet, higher = more verbose).
        agent: Optional AI agent integration.
        oob_session: Optional OOB session (e.g., Interactsh).
    """

    target: str
    mode: ScanMode
    profile: ScanProfile = "local"
    verbosity: int = 0
    agent: Optional[AgentInterface] = None
    oob_session: Optional["InteractSession"] = None

    # Configuration limits for resource management
    max_pages: Optional[int] = None
    concurrency: Optional[int] = None

    # Circuit Breaker tracking
    consecutive_errors: int = 0
    last_error_time: float = 0.0
    is_cooling_down: bool = False

    def __post_init__(self) -> None:
        """
        Initialize defaults based on profile if not explicitly provided.
        """
        if self.max_pages is None:
            self.max_pages = 200 if self.profile == "local" else 2000
        
        if self.concurrency is None:
            self.concurrency = 10 if self.profile == "local" else 50

    def record_status(self, status: int) -> None:
        """
        Record HTTP status code for circuit breaker.
        """
        if status in (403, 429):
            self.consecutive_errors += 1
            self.last_error_time = time.time()
        else:
            self.consecutive_errors = 0

    @property
    def url_mem_cap(self) -> int:
        """
        Returns the URL memory cap based on the profile.
        """
        return 100_000 if self.profile == "local" else 1_000_000
