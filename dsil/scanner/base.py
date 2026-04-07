"""
Scanner base types for DSIL.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Mapping, Literal

from ..core.context import ScanContext

Severity = Literal["info", "low", "medium", "high", "critical"]


@dataclass(slots=True)
class Vulnerability:
    """
    Standard vulnerability/finding record.
    """

    id: str
    name: str
    severity: Severity
    url: str
    evidence: Mapping[str, Any] | str
    confidence: float = 0.5
    verified: bool = False
    cvss_vector: str | None = None
    cvss_score: float | None = None


class BaseScanner(ABC):
    """
    Base class for all scanners.
    """

    id: str
    name: str
    severity: Severity

    @abstractmethod
    async def scan(self, url: str, context: ScanContext) -> list[Vulnerability]:
        """
        Scan a URL and return a list of findings.
        """
        raise NotImplementedError

    def _vuln(
        self,
        url: str,
        evidence: Mapping[str, Any] | str,
        *,
        confidence: float = 0.5,
        verified: bool = False,
    ) -> Vulnerability:
        return Vulnerability(
            id=self.id,
            name=self.name,
            severity=self.severity,
            url=url,
            evidence=evidence,
            confidence=confidence,
            verified=verified,
        )
