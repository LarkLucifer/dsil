"""
Report schemas for DSIL.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Mapping

from ..scanner.base import Vulnerability


@dataclass(slots=True)
class FindingRecord:
    id: str
    name: str
    severity: str
    url: str
    evidence: Mapping[str, Any] | str
    confidence: float
    verified: bool
    remediation: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None

    @classmethod
    def from_vuln(
        cls,
        v: Vulnerability,
        remediation: str | None = None,
        cvss_vector: str | None = None,
        cvss_score: float | None = None,
    ) -> "FindingRecord":
        return cls(
            id=v.id,
            name=v.name,
            severity=v.severity,
            url=v.url,
            evidence=v.evidence,
            confidence=v.confidence,
            verified=v.verified,
            remediation=remediation,
            cvss_vector=cvss_vector or v.cvss_vector,
            cvss_score=cvss_score if cvss_score is not None else v.cvss_score,
        )


@dataclass(slots=True)
class Report:
    target: str
    mode: str
    started_at: str
    finished_at: str
    duration_seconds: float
    executive_summary: str | None
    verified_findings: list[FindingRecord]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
