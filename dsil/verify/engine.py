"""
False-positive verification engine for DSIL.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Any, Mapping

from ..core.context import ScanContext
from ..scanner.base import Vulnerability
from . import rules

logger = logging.getLogger("dsil.verify.engine")


class VerificationEngine:
    """
    Verifies findings by re-checking evidence and optionally using an AI agent.
    """

    def __init__(self, context: ScanContext) -> None:
        self.context = context

    async def verify(self, findings: list[Vulnerability]) -> list[Vulnerability]:
        """
        Verify a list of findings and return updated results.
        """
        verified: list[Vulnerability] = []

        for finding in findings:
            updated = await self._verify_one(finding)
            verified.append(updated)

        return verified

    async def _verify_one(self, finding: Vulnerability) -> Vulnerability:
        rule = rules.classify_rule(finding)

        verified = False
        new_evidence: Mapping[str, Any] | str = finding.evidence
        confidence = finding.confidence

        if rule == "missing_headers":
            missing = []
            if isinstance(finding.evidence, dict):
                missing = list(finding.evidence.get("missing_headers", []))

            ok, evidence = await rules.verify_missing_headers(
                finding.url, missing_headers=missing
            )
            verified = ok
            new_evidence = evidence
            confidence = 0.8 if ok else 0.2
        else:
            confidence = max(confidence, 0.4)

        updated = replace(
            finding,
            evidence=new_evidence,
            confidence=confidence,
            verified=verified,
        )

        if self.context.agent is not None:
            try:
                agent_input = {
                    "id": updated.id,
                    "name": updated.name,
                    "severity": updated.severity,
                    "url": updated.url,
                    "evidence": updated.evidence,
                    "verified": updated.verified,
                    "confidence": updated.confidence,
                }
                agent_out = await self.context.agent.fp_assess(agent_input, self.context)
                updated = self._apply_agent_feedback(updated, agent_out)
            except Exception:
                logger.debug("AI agent verification failed", exc_info=True)

        return updated

    def _apply_agent_feedback(
        self, finding: Vulnerability, agent_out: Mapping[str, Any]
    ) -> Vulnerability:
        confidence = agent_out.get("confidence", finding.confidence)
        severity = agent_out.get("severity", finding.severity)
        evidence = agent_out.get("evidence", finding.evidence)

        verdict = str(agent_out.get("verdict", "")).lower()
        verified = finding.verified
        if verdict in {"real", "true", "valid"}:
            verified = True
        elif verdict in {"false positive", "false", "invalid"}:
            verified = False

        return replace(
            finding,
            confidence=confidence,
            severity=severity,
            verified=verified,
            evidence=evidence,
        )
