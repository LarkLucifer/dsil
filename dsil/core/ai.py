"""
AI agent interface for DSIL.

Implements a basic OpenAI Responses API client for Phase 1 integration.
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Mapping, Sequence, TYPE_CHECKING

import aiohttp

from .prompts import (
    VULN_ASSESSOR_SYSTEM,
    PAYLOAD_GENERATOR_SYSTEM,
    EXEC_SUMMARY_SYSTEM,
    REMEDIATION_PLANNER_SYSTEM,
    CVSS_CALCULATOR_SYSTEM,
)

if TYPE_CHECKING:
    from .context import ScanContext


class AgentInterface(ABC):
    """
    Base class for AI agent integrations.

    Implementations can override these methods to provide intelligent
    crawling, payload generation, false-positive assessment, and summaries.
    """

    @abstractmethod
    async def score_url(self, url: str, context: "ScanContext") -> float:
        """
        Return a priority score for a discovered URL.

        Higher score means higher priority for crawling or scanning.
        """
        raise NotImplementedError

    @abstractmethod
    async def generate_payloads(
        self,
        category: str,
        context: "ScanContext",
        hints: Mapping[str, Any] | None = None,
    ) -> Sequence[str]:
        """
        Generate payloads for a given category (e.g., XSS, SSRF).
        """
        raise NotImplementedError

    @abstractmethod
    async def fp_assess(
        self,
        finding: Mapping[str, Any],
        context: "ScanContext",
    ) -> Mapping[str, Any]:
        """
        Assess a potential false positive and return updated evidence.
        """
        raise NotImplementedError

    @abstractmethod
    async def summarize(
        self,
        report: Mapping[str, Any],
        context: "ScanContext",
    ) -> str:
        """
        Summarize a report into a concise human-readable overview.
        """
        raise NotImplementedError

    @abstractmethod
    async def smart_summarize(
        self,
        findings: Sequence[Mapping[str, Any]],
        context: "ScanContext",
    ) -> str:
        """
        Produce a 3-sentence executive summary for verified findings.
        """
        raise NotImplementedError

    @abstractmethod
    async def remediation_plan(
        self,
        finding: Mapping[str, Any],
        context: "ScanContext",
    ) -> str:
        """
        Provide concrete remediation guidance for a finding.
        """
        raise NotImplementedError

    @abstractmethod
    async def calculate_cvss(
        self,
        finding: Mapping[str, Any],
        context: "ScanContext",
    ) -> Mapping[str, Any]:
        """
        Calculate CVSS v3.1 vector and base score.
        """
        raise NotImplementedError


@dataclass(slots=True)
class OpenAIAgent(AgentInterface):
    """
    Minimal OpenAI Responses API implementation.
    """

    api_key: str
    model: str = "gpt-4.1"
    base_url: str = "https://api.openai.com/v1/responses"
    timeout: int = 20

    @classmethod
    def from_env(cls) -> "OpenAIAgent":
        api_key = os.getenv("OPENAI_API_KEY") or os.getenv("DSIL_OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY or DSIL_OPENAI_API_KEY is required")
        model = os.getenv("DSIL_OPENAI_MODEL", "gpt-4.1")
        return cls(api_key=api_key, model=model)

    async def score_url(self, url: str, context: "ScanContext") -> float:
        # Simple heuristic for Phase 1: prioritize shorter URLs.
        return 1.0 if len(url) < 120 else 0.5

    async def generate_payloads(
        self,
        category: str,
        context: "ScanContext",
        hints: Mapping[str, Any] | None = None,
    ) -> Sequence[str]:
        prompt = {
            "category": category,
            "hints": hints or {},
        }
        text = await self._call_model(
            system=PAYLOAD_GENERATOR_SYSTEM,
            user=json.dumps(prompt, ensure_ascii=True),
        )
        return self._parse_json_array(text)

    async def fp_assess(
        self,
        finding: Mapping[str, Any],
        context: "ScanContext",
    ) -> Mapping[str, Any]:
        text = await self._call_model(
            system=VULN_ASSESSOR_SYSTEM,
            user=json.dumps(finding, ensure_ascii=True),
        )
        return self._parse_json_object(text)

    async def summarize(
        self,
        report: Mapping[str, Any],
        context: "ScanContext",
    ) -> str:
        text = await self._call_model(
            system="Summarize this security report in 5 bullet points.",
            user=json.dumps(report, ensure_ascii=True),
        )
        return text.strip()

    async def smart_summarize(
        self,
        findings: Sequence[Mapping[str, Any]],
        context: "ScanContext",
    ) -> str:
        text = await self._call_model(
            system=EXEC_SUMMARY_SYSTEM,
            user=json.dumps({"findings": list(findings)}, ensure_ascii=True),
        )
        return text.strip()

    async def remediation_plan(
        self,
        finding: Mapping[str, Any],
        context: "ScanContext",
    ) -> str:
        text = await self._call_model(
            system=REMEDIATION_PLANNER_SYSTEM,
            user=json.dumps(finding, ensure_ascii=True),
        )
        return text.strip()

    async def calculate_cvss(
        self,
        finding: Mapping[str, Any],
        context: "ScanContext",
    ) -> Mapping[str, Any]:
        text = await self._call_model(
            system=CVSS_CALCULATOR_SYSTEM,
            user=json.dumps(finding, ensure_ascii=True),
        )
        return self._parse_json_object(text)

    async def _call_model(self, system: str, user: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "input": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }

        timeout = aiohttp.ClientTimeout(total=self.timeout)
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.post(self.base_url, json=payload) as resp:
                if resp.status >= 400:
                    text = await resp.text()
                    raise RuntimeError(f"OpenAI API error {resp.status}: {text}")
                data = await resp.json()

        return self._extract_text(data)

    def _extract_text(self, data: Mapping[str, Any]) -> str:
        if isinstance(data, dict) and "output_text" in data:
            return str(data["output_text"])

        output = data.get("output", []) if isinstance(data, dict) else []
        chunks: list[str] = []
        for item in output:
            content = item.get("content", []) if isinstance(item, dict) else []
            for part in content:
                if isinstance(part, dict) and part.get("type") in {"output_text", "text"}:
                    text = part.get("text")
                    if text:
                        chunks.append(str(text))
        return "\n".join(chunks).strip()

    def _parse_json_object(self, text: str) -> Mapping[str, Any]:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"verdict": "Unclear", "confidence": 0.3, "rationale": text.strip()}

    def _parse_json_array(self, text: str) -> Sequence[str]:
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return [str(x) for x in data]
        except json.JSONDecodeError:
            pass
        return []
