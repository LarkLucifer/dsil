"""
Tier 5 scanner: Nuclei Orchestrator.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

from ..base import BaseScanner, Vulnerability
from ..registry import register_scanner
from ...core.context import ScanContext

logger = logging.getLogger("dsil.scanner.nuclei")

@register_scanner(5)
class NucleiOrchestrator(BaseScanner):
    """
    Orchestrates professional-grade scanning using Nuclei.
    """

    id = "NUC-001"
    name = "Nuclei Scan"
    severity = "info"

    async def scan(self, url: str, context: ScanContext) -> list[Vulnerability]:
        # Use a specific template set: tags=cve,exposed-panel,misconfig
        cmd = [
            "nuclei",
            "-target", url,
            "-tags", "cve,exposed-panel,misconfig",
            "-severity", "medium,high,critical",
            "-jsonl",
            "-silent",
            "-nc",
        ]

        logger.info("NucleiOrchestrator: scanning %s", url)
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                # Nuclei sometimes returns non-zero error codes for minor issues
                # but we should log it if it's a real failure
                err_octets = stderr.decode().strip()
                if err_octets:
                    logger.debug("Nuclei non-zero return: %s", err_octets)

            findings: list[Vulnerability] = []
            for line in stdout.decode().splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    
                    # Map Nuclei fields to DSIL Vulnerability
                    info = data.get("info", {})
                    vuln = Vulnerability(
                        id=f"NUC-{data.get('template-id', 'unknown')}",
                        name=info.get("name", "Nuclei finding"),
                        severity=info.get("severity", "info").lower(),
                        url=data.get("matched-at", url),
                        evidence={
                            "template_id": data.get("template-id"),
                            "description": info.get("description"),
                            "matcher_name": data.get("matcher-name"),
                            "full_info": data
                        },
                        confidence=0.9 if data.get("matcher-status") else 0.7,
                        verified=True if info.get("severity") in ["high", "critical"] else False
                    )
                    findings.append(vuln)
                except json.JSONDecodeError:
                    continue

            if findings:
                logger.info("NucleiOrchestrator: found %d vulnerabilities on %s", len(findings), url)
            return findings
            
        except Exception as e:
            logger.error("NucleiOrchestrator error: %s", e)
            return []
