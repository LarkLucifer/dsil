"""
Pipeline orchestration for DSIL.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable
from urllib.parse import urlparse

import aiohttp

from .context import ScanContext
from .scope import ScopeManager
from .evasion import HeaderFactory, random_delay
from ..discovery.crawler import AsyncCrawler
from ..discovery.dedup import DedupStore
from ..discovery.sources import fetch_robots_txt, fetch_sitemap_urls, KatanaSource
from ..discovery.subdomains import SubfinderSource
from ..scanner.executor import TierExecutor
from ..scanner.base import Vulnerability
from ..scanner.tiers import tier0, tier1, tier2, tier3, tier4, tier5  # noqa: F401
from ..verify.engine import VerificationEngine
from ..oob.interactsh import InteractshClient, InteractSession, Interaction
from ..report.schemas import Report, FindingRecord
from ..report.render import ReportRenderer
from ..sast.analyzers import JSStaticAnalyzer

logger = logging.getLogger("dsil.pipeline")

StageFn = Callable[[], Awaitable[None]]


class Pipeline:
    """
    Orchestrates the strict 6-step DSIL pipeline.

    Stages:
        1) Discovery
        2) Dedup
        3) Tiers
        4) Verify
        5) OOB
        6) Report
    """

    def __init__(self, context: ScanContext) -> None:
        self.context = context
        self.scope = ScopeManager(context.target)
        self.dedup = DedupStore()
        self.discovered_urls: list[str] = []
        self.findings: list[Vulnerability] = []
        self.oob_client: InteractshClient | None = None
        self.oob_session: InteractSession | None = None
        self.started_at: datetime | None = None
        self.finished_at: datetime | None = None
        self.report_paths: tuple[str, str, str, str] | None = None

    async def run(self) -> None:
        """
        Run the pipeline in strict order.
        """
        self.started_at = datetime.now(timezone.utc)

        await self._run_stage("Discovery", self._discovery)
        await self._run_stage("Dedup", self._dedup)
        await self._run_stage("SAST", self._sast)
        await self._run_stage("Tiers", self._tiers)
        await self._run_stage("Verify", self._verify)
        await self._run_stage("OOB", self._oob)
        await self._run_stage("Report", self._report)

        self.finished_at = datetime.now(timezone.utc)

    async def _run_stage(self, name: str, func: StageFn) -> None:
        logger.info("Stage start: %s", name)
        await func()
        logger.info("Stage end: %s", name)

    async def _discovery(self) -> None:
        logger.debug("Discovery: target=%s", self.context.target)

        # Step 1.1: Subdomain Recon (Subfinder)
        subfinder = SubfinderSource(self.context.target)
        discovered_subdomains = await subfinder.fetch_subdomains()
        
        # Ensure all discovered subdomains are in scope
        for sub in discovered_subdomains:
            self.scope.add_to_scope(f"http://{sub}")
            self.scope.add_to_scope(f"https://{sub}")

        timeout = aiohttp.ClientTimeout(total=20)
        headers = HeaderFactory.get_headers()

        sitemap_urls = []
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            await self._check_circuit_breaker()
            robots_txt = await fetch_robots_txt(session, self.context.target)
            await random_delay()
            
            await self._check_circuit_breaker()
            sitemap_urls = await fetch_sitemap_urls(
                session, self.context.target, robots_txt=robots_txt
            )
            await random_delay()

        # Step 1.2: Katana Modern Crawling (on all subdomains)
        katana_targets = list(set([self.context.target] + [f"https://{s}" for s in discovered_subdomains]))
        katana_urls = []
        
        logger.info("Discovery: running Katana on %d targets", len(katana_targets))
        
        # Run Katana with limited concurrency to avoid overwhelming the system
        sem = asyncio.Semaphore(3)
        
        async def run_katana(target: str):
            async with sem:
                k = KatanaSource(target)
                return await k.fetch_urls()

        tasks = [run_katana(t) for t in katana_targets]
        results_list = await asyncio.gather(*tasks)
        for r in results_list:
            katana_urls.extend(r)
        
        seeds = list(set([self.context.target, *sitemap_urls, *katana_urls]))

        crawler = AsyncCrawler(
            context=self.context,
            scope=self.scope,
            dedup=self.dedup,
            max_pages=self.context.max_pages,
            concurrency=self.context.concurrency,
        )
        results = await crawler.crawl(seeds)
        self.discovered_urls = [r.url for r in results]

        logger.info(
            "Discovery complete: fetched=%d unique=%d (Subfinder found %d subdomains, Katana found %d total URLs)",
            len(results),
            self.dedup.count,
            len(discovered_subdomains),
            len(katana_urls),
        )

    async def _check_circuit_breaker(self) -> None:
        """
        Implements the 60-second Global Cooldown if 5+ consecutive errors occurred.
        """
        if self.context.is_cooling_down:
            return

        if self.context.consecutive_errors >= 5:
            logger.warning("CIRCUIT BREAKER TRIGGERED: Global Cooldown for 60s")
            self.context.is_cooling_down = True
            await asyncio.sleep(60)
            self.context.consecutive_errors = 0
            self.context.is_cooling_down = False
            logger.info("CIRCUIT BREAKER: Cooldown finished, resuming...")

    async def _dedup(self) -> None:
        logger.debug("Dedup: unique_urls=%d", self.dedup.count)
        await asyncio.sleep(0)

    async def _sast(self) -> None:
        logger.debug("SAST: scanning JS assets")

        js_urls = [u for u in self.discovered_urls if u.lower().endswith(".js")]
        if not js_urls:
            logger.info("SAST: no JS assets discovered")
            return

        analyzer = JSStaticAnalyzer(self.context)
        findings = await analyzer.analyze(js_urls)
        if findings:
            self.findings.extend(findings)
            logger.info("SAST findings: %d", len(findings))

    async def _ensure_oob_session(self) -> None:
        if self.oob_client is None:
            self.oob_client = InteractshClient()

        if self.oob_session is None:
            try:
                self.oob_session = await self.oob_client.register()
                self.context.oob_session = self.oob_session
                logger.info("OOB domain: %s", self.oob_session.oob_domain)
            except Exception:
                logger.debug("OOB registration failed", exc_info=True)

    async def _tiers(self) -> None:
        logger.debug("Tiers: executing tiered scanners")

        await self._ensure_oob_session()

        executor = TierExecutor(
            context=self.context,
            urls=self.discovered_urls,
            concurrency=self.context.concurrency,
        )
        tier_findings = await executor.run()
        self.findings.extend(tier_findings)

        logger.info("Tier scanning complete: findings=%d", len(tier_findings))

    async def _verify(self) -> None:
        logger.debug("Verify: false-positive verification")

        if not self.findings:
            logger.info("Verify: no findings to verify")
            return

        engine = VerificationEngine(self.context)
        self.findings = await engine.verify(self.findings)

        verified_count = sum(1 for f in self.findings if f.verified)
        logger.info("Verify complete: verified=%d total=%d", verified_count, len(self.findings))

    async def _oob(self) -> None:
        logger.debug("OOB: out-of-band correlation")

        await self._ensure_oob_session()
        if self.oob_client is None:
            return

        interactions: list[Interaction] = []
        for attempt in range(3):
            try:
                batch = await self.oob_client.poll()
                interactions.extend(batch)
                if batch:
                    logger.info("OOB interactions detected: %d", len(batch))
                    break
            except Exception:
                logger.debug("OOB polling failed", exc_info=True)

            if attempt < 2:
                await asyncio.sleep(20)

        if not interactions:
            logger.info("OOB interactions: none")
            return

        self._apply_oob_matches(interactions)

    def _apply_oob_matches(self, interactions: list[Interaction]) -> None:
        tokens = self._extract_oob_tokens()
        if not tokens:
            return

        raw_texts: list[str] = []
        for item in interactions:
            if isinstance(item.raw, str):
                raw_texts.append(item.raw)
            elif isinstance(item.raw, dict):
                raw_texts.append(str(item.raw))

        matched = 0
        for i, finding in enumerate(self.findings):
            if not isinstance(finding.evidence, dict):
                continue
            token = finding.evidence.get("oob_token")
            if not token:
                continue

            if any(token in text for text in raw_texts):
                self.findings[i] = replace(
                    finding,
                    verified=True,
                    confidence=max(0.9, finding.confidence),
                )
                matched += 1

        if matched:
            logger.info("OOB matches applied: %d", matched)

    def _extract_oob_tokens(self) -> set[str]:
        tokens: set[str] = set()
        for finding in self.findings:
            if isinstance(finding.evidence, dict) and "oob_token" in finding.evidence:
                token = str(finding.evidence.get("oob_token"))
                if token:
                    tokens.add(token)
        return tokens

    async def _report(self) -> None:
        logger.debug("Report: generating artifacts")

        finished_at = self.finished_at or datetime.now(timezone.utc)
        started_at = self.started_at or finished_at
        duration = (finished_at - started_at).total_seconds()

        verified_findings = [f for f in self.findings if f.verified]
        executive_summary: str | None = None

        if self.context.agent is not None and verified_findings:
            try:
                summary_payload = [
                    {
                        "id": f.id,
                        "name": f.name,
                        "severity": f.severity,
                        "url": f.url,
                        "confidence": f.confidence,
                    }
                    for f in verified_findings
                ]
                executive_summary = await self.context.agent.smart_summarize(
                    summary_payload, self.context
                )
            except Exception:
                logger.debug("AI summary failed", exc_info=True)

        finding_records: list[FindingRecord] = []
        for f in verified_findings:
            remediation: str | None = None
            cvss_vector: str | None = None
            cvss_score: float | None = None

            if self.context.agent is not None:
                try:
                    remediation = await self.context.agent.remediation_plan(
                        {
                            "id": f.id,
                            "name": f.name,
                            "severity": f.severity,
                            "url": f.url,
                            "evidence": f.evidence,
                        },
                        self.context,
                    )
                except Exception:
                    logger.debug("AI remediation failed", exc_info=True)

                try:
                    cvss = await self.context.agent.calculate_cvss(
                        {
                            "id": f.id,
                            "name": f.name,
                            "severity": f.severity,
                            "url": f.url,
                            "evidence": f.evidence,
                        },
                        self.context,
                    )
                    cvss_vector = str(cvss.get("vector")) if cvss.get("vector") else None
                    score_val = cvss.get("score")
                    if isinstance(score_val, (int, float)):
                        cvss_score = float(score_val)
                except Exception:
                    logger.debug("AI CVSS failed", exc_info=True)

            finding_records.append(
                FindingRecord.from_vuln(
                    f,
                    remediation=remediation,
                    cvss_vector=cvss_vector,
                    cvss_score=cvss_score,
                )
            )

        # Aggregate findings by (id, domain)
        aggregated: dict[tuple[str, str], FindingRecord] = {}
        for rec in finding_records:
            domain = urlparse(rec.url).hostname or ""
            key = (rec.id, domain)
            if key not in aggregated:
                aggregated[key] = rec
                if isinstance(rec.evidence, dict):
                    aggregated[key].evidence = {
                        "urls": [rec.url],
                        "evidence": rec.evidence,
                    }
                continue

            existing = aggregated[key]
            if isinstance(existing.evidence, dict):
                urls = existing.evidence.get("urls", [])
                if rec.url not in urls:
                    urls.append(rec.url)
                existing.evidence["urls"] = urls

        report = Report(
            target=self.context.target,
            mode=self.context.mode,
            started_at=started_at.isoformat(),
            finished_at=finished_at.isoformat(),
            duration_seconds=duration,
            executive_summary=executive_summary,
            verified_findings=list(aggregated.values()),
        )

        renderer = ReportRenderer(report)
        out_dir = Path.cwd() / "reports"
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        json_path, md_path, html_path, h1_path = renderer.write_reports(
            out_dir, stem=f"report-{stamp}"
        )
        self.report_paths = (str(json_path), str(md_path), str(html_path), str(h1_path))


async def run_pipeline(context: ScanContext) -> "Pipeline":
    """
    Convenience function to run the pipeline.
    """
    pipeline = Pipeline(context)
    await pipeline.run()
    return pipeline
