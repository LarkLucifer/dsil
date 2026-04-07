import asyncio
import json
import logging
from urllib.parse import urljoin
import xml.etree.ElementTree as ET

import aiohttp

logger = logging.getLogger("dsil.discovery.sources")


class KatanaSource:
    """
    Integrasi Katana untuk crawling JS-heavy targets.
    """

    def __init__(self, target: str):
        self.target = target

    async def fetch_urls(self) -> list[str]:
        # Menjalankan katana dengan subprocess
        cmd = [
            "katana",
            "-u",
            self.target,
            "-jc",
            "-kf",
            "-d",
            "3",
            "-j",
            "-silent",
            "-nc",
        ]

        logger.info("KatanaSource: starting scan for %s", self.target)
        try:
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
            except FileNotFoundError:
                logger.error("Katana not found. Ensure it is installed via 'go install' or apt.")
                return []

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.error("Katana failed (code %d): %s", process.returncode, stderr.decode())
                return []

            urls = []
            for line in stdout.decode().splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    endpoint = data.get("request", {}).get("endpoint", "")
                    if endpoint:
                        urls.append(endpoint)
                except json.JSONDecodeError:
                    continue

            logger.info("KatanaSource: discovered %d endpoints", len(urls))
            return list(set(urls))
        except Exception as e:
            logger.error("KatanaSource error: %s", e)
            return []


async def _fetch_text(
    session: aiohttp.ClientSession,
    url: str,
    timeout: int = 10,
) -> str | None:
    try:
        async with session.get(url, timeout=timeout) as resp:
            if resp.status >= 400:
                logger.debug("Fetch failed: %s status=%s", url, resp.status)
                return None
            return await resp.text()
    except (aiohttp.ClientError, asyncio.TimeoutError):
        logger.debug("Fetch error: %s", url, exc_info=True)
        return None


async def fetch_robots_txt(
    session: aiohttp.ClientSession,
    base_url: str,
    timeout: int = 10,
) -> str | None:
    """
    Fetch robots.txt for a base URL.
    """
    robots_url = urljoin(base_url, "/robots.txt")
    return await _fetch_text(session, robots_url, timeout=timeout)


def _extract_sitemap_urls_from_robots(robots_txt: str) -> list[str]:
    urls: list[str] = []
    for line in robots_txt.splitlines():
        if line.lower().startswith("sitemap:"):
            value = line.split(":", 1)[1].strip()
            if value:
                urls.append(value)
    return urls


def _parse_sitemap(xml_text: str) -> tuple[list[str], bool]:
    """
    Parse sitemap XML. Returns (locs, is_index).
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return ([], False)

    tag = root.tag.lower()
    is_index = tag.endswith("sitemapindex")

    locs = [
        (elem.text or "").strip()
        for elem in root.findall(".//{*}loc")
        if (elem.text or "").strip()
    ]

    return (locs, is_index)


async def fetch_sitemap_urls(
    session: aiohttp.ClientSession,
    base_url: str,
    robots_txt: str | None = None,
    timeout: int = 10,
) -> list[str]:
    """
    Fetch and parse sitemap URLs.
    """
    sitemap_urls = []

    if robots_txt:
        sitemap_urls = _extract_sitemap_urls_from_robots(robots_txt)

    if not sitemap_urls:
        sitemap_urls = [urljoin(base_url, "/sitemap.xml")]

    discovered: list[str] = []
    visited: set[str] = set()

    for sitemap_url in sitemap_urls:
        if sitemap_url in visited:
            continue
        visited.add(sitemap_url)

        xml_text = await _fetch_text(session, sitemap_url, timeout=timeout)
        if not xml_text:
            continue

        locs, is_index = _parse_sitemap(xml_text)
        if not locs:
            continue

        if is_index:
            for child_url in locs:
                if child_url in visited:
                    continue
                visited.add(child_url)
                child_xml = await _fetch_text(session, child_url, timeout=timeout)
                if not child_xml:
                    continue
                child_locs, _ = _parse_sitemap(child_xml)
                discovered.extend(child_locs)
        else:
            discovered.extend(locs)

    return discovered


class PassiveSource:
    """
    Integrasi sumber pasif untuk bug bounty (WaybackUrls, GAU, Subfinder).
    """

    def __init__(self, target: str):
        self.target = target

    async def fetch_urls(self) -> list[str]:
        # Placeholder untuk integrasi alat bantu eksternal
        # Di dunia nyata, kita akan memanggil 'subfinder -d target.com -silent' dsb.
        logger.info("PassiveSource: fetching passive URLs for %s", self.target)
        # Mocking passive data for now
        return []
