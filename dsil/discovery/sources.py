import asyncio
import json
import logging
from pathlib import Path
from urllib.parse import urljoin, urlparse
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
        """
        Fetch URLs using Katana with a fallback mechanism for robustness.
        """
        # Baseline flags that are most likely to work across versions
        base_cmd = ["katana", "-u", self.target, "-j", "-silent", "-nc"]
        # Advanced flags that might cause Code 2 if dependencies (headless) are missing
        advanced_flags = ["-jc", "-kf", "-d", "3"]
        
        cmd = base_cmd + advanced_flags

        logger.info("KatanaSource: starting scan for %s", self.target)
        try:
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
            except FileNotFoundError:
                logger.error("Katana binary not found in PATH.")
                return []

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                err_out = stderr.decode().strip()
                logger.warning("Katana advanced scan failed (code %d): %s", process.returncode, err_out)
                
                # Code 2 often means flag error or missing headless browser
                if process.returncode == 2 or "headless" in err_out.lower():
                    logger.info("KatanaSource: retrying with safe base flags...")
                    process = await asyncio.create_subprocess_exec(
                        *base_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await process.communicate()
                    if process.returncode != 0:
                        logger.error("Katana base scan also failed (code %d): %s", process.returncode, stderr.decode())
                        return []
                else:
                    return []

            raw_urls = []
            for line in stdout.decode().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if isinstance(data, dict):
                        endpoint = data.get("request", {}).get("endpoint") or data.get("url", "")
                        if endpoint:
                            raw_urls.append(endpoint)
                    elif isinstance(data, str):
                        raw_urls.append(data)
                except json.JSONDecodeError:
                    if line.startswith("http"):
                        raw_urls.append(line)

            # --- SMART FILTERING ---
            excluded_extensions = {
                ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
                ".css", ".js", ".woff", ".woff2", ".ttf", ".otf",
                ".pdf", ".docx", ".xlsx", ".csv", ".mp4", ".avi", ".mov", ".wmv",
                ".zip", ".tar.gz", ".tgz", ".rar", ".7z"
            }
            
            filtered_urls = []
            priority_urls = []

            for url in set(raw_urls):
                parsed = urlparse(url) if 'urlparse' in globals() else None
                # Fallback if urlparse not imported (it's imported in this file now? let me check)
                # Wait, I didn't see urlparse imported in sources.py, let me check the imports.
                # Lines 1-7: from urllib.parse import urljoin
                # I should add urlparse to the imports.
                
                ext = Path(url.split("?")[0]).suffix.lower()
                if ext in excluded_extensions:
                    continue
                
                if "?" in url:
                    priority_urls.append(url)
                else:
                    filtered_urls.append(url)

            # Combine priority first, then others
            final_urls = priority_urls + filtered_urls
            
            logger.info(
                "KatanaSource: discovered %d endpoints (%d prioritized, %d total filtered)", 
                len(raw_urls), len(priority_urls), len(final_urls)
            )
            return final_urls
        except Exception as e:
            logger.exception("KatanaSource unexpected error")
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
