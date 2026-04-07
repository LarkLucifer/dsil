"""
Verification rules for DSIL.
"""

from __future__ import annotations

import asyncio
from typing import Any, Mapping

import aiohttp

from ..scanner.base import Vulnerability


async def verify_missing_headers(
    url: str,
    missing_headers: list[str],
    timeout: int = 10,
) -> tuple[bool, Mapping[str, Any]]:
    """
    Re-check missing headers with a second request.
    """
    headers = {"User-Agent": "DSIL/0.1.0"}
    client_timeout = aiohttp.ClientTimeout(total=timeout)

    try:
        async with aiohttp.ClientSession(timeout=client_timeout, headers=headers) as session:
            async with session.get(url, allow_redirects=True) as resp:
                still_missing = [h for h in missing_headers if h not in resp.headers]
                evidence = {
                    "status": resp.status,
                    "missing_headers": still_missing,
                }
                return (len(still_missing) == len(missing_headers), evidence)
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return (False, {"error": "verification_request_failed"})


def classify_rule(finding: Vulnerability) -> str:
    """
    Return the rule key for a given finding.
    """
    if finding.id == "HDR-001":
        return "missing_headers"
    return "generic"
