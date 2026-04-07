"""
Interactsh client wrapper for DSIL OOB detection.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Mapping

import aiohttp

logger = logging.getLogger("dsil.oob.interactsh")


@dataclass(slots=True)
class InteractSession:
    correlation_id: str
    secret_key: str
    domain: str

    @property
    def oob_domain(self) -> str:
        if self.correlation_id in self.domain:
            return self.domain
        return f"{self.correlation_id}.{self.domain}".strip(".")


@dataclass(slots=True)
class Interaction:
    raw: str | Mapping[str, Any]
    protocol: str | None = None
    timestamp: str | None = None
    remote_address: str | None = None
    correlation_id: str | None = None


class InteractshClient:
    """
    Minimal Interactsh client wrapper.

    The API format varies across deployments; this implementation is designed
    to be tolerant of missing/renamed fields.
    """

    def __init__(
        self,
        base_url: str = "https://interact.sh",
        timeout: int = 10,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session_info: InteractSession | None = None

    async def register(self) -> InteractSession:
        """
        Register a new Interactsh session.
        """
        url = f"{self.base_url}/register"
        data = await self._request_json("POST", url, json={})

        correlation_id = (
            data.get("correlation_id")
            or data.get("correlation-id")
            or data.get("correlationId")
        )
        secret_key = data.get("secret_key") or data.get("secret-key") or data.get("secret")
        domain = data.get("domain") or data.get("host") or data.get("server")

        if not (correlation_id and secret_key and domain):
            raise ValueError("Interactsh register response missing required fields")

        self.session_info = InteractSession(
            correlation_id=str(correlation_id),
            secret_key=str(secret_key),
            domain=str(domain),
        )
        return self.session_info

    async def poll(
        self,
        correlation_id: str | None = None,
    ) -> list[Interaction]:
        """
        Poll for interactions. Requires a registered session.
        """
        if self.session_info is None:
            raise RuntimeError("Interactsh session not registered")

        corr_id = correlation_id or self.session_info.correlation_id
        url = f"{self.base_url}/poll"
        payload = {
            "correlation_id": corr_id,
            "secret_key": self.session_info.secret_key,
        }

        data = await self._request_json("POST", url, json=payload)
        raw_items = data.get("data") or data.get("interactions") or []

        interactions: list[Interaction] = []
        for item in raw_items:
            if isinstance(item, str):
                interactions.append(Interaction(raw=item, correlation_id=corr_id))
                continue

            if isinstance(item, dict):
                interactions.append(
                    Interaction(
                        raw=item,
                        protocol=item.get("protocol"),
                        timestamp=item.get("time") or item.get("timestamp"),
                        remote_address=item.get("remote_address") or item.get("remote"),
                        correlation_id=item.get("correlation_id") or corr_id,
                    )
                )

        return interactions

    async def _request_json(
        self,
        method: str,
        url: str,
        json: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        headers = {"User-Agent": "DSIL/0.1.0"}

        try:
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.request(method, url, json=json) as resp:
                    if resp.status >= 400:
                        raise RuntimeError(f"Interactsh request failed: {resp.status}")
                    return await resp.json()
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            raise RuntimeError("Interactsh request error") from exc
