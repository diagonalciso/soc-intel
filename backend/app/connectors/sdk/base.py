"""
Connector SDK base class.
All connectors inherit from BaseConnector and implement run().
"""
import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


@dataclass
class ConnectorConfig:
    name: str
    display_name: str
    connector_type: str  # import_external, enrichment, stream, export
    description: str = ""
    schedule: str = "0 */6 * * *"  # every 6 hours by default
    config: dict = field(default_factory=dict)
    # Source trust: 0-100, applied to indicator confidence at ingest.
    # 95 = official govt/authoritative, 80 = vetted community, 65 = open community.
    source_reliability: int = 80
    # Default TLP for objects from this connector (overridden per-object if set).
    default_tlp: str = "TLP:CLEAR"


@dataclass
class IngestResult:
    objects_created: int = 0
    objects_updated: int = 0
    errors: int = 0
    messages: list[str] = field(default_factory=list)


class BaseConnector(ABC):
    def __init__(self, config: ConnectorConfig):
        self.config = config
        self.logger = logging.getLogger(f"connector.{config.name}")
        self._http: httpx.AsyncClient | None = None

    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
        return self._http

    @property
    def tor_http(self) -> httpx.AsyncClient:
        """HTTP client routed through Tor for dark web requests."""
        proxies = {"http://": settings.tor_proxy, "https://": settings.tor_proxy}
        return httpx.AsyncClient(
            timeout=60.0,
            follow_redirects=True,
            proxies=proxies,
            verify=False,
        )

    @abstractmethod
    async def run(self) -> IngestResult:
        """Main connector logic. Must return IngestResult."""
        ...

    async def push_to_platform(self, objects: list[dict]) -> IngestResult:
        """Send STIX objects to the platform's bulk ingest endpoint."""
        if not objects:
            return IngestResult()

        # Stamp source reliability and default TLP onto each object if not set
        for obj in objects:
            if "x_clawint_source_reliability" not in obj:
                obj["x_clawint_source_reliability"] = self.config.source_reliability
            if "x_clawint_tlp" not in obj:
                obj["x_clawint_tlp"] = self.config.default_tlp

        api_url = "http://api:8000"
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                # Use internal service account API key (set via env)
                headers = {"Authorization": f"Bearer {settings.connector_api_key}"}
                response = await client.post(
                    f"{api_url}/api/intel/bulk",
                    json=objects,
                    headers=headers,
                )
                if response.status_code == 200:
                    data = response.json()
                    return IngestResult(
                        objects_created=data.get("indexed", 0),
                        errors=data.get("errors", 0),
                    )
        except Exception as e:
            self.logger.error(f"Failed to push objects: {e}")
            return IngestResult(errors=len(objects))

        return IngestResult()

    async def close(self):
        if self._http:
            await self._http.aclose()
            self._http = None
