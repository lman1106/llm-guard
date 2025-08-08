from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional
import httpx


@dataclass
class FactCheckResult:
    status: str  # one of: confirmed, contradicted, unknown, error
    sources: List[str]
    error: Optional[str] = None


class FactChecker:
    def __init__(self, url: Optional[str], api_key: Optional[str]) -> None:
        self.url = url
        self.api_key = api_key

    async def check(self, text: str) -> FactCheckResult:
        if not self.url:
            return FactCheckResult(status="unknown", sources=[])
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(self.url, json={"text": text}, headers=headers)
                if resp.status_code != 200:
                    return FactCheckResult(status="error", sources=[], error=f"status={resp.status_code}")
                data = resp.json()
                status = data.get("status", "unknown")
                sources = data.get("sources", [])
                return FactCheckResult(status=status, sources=sources)
        except Exception as exc:  # noqa: BLE001
            return FactCheckResult(status="error", sources=[], error=str(exc))


def classify_risk_domain(text: str, high_risk_domains: List[str]) -> str:
    lower = text.lower()
    for domain in high_risk_domains:
        if domain.lower() in lower:
            return "high"
    return "low"