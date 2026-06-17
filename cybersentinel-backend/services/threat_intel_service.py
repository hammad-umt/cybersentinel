"""
services/threat_intel_service.py

Async threat intelligence integration for CyberSentinel.
This service queries AbuseIPDB, GeoIP, and VirusTotal with 24-hour database
caching so scoring endpoints can enrich IPs without repeatedly calling vendors.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import httpx
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from db.models import IPReputationCache, VirusScanCache
from schemas.threat_intel import EnrichedThreatContext, IPIntelResult, VTResult


CACHE_TTL = timedelta(hours=24)
HTTP_TIMEOUT_SECONDS = 10.0


class ThreatIntelService:
    """Fetches and caches external IP threat intelligence."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def check_ip(self, ip: str) -> IPIntelResult:
        """Query AbuseIPDB and GeoIP for an IP address, using a 24-hour cache."""
        cached = await self._get_fresh_ip_cache(ip)
        if cached is not None:
            return self._ip_result_from_cache(cached, cached=True)

        provider_status: Dict[str, str] = {}
        raw: Dict[str, Any] = {}
        abuse_data: Dict[str, Any] = {}
        geo_data: Dict[str, Any] = {}

        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            if settings.abuseipdb_configured:
                try:
                    response = await client.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        headers={
                            "Key": settings.ABUSEIPDB_API_KEY,
                            "Accept": "application/json",
                        },
                        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                    )
                    response.raise_for_status()
                    abuse_payload = response.json()
                    abuse_data = abuse_payload.get("data", {})
                    raw["abuseipdb"] = abuse_payload
                    provider_status["abuseipdb"] = "ok"
                except Exception as exc:
                    provider_status["abuseipdb"] = "error"
                    logger.warning("AbuseIPDB lookup failed for {}: {}", ip, exc)
            else:
                provider_status["abuseipdb"] = "skipped_missing_api_key"

            try:
                geo_url = f"{settings.GEOIP_BASE_URL.rstrip('/')}/{ip}"
                response = await client.get(geo_url)
                response.raise_for_status()
                geo_data = response.json()
                raw["geoip"] = geo_data
                provider_status["geoip"] = "ok" if geo_data.get("status") != "fail" else "unavailable"
            except Exception as exc:
                provider_status["geoip"] = "error"
                logger.warning("GeoIP lookup failed for {}: {}", ip, exc)

        raw["provider_status"] = provider_status
        score = _ip_intel_score(abuse_data)
        now = _now_utc()
        cache = await self._upsert_ip_cache(ip, abuse_data, geo_data, raw, score, now)
        result = self._ip_result_from_cache(cache, cached=False)
        result.provider_status = provider_status
        return result

    async def check_virustotal(self, ip: str) -> VTResult:
        """Query VirusTotal's IP report endpoint, using a 24-hour cache."""
        cached = await self._get_fresh_vt_cache(ip)
        if cached is not None:
            return self._vt_result_from_cache(cached, cached=True, provider_status="ok")

        now = _now_utc()
        if not settings.virustotal_configured:
            return VTResult(
                ip=ip,
                provider_status="skipped_missing_api_key",
                scanned_at=now,
            )

        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
                response = await client.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                )
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:
            logger.warning("VirusTotal lookup failed for {}: {}", ip, exc)
            return VTResult(ip=ip, provider_status="error", scanned_at=now)

        stats = (
            payload.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        total = malicious + suspicious + harmless + undetected
        score = _vt_score(malicious, suspicious, total)
        threat_level = _threat_level(score)

        cache = await self._upsert_vt_cache(
            ip=ip,
            threat_level=threat_level,
            malicious_count=malicious,
            suspicious_count=suspicious,
            total_engines=total,
            threat_score=score,
            raw=payload,
            scanned_at=now,
        )
        result = self._vt_result_from_cache(cache, cached=False, provider_status="ok")
        result.harmless_count = harmless
        result.undetected_count = undetected
        return result

    async def enrich(self, ip: str) -> EnrichedThreatContext:
        """Return combined AbuseIPDB, GeoIP, and VirusTotal context."""
        ip_result = await self.check_ip(ip)
        vt_result = await self.check_virustotal(ip)
        intel_score = round(max(ip_result.threat_score, vt_result.threat_score), 2)
        notes = [
            f"{provider}:{status}"
            for provider, status in ip_result.provider_status.items()
            if status.startswith("skipped") or status == "error"
        ]
        if vt_result.provider_status.startswith("skipped") or vt_result.provider_status == "error":
            notes.append(f"virustotal:{vt_result.provider_status}")

        return EnrichedThreatContext(
            ip=ip,
            ip_reputation=ip_result,
            virustotal=vt_result,
            intel_threat_score=intel_score,
            provider_notes=notes,
            timestamp=_now_utc(),
        )

    async def _get_fresh_ip_cache(self, ip: str) -> IPReputationCache | None:
        row = (await self.db.execute(
            select(IPReputationCache).where(IPReputationCache.ip_address == ip)
        )).scalar_one_or_none()
        if row and _is_fresh(row.looked_up_at):
            return row
        return None

    async def _get_fresh_vt_cache(self, ip: str) -> VirusScanCache | None:
        row = (await self.db.execute(
            select(VirusScanCache).where(VirusScanCache.lookup_key == ip)
        )).scalar_one_or_none()
        if row and _is_fresh(row.scanned_at):
            return row
        return None

    async def _upsert_ip_cache(
        self,
        ip: str,
        abuse_data: Dict[str, Any],
        geo_data: Dict[str, Any],
        raw: Dict[str, Any],
        threat_score: float,
        looked_up_at: str,
    ) -> IPReputationCache:
        row = (await self.db.execute(
            select(IPReputationCache).where(IPReputationCache.ip_address == ip)
        )).scalar_one_or_none()
        if row is None:
            row = IPReputationCache(ip_address=ip)
            self.db.add(row)

        row.looked_up_at = looked_up_at
        row.abuse_confidence_score = _optional_int(abuse_data.get("abuseConfidenceScore"))
        row.total_reports = _optional_int(abuse_data.get("totalReports"))
        row.is_whitelisted = bool(abuse_data.get("isWhitelisted") or False)
        row.isp = abuse_data.get("isp") or geo_data.get("isp")
        row.usage_type = abuse_data.get("usageType")
        row.country_code = geo_data.get("countryCode") or abuse_data.get("countryCode")
        row.country_name = geo_data.get("country")
        row.city = geo_data.get("city")
        row.latitude = _optional_float(geo_data.get("lat"))
        row.longitude = _optional_float(geo_data.get("lon"))
        row.threat_score = threat_score
        row.raw_result_json = json.dumps(raw)
        await self.db.flush()
        await self.db.refresh(row)
        return row

    async def _upsert_vt_cache(
        self,
        ip: str,
        threat_level: str,
        malicious_count: int,
        suspicious_count: int,
        total_engines: int,
        threat_score: float,
        raw: Dict[str, Any],
        scanned_at: str,
    ) -> VirusScanCache:
        row = (await self.db.execute(
            select(VirusScanCache).where(VirusScanCache.lookup_key == ip)
        )).scalar_one_or_none()
        if row is None:
            row = VirusScanCache(lookup_key=ip, scan_type="ip")
            self.db.add(row)

        row.scan_type = "ip"
        row.scanned_at = scanned_at
        row.threat_level = threat_level
        row.malicious_count = malicious_count
        row.suspicious_count = suspicious_count
        row.total_engines = total_engines
        row.threat_score = threat_score
        row.raw_result_json = json.dumps(raw)
        await self.db.flush()
        await self.db.refresh(row)
        return row

    def _ip_result_from_cache(self, row: IPReputationCache, cached: bool) -> IPIntelResult:
        raw = _loads(row.raw_result_json)
        return IPIntelResult(
            ip=row.ip_address,
            provider_status=raw.get("provider_status", {"cache": "hit" if cached else "refreshed"}),
            abuse_confidence_score=row.abuse_confidence_score,
            total_reports=row.total_reports,
            is_whitelisted=row.is_whitelisted,
            isp=row.isp,
            usage_type=row.usage_type,
            country_code=row.country_code,
            country_name=row.country_name,
            city=row.city,
            latitude=row.latitude,
            longitude=row.longitude,
            threat_score=round(row.threat_score or 0.0, 2),
            cached=cached,
            looked_up_at=row.looked_up_at,
            raw=raw,
        )

    def _vt_result_from_cache(
        self,
        row: VirusScanCache,
        cached: bool,
        provider_status: str,
    ) -> VTResult:
        raw = _loads(row.raw_result_json)
        stats = raw.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return VTResult(
            ip=row.lookup_key,
            provider_status=provider_status,
            threat_level=row.threat_level,
            malicious_count=row.malicious_count,
            suspicious_count=row.suspicious_count,
            harmless_count=int(stats.get("harmless", 0) or 0),
            undetected_count=int(stats.get("undetected", 0) or 0),
            total_engines=row.total_engines,
            threat_score=round(row.threat_score or 0.0, 2),
            cached=cached,
            scanned_at=row.scanned_at,
            raw=raw,
        )


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_fresh(timestamp: str | None) -> bool:
    if not timestamp:
        return False
    try:
        looked_up = datetime.fromisoformat(timestamp)
        if looked_up.tzinfo is None:
            looked_up = looked_up.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - looked_up < CACHE_TTL
    except ValueError:
        return False


def _ip_intel_score(abuse_data: Dict[str, Any]) -> float:
    score = float(abuse_data.get("abuseConfidenceScore") or 0.0)
    if abuse_data.get("isWhitelisted"):
        score = min(score, 10.0)
    return round(max(0.0, min(score, 100.0)), 2)


def _vt_score(malicious: int, suspicious: int, total: int) -> float:
    if total <= 0:
        return 0.0
    weighted = ((malicious * 1.0) + (suspicious * 0.5)) / total
    return round(max(0.0, min(weighted * 100.0, 100.0)), 2)


def _threat_level(score: float) -> str:
    if score >= 60:
        return "malicious"
    if score >= 25:
        return "suspicious"
    return "clean"


def _optional_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _optional_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _loads(raw: str | None) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        loaded = json.loads(raw)
        return loaded if isinstance(loaded, dict) else {}
    except json.JSONDecodeError:
        return {}
