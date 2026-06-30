"""
services/threat_intel_service.py

Async threat intelligence integration for CyberSentinel.
This service queries AbuseIPDB, GeoIP, and VirusTotal with 24-hour database
caching so scoring endpoints can enrich IPs without repeatedly calling vendors.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Literal

import httpx
from loguru import logger
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from db.models import IPReputationCache, VirusScanCache
from schemas.threat_intel import EnrichedThreatContext, IPIntelResult, VTResult, _normalize_scan_url


CACHE_TTL = timedelta(hours=24)
HTTP_TIMEOUT_SECONDS = 12.0
FILE_UPLOAD_TIMEOUT_SECONDS = 120.0
MAX_HTTP_ATTEMPTS = 2
RETRY_BACKOFF_SECONDS = (0.25, 0.75)
VT_BASE_URL = "https://www.virustotal.com/api/v3"
URL_POLL_ATTEMPTS = 15
URL_POLL_INTERVAL_SECONDS = 2.0
FILE_POLL_ATTEMPTS = 50
FILE_POLL_INTERVAL_SECONDS = 3.0


class ThreatIntelService:
    """Fetches and caches external IP threat intelligence."""

    def __init__(self, db: AsyncSession, user_id: str):
        self.db = db
        self.user_id = user_id

    async def check_ip(self, ip: str) -> IPIntelResult:
        """Query AbuseIPDB and GeoIP for an IP address, using a 24-hour cache."""
        cached = await self._get_fresh_ip_cache(ip)
        if cached is not None:
            return self._ip_result_from_cache(cached, cached=True)

        provider_status: Dict[str, str] = {}
        raw: Dict[str, Any] = {}

        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            abuse_task = self._fetch_abuseipdb(client, ip)
            geo_task = self._fetch_geoip(client, ip)
            abuse_result, geo_result = await asyncio.gather(
                abuse_task,
                geo_task,
                return_exceptions=True,
            )

            abuse_data: Dict[str, Any] = {}
            geo_data: Dict[str, Any] = {}

            if isinstance(abuse_result, Exception):
                provider_status["abuseipdb"] = "error"
                logger.warning("AbuseIPDB lookup failed for {}: {}", ip, abuse_result)
            elif abuse_result is not None:
                abuse_data, raw_abuse, provider_status["abuseipdb"] = abuse_result
                raw["abuseipdb"] = raw_abuse
            else:
                provider_status["abuseipdb"] = "skipped_missing_api_key"

            if isinstance(geo_result, Exception):
                provider_status["geoip"] = "error"
                logger.warning("GeoIP lookup failed for {}: {}", ip, geo_result)
            elif geo_result is not None:
                geo_data, raw_geo, provider_status["geoip"] = geo_result
                raw["geoip"] = raw_geo
            else:
                provider_status["geoip"] = "unavailable"

        raw["provider_status"] = provider_status
        score = _ip_intel_score(abuse_data)
        now = _now_utc()
        cache = await self._upsert_ip_cache(ip, abuse_data, geo_data, raw, score, now)
        result = self._ip_result_from_cache(cache, cached=False)
        result.provider_status = provider_status
        return result

    async def check_virustotal(self, ip: str) -> VTResult:
        """Query VirusTotal's IP report endpoint, using a 24-hour cache."""
        cached = await self._get_fresh_vt_cache(ip, "ip")
        if cached is not None:
            return self._vt_result_from_cache(cached, cached=True, provider_status="ok")

        now = _now_utc()
        if not settings.virustotal_configured:
            return VTResult(
                lookup_key=ip,
                scan_type="ip",
                ip=ip,
                provider_status="skipped_missing_api_key",
                scanned_at=now,
            )

        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
                response = await _request_with_retry(
                    client,
                    "GET",
                    f"{VT_BASE_URL}/ip_addresses/{ip}",
                    provider="VirusTotal",
                    headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                )
                payload = response.json()
        except Exception as exc:
            logger.warning("VirusTotal lookup failed for {}: {}", ip, exc)
            return VTResult(
                lookup_key=ip,
                scan_type="ip",
                ip=ip,
                provider_status="error",
                scanned_at=now,
            )

        return await self._persist_vt_payload(
            lookup_key=ip,
            scan_type="ip",
            payload=payload,
            scanned_at=now,
            ip=ip,
            cached=False,
            provider_status="ok",
        )

    async def check_file(self, file_bytes: bytes) -> VTResult:
        """Compute SHA-256 and query VirusTotal's file analysis endpoints."""
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        cached = await self._get_fresh_vt_cache(file_hash, "file")
        if cached is not None:
            return self._vt_result_from_cache(cached, cached=True, provider_status="ok")

        now = _now_utc()
        if not settings.virustotal_configured:
            return VTResult(
                lookup_key=file_hash,
                scan_type="file",
                provider_status="skipped_missing_api_key",
                scanned_at=now,
            )

        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
                headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
                payload = await self._fetch_vt_file_report(client, headers, file_hash, file_bytes)
        except TimeoutError as exc:
            logger.warning("VirusTotal file scan still queued for {}: {}", file_hash, exc)
            return VTResult(
                lookup_key=file_hash,
                scan_type="file",
                provider_status="pending",
                scanned_at=now,
            )
        except Exception as exc:
            logger.warning("VirusTotal file scan failed for {}: {}", file_hash, exc)
            return VTResult(
                lookup_key=file_hash,
                scan_type="file",
                provider_status="error",
                scanned_at=now,
            )

        return await self._persist_vt_payload(
            lookup_key=file_hash,
            scan_type="file",
            payload=payload,
            scanned_at=now,
            cached=False,
            provider_status="ok",
        )

    async def check_url(self, url: str) -> VTResult:
        """Submit and poll VirusTotal's URL analysis endpoint."""
        lookup_key = _normalize_scan_url(url)
        if not lookup_key:
            raise ValueError("URL is required")
        cached = await self._get_fresh_vt_cache(lookup_key, "url")
        if cached is not None:
            return self._vt_result_from_cache(cached, cached=True, provider_status="ok")

        now = _now_utc()
        if not settings.virustotal_configured:
            return VTResult(
                lookup_key=lookup_key,
                scan_type="url",
                provider_status="skipped_missing_api_key",
                scanned_at=now,
            )

        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
                headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
                payload = await self._fetch_vt_url_report(client, headers, lookup_key)
        except Exception as exc:
            logger.warning("VirusTotal URL scan failed for {}: {}", lookup_key, exc)
            return VTResult(
                lookup_key=lookup_key,
                scan_type="url",
                provider_status="error",
                scanned_at=now,
            )

        return await self._persist_vt_payload(
            lookup_key=lookup_key,
            scan_type="url",
            payload=payload,
            scanned_at=now,
            cached=False,
            provider_status="ok",
        )

    async def enrich(self, ip: str) -> EnrichedThreatContext:
        """Return combined AbuseIPDB, GeoIP, and VirusTotal context."""
        ip_result, vt_result = await asyncio.gather(
            self.check_ip(ip),
            self.check_virustotal(ip),
        )
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

    async def _fetch_abuseipdb(
        self,
        client: httpx.AsyncClient,
        ip: str,
    ) -> tuple[Dict[str, Any], Dict[str, Any], str] | None:
        if not settings.abuseipdb_configured:
            return None
        response = await _request_with_retry(
            client,
            "GET",
            "https://api.abuseipdb.com/api/v2/check",
            provider="AbuseIPDB",
            headers={
                "Key": settings.ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
        )
        abuse_payload = response.json()
        return abuse_payload.get("data", {}), abuse_payload, "ok"

    async def _fetch_geoip(
        self,
        client: httpx.AsyncClient,
        ip: str,
    ) -> tuple[Dict[str, Any], Dict[str, Any], str]:
        geo_url = f"{settings.GEOIP_BASE_URL.rstrip('/')}/{ip}"
        response = await _request_with_retry(
            client,
            "GET",
            geo_url,
            provider="GeoIP",
            params={"fields": "status,message,country,countryCode,city,lat,lon,isp,as,query"},
        )
        geo_data = response.json()
        status = "ok" if geo_data.get("status") != "fail" else "unavailable"
        return geo_data, geo_data, status

    async def _fetch_vt_file_report(
        self,
        client: httpx.AsyncClient,
        headers: Dict[str, str],
        file_hash: str,
        file_bytes: bytes,
    ) -> Dict[str, Any]:
        try:
            response = await _request_with_retry(
                client,
                "GET",
                f"{VT_BASE_URL}/files/{file_hash}",
                provider="VirusTotal",
                headers=headers,
            )
            return response.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise

        async with httpx.AsyncClient(timeout=FILE_UPLOAD_TIMEOUT_SECONDS) as upload_client:
            response = await _request_with_retry(
                upload_client,
                "POST",
                f"{VT_BASE_URL}/files",
                provider="VirusTotal",
                headers=headers,
                files={"file": ("upload.bin", file_bytes)},
            )
            upload_payload = response.json()
            analysis_id = upload_payload.get("data", {}).get("id")
            if not analysis_id:
                raise ValueError("VirusTotal file upload did not return an analysis id")

            analysis_payload: Dict[str, Any] | None
            try:
                analysis_payload = await _poll_vt_analysis(
                    upload_client,
                    analysis_id,
                    headers,
                    attempts=FILE_POLL_ATTEMPTS,
                    interval_seconds=FILE_POLL_INTERVAL_SECONDS,
                )
            except TimeoutError:
                logger.info(
                    "VirusTotal file analysis {} still queued; checking /files/{}",
                    analysis_id,
                    file_hash,
                )
                analysis_payload = None

            return await self._resolve_vt_file_payload(
                upload_client,
                headers,
                file_hash,
                analysis_payload,
            )

    async def _resolve_vt_file_payload(
        self,
        client: httpx.AsyncClient,
        headers: Dict[str, str],
        file_hash: str,
        analysis_payload: Dict[str, Any] | None,
    ) -> Dict[str, Any]:
        """Prefer the file report object; fall back to the analysis poll payload."""
        try:
            response = await _request_with_retry(
                client,
                "GET",
                f"{VT_BASE_URL}/files/{file_hash}",
                provider="VirusTotal",
                headers=headers,
            )
            report = response.json()
            if _extract_vt_stats(report):
                return report
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise
        except Exception as exc:
            logger.debug("VirusTotal file report not ready for {}: {}", file_hash, exc)

        if analysis_payload is not None and _extract_vt_stats(analysis_payload):
            return analysis_payload

        raise TimeoutError(
            f"VirusTotal file {file_hash} analysis did not complete in time"
        )

    async def _fetch_vt_url_report(
        self,
        client: httpx.AsyncClient,
        headers: Dict[str, str],
        url: str,
    ) -> Dict[str, Any]:
        url_id = _vt_url_identifier(url)
        try:
            response = await _request_with_retry(
                client,
                "GET",
                f"{VT_BASE_URL}/urls/{url_id}",
                provider="VirusTotal",
                headers=headers,
            )
            return response.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise

        response = await _request_with_retry(
            client,
            "POST",
            f"{VT_BASE_URL}/urls",
            provider="VirusTotal",
            headers=headers,
            files={"url": (None, url)},
        )
        submit_payload = response.json()
        analysis_id = submit_payload.get("data", {}).get("id")
        if not analysis_id:
            raise ValueError("VirusTotal URL submission did not return an analysis id")
        analysis_payload = await _poll_vt_analysis(client, analysis_id, headers)
        return await self._resolve_vt_url_payload(client, headers, url, analysis_payload)

    async def _resolve_vt_url_payload(
        self,
        client: httpx.AsyncClient,
        headers: Dict[str, str],
        url: str,
        analysis_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Prefer the URL report object; fall back to the analysis poll payload."""
        url_id = _vt_url_identifier(url)
        try:
            response = await _request_with_retry(
                client,
                "GET",
                f"{VT_BASE_URL}/urls/{url_id}",
                provider="VirusTotal",
                headers=headers,
            )
            report = response.json()
            if _extract_vt_stats(report):
                return report
        except Exception as exc:
            logger.debug("VirusTotal URL report not ready for {}: {}", url, exc)
        return analysis_payload

    async def _get_fresh_ip_cache(self, ip: str) -> IPReputationCache | None:
        row = (await self.db.execute(
            select(IPReputationCache).where(
                IPReputationCache.user_id == self.user_id,
                IPReputationCache.ip_address == ip,
            )
        )).scalar_one_or_none()
        if row and _is_fresh(row.looked_up_at):
            return row
        return None

    async def _get_fresh_vt_cache(
        self,
        lookup_key: str,
        scan_type: Literal["ip", "file", "url"],
    ) -> VirusScanCache | None:
        row = await self._load_vt_cache_row(lookup_key, scan_type)
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
            select(IPReputationCache).where(
                IPReputationCache.user_id == self.user_id,
                IPReputationCache.ip_address == ip,
            )
        )).scalar_one_or_none()
        if row is None:
            row = IPReputationCache(user_id=self.user_id, ip_address=ip)
            self.db.add(row)

        asn, as_org = _parse_as_field(geo_data.get("as"))

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
        row.asn = asn
        row.as_org = as_org
        row.threat_score = threat_score
        row.raw_result_json = json.dumps(raw)
        await self.db.flush()
        await self.db.refresh(row)
        return row

    async def _persist_vt_payload(
        self,
        lookup_key: str,
        scan_type: Literal["ip", "file", "url"],
        payload: Dict[str, Any],
        scanned_at: str,
        provider_status: str,
        cached: bool,
        ip: str | None = None,
    ) -> VTResult:
        stats = _extract_vt_stats(payload)
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        total = malicious + suspicious + harmless + undetected
        score = _vt_score(malicious, suspicious, total)
        threat_level = _threat_level(score, malicious, suspicious)

        cache = await self._upsert_vt_cache(
            lookup_key=lookup_key,
            scan_type=scan_type,
            threat_level=threat_level,
            malicious_count=malicious,
            suspicious_count=suspicious,
            total_engines=total,
            threat_score=score,
            raw=payload,
            scanned_at=scanned_at,
        )
        result = self._vt_result_from_cache(cache, cached=cached, provider_status=provider_status)
        result.harmless_count = harmless
        result.undetected_count = undetected
        if ip:
            result.ip = ip
        return result

    async def _upsert_vt_cache(
        self,
        lookup_key: str,
        scan_type: Literal["ip", "file", "url"],
        threat_level: str,
        malicious_count: int,
        suspicious_count: int,
        total_engines: int,
        threat_score: float,
        raw: Dict[str, Any],
        scanned_at: str,
    ) -> VirusScanCache:
        for attempt in range(2):
            row = await self._load_vt_cache_row(lookup_key, scan_type)
            if row is None:
                row = VirusScanCache(
                    user_id=self.user_id,
                    lookup_key=lookup_key,
                    scan_type=scan_type,
                )
                self.db.add(row)

            row.scan_type = scan_type
            row.scanned_at = scanned_at
            row.threat_level = threat_level
            row.malicious_count = malicious_count
            row.suspicious_count = suspicious_count
            row.total_engines = total_engines
            row.threat_score = threat_score
            row.raw_result_json = json.dumps(raw)

            try:
                await self.db.flush()
                await self.db.refresh(row)
                return row
            except IntegrityError:
                if attempt == 0:
                    await self.db.rollback()
                    continue
                raise
        raise RuntimeError("virus_scan_cache upsert failed after retry")

    async def _load_vt_cache_row(
        self,
        lookup_key: str,
        scan_type: Literal["ip", "file", "url"],
    ) -> VirusScanCache | None:
        row = (await self.db.execute(
            select(VirusScanCache).where(
                VirusScanCache.user_id == self.user_id,
                VirusScanCache.lookup_key == lookup_key,
                VirusScanCache.scan_type == scan_type,
            )
        )).scalar_one_or_none()
        if row is not None:
            return row
        # Legacy global unique index: row may exist under another user_id.
        return (await self.db.execute(
            select(VirusScanCache).where(
                VirusScanCache.lookup_key == lookup_key,
                VirusScanCache.scan_type == scan_type,
            )
        )).scalar_one_or_none()

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
            asn=row.asn,
            as_org=row.as_org,
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
        stats = _extract_vt_stats(raw)
        malicious = int(row.malicious_count or 0)
        suspicious = int(row.suspicious_count or 0)
        score = round(row.threat_score or 0.0, 2)
        return VTResult(
            lookup_key=row.lookup_key,
            scan_type=row.scan_type,  # type: ignore[arg-type]
            ip=row.lookup_key if row.scan_type == "ip" else None,
            provider_status=provider_status,
            threat_level=_threat_level(score, malicious, suspicious),
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


def _vt_url_identifier(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")


async def _request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    provider: str,
    **kwargs: Any,
) -> httpx.Response:
    last_exc: Exception | None = None
    for attempt in range(1, MAX_HTTP_ATTEMPTS + 1):
        try:
            response = await client.request(method, url, **kwargs)
            if response.status_code >= 500:
                raise httpx.HTTPStatusError(
                    f"{provider} returned {response.status_code}",
                    request=response.request,
                    response=response,
                )
            response.raise_for_status()
            return response
        except httpx.HTTPStatusError as exc:
            if 400 <= exc.response.status_code < 500:
                raise
            last_exc = exc
        except (httpx.TransportError, httpx.TimeoutException) as exc:
            last_exc = exc

        if attempt < MAX_HTTP_ATTEMPTS:
            delay = RETRY_BACKOFF_SECONDS[attempt - 1]
            logger.warning(
                "{provider} attempt {attempt}/{max_attempts} failed for {url}: {error}. Retrying in {delay}s.",
                provider=provider,
                attempt=attempt,
                max_attempts=MAX_HTTP_ATTEMPTS,
                url=url,
                error=last_exc,
                delay=delay,
            )
            await asyncio.sleep(delay)

    assert last_exc is not None
    logger.warning(
        "{provider} gave up after {max_attempts} attempts for {url}: {error}",
        provider=provider,
        max_attempts=MAX_HTTP_ATTEMPTS,
        url=url,
        error=last_exc,
    )
    raise last_exc


async def _poll_vt_analysis(
    client: httpx.AsyncClient,
    analysis_id: str,
    headers: Dict[str, str],
    *,
    attempts: int = URL_POLL_ATTEMPTS,
    interval_seconds: float = URL_POLL_INTERVAL_SECONDS,
) -> Dict[str, Any]:
    for attempt in range(1, attempts + 1):
        response = await _request_with_retry(
            client,
            "GET",
            f"{VT_BASE_URL}/analyses/{analysis_id}",
            provider="VirusTotal",
            headers=headers,
        )
        payload = response.json()
        status = payload.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            return payload
        if attempt < attempts:
            await asyncio.sleep(interval_seconds)
    raise TimeoutError(f"VirusTotal analysis {analysis_id} did not complete in time")


def _extract_vt_stats(payload: Dict[str, Any]) -> Dict[str, Any]:
    attributes = payload.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats")
    if stats:
        return stats
    stats = attributes.get("stats")
    return stats or {}


def _parse_as_field(raw_as: Any) -> tuple[str | None, str | None]:
    if not raw_as or not isinstance(raw_as, str):
        return None, None
    match = re.match(r"^(AS\d+)\s+(.+)$", raw_as.strip())
    if match:
        return match.group(1), match.group(2)
    return raw_as, None


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


def _threat_level(score: float, malicious: int = 0, suspicious: int = 0) -> str:
    """Map VT engine votes + ratio score to clean / suspicious / malicious."""
    if malicious >= 5 or score >= 50:
        return "malicious"
    if malicious >= 1 or suspicious >= 2 or score >= 12:
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
