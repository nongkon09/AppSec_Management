"""Exploitation signals the severity policy needs but the SCA platform may not supply
(Requirement.md FR-4.1: CVSS + EPSS + CISA KEV).

Dependency-Track 4.x has no CISA KEV data at all, and attaches EPSS only to NVD-sourced
CVE records — advisories matched through OSV/GitHub (the usual case for purl-only SBOMs)
carry neither. Both signals are public feeds keyed by CVE ID, so the pull-sync enriches
findings from them directly:

- CISA Known Exploited Vulnerabilities catalogue (one JSON download per sync run).
- FIRST EPSS API (batched lookups for CVEs that arrived without a score).
- OSV.dev, to find the CVE behind a GHSA/OSV advisory ID. Dependency-Track 4.14 does not
  populate its alias table from the OSV mirror, so its findings carry the GHSA ID only.

Both are best-effort: an unreachable feed leaves the SCA platform's values untouched and
the sync carries on. Setting either URL to an empty string disables that lookup (tests
and air-gapped deployments).
"""

import logging
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Protocol

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)

# FIRST's API accepts a comma-separated list; 100 keeps the query string well inside
# URL length limits and matches the API's default page size.
EPSS_BATCH_SIZE = 100
OSV_LOOKUP_WORKERS = 8

# Advisory -> CVE mappings do not change, so they are kept for the life of the process
# (the scheduler runs in-process); an empty tuple records "this advisory has no CVE".
_cve_alias_cache: dict[str, tuple[str, ...]] = {}


class ThreatIntel(Protocol):
    def is_kev(self, cve_id: str) -> bool: ...

    def epss_scores(self, cve_ids: Iterable[str]) -> dict[str, float]: ...

    def cve_aliases(self, advisory_ids: Iterable[str]) -> dict[str, tuple[str, ...]]: ...


class PublicFeedThreatIntel:
    """`ThreatIntel` backed by the public CISA KEV feed and the FIRST EPSS API."""

    def __init__(
        self,
        kev_feed_url: str | None = None,
        epss_api_url: str | None = None,
        osv_api_url: str | None = None,
    ) -> None:
        settings = get_settings()
        self._kev_feed_url = settings.cisa_kev_feed_url if kev_feed_url is None else kev_feed_url
        self._epss_api_url = settings.epss_api_url if epss_api_url is None else epss_api_url
        self._osv_api_url = (settings.osv_api_url if osv_api_url is None else osv_api_url).rstrip(
            "/"
        )
        self._kev: set[str] | None = None

    def _load_kev(self) -> set[str]:
        if self._kev is not None:
            return self._kev
        self._kev = set()
        if not self._kev_feed_url:
            return self._kev
        try:
            response = httpx.get(self._kev_feed_url, timeout=30.0, follow_redirects=True)
            response.raise_for_status()
            self._kev = {
                item["cveID"].upper()
                for item in response.json().get("vulnerabilities", [])
                if item.get("cveID")
            }
        except (httpx.HTTPError, ValueError, KeyError):
            logger.exception("CISA KEV feed unavailable; KEV flags come from the SCA platform only")
        return self._kev

    def is_kev(self, cve_id: str) -> bool:
        return cve_id.upper() in self._load_kev()

    def epss_scores(self, cve_ids: Iterable[str]) -> dict[str, float]:
        wanted = sorted({cve.upper() for cve in cve_ids if cve.upper().startswith("CVE-")})
        if not wanted or not self._epss_api_url:
            return {}
        scores: dict[str, float] = {}
        for start in range(0, len(wanted), EPSS_BATCH_SIZE):
            batch = wanted[start : start + EPSS_BATCH_SIZE]
            try:
                response = httpx.get(
                    self._epss_api_url, params={"cve": ",".join(batch)}, timeout=30.0
                )
                response.raise_for_status()
                for row in response.json().get("data", []):
                    scores[row["cve"].upper()] = float(row["epss"])
            except (httpx.HTTPError, ValueError, KeyError):
                logger.exception(
                    "EPSS lookup failed for %d CVEs; leaving them unscored", len(batch)
                )
        return scores

    def _lookup_cves(self, client: httpx.Client, advisory_id: str) -> None:
        try:
            response = client.get(f"{self._osv_api_url}/{advisory_id}")
            if response.status_code == 404:
                _cve_alias_cache[advisory_id] = ()
                return
            response.raise_for_status()
            aliases = response.json().get("aliases") or []
        except (httpx.HTTPError, ValueError):
            logger.warning("OSV alias lookup failed for %s; keeping the advisory ID", advisory_id)
            return  # not cached, so a later sync retries
        _cve_alias_cache[advisory_id] = tuple(
            sorted({str(a).upper() for a in aliases if str(a).upper().startswith("CVE-")})
        )

    def cve_aliases(self, advisory_ids: Iterable[str]) -> dict[str, tuple[str, ...]]:
        """Maps non-CVE advisory IDs (GHSA-…, PYSEC-…) to every CVE OSV lists for them.
        Advisories with no CVE are left out."""
        wanted = {i for i in advisory_ids if not i.upper().startswith("CVE-")}
        if self._osv_api_url:
            unknown = sorted(i for i in wanted if i not in _cve_alias_cache)
            if unknown:
                with (
                    httpx.Client(timeout=20.0) as client,
                    ThreadPoolExecutor(max_workers=OSV_LOOKUP_WORKERS) as pool,
                ):
                    list(pool.map(lambda advisory: self._lookup_cves(client, advisory), unknown))
        return {i: cves for i in wanted if (cves := _cve_alias_cache.get(i))}
