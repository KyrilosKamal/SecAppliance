"""Online CVE enrichment via the CIRCL Vulnerability-Lookup API.

The public API indexes advisories by (vendor, product) and exposes no
product-version filter: a `version` query parameter is accepted and silently
ignored. The banner version is therefore matched against each record's
``containers.cna.affected[].versions[]`` locally, and records with no machine
readable affected versions are kept (product-level match). Ranges are honoured,
so a product whose only indexed records stop at an older range yields nothing:
``nginx/1.18.0`` matches no record because the nginx advisories in the index
state versions such as ``through 1.6.2``.

Offline signature matching (``core.vuln_lookup``) stays authoritative; this
module only adds context and is expected to fail soft.
"""

import asyncio
import json
import re
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

from utils.logger import logger

#: Verified working search route. Returns a flat JSON list of CVE 5.1 records.
API_SEARCH_URL = "https://vulnerability.circl.lu/api/vulnerability/"

#: CIRCL's vendor id differs from the banner product name for some products.
#: Only entries confirmed against the live API are listed; everything else falls
#: back to (product, product), which the same route accepts.
VENDOR_HINTS: Dict[str, Tuple[str, str]] = {
    "openssh": ("openbsd", "openssh"),
    "apache": ("apache", "http_server"),  # CPE name, not the "httpd" package name
    "nginx": ("nginx", "nginx"),
}

#: Seconds before a lookup is abandoned; the scan must not stall on the network.
LOOKUP_TIMEOUT = 10.0

#: Per-request cap. The API returns up to 30 by default and some product queries
#: are ~130 KB unconstrained, which is wasted work for a report section.
MAX_RESULTS = 25

_SSH_RE = re.compile(r"OpenSSH[_-](\d+(?:\.\d+)*)", re.IGNORECASE)
_SLASH_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9._+-]*)/(\d+(?:\.\d+)*)")


def parse_banner(banner: str) -> Optional[Tuple[str, str]]:
    """Extract (product, version) from a service banner.

    Args:
        banner: Raw banner text, e.g. ``SSH-2.0-OpenSSH_8.9p1``.

    Returns:
        A lowercase ``(product, version)`` tuple, or None when nothing matches.
        The version keeps only its numeric components: ``8.9p1`` -> ``8.9``.

    Examples:
        >>> parse_banner("SSH-2.0-OpenSSH_8.9p1")
        ('openssh', '8.9')
        >>> parse_banner("Apache/2.4.52 (Ubuntu)")
        ('apache', '2.4.52')
        >>> parse_banner("nginx/1.18.0")
        ('nginx', '1.18.0')
    """
    if not banner:
        return None

    match = _SSH_RE.search(banner)
    if match:
        return ("openssh", match.group(1))

    match = _SLASH_RE.search(banner)
    if match:
        product, version = match.group(1).lower(), match.group(2)
        # "Server: OpenSSH/9.6" and "SSH-2.0/..." would otherwise key on "ssh".
        if product in ("ssh", "sshd"):
            return ("openssh", version)
        return (product, version)

    return None


def banner_key(product: str, version: str) -> str:
    """Build the cache key for a parsed banner."""
    return f"{product}/{version}"


def _affected_versions(record: Dict[str, Any]) -> List[str]:
    """Collect the affected version strings a CVE record declares."""
    cna = (record.get("containers") or {}).get("cna") or {}
    versions: List[str] = []
    for affected in cna.get("affected") or []:
        for entry in affected.get("versions") or []:
            value = entry.get("version")
            if value:
                versions.append(str(value))
    return versions


def _version_matches(record: Dict[str, Any], version: str) -> bool:
    """True when the scanned version appears in the record's affected versions.

    Compares on the first two components (``8.9.4`` -> ``8.9``) because advisories
    state either exact versions or ranges like ``through 1.6.2``. Records without
    machine readable versions are kept: they describe the product, not a range.
    """
    versions = _affected_versions(record)
    if not versions:
        return True

    short = ".".join(version.split(".")[:2])
    pattern = re.compile(r"(?<![\d.])" + re.escape(short) + r"(?![\d])")
    return any(pattern.search(candidate) for candidate in versions)


def _extract_cvss(containers: Dict[str, Any]) -> Tuple[str, float]:
    """Return (severity, score) from the first usable CVSS metric.

    CVE 5.1 puts the vector under a versioned key; live records use cvssV3_1,
    cvssV3_0 and cvssV4_0 interchangeably, so all are tried in that order.

    CNA metrics are preferred, but some records (notably Apache advisories)
    carry only a textual severity in the CNA and put the real CVSS vector in an
    ADP container. Both are scanned before falling back to UNKNOWN/0.0.
    """
    sources = [(containers.get("cna") or {}).get("metrics") or []]
    for adp in containers.get("adp") or []:
        if isinstance(adp, dict):
            sources.append(adp.get("metrics") or [])

    for metrics in sources:
        for metric in metrics:
            if not isinstance(metric, dict):
                continue
            for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
                vector = metric.get(key)
                if isinstance(vector, dict):
                    severity = vector.get("baseSeverity") or "UNKNOWN"
                    score = vector.get("baseScore")
                    return str(severity).upper(), float(score) if score is not None else 0.0
    return "UNKNOWN", 0.0


def _extract_finding(record: Dict[str, Any]) -> Dict[str, Any]:
    """Map a CVE 5.1 record onto the flat finding dict callers consume."""
    cve_id = (record.get("cveMetadata") or {}).get("cveId", "Unknown")
    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}

    descriptions = cna.get("descriptions") or []
    summary = "No description available."
    if descriptions and isinstance(descriptions[0], dict):
        summary = descriptions[0].get("value") or summary

    severity, score = _extract_cvss(containers)
    return {
        "cve_id": cve_id,
        "summary": summary,
        "severity": severity,
        "cvss_score": score,
    }


async def _fetch_records(session: aiohttp.ClientSession, vendor: str, product: str) -> List[Any]:
    """Perform the single API request and return the raw record list."""
    params = {"vendor": vendor, "product": product, "per_page": MAX_RESULTS}
    async with session.get(API_SEARCH_URL, params=params) as response:
        if response.status != 200:
            logger.warning(
                f"CIRCL lookup for {vendor}/{product} returned HTTP {response.status}"
            )
            return []
        payload = await response.json(content_type=None)

    if isinstance(payload, dict):
        # The /vulnerability/search/{vendor}/{product} route wraps records per
        # source; accept both shapes so a route change degrades instead of breaking.
        payload = [item for bucket in (payload.get("results") or {}).values()
                   for item in (bucket if isinstance(bucket, list) else [])]
    if not isinstance(payload, list):
        logger.warning(f"Unexpected CIRCL payload for {vendor}/{product}: {type(payload).__name__}")
        return []
    return payload


async def lookup_online_cves(
    session: aiohttp.ClientSession, banner: str, max_results: int = MAX_RESULTS
) -> List[Dict[str, Any]]:
    """Look a service banner up on CIRCL and return matching CVE findings.

    Args:
        session: Caller-owned aiohttp session (connection pooling is the caller's).
        banner: Raw banner text; unparseable banners return an empty list.
        max_results: Maximum findings returned, highest CVSS score first.

    Returns:
        Dicts with ``cve_id``, ``summary``, ``severity`` and ``cvss_score``.
        Network failures and malformed payloads return an empty list.

    Raises:
        Nothing. This is enrichment; a CVE lookup failure must not fail a scan.
    """
    parsed = parse_banner(banner)
    if not parsed:
        return []
    product, version = parsed
    vendor, product_id = VENDOR_HINTS.get(product, (product, product))

    try:
        records = await asyncio.wait_for(
            _fetch_records(session, vendor, product_id), timeout=LOOKUP_TIMEOUT
        )
    except asyncio.TimeoutError:
        logger.warning(f"CIRCL lookup for {banner_key(product, version)} timed out")
        return []
    except aiohttp.ClientError as e:
        logger.warning(f"CIRCL lookup for {banner_key(product, version)} failed: {e}")
        return []
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"CIRCL returned unparseable JSON for {product}: {e}")
        return []

    findings: List[Dict[str, Any]] = []
    seen = set()
    for record in records:
        if isinstance(record, list) and len(record) == 2 and isinstance(record[1], dict):
            record = record[1]  # [vuln_id, record] pair form
        if not isinstance(record, dict):
            continue
        if not _version_matches(record, version):
            continue
        finding = _extract_finding(record)
        if finding["cve_id"] in seen:
            continue
        seen.add(finding["cve_id"])
        findings.append(finding)

    findings.sort(key=lambda f: f["cvss_score"], reverse=True)
    logger.debug(
        f"CIRCL lookup {banner_key(product, version)}: "
        f"{len(findings)} finding(s) from {len(records)} record(s)"
    )
    return findings[:max_results]


async def lookup_with_cache(
    session: aiohttp.ClientSession,
    db: Any,
    banner: str,
    max_results: int = MAX_RESULTS,
) -> List[Dict[str, Any]]:
    """Cached wrapper around :func:`lookup_online_cves` used by both scanners.

    Args:
        session: Caller-owned aiohttp session.
        db: Object exposing ``get_cached_cves``/``cache_cves`` (DatabaseManager).
        banner: Raw banner or ``Server`` header value.
        max_results: Maximum findings returned.

    Returns:
        Findings, or an empty list for an unparseable banner. Empty results are
        not cached: ``[]`` is also what a failed lookup returns, and caching it
        for 7 days would hide the outage.
    """
    parsed = parse_banner(banner)
    if not parsed:
        return []

    key = banner_key(*parsed)
    cached = await db.get_cached_cves(key)
    if cached is not None:
        try:
            cached_findings = json.loads(cached)
        except json.JSONDecodeError:
            logger.warning(f"Discarding unparseable CVE cache entry for {key}")
            cached_findings = None
        if isinstance(cached_findings, list):
            return cached_findings[:max_results]

    findings = await lookup_online_cves(session, banner, max_results=max_results)
    if findings:
        await db.cache_cves(key, json.dumps(findings))
    return findings
