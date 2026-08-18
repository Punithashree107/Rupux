"""
Core logic for the Real Zone CVE Lookup tool.

Queries the NVD (National Vulnerability Database) public REST API v2.0
-- the official, free, U.S. government-run vulnerability database.
No API key is required for casual/personal use, but requests are
rate-limited (roughly 5 requests per 30 seconds without a key). If
that limit is hit, the API returns 403/429 and this module surfaces
a clear message rather than failing silently.

Docs: https://nvd.nist.gov/developers/vulnerabilities
"""
import re
from dataclasses import dataclass, field
from typing import List, Optional

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 15

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@dataclass
class CveEntry:
    cve_id: str
    description: str
    severity: str            # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NOT SCORED"
    score: Optional[float]
    cvss_version: str        # "3.1" | "3.0" | "2.0" | "n/a"
    published: str
    references: List[str] = field(default_factory=list)


@dataclass
class CveSearchResult:
    query: str
    total_results: int = 0
    entries: List[CveEntry] = field(default_factory=list)
    error: Optional[str] = None


def _extract_cvss(metrics: dict) -> tuple:
    """Prefers the newest available CVSS version: 3.1 > 3.0 > 2.0."""
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity", "UNKNOWN")
            return score, severity, version

    v2_entries = metrics.get("cvssMetricV2")
    if v2_entries:
        data = v2_entries[0].get("cvssData", {})
        score = data.get("baseScore")
        # CVSS v2 has no baseSeverity field in the schema -- derive it from score.
        if score is not None:
            if score >= 7.0:
                severity = "HIGH"
            elif score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
        else:
            severity = "UNKNOWN"
        return score, severity, "2.0"

    return None, "NOT SCORED", "n/a"


def _parse_vulnerability(vuln_wrapper: dict) -> CveEntry:
    cve = vuln_wrapper.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")

    descriptions = cve.get("descriptions", [])
    description = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
        descriptions[0].get("value", "") if descriptions else "No description available.",
    )

    score, severity, cvss_version = _extract_cvss(cve.get("metrics", {}))
    published = cve.get("published", "Unknown")[:10]  # just the date portion

    references = [ref.get("url", "") for ref in cve.get("references", [])][:5]

    return CveEntry(
        cve_id=cve_id, description=description, severity=severity,
        score=score, cvss_version=cvss_version, published=published,
        references=references,
    )


def _friendly_error(status_code: int, body_snippet: str = "") -> str:
    if status_code in (403, 429):
        return (
            "NVD rate limit reached (the public API allows ~5 requests per 30 seconds "
            "without an API key). Wait a moment and try again."
        )
    if status_code == 404:
        return "No results found."
    return f"NVD API returned an unexpected error (HTTP {status_code}). {body_snippet}".strip()


def search_cves(query: str, results_limit: int = 15) -> CveSearchResult:
    """
    Accepts either an exact CVE ID (e.g. 'CVE-2021-44228') for a direct
    lookup, or a free-text keyword (e.g. 'apache log4j') for a keyword
    search against CVE descriptions.
    """
    import requests

    query = query.strip()
    if not query:
        return CveSearchResult(query=query, error="Enter a CVE ID or keyword to search.")

    headers = {"User-Agent": "Rupux-RealZone/1.0 (educational-use)"}

    if CVE_ID_PATTERN.match(query):
        params = {"cveId": query.upper()}
    else:
        params = {"keywordSearch": query, "resultsPerPage": results_limit}

    try:
        resp = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.Timeout:
        return CveSearchResult(query=query, error="Request to NVD timed out. Try again.")
    except requests.exceptions.ConnectionError as e:
        return CveSearchResult(query=query, error=f"Could not reach NVD: {e}")
    except Exception as e:
        return CveSearchResult(query=query, error=f"Request failed: {e}")

    if resp.status_code != 200:
        return CveSearchResult(query=query, error=_friendly_error(resp.status_code, resp.text[:200]))

    try:
        data = resp.json()
    except Exception:
        return CveSearchResult(query=query, error="NVD returned an unreadable response.")

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return CveSearchResult(query=query, total_results=0, error="No CVEs found for that search.")

    entries = [_parse_vulnerability(v) for v in vulnerabilities]
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4, "NOT SCORED": 5}
    entries.sort(key=lambda e: severity_rank.get(e.severity, 6))

    return CveSearchResult(
        query=query,
        total_results=data.get("totalResults", len(entries)),
        entries=entries,
    )
