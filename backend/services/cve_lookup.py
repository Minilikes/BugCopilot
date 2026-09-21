"""CVE lookup service using NVD API v2 and OSV.dev."""

import asyncio
import httpx
from backend import config


NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_BASE = "https://api.osv.dev/v1/query"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}


async def lookup_nvd(product: str, version: str = "") -> list[dict]:
    """
    Query NVD API v2 for CVEs matching a product + version.
    Returns top 10 CVEs sorted by CVSS score.
    """
    keyword = f"{product} {version}".strip()
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 10,
        "keywordExactMatch": False,
    }
    headers = {}
    if config.NVD_API_KEY:
        headers["apiKey"] = config.NVD_API_KEY

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(NVD_BASE, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"error": str(e), "source": "nvd"}]

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )
        # Extract CVSS score
        metrics = cve.get("metrics", {})
        cvss_score = 0.0
        severity = "UNKNOWN"
        cvss_vector = ""
        # Try CVSS 3.1, then 3.0, then 2.0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss_data = m.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = m.get("baseSeverity", cvss_data.get("baseSeverity", "UNKNOWN"))
                cvss_vector = cvss_data.get("vectorString", "")
                break

        results.append({
            "cve_id": cve_id,
            "description": description[:400],
            "cvss_score": cvss_score,
            "severity": severity,
            "cvss_vector": cvss_vector,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "source": "nvd",
        })

    # Sort by CVSS score descending
    results.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
    return results[:5]


async def lookup_osv(package: str, version: str, ecosystem: str = "") -> list[dict]:
    """
    Query OSV.dev for vulnerabilities in a package.
    Best for JS (npm), Python (PyPI), Ruby (RubyGems), etc.
    """
    payload: dict = {"version": version, "package": {"name": package}}
    if ecosystem:
        payload["package"]["ecosystem"] = ecosystem

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(OSV_BASE, json=payload)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"error": str(e), "source": "osv"}]

    results = []
    for vuln in data.get("vulns", [])[:5]:
        aliases = vuln.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln.get("id", ""))
        summary = vuln.get("summary", vuln.get("details", "")[:300])
        severity_list = vuln.get("severity", [])
        cvss_score = 0.0
        cvss_vector = ""
        for sev in severity_list:
            if sev.get("type") == "CVSS_V3":
                cvss_vector = sev.get("score", "")
                # Parse base score from vector
                try:
                    from re import search
                    # crude parse — real CVSS lib would be cleaner
                    cvss_score = float(sev.get("score", "0").split("/")[0].replace("CVSS:3.", "").split(":")[0]) if "/" in sev.get("score", "") else 0.0
                except Exception:
                    pass
                break
        results.append({
            "cve_id": cve_id,
            "description": summary,
            "cvss_score": cvss_score,
            "severity": "UNKNOWN",
            "cvss_vector": cvss_vector,
            "url": f"https://osv.dev/vulnerability/{vuln.get('id','')}",
            "source": "osv",
        })

    return results


ECOSYSTEM_MAP = {
    "npm": "npm",
    "jquery": "npm",
    "react": "npm",
    "angular": "npm",
    "vue": "npm",
    "lodash": "npm",
    "bootstrap": "npm",
    "django": "PyPI",
    "flask": "PyPI",
    "rails": "RubyGems",
    "laravel": "Packagist",
    "wordpress": "",
    "drupal": "",
    "joomla": "",
}


async def lookup_tech_cves(tech_name: str, version: str) -> list[dict]:
    """
    High-level wrapper: try OSV first (for JS/Python packages),
    fall back to NVD keyword search.
    """
    ecosystem = ECOSYSTEM_MAP.get(tech_name.lower(), "")
    results = []

    # Rate limit
    await asyncio.sleep(config.RATE_LIMIT_DELAY)

    if ecosystem:
        results = await lookup_osv(tech_name, version, ecosystem)

    if not results or all("error" in r for r in results):
        await asyncio.sleep(config.RATE_LIMIT_DELAY)
        results = await lookup_nvd(tech_name, version)

    return results
