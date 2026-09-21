"""
Passive recon engine — all steps are explicitly opt-in and rate-limited.
No destructive, brute-force, or DoS actions are ever performed.
"""

import asyncio
import json
import re
import hashlib
from urllib.parse import urljoin, urlparse
from typing import AsyncGenerator

import httpx
import dns.resolver
from bs4 import BeautifulSoup

from backend import config
from backend.services.scope_guard import ScopeGuard

# Common browser-like headers to avoid being blocked by basic WAFs
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; BugCopilot-Recon/1.0; Security Research)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# Regex patterns for JS secret detection (intentionally conservative — flags for human review)
JS_SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9\-_]{16,})["\']', "API Key"),
    (r'(?i)(secret|token)\s*[=:]\s*["\']([A-Za-z0-9\-_\.]{16,})["\']', "Secret/Token"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', "Password"),
    (r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*["\']([^"\']{10,})["\']', "AWS Credential"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(?i)(private_key|privatekey)\s*[=:]\s*["\']([^"\']{10,})["\']', "Private Key"),
    (r'(?i)bearer\s+([A-Za-z0-9\-_\.]{20,})', "Bearer Token"),
]

# Regex for endpoint discovery in JS
JS_ENDPOINT_PATTERNS = [
    r'["\'](/(?:api|v\d+|graphql|rest|internal|admin|user|auth|login|account)[^"\'?\s]*)["\']',
    r'["\'](https?://[^"\'?\s]{10,})["\']',
    r'(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["\']([^"\']+)["\']',
    r'(?:url|endpoint|path|route)\s*[:=]\s*["\']([/][^"\'?\s]+)["\']',
]

# Known security header checks
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "required": True,
        "good": lambda v: "max-age" in v.lower() and int(re.search(r'max-age=(\d+)', v or '0').group(1) if re.search(r'max-age=(\d+)', v or '0') else 0) >= 15552000,
        "issue": "Missing or weak HSTS — site may be vulnerable to SSL stripping",
        "score": 7,
    },
    "Content-Security-Policy": {
        "required": True,
        "good": lambda v: bool(v) and "unsafe-inline" not in v,
        "issue": "Missing or weak CSP — increases XSS exploitability",
        "score": 6,
    },
    "X-Frame-Options": {
        "required": True,
        "good": lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
        "issue": "Missing X-Frame-Options — potential clickjacking vector",
        "score": 4,
    },
    "X-Content-Type-Options": {
        "required": True,
        "good": lambda v: v.lower() == "nosniff",
        "issue": "Missing X-Content-Type-Options: nosniff — MIME sniffing risk",
        "score": 3,
    },
    "Referrer-Policy": {
        "required": False,
        "good": lambda v: bool(v),
        "issue": "Missing Referrer-Policy — potential information leakage in referrer",
        "score": 2,
    },
    "Permissions-Policy": {
        "required": False,
        "good": lambda v: bool(v),
        "issue": "Missing Permissions-Policy header",
        "score": 1,
    },
}

# Tech fingerprinting signatures
TECH_SIGNATURES = {
    "headers": {
        "X-Powered-By": {"php": "PHP", "asp.net": "ASP.NET", "express": "Express.js"},
        "Server": {
            "nginx": "Nginx", "apache": "Apache", "iis": "Microsoft IIS",
            "cloudflare": "Cloudflare", "lighttpd": "LightHTTPD",
        },
        "X-Generator": {},
        "X-Drupal-Cache": {"": "Drupal"},
        "X-Shopify-Stage": {"": "Shopify"},
    },
    "html_patterns": {
        r'wp-content|wp-includes': "WordPress",
        r'Drupal\.settings|drupal\.org': "Drupal",
        r'<meta name="generator" content="([^"]+)"': None,  # Extract version
        r'jquery[.-](\d+\.\d+[\.\d]*)': "jQuery",
        r'react(?:\.min)?\.js|react-dom': "React",
        r'angular(?:\.min)?\.js|ng-version': "Angular",
        r'vue(?:\.min)?\.js': "Vue.js",
        r'bootstrap[.-](\d+\.\d+[\.\d]*)': "Bootstrap",
        r'next(?:js)?[/-](\d+)': "Next.js",
        r'__NUXT__': "Nuxt.js",
        r'_rails_': "Ruby on Rails",
        r'laravel': "Laravel",
        r'django': "Django",
        r'flask': "Flask",
    },
}


async def _rate_limited_get(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    await asyncio.sleep(config.RATE_LIMIT_DELAY)
    try:
        resp = await client.get(url, headers=HEADERS, timeout=10.0, follow_redirects=True)
        return resp
    except Exception:
        return None


# ── Module 2a: Subdomain Enumeration ─────────────────────────────────────────

async def enumerate_subdomains(domain: str, guard: ScopeGuard) -> list[dict]:
    """
    Passive subdomain enumeration via:
    1. Certificate Transparency (crt.sh)
    2. DNS resolution of found subdomains
    """
    results = []
    found = set()

    # Step 1: crt.sh certificate transparency
    crtsh_url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            await asyncio.sleep(config.RATE_LIMIT_DELAY)
            resp = await client.get(crtsh_url, headers=HEADERS)
            if resp.status_code == 200:
                entries = resp.json()
                for entry in entries:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub and sub.endswith(domain) and sub not in found:
                            found.add(sub)
    except Exception as e:
        results.append({
            "target": domain, "title": "crt.sh lookup failed",
            "data": {"error": str(e)}, "score": 0,
        })

    # Step 2: DNS resolve each found subdomain
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    for sub in sorted(found):
        in_scope, reason = guard.is_in_scope(sub)
        if not in_scope:
            continue
        await asyncio.sleep(0.2)  # lighter delay for DNS
        try:
            answers = resolver.resolve(sub, "A")
            ips = [str(r) for r in answers]
            score = 6 if any(x in sub for x in ["api", "admin", "internal", "dev", "staging", "beta", "test"]) else 3
            results.append({
                "target": sub,
                "title": f"Subdomain: {sub}",
                "data": {"ips": ips, "source": "crt.sh + DNS"},
                "score": score,
                "score_reason": f"Resolves to {', '.join(ips)}. High-value prefix detected." if score == 6 else "Active subdomain.",
            })
        except dns.exception.DNSException:
            pass  # Subdomain doesn't resolve — skip silently

    return results


# ── Module 2b: Tech Stack Fingerprinting ─────────────────────────────────────

async def fingerprint_tech(url: str) -> dict:
    """Detect technologies used by a target URL via headers and HTML analysis."""
    techs = {}

    async with httpx.AsyncClient(timeout=10.0) as client:
        await asyncio.sleep(config.RATE_LIMIT_DELAY)
        resp = await client.get(url, headers=HEADERS, follow_redirects=True)

    if not resp:
        return {"error": "Could not fetch URL"}

    # Check security headers
    for header, val in resp.headers.items():
        for sig_header, sigs in TECH_SIGNATURES["headers"].items():
            if header.lower() == sig_header.lower():
                for keyword, tech_name in sigs.items():
                    if not keyword or keyword.lower() in val.lower():
                        name = tech_name or val
                        # Extract version from header value if possible
                        version_match = re.search(r'[\d]+\.[\d]+(?:\.[\d]+)?', val)
                        version = version_match.group(0) if version_match else ""
                        techs[name] = {"version": version, "source": f"header:{sig_header}"}

    # Parse HTML
    try:
        soup = BeautifulSoup(resp.text, "html.parser")
        html_text = resp.text

        for pattern, tech_name in TECH_SIGNATURES["html_patterns"].items():
            match = re.search(pattern, html_text, re.IGNORECASE)
            if match:
                if tech_name is None:
                    # Extract from match groups
                    detected = match.group(1) if match.lastindex else match.group(0)
                    techs[detected] = {"version": "", "source": "html_meta"}
                else:
                    version = match.group(1) if match.lastindex else ""
                    if tech_name not in techs:
                        techs[tech_name] = {"version": version, "source": "html_pattern"}

        # Check JS files referenced
        js_files = [
            script.get("src", "")
            for script in soup.find_all("script", src=True)
        ]

    except Exception:
        js_files = []

    return {
        "url": url,
        "status_code": resp.status_code,
        "server": resp.headers.get("Server", ""),
        "technologies": techs,
        "js_files": js_files[:20],  # cap at 20
    }


# ── Module 2c: JS File Parsing ───────────────────────────────────────────────

async def parse_js_files(base_url: str, js_urls: list[str], guard: ScopeGuard) -> list[dict]:
    """
    Fetch in-scope JS files and extract:
    - Interesting API endpoints
    - Potential hardcoded secrets (flagged for human review, never acted on)
    """
    findings = []
    parsed_base = urlparse(base_url)

    async with httpx.AsyncClient(timeout=10.0) as client:
        for js_url in js_urls[:15]:  # max 15 JS files
            # Resolve relative URLs
            if not js_url.startswith("http"):
                js_url = urljoin(base_url, js_url)

            in_scope, _ = guard.is_in_scope(js_url)
            if not in_scope:
                continue

            resp = await _rate_limited_get(client, js_url)
            if not resp or resp.status_code != 200:
                continue

            content = resp.text

            # Extract endpoints
            endpoints = set()
            for pattern in JS_ENDPOINT_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    ep = match.group(1)
                    if len(ep) > 2 and len(ep) < 200:
                        endpoints.add(ep)

            if endpoints:
                findings.append({
                    "target": js_url,
                    "title": f"JS Endpoints: {len(endpoints)} found in {js_url.split('/')[-1]}",
                    "data": {"endpoints": sorted(endpoints)[:50], "type": "js_endpoint"},
                    "score": 5,
                    "score_reason": f"Found {len(endpoints)} potential API endpoint(s) in JS file.",
                })

            # Check for potential secrets (flag for human review only)
            for pattern, secret_type in JS_SECRET_PATTERNS:
                for match in re.finditer(pattern, content):
                    value = match.group(0)
                    # Redact most of the value for safety
                    redacted = value[:20] + "..." if len(value) > 20 else value
                    findings.append({
                        "target": js_url,
                        "title": f"Possible {secret_type} in JS file",
                        "data": {
                            "type": "js_secret",
                            "secret_type": secret_type,
                            "snippet": redacted,
                            "note": "Human review required — verify this is not a placeholder or test value",
                        },
                        "score": 9,
                        "score_reason": f"Possible hardcoded {secret_type} — high priority for manual review.",
                    })

    return findings


# ── Module 2d: robots.txt + Sitemap ──────────────────────────────────────────

async def crawl_robots_sitemap(base_url: str) -> list[dict]:
    """Fetch robots.txt and sitemap.xml for interesting paths."""
    results = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    async with httpx.AsyncClient(timeout=8.0) as client:
        # robots.txt
        await asyncio.sleep(config.RATE_LIMIT_DELAY)
        resp = await _rate_limited_get(client, f"{origin}/robots.txt")
        if resp and resp.status_code == 200 and "User-agent" in resp.text:
            disallowed = re.findall(r'(?i)Disallow:\s*(.+)', resp.text)
            interesting = [p.strip() for p in disallowed if any(
                k in p.lower() for k in ["admin", "api", "backup", "config", "internal", "private", "dev", "test", "debug"]
            )]
            results.append({
                "target": f"{origin}/robots.txt",
                "title": f"robots.txt — {len(disallowed)} Disallow rules",
                "data": {
                    "all_disallowed": [p.strip() for p in disallowed[:50]],
                    "interesting_paths": interesting,
                },
                "score": 7 if interesting else 2,
                "score_reason": f"{len(interesting)} interesting disallowed paths found." if interesting else "Standard robots.txt.",
            })

        # sitemap.xml
        await asyncio.sleep(config.RATE_LIMIT_DELAY)
        resp = await _rate_limited_get(client, f"{origin}/sitemap.xml")
        if resp and resp.status_code == 200 and "<urlset" in resp.text:
            urls = re.findall(r'<loc>(.+?)</loc>', resp.text)
            results.append({
                "target": f"{origin}/sitemap.xml",
                "title": f"sitemap.xml — {len(urls)} URLs indexed",
                "data": {"urls": urls[:100]},
                "score": 2,
                "score_reason": f"Sitemap contains {len(urls)} URLs for manual review.",
            })

    return results


# ── Module 2e: Header & Cookie Security ──────────────────────────────────────

async def check_headers_cookies(url: str) -> list[dict]:
    """Analyze response headers and Set-Cookie flags for security misconfigurations."""
    issues = []

    async with httpx.AsyncClient(timeout=10.0) as client:
        await asyncio.sleep(config.RATE_LIMIT_DELAY)
        try:
            resp = await client.get(url, headers=HEADERS, timeout=10.0, follow_redirects=True)
        except Exception as e:
            return [{"target": url, "title": "Header check failed", "data": {"error": str(e)}, "score": 0}]

    # Security headers
    for header_name, config_check in SECURITY_HEADERS.items():
        value = resp.headers.get(header_name, "")
        if not value:
            if config_check["required"]:
                issues.append({
                    "target": url,
                    "title": f"Missing {header_name}",
                    "data": {"header": header_name, "value": None, "type": "missing_header"},
                    "score": config_check["score"],
                    "score_reason": config_check["issue"],
                })
        else:
            try:
                if not config_check["good"](value):
                    issues.append({
                        "target": url,
                        "title": f"Weak {header_name}",
                        "data": {"header": header_name, "value": value, "type": "weak_header"},
                        "score": config_check["score"] - 1,
                        "score_reason": f"Weak configuration: {value[:100]}",
                    })
            except Exception:
                pass

    # CORS check
    cors_origin = resp.headers.get("Access-Control-Allow-Origin", "")
    cors_creds = resp.headers.get("Access-Control-Allow-Credentials", "")
    if cors_origin == "*":
        issues.append({
            "target": url,
            "title": "CORS: Wildcard Access-Control-Allow-Origin",
            "data": {"header": "Access-Control-Allow-Origin", "value": cors_origin},
            "score": 5 if cors_creds.lower() == "true" else 3,
            "score_reason": "Wildcard CORS" + (
                " + Allow-Credentials=true is a critical misconfiguration." if cors_creds.lower() == "true"
                else " — informational if no credentials involved."
            ),
        })

    # Cookie flags
    for set_cookie in resp.headers.get_list("Set-Cookie") if hasattr(resp.headers, "get_list") else [resp.headers.get("Set-Cookie", "")]:
        if not set_cookie:
            continue
        cookie_name = set_cookie.split("=")[0].strip()
        missing_flags = []
        if "Secure" not in set_cookie:
            missing_flags.append("Secure")
        if "HttpOnly" not in set_cookie:
            missing_flags.append("HttpOnly")
        samesite = ""
        m = re.search(r'SameSite=([^\s;]+)', set_cookie, re.IGNORECASE)
        if not m:
            missing_flags.append("SameSite")
        else:
            samesite = m.group(1)
            if samesite.lower() == "none" and "Secure" not in set_cookie:
                missing_flags.append("SameSite=None requires Secure")

        if missing_flags:
            issues.append({
                "target": url,
                "title": f"Cookie missing flags: {cookie_name}",
                "data": {
                    "cookie": cookie_name,
                    "missing_flags": missing_flags,
                    "raw": set_cookie[:200],
                },
                "score": 5 if "Secure" in missing_flags and "HttpOnly" in missing_flags else 3,
                "score_reason": f"Cookie '{cookie_name}' missing: {', '.join(missing_flags)}",
            })

    return issues
