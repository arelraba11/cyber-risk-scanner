import httpx
from typing import Dict, Any
from urllib.parse import urlparse

# --- Security headers we want to verify ---
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
]

# --- Header aliases (case-insensitive + variants) ---
ALIASES = {
    "content-security-policy": ["content-security-policy", "content-security-policy-report-only"],
    "x-frame-options": ["x-frame-options"],
    "x-content-type-options": ["x-content-type-options"],
    "strict-transport-security": ["strict-transport-security"],
    "referrer-policy": ["referrer-policy"],
    "permissions-policy": ["permissions-policy"],
    "cross-origin-resource-policy": ["cross-origin-resource-policy"],
    "cross-origin-opener-policy": ["cross-origin-opener-policy"],
    "cross-origin-embedder-policy": ["cross-origin-embedder-policy"],
}


def _normalize_url(url: str) -> str:
    """Ensure URL includes scheme (https:// by default)."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
    return url


async def _check_hsts_preload(domain: str) -> bool:
    """
    Check HSTS preload status using hstspreload.org API only.
    Returns True only if JSON response explicitly includes {"status": "preloaded"}.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; CyberRiskScanner/1.0; +https://example.local)",
        "Accept": "application/json"
    }

    # Try both domain forms: with and without www
    candidates = [domain, domain.replace("www.", ""), f"www.{domain}"]
    endpoints = [
        "https://hstspreload.org/api/v2/status?domain={d}",
        "https://hstspreload.org/api/v2/status/{d}"
    ]

    async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
        for cand in candidates:
            for ep in endpoints:
                url = ep.format(d=cand)
                try:
                    resp = await client.get(url, headers=headers)
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            if data.get("status") == "preloaded":
                                return True
                        except Exception:
                            continue
                except httpx.RequestError:
                    continue
    return False


async def scan_security_headers(url: str, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Perform a full security header scan and classify risk
    based solely on HSTS preload status and header presence.
    """
    url = _normalize_url(url)
    hostname = urlparse(url).hostname or ""

    result: Dict[str, Any] = {
        "headers": {},
        "present_headers": [],
        "missing_headers": [],
        "risk_level": "Unknown",
        "trusted_preload": False,
        "error": None,
    }

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
            try:
                response = await client.head(url)
                if response.status_code >= 400:
                    response = await client.get(url)
            except httpx.HTTPError:
                response = await client.get(url)

            # Normalize headers (lowercase keys)
            resp_headers = {k.lower(): v for k, v in response.headers.items()}
            result["headers"] = resp_headers

            # Identify which headers are present / missing
            present, missing = [], []
            for canonical in SECURITY_HEADERS:
                key = canonical.lower()
                accepted = ALIASES.get(key, [key])
                found = any(a in resp_headers for a in accepted)
                (present if found else missing).append(canonical)

            result["present_headers"] = present
            result["missing_headers"] = missing

            # 🔍 Check HSTS preload status strictly via hstspreload.org
            preload_status = await _check_hsts_preload(hostname)
            result["trusted_preload"] = preload_status

            # Determine final risk level
            if preload_status:
                result["risk_level"] = "Trusted (Preloaded)"
            else:
                missing_count = len(missing)
                if missing_count == 0:
                    result["risk_level"] = "Low"
                elif missing_count <= 3:
                    result["risk_level"] = "Medium"
                else:
                    result["risk_level"] = "High"

    except httpx.RequestError as e:
        result["error"] = f"Request failed: {e}"
        result["risk_level"] = "Unknown"

    return result