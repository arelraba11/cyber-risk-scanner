from fastapi import APIRouter
from pydantic import BaseModel, HttpUrl
from datetime import datetime, timezone

from app.services.scanner import check_ssl_certificate
from app.services.headers_scanner import scan_security_headers
from app.services.logger import save_scan_log

router = APIRouter()

class ScanRequest(BaseModel):
    url: HttpUrl


@router.post("/scan")
async def scan_website(request: ScanRequest):
    """Run SSL + header scans and return simplified, organized results."""
    url = str(request.url).strip()

    ssl_info = await check_ssl_certificate(url)
    header_info = await scan_security_headers(url)

    # --- Extract and sanitize SSL expiration date ---
    cert_expiry = ssl_info.get("certificate_not_after")
    if isinstance(cert_expiry, datetime):
        valid_until = cert_expiry.date().isoformat()
    elif isinstance(cert_expiry, str):
        valid_until = cert_expiry.split("T")[0]
    else:
        valid_until = None

    # --- Simplify SSL info ---
    issuer_full = ssl_info.get("certificate_issuer", "")
    issuer_name = None
    if issuer_full:
        parts = [p.strip() for p in issuer_full.split(",")]
        for p in parts:
            if p.lower().startswith("organizationname="):
                issuer_name = p.split("=")[-1]
                break

    simplified_ssl = {
        "https_supported": ssl_info.get("https_supported"),
        "issuer": issuer_name,
        "valid_until": valid_until,
        "tls_version": ssl_info.get("tls_version"),
    }

    # --- Simplify Headers info ---
    simplified_headers = {
        "present": header_info.get("present_headers", []),
        "missing": header_info.get("missing_headers", []),
    }

    # --- Overall risk calculation ---
    ssl_ok = (
        ssl_info.get("https_supported")
        and ssl_info.get("certificate_valid")
        and not ssl_info.get("error")
    )
    headers_missing = len(header_info.get("missing_headers", []))
    headers_risk = header_info.get("risk_level", "Unknown")

    if not ssl_ok:
        overall_risk = "High"
    elif header_info.get("trusted_preload"):
        overall_risk = "Trusted (Preloaded)"
    elif headers_missing >= 3 or headers_risk == "High":
        overall_risk = "High"
    elif headers_missing >= 1:
        overall_risk = "Medium"
    else:
        overall_risk = "Low"

    # --- Final structured result ---
    result = {
        "url": url,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ssl": simplified_ssl,
        "security_headers": simplified_headers,
        "risk_level": overall_risk,
        "trusted_preload": header_info.get("trusted_preload", False),
    }

    # Save log entry to file
    save_scan_log(result)

    return result