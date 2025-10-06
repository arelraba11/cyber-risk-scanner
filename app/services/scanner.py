"""
scanner.py
TLS/SSL analysis utilities for the Cyber Risk Scanner.
Handles:
- Extracting SSL certificate details from a live connection.
- Detecting TLS version, cipher suite, and certificate validity.
"""

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
import asyncio
from typing import Dict, Any, List, Optional


def _parse_hostname_from_url(url: str) -> str:
    """Extract clean hostname from a given URL."""
    p = urlparse(url)
    hostname = p.netloc or p.path
    hostname = hostname.strip().rstrip("/")
    if ":" in hostname:
        hostname = hostname.split(":")[0]
    return hostname


def _get_cert_via_socket(hostname: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    """Connect via TLS and return parsed certificate + connection info."""
    result: Dict[str, Any] = {
        "hostname": hostname,
        "port": port,
        "https_supported": False,
        "certificate_issuer": None,
        "certificate_subject": None,
        "certificate_san": [],
        "certificate_not_after": None,
        "certificate_valid": False,
        "tls_version": None,
        "cipher_suite": None,
        "key_bits": None,
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["https_supported"] = True

                # TLS info
                try:
                    cipher, version, bits = ssock.cipher()
                    result.update({"cipher_suite": cipher, "tls_version": version, "key_bits": bits})
                except Exception:
                    pass

                # Issuer / Subject
                try:
                    result["certificate_issuer"] = ", ".join(
                        f"{k}={v}" for r in cert.get("issuer", ()) for k, v in r
                    )
                    result["certificate_subject"] = ", ".join(
                        f"{k}={v}" for r in cert.get("subject", ()) for k, v in r
                    )
                except Exception:
                    pass

                # SAN
                try:
                    result["certificate_san"] = [
                        v for (typ, v) in cert.get("subjectAltName", ()) if typ.upper() == "DNS"
                    ]
                except Exception:
                    pass

                # Expiry
                try:
                    exp_str: Optional[str] = cert.get("notAfter")
                    if exp_str:
                        try:
                            dt = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                        except ValueError:
                            dt = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y")
                        dt = dt.replace(tzinfo=timezone.utc)
                        result["certificate_not_after"] = dt
                        result["certificate_valid"] = dt > datetime.now(timezone.utc)
                except Exception:
                    pass

    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except socket.gaierror:
        result["error"] = "DNS lookup failed"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except Exception as e:
        result["error"] = f"Network error: {e}"

    return result


async def check_ssl_certificate(url: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    """Async wrapper for SSL/TLS check."""
    hostname = _parse_hostname_from_url(url)
    if not hostname:
        return {"error": "Invalid URL", "https_supported": False}
    return await asyncio.to_thread(_get_cert_via_socket, hostname, port, timeout)