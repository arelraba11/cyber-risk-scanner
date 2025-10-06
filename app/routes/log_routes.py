from fastapi import APIRouter, Query
from typing import Optional
from app.services.logger import get_scan_logs

router = APIRouter()

@router.get("/logs")
def read_scan_logs(
    limit: int = Query(10, ge=1, le=100, description="Maximum number of logs to return"),
    domain: Optional[str] = Query(None, description="Filter results by domain name")
):
    """
    Retrieve stored scan logs (optionally filtered by domain).
    Returns the newest scans first.
    """
    logs = get_scan_logs(limit=limit, domain=domain)
    return {
        "count": len(logs),
        "filters": {"domain": domain, "limit": limit},
        "results": logs
    }