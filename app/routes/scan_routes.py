from fastapi import APIRouter
from app.models import ScanRequest
from app.services.scanner import check_ssl_certificate
from datetime import datetime

router = APIRouter()

@router.post("/scan")
async def scan_endpoint(request: ScanRequest):
    """
    Simple scan endpoint for now:
    - runs SSL certificate check and returns its structured result
    """
    ssl_info = await check_ssl_certificate(str(request.url))
    response = {
        "url": request.url,
        "scan_timestamp": datetime.utcnow().isoformat() + "Z",
        "ssl": ssl_info
    }
    return response