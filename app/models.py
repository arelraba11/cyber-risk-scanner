"""
models.py
----------
Contains all Pydantic data models used for validation and structured responses.
"""

from pydantic import BaseModel, HttpUrl
from typing import Dict, List, Optional
from datetime import datetime


# Request model – input from user
class ScanRequest(BaseModel):
    """
    Represents the input structure of a scan request.
    """
    url: HttpUrl


# Response model – what the API returns
class ScanResult(BaseModel):
    """
    Represents the result of a website security scan.
    """
    url: str
    https_supported: bool
    certificate_valid: bool
    certificate_issuer: Optional[str]
    certificate_expiry: Optional[datetime]
    security_headers: Dict[str, str]
    missing_headers: List[str]
    risk_level: str
    scan_timestamp: datetime
    error: Optional[str] = None