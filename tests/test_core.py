import json
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
from app.services.logger import LOG_FILE, save_scan_log, get_scan_logs

client = TestClient(app)

def setup_module(module):
    """Setup: ensure clean log file before tests."""
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    if LOG_FILE.exists():
        LOG_FILE.unlink()  # remove old logs

def test_scan_endpoint_example_com():
    """Test the /scan endpoint with example.com"""
    response = client.post("/scan", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()
    assert "ssl" in data
    assert "security_headers" in data
    assert data["url"].startswith("https://example.com")
    assert "risk_level" in data

def test_log_saving_and_retrieval():
    """Test saving and retrieving logs."""
    fake_scan = {
        "url": "https://test.com/",
        "scan_timestamp": "2025-10-06T12:00:00Z",
        "ssl": {"https_supported": True},
        "security_headers": {"present": [], "missing": []},
        "risk_level": "Low",
        "trusted_preload": False
    }

    # Save the log
    save_scan_log(fake_scan)
    assert LOG_FILE.exists()

    # Retrieve logs
    logs = get_scan_logs()
    assert len(logs) >= 1
    assert any("https://test.com" in log["url"] for log in logs)

def test_logs_endpoint():
    """Test the /logs endpoint"""
    response = client.get("/logs")
    assert response.status_code == 200
    data = response.json()
    assert "results" in data
    assert isinstance(data["results"], list)