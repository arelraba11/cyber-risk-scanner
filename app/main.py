"""
main.py
-------
Entry point of the FastAPI application.
Responsible for initializing the app and registering routes.
"""

from fastapi import FastAPI
from app.routes import scan_routes

app = FastAPI(title="Cyber Risk Scanner", version="0.1")

# Register router for /scan
app.include_router(scan_routes.router)

@app.get("/")
def root():
    """
    Health check endpoint.
    Returns a basic response to confirm the server is running.
    """
    return {"status": "ok", "message": "Cyber Risk Scanner API is online."}