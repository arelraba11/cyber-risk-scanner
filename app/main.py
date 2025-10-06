from fastapi import FastAPI
from app.routes import scan_routes, log_routes

app = FastAPI(
    title="Cyber Risk Scanner API",
    version="1.0",
    description="An API for scanning websites for SSL and security header risks."
)

# Register routes
app.include_router(scan_routes.router)
app.include_router(log_routes.router)

@app.get("/")
def root():
    """Health check endpoint."""
    return {
        "status": "ok",
        "message": "Cyber Risk Scanner API is online.",
        "available_endpoints": ["/scan", "/logs"]
    }