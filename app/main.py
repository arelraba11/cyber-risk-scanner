from fastapi import FastAPI
from app.routes import scan_routes

app = FastAPI(title="Cyber Risk Scanner API")

app.include_router(scan_routes.router)

@app.get("/")
def root():
    return {"status": "ok", "message": "Cyber Risk Scanner API is online."}