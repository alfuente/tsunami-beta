#!/usr/bin/env python3
"""
simple_test_api.py - API simplificada para testing de reorganización
"""

from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Any
import uvicorn

app = FastAPI(
    title="Domain Backend - Test Mode",
    description="Simplified API for testing reorganization",
    version="6.0.0-test"
)

class SimpleResponse(BaseModel):
    domain: str
    message: str
    status: str = "success"
    backend_location: str = "domain-backend directory"

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "message": "Domain Backend API is running from domain-backend directory",
        "reorganization_status": "success"
    }

@app.get("/api/v1/test/{domain}")
async def test_endpoint(domain: str):
    return SimpleResponse(
        domain=domain,
        message=f"Successfully reached domain-backend API for {domain}",
        backend_location="domain-backend directory"
    )

@app.get("/api/v1/status")
async def status():
    return {
        "service": "domain-backend",
        "status": "operational",
        "location": "domain-backend directory",
        "reorganization": "completed successfully"
    }

if __name__ == "__main__":
    print("🚀 Starting Domain Backend Test API...")
    print("📍 Running from: domain-backend directory")
    print("🔗 Health check: http://localhost:8000/health")
    print("📖 Test endpoint: http://localhost:8000/api/v1/test/example.com")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)