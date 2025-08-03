#!/usr/bin/env python3
"""
test_config.py - Minimal test configuration for API
"""

from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

app = FastAPI(
    title="Subdomain Discovery API - Test Mode",
    description="Test mode with mock data",
    version="6.0.0-test",
    docs_url="/docs",
    redoc_url="/redoc"
)

class MockDiscoveryResult(BaseModel):
    domain: str
    subdomains: List[str] = []
    providers: List[Dict[str, Any]] = []
    services: List[Dict[str, Any]] = []
    certificates: List[Dict[str, Any]] = []
    risks: List[Dict[str, Any]] = []
    processing_time: float = 1.5
    errors: List[str] = []

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "mode": "test",
        "discovery_engine_available": False
    }

@app.get("/api/v1/discovery/{domain}")
async def mock_discovery(domain: str):
    return MockDiscoveryResult(
        domain=domain,
        subdomains=[f"www.{domain}", f"mail.{domain}", f"api.{domain}"],
        providers=[
            {"name": "cloudflare", "confidence": 0.9, "source": "mock"},
            {"name": "google", "confidence": 0.8, "source": "mock"}
        ],
        services=[
            {"name": "web", "type": "http", "confidence": 0.9},
            {"name": "email", "type": "smtp", "confidence": 0.8}
        ]
    )

@app.get("/api/v1/discoveryWithProviders/{domain}")
async def mock_discovery_with_providers(domain: str):
    result = await mock_discovery(domain)
    result.providers.extend([
        {"name": "microsoft_365", "confidence": 0.95, "source": "mx_record"},
        {"name": "amazon", "confidence": 0.7, "source": "ip_analysis"}
    ])
    return result

if __name__ == "__main__":
    import uvicorn
    print("🧪 Starting test API server...")
    print("📖 Swagger docs: http://localhost:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)
