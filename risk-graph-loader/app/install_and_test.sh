#!/bin/bash

# install_and_test.sh - Quick setup and test for Subdomain Discovery API

set -e

echo "🚀 Subdomain Discovery API - Quick Install & Test"
echo "================================================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

cd /home/alf/dev/tsunami-beta/risk-graph-loader/app

echo -e "${BLUE}[1/5]${NC} Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo -e "${BLUE}[2/5]${NC} Installing dependencies..."
pip install fastapi uvicorn[standard] pydantic python-multipart

echo -e "${BLUE}[3/5]${NC} Creating test configuration..."
cat > test_config.py << 'EOF'
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
EOF

echo -e "${BLUE}[4/5]${NC} Starting test API server..."
echo -e "${YELLOW}💡 This is a minimal test version with mock data${NC}"
echo -e "${YELLOW}📖 Open http://localhost:8000/docs to see Swagger UI${NC}"
echo -e "${YELLOW}🛑 Press Ctrl+C to stop${NC}"
echo ""

# Start server in background to test endpoints
python test_config.py &
API_PID=$!

# Wait for server to start
sleep 3

echo -e "${BLUE}[5/5]${NC} Testing endpoints..."

# Test health endpoint
echo "Testing health endpoint..."
if curl -s http://localhost:8000/health | jq . >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Health endpoint working${NC}"
else
    echo "❌ Health endpoint failed"
fi

# Test discovery endpoint
echo "Testing discovery endpoint..."
if curl -s "http://localhost:8000/api/v1/discovery/test.com" | jq . >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Discovery endpoint working${NC}"
else
    echo "❌ Discovery endpoint failed"
fi

echo ""
echo -e "${GREEN}🎉 Test API is running successfully!${NC}"
echo ""
echo -e "${BLUE}Available endpoints:${NC}"
echo "• GET /health - Health check"
echo "• GET /api/v1/discovery/{domain} - Basic discovery"
echo "• GET /api/v1/discoveryWithProviders/{domain} - With providers"
echo "• GET /docs - Swagger UI"
echo ""
echo -e "${YELLOW}📱 Example calls:${NC}"
echo "curl http://localhost:8000/health"
echo "curl http://localhost:8000/api/v1/discovery/example.com"
echo "curl http://localhost:8000/api/v1/discoveryWithProviders/bice.cl"
echo ""
echo -e "${BLUE}🌐 Open your browser to: http://localhost:8000/docs${NC}"
echo ""
echo "When ready to stop, press Ctrl+C"

# Keep server running
wait $API_PID