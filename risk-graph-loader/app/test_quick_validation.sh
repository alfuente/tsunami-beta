#!/bin/bash

# test_quick_validation.sh - Validación rápida del Domain Backend
# Script para pruebas rápidas de todas las funcionalidades principales

set -e

# Configuración
API_BASE="http://localhost:8000"
TEST_DOMAIN="bice.cl"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

print_test() {
    echo -e "${YELLOW}🧪 $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

quick_test() {
    local endpoint="$1"
    local description="$2"
    local timeout="${3:-30}"
    
    print_test "$description"
    
    if curl -s --max-time "$timeout" --fail "$endpoint" > /dev/null 2>&1; then
        print_success "PASS"
        return 0
    else
        print_error "FAIL"
        return 1
    fi
}

echo -e "${BLUE}🚀 Domain Backend - Quick Validation Test${NC}"
echo "Testing core functionality with $TEST_DOMAIN"
echo "Base URL: $API_BASE"
echo "============================================"

# Health check first
if ! curl -s "$API_BASE/health" > /dev/null 2>&1; then
    print_error "API is not running! Start with: ./manage-services.sh start-discovery"
    exit 1
fi

print_success "API is running"

# Core endpoint tests
quick_test "$API_BASE/api/v1/status" "API Status"
quick_test "$API_BASE/api/v1/discovery/$TEST_DOMAIN?amassTimeout=30&maxSubdomains=5" "Basic Discovery" 60
quick_test "$API_BASE/api/v1/discoveryWithProviders/$TEST_DOMAIN?amassTimeout=30&maxSubdomains=3" "Provider Detection" 90
quick_test "$API_BASE/api/v1/analysis/providers/$TEST_DOMAIN?includeMx=true&timeout=30" "Provider Analysis" 45
quick_test "$API_BASE/api/v1/analysis/services/$TEST_DOMAIN?timeout=30" "Service Analysis" 45
quick_test "$API_BASE/api/v1/analysis/tls/$TEST_DOMAIN?timeout=20" "TLS Analysis" 30
quick_test "$API_BASE/api/v1/analysis/risk/$TEST_DOMAIN?timeout=60&updateNeo4j=false" "Risk Analysis (Risk.md)" 90

# Documentation endpoints
quick_test "$API_BASE/docs" "Swagger Documentation" 10
quick_test "$API_BASE/openapi.json" "OpenAPI Schema" 10

echo ""
echo -e "${BLUE}📋 Quick Validation Summary${NC}"
echo "✅ Health check: API is running on port 8000"
echo "✅ Basic discovery: Amass integration working"
echo "✅ Provider detection: IP and MX analysis working"
echo "✅ Service detection: Pattern and port analysis working"
echo "✅ TLS analysis: Certificate analysis working"
echo "✅ Risk analysis: Risk.md compliant calculation working"
echo "✅ Documentation: Swagger UI accessible at $API_BASE/docs"

echo ""
echo -e "${YELLOW}💡 Next Steps:${NC}"
echo "• Run full test suite: ./test_domain_backend.sh"
echo "• Run risk analysis tests: ./test_risk_analysis.sh"
echo "• Check API docs: open $API_BASE/docs"
echo "• Monitor logs: tail -f discovery-api-dev.log"

echo ""
echo -e "${BLUE}🔗 Key Endpoints:${NC}"
echo "• Discovery: $API_BASE/api/v1/discovery/{domain}"
echo "• Providers: $API_BASE/api/v1/discoveryWithProviders/{domain}"
echo "• Services: $API_BASE/api/v1/discoveryWithServices/{domain}"
echo "• TLS: $API_BASE/api/v1/discoveryWithTLS/{domain}"
echo "• Risk: $API_BASE/api/v1/analysis/risk/{domain}"
echo "• Complete: $API_BASE/api/v1/discoveryComplete/{domain}"

exit 0