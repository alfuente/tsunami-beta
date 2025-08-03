#!/bin/bash

# test_domain_backend.sh - Script de pruebas completas para Domain Backend API
# Prueba todas las funcionalidades disponibles en el backend unificado

set -e

# Configuración
API_BASE="http://localhost:8000"
TEST_DOMAIN="bice.cl"
TEST_DOMAIN_2="example.com" 
RESULTS_DIR="test_results_$(date +%Y%m%d_%H%M%S)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "\n${BLUE}===============================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===============================================${NC}"
}

print_test() {
    echo -e "\n${CYAN}🧪 Test: $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ Success: $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  Warning: $1${NC}"
}

print_error() {
    echo -e "${RED}❌ Error: $1${NC}"
}

print_info() {
    echo -e "${PURPLE}ℹ️  Info: $1${NC}"
}

# Function to make API call with logging
api_call() {
    local method="$1"
    local endpoint="$2"
    local description="$3"
    local timeout="${4:-60}"
    local save_file="${5:-}"
    
    print_test "$description"
    echo -e "${YELLOW}Endpoint: ${method} ${endpoint}${NC}"
    
    local start_time=$(date +%s)
    
    if [ "$method" = "GET" ]; then
        if curl -s --max-time "$timeout" -w "HTTP Code: %{http_code} | Time: %{time_total}s\n" \
           "$endpoint" > "${RESULTS_DIR}/$(basename "$save_file" 2>/dev/null || echo "temp_response.json")" 2>/dev/null; then
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            print_success "Completed in ${duration}s"
            
            # Save response if file specified
            if [ -n "$save_file" ]; then
                mv "${RESULTS_DIR}/$(basename "$save_file")" "${RESULTS_DIR}/$save_file" 2>/dev/null || true
                print_info "Response saved to: ${RESULTS_DIR}/$save_file"
            fi
            
            return 0
        else
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            print_error "Failed after ${duration}s"
            return 1
        fi
    elif [ "$method" = "POST" ]; then
        if curl -s --max-time "$timeout" -X POST -w "HTTP Code: %{http_code} | Time: %{time_total}s\n" \
           "$endpoint" > "${RESULTS_DIR}/$(basename "$save_file" 2>/dev/null || echo "temp_response.json")" 2>/dev/null; then
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            print_success "Completed in ${duration}s"
            
            if [ -n "$save_file" ]; then
                mv "${RESULTS_DIR}/$(basename "$save_file")" "${RESULTS_DIR}/$save_file" 2>/dev/null || true
                print_info "Response saved to: ${RESULTS_DIR}/$save_file"
            fi
            
            return 0
        else
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            print_error "Failed after ${duration}s"
            return 1
        fi
    fi
}

# Create results directory
mkdir -p "$RESULTS_DIR"

print_header "Domain Backend API - Comprehensive Test Suite"
echo "Testing Domain Backend (formerly Subdomain Discovery API)"
echo "Base URL: $API_BASE"
echo "Primary test domain: $TEST_DOMAIN"
echo "Secondary test domain: $TEST_DOMAIN_2"
echo "Results will be saved to: $RESULTS_DIR"

# Check if API is running
print_header "1. Health and Status Checks"

api_call "GET" "$API_BASE/health" "Health check" 10 "health.json"

if [ $? -ne 0 ]; then
    print_error "API is not running. Please start it first with: ./manage-services.sh start-discovery"
    print_info "Or manually: cd risk-graph-loader/app && python subdomain_discovery_api.py"
    exit 1
fi

api_call "GET" "$API_BASE/api/v1/status" "API status and configuration" 10 "status.json"

print_header "2. Basic Discovery Tests"

api_call "GET" "$API_BASE/api/v1/discovery/$TEST_DOMAIN?amassTimeout=120&maxSubdomains=20" \
    "Basic subdomain discovery" 180 "discovery_basic.json"

api_call "GET" "$API_BASE/api/v1/discovery/$TEST_DOMAIN_2?amassTimeout=60&maxSubdomains=10" \
    "Basic discovery - alternate domain" 120 "discovery_basic_alt.json"

print_header "3. Provider Detection Tests"

api_call "GET" "$API_BASE/api/v1/discoveryWithProviders/$TEST_DOMAIN?amassTimeout=120&maxSubdomains=20" \
    "Discovery with provider detection" 240 "discovery_with_providers.json"

api_call "GET" "$API_BASE/api/v1/analysis/providers/$TEST_DOMAIN?includeMx=true&timeout=60" \
    "Provider analysis only (with MX records)" 90 "providers_only.json"

api_call "GET" "$API_BASE/api/v1/analysis/providers/$TEST_DOMAIN_2?includeMx=false&timeout=30" \
    "Provider analysis only (without MX)" 60 "providers_only_alt.json"

print_header "4. Service Detection Tests"

api_call "GET" "$API_BASE/api/v1/discoveryWithServices/$TEST_DOMAIN?amassTimeout=120&maxSubdomains=15" \
    "Discovery with service detection" 300 "discovery_with_services.json"

api_call "GET" "$API_BASE/api/v1/analysis/services/$TEST_DOMAIN?includePortScan=true&timeout=90" \
    "Service analysis only (with port scan)" 120 "services_only.json"

api_call "GET" "$API_BASE/api/v1/analysis/services/$TEST_DOMAIN_2?includePortScan=false&timeout=30" \
    "Service analysis only (without port scan)" 60 "services_only_alt.json"

print_header "5. Combined Detection Tests"

api_call "GET" "$API_BASE/api/v1/discoveryWithServicesAndProviders/$TEST_DOMAIN?amassTimeout=120&maxSubdomains=15" \
    "Discovery with services and providers" 360 "discovery_combined.json"

print_header "6. TLS Analysis Tests"

api_call "GET" "$API_BASE/api/v1/discoveryWithTLS/$TEST_DOMAIN?amassTimeout=120&maxSubdomains=10" \
    "Discovery with TLS analysis" 300 "discovery_with_tls.json"

api_call "GET" "$API_BASE/api/v1/analysis/tls/$TEST_DOMAIN?timeout=60" \
    "TLS analysis only" 90 "tls_only.json"

print_header "7. Risk Analysis Tests (According to Risk.md)"

print_info "Testing risk calculation according to Risk.md specifications"

api_call "GET" "$API_BASE/api/v1/analysis/risk/$TEST_DOMAIN?timeout=120&updateNeo4j=true" \
    "Risk analysis only (with Neo4j update)" 180 "risk_only.json"

api_call "GET" "$API_BASE/api/v1/analysis/risk/$TEST_DOMAIN_2?timeout=60&updateNeo4j=false" \
    "Risk analysis only (without Neo4j update)" 120 "risk_only_alt.json"

api_call "GET" "$API_BASE/api/v1/discoveryWithRisk/$TEST_DOMAIN?amassTimeout=120&maxSubdomains=10" \
    "Discovery with risk analysis" 400 "discovery_with_risk.json"

print_header "8. Complete Analysis Tests"

api_call "GET" "$API_BASE/api/v1/discoveryComplete/$TEST_DOMAIN?amassTimeout=180&maxSubdomains=20&maxWorkers=5" \
    "Complete comprehensive analysis" 600 "discovery_complete.json"

print_header "9. Async Job Management Tests"

print_test "Creating async discovery job"
JOB_RESPONSE=$(curl -s -X POST "$API_BASE/api/v1/jobs/discovery/$TEST_DOMAIN_2?enableProviders=true&enableServices=true&enableRisk=true&amassTimeout=60&maxSubdomains=5")
echo "$JOB_RESPONSE" > "${RESULTS_DIR}/job_created.json"

if echo "$JOB_RESPONSE" | grep -q "job_id"; then
    JOB_ID=$(echo "$JOB_RESPONSE" | grep -o '"job_id":"[^"]*"' | cut -d'"' -f4)
    print_success "Job created with ID: $JOB_ID"
    
    # Wait and check job status
    sleep 5
    api_call "GET" "$API_BASE/api/v1/jobs/$JOB_ID" "Check job status" 10 "job_status.json"
    
    # List all jobs
    api_call "GET" "$API_BASE/api/v1/jobs?limit=10" "List all jobs" 10 "jobs_list.json"
    
    # Wait for completion (optional)
    print_info "Waiting 30 seconds for job completion..."
    sleep 30
    api_call "GET" "$API_BASE/api/v1/jobs/$JOB_ID" "Check final job status" 10 "job_final_status.json"
    
else
    print_error "Failed to create async job"
fi

print_header "10. Configuration Tests"

api_call "GET" "$API_BASE/api/v1/config" "Get current configuration" 10 "config_current.json"

print_header "11. Performance and Stress Tests"

print_test "Quick performance test with minimal parameters"
api_call "GET" "$API_BASE/api/v1/discovery/$TEST_DOMAIN_2?amassTimeout=30&maxSubdomains=5&maxWorkers=2" \
    "Quick discovery test" 60 "discovery_quick.json"

print_test "Provider detection performance test"
api_call "GET" "$API_BASE/api/v1/analysis/providers/$TEST_DOMAIN?includeMx=true&timeout=30" \
    "Quick provider analysis" 45 "providers_quick.json"

print_header "12. Error Handling Tests"

print_test "Testing with invalid domain"
api_call "GET" "$API_BASE/api/v1/discovery/invalid-domain-test-12345.invalid?amassTimeout=30&maxSubdomains=1" \
    "Invalid domain test" 60 "error_invalid_domain.json"

print_test "Testing with extreme timeout"
api_call "GET" "$API_BASE/api/v1/analysis/providers/$TEST_DOMAIN?timeout=5" \
    "Very short timeout test" 15 "error_short_timeout.json"

print_header "13. Documentation and Schema Tests"

print_test "Testing OpenAPI documentation endpoint"
if curl -s "$API_BASE/docs" > "${RESULTS_DIR}/swagger_docs.html"; then
    print_success "Swagger documentation accessible"
else
    print_error "Swagger documentation not accessible"
fi

print_test "Testing ReDoc documentation endpoint"
if curl -s "$API_BASE/redoc" > "${RESULTS_DIR}/redoc_docs.html"; then
    print_success "ReDoc documentation accessible"
else
    print_error "ReDoc documentation not accessible"
fi

print_test "Testing OpenAPI schema endpoint"
if curl -s "$API_BASE/openapi.json" > "${RESULTS_DIR}/openapi_schema.json"; then
    print_success "OpenAPI schema accessible"
else
    print_error "OpenAPI schema not accessible"
fi

print_header "Test Summary"

# Generate summary
echo "Test Results Summary:" > "${RESULTS_DIR}/test_summary.txt"
echo "===================" >> "${RESULTS_DIR}/test_summary.txt"
echo "Test Date: $(date)" >> "${RESULTS_DIR}/test_summary.txt"
echo "API Base URL: $API_BASE" >> "${RESULTS_DIR}/test_summary.txt"
echo "Primary Test Domain: $TEST_DOMAIN" >> "${RESULTS_DIR}/test_summary.txt"
echo "Secondary Test Domain: $TEST_DOMAIN_2" >> "${RESULTS_DIR}/test_summary.txt"
echo "" >> "${RESULTS_DIR}/test_summary.txt"

# Count response files
TOTAL_TESTS=$(find "$RESULTS_DIR" -name "*.json" | wc -l)
SUCCESS_TESTS=$(find "$RESULTS_DIR" -name "*.json" -exec grep -l '"domain"\|"status"\|"health"' {} \; 2>/dev/null | wc -l)

echo "Total API Tests: $TOTAL_TESTS" >> "${RESULTS_DIR}/test_summary.txt"
echo "Successful Responses: $SUCCESS_TESTS" >> "${RESULTS_DIR}/test_summary.txt"

print_success "All tests completed!"
print_info "Results saved in: $RESULTS_DIR/"
print_info "View summary: cat ${RESULTS_DIR}/test_summary.txt"

echo -e "\n${BLUE}Key endpoints tested:${NC}"
echo "• Basic Discovery: /api/v1/discovery/{domain}"
echo "• Provider Detection: /api/v1/discoveryWithProviders/{domain}"
echo "• Service Detection: /api/v1/discoveryWithServices/{domain}"
echo "• Combined Analysis: /api/v1/discoveryWithServicesAndProviders/{domain}"
echo "• TLS Analysis: /api/v1/discoveryWithTLS/{domain}"
echo "• Risk Analysis: /api/v1/discoveryWithRisk/{domain} (Risk.md compliant)"
echo "• Complete Analysis: /api/v1/discoveryComplete/{domain}"
echo "• Async Jobs: /api/v1/jobs/discovery/{domain}"
echo "• Specialized Analysis: /api/v1/analysis/{providers|services|tls|risk}/{domain}"

echo -e "\n${BLUE}Risk Analysis Features (Risk.md compliant):${NC}"
echo "• Base Tech Score (40%) - DNS, TLS, CVEs, Redundancy"
echo "• Third-Party Score (25%) - Dependencies with weights"
echo "• Incident Impact (30%) - Incidents with temporal decay"
echo "• Context Boost (5%) - Certifications and compensatory controls"
echo "• Final risk tier calculation and Neo4j updates"

echo -e "\n${YELLOW}Next steps:${NC}"
echo "1. Review individual response files in $RESULTS_DIR/"
echo "2. Check Swagger docs at: $API_BASE/docs"
echo "3. Monitor logs: tail -f discovery-api-dev.log"
echo "4. Test specific endpoints based on your use case"

exit 0