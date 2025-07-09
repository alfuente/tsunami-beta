#!/bin/bash

# Test script for risk-graph-service API endpoints
# Usage: ./test_api.sh [base_url]

set -e

# Configuration
BASE_URL="${1:-http://localhost:8000}"
API_URL="$BASE_URL/api/v1"
RESULTS_DIR="test_results"
DATE=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$RESULTS_DIR/api_test_$DATE.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create results directory
mkdir -p "$RESULTS_DIR"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Test function
test_endpoint() {
    local method="$1"
    local endpoint="$2"
    local expected_status="$3"
    local description="$4"
    local data="$5"
    
    echo -e "\n${BLUE}Testing: $description${NC}"
    echo "Endpoint: $method $endpoint"
    
    if [ -n "$data" ]; then
        response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
            -X "$method" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "$endpoint")
    else
        response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
            -X "$method" \
            "$endpoint")
    fi
    
    # Extract HTTP status and body
    status=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    body=$(echo "$response" | sed -E 's/HTTPSTATUS:[0-9]*$//')
    
    # Check status
    if [ "$status" = "$expected_status" ]; then
        echo -e "${GREEN}✓ Status: $status (Expected: $expected_status)${NC}"
        log "PASS: $description - Status: $status"
    else
        echo -e "${RED}✗ Status: $status (Expected: $expected_status)${NC}"
        log "FAIL: $description - Status: $status, Expected: $expected_status"
        echo "Response: $body"
        return 1
    fi
    
    # Pretty print JSON response if valid
    if echo "$body" | jq . >/dev/null 2>&1; then
        echo "Response:"
        echo "$body" | jq .
    else
        echo "Response: $body"
    fi
    
    return 0
}

# Test health check
test_health() {
    echo -e "\n${YELLOW}=== HEALTH CHECK TESTS ===${NC}"
    
    test_endpoint "GET" "$BASE_URL/health" "200" "Health check endpoint"
    test_endpoint "GET" "$API_URL/health" "200" "API health check endpoint"
}

# Test domain endpoints
test_domains() {
    echo -e "\n${YELLOW}=== DOMAIN TESTS ===${NC}"
    
    # Get all domains
    test_endpoint "GET" "$API_URL/domains" "200" "Get all domains"
    
    # Get domains with limit
    test_endpoint "GET" "$API_URL/domains?limit=5" "200" "Get domains with limit"
    
    # Get specific domain (assuming bci.cl exists from our previous tests)
    test_endpoint "GET" "$API_URL/domains/bci.cl" "200" "Get specific domain (bci.cl)"
    
    # Get non-existent domain
    test_endpoint "GET" "$API_URL/domains/nonexistent.com" "404" "Get non-existent domain"
}

# Test subdomain endpoints
test_subdomains() {
    echo -e "\n${YELLOW}=== SUBDOMAIN TESTS ===${NC}"
    
    # Get all subdomains
    test_endpoint "GET" "$API_URL/subdomains" "200" "Get all subdomains"
    
    # Get subdomains with limit
    test_endpoint "GET" "$API_URL/subdomains?limit=10" "200" "Get subdomains with limit"
    
    # Get subdomains for specific domain
    test_endpoint "GET" "$API_URL/domains/bci.cl/subdomains" "200" "Get subdomains for bci.cl"
    
    # Get specific subdomain (assuming www.bci.cl exists)
    test_endpoint "GET" "$API_URL/subdomains/www.bci.cl" "200" "Get specific subdomain (www.bci.cl)"
}

# Test IP address endpoints
test_ips() {
    echo -e "\n${YELLOW}=== IP ADDRESS TESTS ===${NC}"
    
    # Get all IPs
    test_endpoint "GET" "$API_URL/ips" "200" "Get all IP addresses"
    
    # Get IPs with limit
    test_endpoint "GET" "$API_URL/ips?limit=5" "200" "Get IPs with limit"
    
    # Get IPs by provider
    test_endpoint "GET" "$API_URL/ips?provider=cloudflare" "200" "Get IPs by provider (cloudflare)"
}

# Test provider endpoints
test_providers() {
    echo -e "\n${YELLOW}=== PROVIDER TESTS ===${NC}"
    
    # Get all providers
    test_endpoint "GET" "$API_URL/providers" "200" "Get all providers"
    
    # Get provider statistics
    test_endpoint "GET" "$API_URL/providers/stats" "200" "Get provider statistics"
}

# Test search endpoints
test_search() {
    echo -e "\n${YELLOW}=== SEARCH TESTS ===${NC}"
    
    # Search domains
    test_endpoint "GET" "$API_URL/search/domains?q=bci" "200" "Search domains by query"
    
    # Search subdomains
    test_endpoint "GET" "$API_URL/search/subdomains?q=www" "200" "Search subdomains by query"
    
    # Search IPs
    test_endpoint "GET" "$API_URL/search/ips?q=104" "200" "Search IPs by query"
}

# Test analytics endpoints
test_analytics() {
    echo -e "\n${YELLOW}=== ANALYTICS TESTS ===${NC}"
    
    # Get domain statistics
    test_endpoint "GET" "$API_URL/analytics/domains/stats" "200" "Get domain statistics"
    
    # Get subdomain statistics
    test_endpoint "GET" "$API_URL/analytics/subdomains/stats" "200" "Get subdomain statistics"
    
    # Get provider distribution
    test_endpoint "GET" "$API_URL/analytics/providers/distribution" "200" "Get provider distribution"
    
    # Get risk metrics
    test_endpoint "GET" "$API_URL/analytics/risk/metrics" "200" "Get risk metrics"
}

# Test graph endpoints
test_graph() {
    echo -e "\n${YELLOW}=== GRAPH TESTS ===${NC}"
    
    # Get graph for domain
    test_endpoint "GET" "$API_URL/graph/domain/bci.cl" "200" "Get graph for domain (bci.cl)"
    
    # Get graph with depth
    test_endpoint "GET" "$API_URL/graph/domain/bci.cl?depth=2" "200" "Get graph for domain with depth"
}

# Test export endpoints
test_export() {
    echo -e "\n${YELLOW}=== EXPORT TESTS ===${NC}"
    
    # Export domains to CSV
    test_endpoint "GET" "$API_URL/export/domains?format=csv" "200" "Export domains to CSV"
    
    # Export domains to JSON
    test_endpoint "GET" "$API_URL/export/domains?format=json" "200" "Export domains to JSON"
}

# Test data ingestion endpoints (POST/PUT)
test_ingestion() {
    echo -e "\n${YELLOW}=== DATA INGESTION TESTS ===${NC}"
    
    # Test domain creation
    local domain_data='{
        "fqdn": "test-domain.com",
        "tld": "com",
        "domain_name": "test-domain"
    }'
    
    test_endpoint "POST" "$API_URL/domains" "201" "Create new domain" "$domain_data"
    
    # Test subdomain creation
    local subdomain_data='{
        "fqdn": "api.test-domain.com",
        "subdomain_name": "api",
        "domain_name": "test-domain",
        "tld": "com",
        "parent_domain": "test-domain.com"
    }'
    
    test_endpoint "POST" "$API_URL/subdomains" "201" "Create new subdomain" "$subdomain_data"
}

# Test error cases
test_error_cases() {
    echo -e "\n${YELLOW}=== ERROR HANDLING TESTS ===${NC}"
    
    # Test invalid JSON
    test_endpoint "POST" "$API_URL/domains" "400" "Create domain with invalid JSON" '{"invalid": json}'
    
    # Test missing required fields
    test_endpoint "POST" "$API_URL/domains" "400" "Create domain with missing fields" '{}'
    
    # Test invalid endpoint
    test_endpoint "GET" "$API_URL/invalid-endpoint" "404" "Test invalid endpoint"
}

# Test performance endpoints
test_performance() {
    echo -e "\n${YELLOW}=== PERFORMANCE TESTS ===${NC}"
    
    # Test large dataset queries
    test_endpoint "GET" "$API_URL/domains?limit=1000" "200" "Large domains query"
    
    # Test complex search
    test_endpoint "GET" "$API_URL/search/subdomains?q=api&limit=100" "200" "Complex subdomain search"
}

# Main test execution
main() {
    echo -e "${BLUE}Starting API tests for: $BASE_URL${NC}"
    echo "Results will be logged to: $LOG_FILE"
    
    # Check if service is running
    echo -e "\n${YELLOW}Checking service availability...${NC}"
    if ! curl -s "$BASE_URL/health" >/dev/null; then
        echo -e "${RED}✗ Service is not available at $BASE_URL${NC}"
        echo "Please make sure the risk-graph-service is running"
        exit 1
    fi
    echo -e "${GREEN}✓ Service is available${NC}"
    
    # Initialize test counters
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    
    # Run test suites
    test_suites=(
        "test_health"
        "test_domains" 
        "test_subdomains"
        "test_ips"
        "test_providers"
        "test_search"
        "test_analytics"
        "test_graph"
        "test_export"
        "test_ingestion"
        "test_error_cases"
        "test_performance"
    )
    
    for suite in "${test_suites[@]}"; do
        echo -e "\n${BLUE}Running $suite...${NC}"
        if $suite; then
            ((passed_tests++))
        else
            ((failed_tests++))
        fi
        ((total_tests++))
        sleep 1  # Brief pause between test suites
    done
    
    # Print summary
    echo -e "\n${YELLOW}=== TEST SUMMARY ===${NC}"
    echo "Total test suites: $total_tests"
    echo -e "Passed: ${GREEN}$passed_tests${NC}"
    echo -e "Failed: ${RED}$failed_tests${NC}"
    
    if [ $failed_tests -eq 0 ]; then
        echo -e "\n${GREEN}🎉 All tests passed!${NC}"
        log "All tests passed successfully"
        exit 0
    else
        echo -e "\n${RED}❌ Some tests failed. Check the log for details.${NC}"
        log "Some tests failed"
        exit 1
    fi
}

# Check dependencies
check_dependencies() {
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}curl is required but not installed${NC}"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        echo -e "${YELLOW}jq is not installed - JSON responses will not be formatted${NC}"
    fi
}

# Help function
show_help() {
    echo "Usage: $0 [base_url]"
    echo ""
    echo "Test the risk-graph-service API endpoints"
    echo ""
    echo "Arguments:"
    echo "  base_url    Base URL of the service (default: http://localhost:8000)"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Test local service"
    echo "  $0 http://localhost:8000              # Test service on specific port"
    echo "  $0 https://api.example.com            # Test remote service"
    echo ""
    echo "Options:"
    echo "  -h, --help    Show this help message"
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
esac

# Run tests
check_dependencies
main "$@"