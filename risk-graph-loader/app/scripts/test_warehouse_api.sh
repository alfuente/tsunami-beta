#!/bin/bash

# Test script for risk-warehouse-service API endpoints
# Usage: ./test_warehouse_api.sh [base_url]

set -e

# Configuration
BASE_URL="${1:-http://localhost:8001}"
API_URL="$BASE_URL/api/v1"
RESULTS_DIR="test_results"
DATE=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$RESULTS_DIR/warehouse_test_$DATE.log"

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

# Test warehouse datasets
test_datasets() {
    echo -e "\n${YELLOW}=== DATASET TESTS ===${NC}"
    
    # Get all datasets
    test_endpoint "GET" "$API_URL/datasets" "200" "Get all datasets"
    
    # Get specific dataset
    test_endpoint "GET" "$API_URL/datasets/domains" "200" "Get domains dataset"
    test_endpoint "GET" "$API_URL/datasets/subdomains" "200" "Get subdomains dataset"
    test_endpoint "GET" "$API_URL/datasets/ips" "200" "Get IPs dataset"
    
    # Get dataset metadata
    test_endpoint "GET" "$API_URL/datasets/domains/metadata" "200" "Get domains dataset metadata"
}

# Test ETL operations
test_etl() {
    echo -e "\n${YELLOW}=== ETL TESTS ===${NC}"
    
    # Trigger ETL job
    local etl_job='{
        "source": "neo4j",
        "target": "iceberg",
        "dataset": "domains",
        "incremental": false
    }'
    
    test_endpoint "POST" "$API_URL/etl/jobs" "202" "Create ETL job" "$etl_job"
    
    # Get ETL jobs
    test_endpoint "GET" "$API_URL/etl/jobs" "200" "Get all ETL jobs"
    
    # Get ETL job status
    test_endpoint "GET" "$API_URL/etl/jobs/latest" "200" "Get latest ETL job status"
}

# Test data quality
test_data_quality() {
    echo -e "\n${YELLOW}=== DATA QUALITY TESTS ===${NC}"
    
    # Get data quality metrics
    test_endpoint "GET" "$API_URL/quality/metrics" "200" "Get data quality metrics"
    
    # Get data quality for specific dataset
    test_endpoint "GET" "$API_URL/quality/datasets/domains" "200" "Get domain data quality"
    
    # Run data quality check
    local quality_check='{
        "dataset": "domains",
        "checks": ["completeness", "uniqueness", "validity"]
    }'
    
    test_endpoint "POST" "$API_URL/quality/checks" "202" "Run data quality check" "$quality_check"
}

# Test analytics and reporting
test_analytics() {
    echo -e "\n${YELLOW}=== ANALYTICS TESTS ===${NC}"
    
    # Get analytics dashboard data
    test_endpoint "GET" "$API_URL/analytics/dashboard" "200" "Get analytics dashboard"
    
    # Get time series data
    test_endpoint "GET" "$API_URL/analytics/timeseries/domains?period=7d" "200" "Get domain time series"
    
    # Get aggregated metrics
    test_endpoint "GET" "$API_URL/analytics/aggregations/providers" "200" "Get provider aggregations"
}

# Test data lineage
test_lineage() {
    echo -e "\n${YELLOW}=== DATA LINEAGE TESTS ===${NC}"
    
    # Get data lineage
    test_endpoint "GET" "$API_URL/lineage/datasets/domains" "200" "Get domain dataset lineage"
    
    # Get lineage graph
    test_endpoint "GET" "$API_URL/lineage/graph" "200" "Get complete lineage graph"
}

# Test data catalog
test_catalog() {
    echo -e "\n${YELLOW}=== DATA CATALOG TESTS ===${NC}"
    
    # Get catalog entries
    test_endpoint "GET" "$API_URL/catalog" "200" "Get data catalog"
    
    # Search catalog
    test_endpoint "GET" "$API_URL/catalog/search?q=domain" "200" "Search data catalog"
    
    # Get schema information
    test_endpoint "GET" "$API_URL/catalog/schemas/domains" "200" "Get domain schema"
}

# Test data export
test_export() {
    echo -e "\n${YELLOW}=== DATA EXPORT TESTS ===${NC}"
    
    # Export dataset
    local export_request='{
        "dataset": "domains",
        "format": "parquet",
        "filters": {"tld": "cl"},
        "compression": "snappy"
    }'
    
    test_endpoint "POST" "$API_URL/export" "202" "Create export job" "$export_request"
    
    # Get export jobs
    test_endpoint "GET" "$API_URL/export/jobs" "200" "Get export jobs"
}

# Test batch processing
test_batch() {
    echo -e "\n${YELLOW}=== BATCH PROCESSING TESTS ===${NC}"
    
    # Submit batch job
    local batch_job='{
        "job_type": "risk_scoring",
        "parameters": {
            "dataset": "subdomains",
            "model_version": "v1.0"
        }
    }'
    
    test_endpoint "POST" "$API_URL/batch/jobs" "202" "Submit batch job" "$batch_job"
    
    # Get batch jobs
    test_endpoint "GET" "$API_URL/batch/jobs" "200" "Get batch jobs"
    
    # Get job queue status
    test_endpoint "GET" "$API_URL/batch/queue/status" "200" "Get batch queue status"
}

# Test configuration
test_config() {
    echo -e "\n${YELLOW}=== CONFIGURATION TESTS ===${NC}"
    
    # Get service configuration
    test_endpoint "GET" "$API_URL/config" "200" "Get service configuration"
    
    # Get data source configuration
    test_endpoint "GET" "$API_URL/config/datasources" "200" "Get data source configuration"
    
    # Update configuration (if allowed)
    local config_update='{
        "batch_size": 1000,
        "timeout": 300
    }'
    
    test_endpoint "PUT" "$API_URL/config/processing" "200" "Update processing config" "$config_update"
}

# Test monitoring
test_monitoring() {
    echo -e "\n${YELLOW}=== MONITORING TESTS ===${NC}"
    
    # Get system metrics
    test_endpoint "GET" "$API_URL/monitoring/metrics" "200" "Get system metrics"
    
    # Get service health
    test_endpoint "GET" "$API_URL/monitoring/health" "200" "Get detailed health status"
    
    # Get performance metrics
    test_endpoint "GET" "$API_URL/monitoring/performance" "200" "Get performance metrics"
}

# Test SQL interface
test_sql() {
    echo -e "\n${YELLOW}=== SQL INTERFACE TESTS ===${NC}"
    
    # Execute SQL query
    local sql_query='{
        "query": "SELECT count(*) as total FROM domains WHERE tld = '\''cl'\''",
        "limit": 1000
    }'
    
    test_endpoint "POST" "$API_URL/sql/execute" "200" "Execute SQL query" "$sql_query"
    
    # Get query history
    test_endpoint "GET" "$API_URL/sql/history" "200" "Get SQL query history"
    
    # Validate SQL query
    local validate_query='{
        "query": "SELECT * FROM domains WHERE invalid_column = '\''test'\''"
    }'
    
    test_endpoint "POST" "$API_URL/sql/validate" "400" "Validate invalid SQL query" "$validate_query"
}

# Test streaming data
test_streaming() {
    echo -e "\n${YELLOW}=== STREAMING TESTS ===${NC}"
    
    # Get streaming status
    test_endpoint "GET" "$API_URL/streaming/status" "200" "Get streaming status"
    
    # Get stream metadata
    test_endpoint "GET" "$API_URL/streaming/streams" "200" "Get available streams"
    
    # Create stream subscription
    local subscription='{
        "stream": "domain_updates",
        "filters": {"tld": "cl"},
        "format": "json"
    }'
    
    test_endpoint "POST" "$API_URL/streaming/subscriptions" "201" "Create stream subscription" "$subscription"
}

# Main test execution
main() {
    echo -e "${BLUE}Starting Warehouse API tests for: $BASE_URL${NC}"
    echo "Results will be logged to: $LOG_FILE"
    
    # Check if service is running
    echo -e "\n${YELLOW}Checking service availability...${NC}"
    if ! curl -s "$BASE_URL/health" >/dev/null; then
        echo -e "${RED}✗ Service is not available at $BASE_URL${NC}"
        echo "Please make sure the risk-warehouse-service is running"
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
        "test_datasets"
        "test_etl"
        "test_data_quality"
        "test_analytics"
        "test_lineage"
        "test_catalog"
        "test_export"
        "test_batch"
        "test_config"
        "test_monitoring"
        "test_sql"
        "test_streaming"
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
    echo "Test the risk-warehouse-service API endpoints"
    echo ""
    echo "Arguments:"
    echo "  base_url    Base URL of the service (default: http://localhost:8001)"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Test local service"
    echo "  $0 http://localhost:8001              # Test service on specific port"
    echo "  $0 https://warehouse.example.com      # Test remote service"
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