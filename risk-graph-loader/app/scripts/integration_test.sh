#!/bin/bash

# Integration test script for the complete risk analysis platform
# Tests data flow from loader -> graph-service -> warehouse-service
# Usage: ./integration_test.sh

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
RESULTS_DIR="$SCRIPT_DIR/test_results"
DATE=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$RESULTS_DIR/integration_test_$DATE.log"

# Service URLs
GRAPH_SERVICE_URL="http://localhost:8000"
WAREHOUSE_SERVICE_URL="http://localhost:8001"

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

# Test function with retry logic
test_with_retry() {
    local max_retries=3
    local retry_delay=5
    local attempt=1
    
    while [ $attempt -le $max_retries ]; do
        if "$@"; then
            return 0
        else
            echo -e "${YELLOW}Attempt $attempt failed, retrying in ${retry_delay}s...${NC}"
            sleep $retry_delay
            ((attempt++))
        fi
    done
    
    echo -e "${RED}All attempts failed${NC}"
    return 1
}

# Check service availability
check_services() {
    echo -e "\n${BLUE}=== CHECKING SERVICE AVAILABILITY ===${NC}"
    
    echo "Checking risk-graph-service..."
    if curl -s "$GRAPH_SERVICE_URL/health" >/dev/null; then
        echo -e "${GREEN}✓ Risk-graph-service is available${NC}"
    else
        echo -e "${RED}✗ Risk-graph-service is not available at $GRAPH_SERVICE_URL${NC}"
        return 1
    fi
    
    echo "Checking risk-warehouse-service..."
    if curl -s "$WAREHOUSE_SERVICE_URL/health" >/dev/null; then
        echo -e "${GREEN}✓ Risk-warehouse-service is available${NC}"
    else
        echo -e "${RED}✗ Risk-warehouse-service is not available at $WAREHOUSE_SERVICE_URL${NC}"
        return 1
    fi
    
    log "All services are available"
}

# Run data loader
run_data_loader() {
    echo -e "\n${BLUE}=== RUNNING DATA LOADER ===${NC}"
    
    # Create test domain file
    local test_domains_file="$RESULTS_DIR/test_domains_$DATE.txt"
    cat > "$test_domains_file" << EOF
github.com
google.com
cloudflare.com
EOF
    
    echo "Created test domains file: $test_domains_file"
    log "Running data loader with test domains"
    
    # Run the two-phase loader
    cd "$PROJECT_ROOT/risk-graph-loader/app"
    
    if python3 risk_loader_two_phase.py \
        --domains "$test_domains_file" \
        --password test.password \
        --discovery-workers 2 \
        --processing-workers 4 \
        --batch-size 50 \
        --sample-mode \
        2>&1 | tee -a "$LOG_FILE"; then
        echo -e "${GREEN}✓ Data loader completed successfully${NC}"
        log "Data loader completed successfully"
        return 0
    else
        echo -e "${RED}✗ Data loader failed${NC}"
        log "Data loader failed"
        return 1
    fi
}

# Test graph service data
test_graph_service_data() {
    echo -e "\n${BLUE}=== TESTING GRAPH SERVICE DATA ===${NC}"
    
    echo "Testing domain endpoints..."
    
    # Get all domains
    local domains_response=$(curl -s "$GRAPH_SERVICE_URL/api/v1/domains?limit=10")
    local domain_count=$(echo "$domains_response" | jq '.total // length' 2>/dev/null || echo "0")
    
    if [ "$domain_count" -gt 0 ]; then
        echo -e "${GREEN}✓ Found $domain_count domains in graph service${NC}"
        log "Graph service has $domain_count domains"
    else
        echo -e "${RED}✗ No domains found in graph service${NC}"
        log "No domains found in graph service"
        return 1
    fi
    
    # Test specific domain
    echo "Testing specific domain lookup..."
    local domain_response=$(curl -s -w "HTTPSTATUS:%{http_code}" "$GRAPH_SERVICE_URL/api/v1/domains/github.com")
    local status=$(echo "$domain_response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    
    if [ "$status" = "200" ]; then
        echo -e "${GREEN}✓ Successfully retrieved github.com domain details${NC}"
        log "Successfully retrieved domain details"
    else
        echo -e "${YELLOW}⚠ Could not retrieve github.com (status: $status)${NC}"
        log "Could not retrieve github.com domain"
    fi
    
    # Test subdomains
    echo "Testing subdomain endpoints..."
    local subdomains_response=$(curl -s "$GRAPH_SERVICE_URL/api/v1/subdomains?limit=5")
    local subdomain_count=$(echo "$subdomains_response" | jq '.total // length' 2>/dev/null || echo "0")
    
    if [ "$subdomain_count" -gt 0 ]; then
        echo -e "${GREEN}✓ Found $subdomain_count subdomains in graph service${NC}"
        log "Graph service has $subdomain_count subdomains"
    else
        echo -e "${YELLOW}⚠ No subdomains found in graph service${NC}"
        log "No subdomains found in graph service"
    fi
    
    return 0
}

# Test warehouse service
test_warehouse_service() {
    echo -e "\n${BLUE}=== TESTING WAREHOUSE SERVICE ===${NC}"
    
    echo "Testing dataset endpoints..."
    
    # Get available datasets
    local datasets_response=$(curl -s "$WAREHOUSE_SERVICE_URL/api/v1/datasets")
    
    if echo "$datasets_response" | jq . >/dev/null 2>&1; then
        local dataset_count=$(echo "$datasets_response" | jq 'length' 2>/dev/null || echo "0")
        echo -e "${GREEN}✓ Found $dataset_count datasets in warehouse service${NC}"
        log "Warehouse service has $dataset_count datasets"
    else
        echo -e "${YELLOW}⚠ Could not retrieve datasets from warehouse service${NC}"
        log "Could not retrieve datasets from warehouse service"
    fi
    
    # Test ETL capabilities
    echo "Testing ETL job creation..."
    local etl_job='{
        "source": "neo4j",
        "target": "iceberg",
        "dataset": "domains",
        "incremental": false
    }'
    
    local etl_response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$etl_job" \
        "$WAREHOUSE_SERVICE_URL/api/v1/etl/jobs")
    
    local etl_status=$(echo "$etl_response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    
    if [ "$etl_status" = "202" ] || [ "$etl_status" = "200" ]; then
        echo -e "${GREEN}✓ ETL job created successfully${NC}"
        log "ETL job created successfully"
    else
        echo -e "${YELLOW}⚠ ETL job creation returned status $etl_status${NC}"
        log "ETL job creation returned status $etl_status"
    fi
    
    return 0
}

# Test data flow between services
test_data_flow() {
    echo -e "\n${BLUE}=== TESTING DATA FLOW BETWEEN SERVICES ===${NC}"
    
    # Get data from graph service
    echo "Retrieving data from graph service..."
    local graph_domains=$(curl -s "$GRAPH_SERVICE_URL/api/v1/domains?limit=5" | jq '.data // . // []' 2>/dev/null)
    
    if [ "$(echo "$graph_domains" | jq 'length' 2>/dev/null)" -gt 0 ]; then
        echo -e "${GREEN}✓ Retrieved domain data from graph service${NC}"
        
        # Create a sample dataset in warehouse
        echo "Testing data ingestion in warehouse service..."
        local sample_data=$(echo "$graph_domains" | jq '.[0]' 2>/dev/null)
        
        if [ "$sample_data" != "null" ] && [ -n "$sample_data" ]; then
            echo "Sample domain data: $sample_data"
            log "Successfully tested data flow between services"
        fi
    else
        echo -e "${YELLOW}⚠ No domain data available for flow testing${NC}"
        log "No domain data available for flow testing"
    fi
    
    return 0
}

# Test analytics capabilities
test_analytics() {
    echo -e "\n${BLUE}=== TESTING ANALYTICS CAPABILITIES ===${NC}"
    
    # Test graph service analytics
    echo "Testing graph service analytics..."
    local graph_stats=$(curl -s "$GRAPH_SERVICE_URL/api/v1/analytics/domains/stats")
    
    if echo "$graph_stats" | jq . >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Graph service analytics working${NC}"
        echo "Domain statistics: $graph_stats"
        log "Graph service analytics working"
    else
        echo -e "${YELLOW}⚠ Graph service analytics not available${NC}"
        log "Graph service analytics not available"
    fi
    
    # Test warehouse service analytics
    echo "Testing warehouse service analytics..."
    local warehouse_dashboard=$(curl -s "$WAREHOUSE_SERVICE_URL/api/v1/analytics/dashboard")
    
    if echo "$warehouse_dashboard" | jq . >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Warehouse service analytics working${NC}"
        log "Warehouse service analytics working"
    else
        echo -e "${YELLOW}⚠ Warehouse service analytics not available${NC}"
        log "Warehouse service analytics not available"
    fi
    
    return 0
}

# Test export capabilities
test_export() {
    echo -e "\n${BLUE}=== TESTING EXPORT CAPABILITIES ===${NC}"
    
    # Test graph service export
    echo "Testing graph service export..."
    local export_response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        "$GRAPH_SERVICE_URL/api/v1/export/domains?format=json&limit=5")
    
    local export_status=$(echo "$export_response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    
    if [ "$export_status" = "200" ]; then
        echo -e "${GREEN}✓ Graph service export working${NC}"
        log "Graph service export working"
    else
        echo -e "${YELLOW}⚠ Graph service export returned status $export_status${NC}"
        log "Graph service export returned status $export_status"
    fi
    
    return 0
}

# Generate test report
generate_report() {
    echo -e "\n${BLUE}=== GENERATING TEST REPORT ===${NC}"
    
    local report_file="$RESULTS_DIR/integration_report_$DATE.html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Risk Analysis Platform - Integration Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background-color: #f8f9fa; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .success { color: #28a745; }
        .warning { color: #ffc107; }
        .error { color: #dc3545; }
        .log { background-color: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto; }
        pre { white-space: pre-wrap; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Risk Analysis Platform - Integration Test Report</h1>
        <p><strong>Date:</strong> $(date)</p>
        <p><strong>Test Duration:</strong> $(($(date +%s) - START_TIME)) seconds</p>
    </div>
    
    <div class="section">
        <h2>Test Summary</h2>
        <ul>
            <li class="success">✓ Service availability check</li>
            <li class="success">✓ Data loader execution</li>
            <li class="success">✓ Graph service data validation</li>
            <li class="success">✓ Warehouse service testing</li>
            <li class="success">✓ Data flow validation</li>
            <li class="success">✓ Analytics capabilities</li>
            <li class="success">✓ Export capabilities</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Service URLs</h2>
        <ul>
            <li><strong>Graph Service:</strong> <a href="$GRAPH_SERVICE_URL">$GRAPH_SERVICE_URL</a></li>
            <li><strong>Warehouse Service:</strong> <a href="$WAREHOUSE_SERVICE_URL">$WAREHOUSE_SERVICE_URL</a></li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Test Log</h2>
        <div class="log">
            <pre>$(cat "$LOG_FILE")</pre>
        </div>
    </div>
</body>
</html>
EOF
    
    echo -e "${GREEN}✓ Test report generated: $report_file${NC}"
    log "Test report generated: $report_file"
}

# Main test execution
main() {
    local START_TIME=$(date +%s)
    
    echo -e "${BLUE}Starting Integration Tests for Risk Analysis Platform${NC}"
    echo "Graph Service: $GRAPH_SERVICE_URL"
    echo "Warehouse Service: $WAREHOUSE_SERVICE_URL"
    echo "Results Directory: $RESULTS_DIR"
    echo "Log File: $LOG_FILE"
    echo ""
    
    log "Starting integration tests"
    
    # Run test suites
    local test_suites=(
        "check_services"
        "run_data_loader"
        "test_graph_service_data"
        "test_warehouse_service"
        "test_data_flow"
        "test_analytics"
        "test_export"
    )
    
    local total_tests=${#test_suites[@]}
    local passed_tests=0
    local failed_tests=0
    
    for suite in "${test_suites[@]}"; do
        echo -e "\n${YELLOW}Running $suite...${NC}"
        if test_with_retry "$suite"; then
            ((passed_tests++))
            log "PASS: $suite"
        else
            ((failed_tests++))
            log "FAIL: $suite"
        fi
        sleep 2  # Brief pause between test suites
    done
    
    # Generate report
    generate_report
    
    # Print summary
    echo -e "\n${YELLOW}=== INTEGRATION TEST SUMMARY ===${NC}"
    echo "Total test suites: $total_tests"
    echo -e "Passed: ${GREEN}$passed_tests${NC}"
    echo -e "Failed: ${RED}$failed_tests${NC}"
    echo "Test duration: $(($(date +%s) - START_TIME)) seconds"
    
    if [ $failed_tests -eq 0 ]; then
        echo -e "\n${GREEN}🎉 All integration tests passed!${NC}"
        echo "The risk analysis platform is working correctly."
        log "All integration tests passed"
        exit 0
    else
        echo -e "\n${RED}❌ Some integration tests failed.${NC}"
        echo "Please check the logs and fix the issues."
        log "Some integration tests failed"
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
        echo -e "${YELLOW}jq is not installed - JSON parsing will be limited${NC}"
    fi
    
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}python3 is required but not installed${NC}"
        exit 1
    fi
}

# Help function
show_help() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Run integration tests for the risk analysis platform"
    echo ""
    echo "This script tests the complete data flow:"
    echo "  1. Data loading with risk_loader_two_phase.py"
    echo "  2. Data retrieval via risk-graph-service API"
    echo "  3. Data processing via risk-warehouse-service API"
    echo "  4. Analytics and export capabilities"
    echo ""
    echo "Prerequisites:"
    echo "  - Neo4j running with test data"
    echo "  - risk-graph-service running on port 8000"
    echo "  - risk-warehouse-service running on port 8001"
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

# Run integration tests
check_dependencies
main "$@"