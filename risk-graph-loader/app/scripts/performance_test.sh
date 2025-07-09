#!/bin/bash

# Performance test script for risk-graph-service and risk-warehouse-service
# Tests load handling, response times, and throughput
# Usage: ./performance_test.sh [options]

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/test_results"
DATE=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$RESULTS_DIR/performance_test_$DATE.log"

# Service URLs
GRAPH_SERVICE_URL="http://localhost:8000"
WAREHOUSE_SERVICE_URL="http://localhost:8001"

# Test parameters
CONCURRENT_USERS=10
TEST_DURATION=60
RAMP_UP_TIME=10
REQUESTS_PER_SECOND=10

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --concurrent-users)
            CONCURRENT_USERS="$2"
            shift 2
            ;;
        --test-duration)
            TEST_DURATION="$2"
            shift 2
            ;;
        --ramp-up-time)
            RAMP_UP_TIME="$2"
            shift 2
            ;;
        --requests-per-second)
            REQUESTS_PER_SECOND="$2"
            shift 2
            ;;
        --graph-service-url)
            GRAPH_SERVICE_URL="$2"
            shift 2
            ;;
        --warehouse-service-url)
            WAREHOUSE_SERVICE_URL="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Create results directory
mkdir -p "$RESULTS_DIR"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Check if Apache Bench is available
check_ab() {
    if ! command -v ab &> /dev/null; then
        echo -e "${RED}Apache Bench (ab) is required but not installed${NC}"
        echo "Install with: sudo apt-get install apache2-utils"
        exit 1
    fi
}

# Check if wrk is available (better load testing tool)
check_wrk() {
    if command -v wrk &> /dev/null; then
        echo -e "${GREEN}✓ wrk is available${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠ wrk is not installed, falling back to ab${NC}"
        return 1
    fi
}

# Performance test with Apache Bench
run_ab_test() {
    local url="$1"
    local description="$2"
    local concurrent="$3"
    local requests="$4"
    local output_file="$5"
    
    echo -e "\n${BLUE}Testing: $description${NC}"
    echo "URL: $url"
    echo "Concurrent users: $concurrent"
    echo "Total requests: $requests"
    
    log "Starting AB test: $description"
    
    ab -n "$requests" -c "$concurrent" -g "$output_file.gnuplot" "$url" > "$output_file" 2>&1
    
    # Parse results
    local requests_per_sec=$(grep "Requests per second" "$output_file" | awk '{print $4}')
    local time_per_request=$(grep "Time per request" "$output_file" | head -1 | awk '{print $4}')
    local failed_requests=$(grep "Failed requests" "$output_file" | awk '{print $3}')
    
    echo "Results:"
    echo "  Requests per second: $requests_per_sec"
    echo "  Time per request: $time_per_request ms"
    echo "  Failed requests: $failed_requests"
    
    log "AB test completed: $description - RPS: $requests_per_sec, Failed: $failed_requests"
}

# Performance test with wrk
run_wrk_test() {
    local url="$1"
    local description="$2"
    local threads="$3"
    local connections="$4"
    local duration="$5"
    local output_file="$6"
    
    echo -e "\n${BLUE}Testing: $description${NC}"
    echo "URL: $url"
    echo "Threads: $threads"
    echo "Connections: $connections"
    echo "Duration: $duration seconds"
    
    log "Starting WRK test: $description"
    
    wrk -t"$threads" -c"$connections" -d"$duration"s --latency "$url" > "$output_file" 2>&1
    
    # Parse results
    local requests_per_sec=$(grep "Requests/sec" "$output_file" | awk '{print $2}')
    local avg_latency=$(grep "Latency" "$output_file" | awk '{print $2}')
    local total_requests=$(grep "requests in" "$output_file" | awk '{print $1}')
    
    echo "Results:"
    echo "  Requests per second: $requests_per_sec"
    echo "  Average latency: $avg_latency"
    echo "  Total requests: $total_requests"
    
    log "WRK test completed: $description - RPS: $requests_per_sec, Latency: $avg_latency"
}

# Test graph service endpoints
test_graph_service_performance() {
    echo -e "\n${YELLOW}=== GRAPH SERVICE PERFORMANCE TESTS ===${NC}"
    
    local use_wrk=false
    if check_wrk; then
        use_wrk=true
    fi
    
    # Test domains endpoint
    local domains_url="$GRAPH_SERVICE_URL/api/v1/domains?limit=10"
    local domains_output="$RESULTS_DIR/graph_domains_$DATE"
    
    if [ "$use_wrk" = true ]; then
        run_wrk_test "$domains_url" "Graph Service - Domains List" 4 "$CONCURRENT_USERS" "$TEST_DURATION" "$domains_output.txt"
    else
        run_ab_test "$domains_url" "Graph Service - Domains List" "$CONCURRENT_USERS" $((CONCURRENT_USERS * 50)) "$domains_output.txt"
    fi
    
    # Test subdomains endpoint
    local subdomains_url="$GRAPH_SERVICE_URL/api/v1/subdomains?limit=10"
    local subdomains_output="$RESULTS_DIR/graph_subdomains_$DATE"
    
    if [ "$use_wrk" = true ]; then
        run_wrk_test "$subdomains_url" "Graph Service - Subdomains List" 4 "$CONCURRENT_USERS" "$TEST_DURATION" "$subdomains_output.txt"
    else
        run_ab_test "$subdomains_url" "Graph Service - Subdomains List" "$CONCURRENT_USERS" $((CONCURRENT_USERS * 50)) "$subdomains_output.txt"
    fi
    
    # Test search endpoint
    local search_url="$GRAPH_SERVICE_URL/api/v1/search/domains?q=github"
    local search_output="$RESULTS_DIR/graph_search_$DATE"
    
    if [ "$use_wrk" = true ]; then
        run_wrk_test "$search_url" "Graph Service - Domain Search" 4 "$CONCURRENT_USERS" "$TEST_DURATION" "$search_output.txt"
    else
        run_ab_test "$search_url" "Graph Service - Domain Search" "$CONCURRENT_USERS" $((CONCURRENT_USERS * 30)) "$search_output.txt"
    fi
    
    # Test analytics endpoint
    local analytics_url="$GRAPH_SERVICE_URL/api/v1/analytics/domains/stats"
    local analytics_output="$RESULTS_DIR/graph_analytics_$DATE"
    
    if [ "$use_wrk" = true ]; then
        run_wrk_test "$analytics_url" "Graph Service - Analytics" 4 "$CONCURRENT_USERS" "$TEST_DURATION" "$analytics_output.txt"
    else
        run_ab_test "$analytics_url" "Graph Service - Analytics" "$CONCURRENT_USERS" $((CONCURRENT_USERS * 20)) "$analytics_output.txt"
    fi
}

# Test warehouse service endpoints
test_warehouse_service_performance() {
    echo -e "\n${YELLOW}=== WAREHOUSE SERVICE PERFORMANCE TESTS ===${NC}"
    
    local use_wrk=false
    if check_wrk; then
        use_wrk=true
    fi
    
    # Test datasets endpoint
    local datasets_url="$WAREHOUSE_SERVICE_URL/api/v1/datasets"
    local datasets_output="$RESULTS_DIR/warehouse_datasets_$DATE"
    
    if [ "$use_wrk" = true ]; then
        run_wrk_test "$datasets_url" "Warehouse Service - Datasets List" 4 "$CONCURRENT_USERS" "$TEST_DURATION" "$datasets_output.txt"
    else
        run_ab_test "$datasets_url" "Warehouse Service - Datasets List" "$CONCURRENT_USERS" $((CONCURRENT_USERS * 50)) "$datasets_output.txt"
    fi
    
    # Test analytics dashboard
    local dashboard_url="$WAREHOUSE_SERVICE_URL/api/v1/analytics/dashboard"
    local dashboard_output="$RESULTS_DIR/warehouse_dashboard_$DATE"
    
    if [ "$use_wrk" = true ]; then
        run_wrk_test "$dashboard_url" "Warehouse Service - Analytics Dashboard" 4 "$CONCURRENT_USERS" "$TEST_DURATION" "$dashboard_output.txt"
    else
        run_ab_test "$dashboard_url" "Warehouse Service - Analytics Dashboard" "$CONCURRENT_USERS" $((CONCURRENT_USERS * 30)) "$dashboard_output.txt"
    fi
    
    # Test monitoring endpoint
    local monitoring_url="$WAREHOUSE_SERVICE_URL/api/v1/monitoring/metrics"
    local monitoring_output="$RESULTS_DIR/warehouse_monitoring_$DATE"
    
    if [ "$use_wrk" = true ]; then
        run_wrk_test "$monitoring_url" "Warehouse Service - Monitoring" 4 "$CONCURRENT_USERS" "$TEST_DURATION" "$monitoring_output.txt"
    else
        run_ab_test "$monitoring_url" "Warehouse Service - Monitoring" "$CONCURRENT_USERS" $((CONCURRENT_USERS * 40)) "$monitoring_output.txt"
    fi
}

# Test stress scenarios
test_stress_scenarios() {
    echo -e "\n${YELLOW}=== STRESS TEST SCENARIOS ===${NC}"
    
    # High concurrency test
    echo -e "\n${BLUE}High Concurrency Test${NC}"
    local high_concurrency=$((CONCURRENT_USERS * 3))
    local stress_url="$GRAPH_SERVICE_URL/api/v1/domains?limit=5"
    local stress_output="$RESULTS_DIR/stress_high_concurrency_$DATE"
    
    if check_wrk; then
        run_wrk_test "$stress_url" "Stress Test - High Concurrency" 8 "$high_concurrency" 30 "$stress_output.txt"
    else
        run_ab_test "$stress_url" "Stress Test - High Concurrency" "$high_concurrency" $((high_concurrency * 10)) "$stress_output.txt"
    fi
    
    # Large dataset test
    echo -e "\n${BLUE}Large Dataset Test${NC}"
    local large_dataset_url="$GRAPH_SERVICE_URL/api/v1/domains?limit=1000"
    local large_dataset_output="$RESULTS_DIR/stress_large_dataset_$DATE"
    
    if check_wrk; then
        run_wrk_test "$large_dataset_url" "Stress Test - Large Dataset" 4 "$CONCURRENT_USERS" 30 "$large_dataset_output.txt"
    else
        run_ab_test "$large_dataset_url" "Stress Test - Large Dataset" "$CONCURRENT_USERS" $((CONCURRENT_USERS * 20)) "$large_dataset_output.txt"
    fi
    
    # Complex query test
    echo -e "\n${BLUE}Complex Query Test${NC}"
    local complex_query_url="$GRAPH_SERVICE_URL/api/v1/graph/domain/github.com?depth=3"
    local complex_query_output="$RESULTS_DIR/stress_complex_query_$DATE"
    
    if check_wrk; then
        run_wrk_test "$complex_query_url" "Stress Test - Complex Query" 2 5 20 "$complex_query_output.txt"
    else
        run_ab_test "$complex_query_url" "Stress Test - Complex Query" 5 50 "$complex_query_output.txt"
    fi
}

# Test response time distribution
test_response_time_distribution() {
    echo -e "\n${YELLOW}=== RESPONSE TIME DISTRIBUTION TEST ===${NC}"
    
    local test_url="$GRAPH_SERVICE_URL/api/v1/domains?limit=10"
    local distribution_output="$RESULTS_DIR/response_time_distribution_$DATE"
    
    echo "Testing response time distribution..."
    
    # Run 100 individual requests and measure response times
    echo "timestamp,response_time_ms" > "$distribution_output.csv"
    
    for i in {1..100}; do
        local start_time=$(date +%s%3N)
        curl -s "$test_url" >/dev/null
        local end_time=$(date +%s%3N)
        local response_time=$((end_time - start_time))
        
        echo "$(date '+%Y-%m-%d %H:%M:%S'),$response_time" >> "$distribution_output.csv"
        
        if [ $((i % 10)) -eq 0 ]; then
            echo "Completed $i/100 requests"
        fi
        
        sleep 0.1
    done
    
    # Calculate statistics
    local avg_response_time=$(awk -F',' 'NR>1 {sum+=$2; count++} END {print sum/count}' "$distribution_output.csv")
    local max_response_time=$(awk -F',' 'NR>1 {if($2>max) max=$2} END {print max}' "$distribution_output.csv")
    local min_response_time=$(awk -F',' 'NR>1 {if(min=="" || $2<min) min=$2} END {print min}' "$distribution_output.csv")
    
    echo "Response Time Statistics:"
    echo "  Average: ${avg_response_time}ms"
    echo "  Maximum: ${max_response_time}ms"
    echo "  Minimum: ${min_response_time}ms"
    
    log "Response time distribution test completed - Avg: ${avg_response_time}ms, Max: ${max_response_time}ms, Min: ${min_response_time}ms"
}

# Generate performance report
generate_performance_report() {
    echo -e "\n${BLUE}=== GENERATING PERFORMANCE REPORT ===${NC}"
    
    local report_file="$RESULTS_DIR/performance_report_$DATE.html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Risk Analysis Platform - Performance Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background-color: #f8f9fa; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .results { background-color: #f8f9fa; padding: 15px; border-radius: 5px; }
        .metric { margin: 10px 0; }
        .good { color: #28a745; }
        .warning { color: #ffc107; }
        .error { color: #dc3545; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Risk Analysis Platform - Performance Test Report</h1>
        <p><strong>Date:</strong> $(date)</p>
        <p><strong>Test Configuration:</strong></p>
        <ul>
            <li>Concurrent Users: $CONCURRENT_USERS</li>
            <li>Test Duration: $TEST_DURATION seconds</li>
            <li>Graph Service: $GRAPH_SERVICE_URL</li>
            <li>Warehouse Service: $WAREHOUSE_SERVICE_URL</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Test Results Summary</h2>
        <p>Performance tests completed successfully. Detailed results are available in the log files.</p>
    </div>
    
    <div class="section">
        <h2>Result Files</h2>
        <ul>
            <li><strong>Log File:</strong> $LOG_FILE</li>
            <li><strong>Results Directory:</strong> $RESULTS_DIR</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Performance Metrics</h2>
        <p>Check individual result files for detailed performance metrics including:</p>
        <ul>
            <li>Requests per second</li>
            <li>Average response time</li>
            <li>Failed requests</li>
            <li>Latency distribution</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
            <li>Monitor response times under load</li>
            <li>Scale services horizontally if needed</li>
            <li>Optimize database queries for better performance</li>
            <li>Implement caching for frequently accessed data</li>
        </ul>
    </div>
</body>
</html>
EOF
    
    echo -e "${GREEN}✓ Performance report generated: $report_file${NC}"
    log "Performance report generated: $report_file"
}

# Check service availability
check_services() {
    echo -e "\n${BLUE}=== CHECKING SERVICE AVAILABILITY ===${NC}"
    
    echo "Checking risk-graph-service..."
    if curl -s "$GRAPH_SERVICE_URL/health" >/dev/null; then
        echo -e "${GREEN}✓ Risk-graph-service is available${NC}"
    else
        echo -e "${RED}✗ Risk-graph-service is not available at $GRAPH_SERVICE_URL${NC}"
        exit 1
    fi
    
    echo "Checking risk-warehouse-service..."
    if curl -s "$WAREHOUSE_SERVICE_URL/health" >/dev/null; then
        echo -e "${GREEN}✓ Risk-warehouse-service is available${NC}"
    else
        echo -e "${RED}✗ Risk-warehouse-service is not available at $WAREHOUSE_SERVICE_URL${NC}"
        exit 1
    fi
    
    log "All services are available for performance testing"
}

# Main execution
main() {
    echo -e "${BLUE}Starting Performance Tests${NC}"
    echo "Graph Service: $GRAPH_SERVICE_URL"
    echo "Warehouse Service: $WAREHOUSE_SERVICE_URL"
    echo "Concurrent Users: $CONCURRENT_USERS"
    echo "Test Duration: $TEST_DURATION seconds"
    echo "Results Directory: $RESULTS_DIR"
    echo ""
    
    log "Starting performance tests"
    
    # Check prerequisites
    check_ab
    check_services
    
    # Run performance tests
    test_graph_service_performance
    test_warehouse_service_performance
    test_stress_scenarios
    test_response_time_distribution
    
    # Generate report
    generate_performance_report
    
    echo -e "\n${GREEN}🎉 Performance tests completed!${NC}"
    echo "Results are available in: $RESULTS_DIR"
    log "Performance tests completed successfully"
}

# Help function
show_help() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Run performance tests for risk-graph-service and risk-warehouse-service"
    echo ""
    echo "Options:"
    echo "  --concurrent-users NUM         Number of concurrent users (default: 10)"
    echo "  --test-duration SECONDS        Test duration in seconds (default: 60)"
    echo "  --ramp-up-time SECONDS         Ramp up time in seconds (default: 10)"
    echo "  --requests-per-second NUM      Requests per second (default: 10)"
    echo "  --graph-service-url URL        Graph service URL (default: http://localhost:8000)"
    echo "  --warehouse-service-url URL    Warehouse service URL (default: http://localhost:8001)"
    echo "  -h, --help                     Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                        # Run with default settings"
    echo "  $0 --concurrent-users 20 --test-duration 120   # Heavy load test"
    echo "  $0 --concurrent-users 5 --test-duration 30     # Light load test"
    echo ""
    echo "Prerequisites:"
    echo "  - Apache Bench (ab) installed: sudo apt-get install apache2-utils"
    echo "  - wrk (optional, for better load testing): https://github.com/wg/wrk"
    echo "  - Services running and accessible"
}

# Run main function
main "$@"