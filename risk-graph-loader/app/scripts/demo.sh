#!/bin/bash

# Demo script showing how to use all the testing scripts together
# This script demonstrates a complete testing workflow

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🎬 Risk Analysis Platform - Complete Testing Demo${NC}"
echo "================================================================="
echo ""

# Step 1: Start development services
echo -e "${YELLOW}Step 1: Starting Development Services${NC}"
echo "Starting risk-graph-service and risk-warehouse-service..."
echo ""

if ./start_dev_services.sh; then
    echo -e "${GREEN}✓ Services started successfully${NC}"
    sleep 5
else
    echo -e "${RED}✗ Failed to start services${NC}"
    exit 1
fi

# Step 2: Check service status
echo -e "\n${YELLOW}Step 2: Checking Service Status${NC}"
./start_dev_services.sh --status

# Step 3: Run API tests
echo -e "\n${YELLOW}Step 3: Running API Tests${NC}"
echo "Testing risk-graph-service API..."
if ./test_api.sh; then
    echo -e "${GREEN}✓ Graph service API tests passed${NC}"
else
    echo -e "${RED}✗ Graph service API tests failed${NC}"
fi

echo -e "\nTesting risk-warehouse-service API..."
if ./test_warehouse_api.sh; then
    echo -e "${GREEN}✓ Warehouse service API tests passed${NC}"
else
    echo -e "${RED}✗ Warehouse service API tests failed${NC}"
fi

# Step 4: Run integration tests
echo -e "\n${YELLOW}Step 4: Running Integration Tests${NC}"
echo "Testing complete data flow..."
if ./integration_test.sh; then
    echo -e "${GREEN}✓ Integration tests passed${NC}"
else
    echo -e "${RED}✗ Integration tests failed${NC}"
fi

# Step 5: Run performance tests
echo -e "\n${YELLOW}Step 5: Running Performance Tests${NC}"
echo "Testing performance with light load..."
if ./performance_test.sh --concurrent-users 5 --test-duration 30; then
    echo -e "${GREEN}✓ Performance tests completed${NC}"
else
    echo -e "${RED}✗ Performance tests failed${NC}"
fi

# Step 6: Show results
echo -e "\n${YELLOW}Step 6: Test Results Summary${NC}"
echo "Test results are available in:"
echo "  - test_results/ directory"
echo "  - HTML reports for detailed analysis"
echo "  - CSV files for performance data"
echo ""

echo "Recent test files:"
ls -la test_results/ | tail -10

# Step 7: Cleanup option
echo -e "\n${YELLOW}Step 7: Cleanup${NC}"
read -p "Do you want to stop the services? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Stopping services..."
    ./start_dev_services.sh --stop
    echo -e "${GREEN}✓ Services stopped${NC}"
else
    echo "Services are still running. Use './start_dev_services.sh --stop' to stop them."
fi

echo -e "\n${GREEN}🎉 Demo completed successfully!${NC}"
echo "================================================================="