#!/bin/bash

# Test script for ACCS (Algoritmo de Centralidad y Criticidad Sistémica)
# This script tests the Systemic Centrality and Criticality Algorithm

API_BASE="http://localhost:8002"
SCRIPT_NAME="ACCS Algorithm Test"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}${SCRIPT_NAME}${NC}"
echo -e "${BLUE}=========================================${NC}"
echo

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Function to calculate execution time
calculate_time() {
    local start_time=$1
    local end_time=$2
    local duration=$((end_time - start_time))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))
    
    if [ $minutes -gt 0 ]; then
        echo "${minutes}m ${seconds}s"
    else
        echo "${seconds}s"
    fi
}

# Test 1: Basic ACCS calculation with default parameters
print_header "Test 1: Basic ACCS Calculation"

REQUEST_PAYLOAD='{
    "node_types": ["Organization", "Domain"],
    "include_critical_bonus": true
}'

echo "Request payload:"
echo "$REQUEST_PAYLOAD" | jq .
echo

print_status "Starting ACCS calculation..."
START_TIME=$(date +%s)
START_TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

print_status "Start time: $START_TIMESTAMP"

RESPONSE=$(curl -s -X POST "${API_BASE}/algorithms/accs" \
    -H "Content-Type: application/json" \
    -d "$REQUEST_PAYLOAD")

END_TIME=$(date +%s)
END_TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
EXECUTION_TIME=$(calculate_time $START_TIME $END_TIME)

print_status "End time: $END_TIMESTAMP"
print_status "Total execution time: $EXECUTION_TIME"
echo

# Check if response is valid JSON
if echo "$RESPONSE" | jq . >/dev/null 2>&1; then
    ALGORITHM=$(echo "$RESPONSE" | jq -r '.algorithm // "N/A"')
    TOTAL_NODES=$(echo "$RESPONSE" | jq -r '.total_nodes // 0')
    CRITICAL_NODES=$(echo "$RESPONSE" | jq -r '.summary.critical_nodes // 0')
    HIGH_RISK_NODES=$(echo "$RESPONSE" | jq -r '.summary.high_risk_nodes // 0')
    AVERAGE_ICS=$(echo "$RESPONSE" | jq -r '.summary.average_ics // 0')
    
    print_status "Algorithm: $ALGORITHM"
    print_status "Total nodes analyzed: $TOTAL_NODES"
    print_status "Critical nodes (ICS ≥ 0.8): $CRITICAL_NODES"
    print_status "High risk nodes (ICS ≥ 0.6): $HIGH_RISK_NODES"
    print_status "Average ICS score: $AVERAGE_ICS"
    
    # Show top 5 most critical entities
    print_header "Top 5 Most Critical Entities"
    echo "$RESPONSE" | jq -r '
        .results | to_entries | 
        sort_by(-.value.ics) | 
        limit(5; .[]) | 
        "\(.key): ICS = \(.value.ics | tostring | .[0:5]) (\(.value.classification))"
    ' 2>/dev/null || print_warning "Could not parse top entities"
    
    echo
    print_header "Detailed Results Sample (First 3 entities)"
    echo "$RESPONSE" | jq '.results | to_entries | limit(3; .[])' 2>/dev/null
    
else
    print_error "Invalid response received"
    print_error "Raw response: $RESPONSE"
fi

echo
echo "========================================="

# Test 2: ACCS with sector filtering
print_header "Test 2: ACCS with Banking Sector Filter"

REQUEST_PAYLOAD_2='{
    "node_types": ["Organization"],
    "sectors": ["banking", "telecommunications"],
    "include_critical_bonus": true
}'

echo "Request payload:"
echo "$REQUEST_PAYLOAD_2" | jq .
echo

print_status "Starting filtered ACCS calculation..."
START_TIME_2=$(date +%s)
START_TIMESTAMP_2=$(date '+%Y-%m-%d %H:%M:%S')

print_status "Start time: $START_TIMESTAMP_2"

RESPONSE_2=$(curl -s -X POST "${API_BASE}/algorithms/accs" \
    -H "Content-Type: application/json" \
    -d "$REQUEST_PAYLOAD_2")

END_TIME_2=$(date +%s)
END_TIMESTAMP_2=$(date '+%Y-%m-%d %H:%M:%S')
EXECUTION_TIME_2=$(calculate_time $START_TIME_2 $END_TIME_2)

print_status "End time: $END_TIMESTAMP_2"
print_status "Total execution time: $EXECUTION_TIME_2"
echo

if echo "$RESPONSE_2" | jq . >/dev/null 2>&1; then
    TOTAL_NODES_2=$(echo "$RESPONSE_2" | jq -r '.total_nodes // 0')
    CRITICAL_NODES_2=$(echo "$RESPONSE_2" | jq -r '.summary.critical_nodes // 0')
    
    print_status "Filtered results - Total nodes: $TOTAL_NODES_2"
    print_status "Critical nodes in banking/telecom: $CRITICAL_NODES_2"
    
    if [ "$TOTAL_NODES_2" -gt 0 ]; then
        print_header "Top Critical Banking/Telecom Entities"
        echo "$RESPONSE_2" | jq -r '
            .results | to_entries | 
            sort_by(-.value.ics) | 
            limit(3; .[]) | 
            "\(.key): ICS = \(.value.ics | tostring | .[0:5]), Sector = \(.value.sector)"
        ' 2>/dev/null
    else
        print_warning "No results found for banking/telecommunications sectors"
    fi
else
    print_error "Invalid response received for filtered test"
fi

echo
echo "========================================="

# Performance summary
print_header "Performance Summary"
print_status "Test 1 (All nodes) execution time: $EXECUTION_TIME"
print_status "Test 2 (Filtered) execution time: $EXECUTION_TIME_2"

if [ "$TOTAL_NODES" -gt 0 ] && [ ${START_TIME} -gt 0 ]; then
    NODES_PER_SECOND=$((TOTAL_NODES / (END_TIME - START_TIME + 1)))
    print_status "Processing rate: ~$NODES_PER_SECOND nodes/second"
fi

echo
print_header "ACCS Algorithm Information"
print_status "Formula: ICS = 0.3 × Grado + 0.25 × Intermediación + 0.25 × PageRank + 0.2 × Cercanía + Bonus"
print_status "Critical sectors bonus: banking, telecommunications, energy (+0.2), government, health (+0.1)"
print_status "Classification: Critical (≥0.8), High (≥0.6), Medium (≥0.4), Low (<0.4)"

echo
print_status "ACCS algorithm test completed!"
echo -e "${BLUE}=========================================${NC}"