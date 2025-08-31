#!/bin/bash

# Test script for APR (Algoritmo de Propagación de Riesgo)
# This script tests the Risk Propagation Algorithm using epidemiological model

API_BASE="http://localhost:8002"
SCRIPT_NAME="APR Algorithm Test (Risk Propagation)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
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

print_simulation() {
    echo -e "${PURPLE}[SIM]${NC} $1"
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

# Function to get sample node for testing
get_sample_node() {
    print_status "Finding sample node for propagation test..."
    
    # Try to get a domain node first
    SAMPLE_RESPONSE=$(curl -s "${API_BASE}/stats" 2>/dev/null)
    
    if echo "$SAMPLE_RESPONSE" | jq . >/dev/null 2>&1; then
        # Try to extract a node from stats or use a common domain
        SAMPLE_NODE="bancochile.cl"  # Common Chilean domain for testing
    else
        SAMPLE_NODE="test.example.com"  # Fallback
    fi
    
    echo "$SAMPLE_NODE"
}

# Test 1: Basic APR simulation with default parameters
print_header "Test 1: Basic Risk Propagation Simulation"

SAMPLE_NODE=$(get_sample_node)
print_status "Using initial node: $SAMPLE_NODE"

REQUEST_PAYLOAD="{
    \"initial_node\": \"$SAMPLE_NODE\",
    \"max_time\": 30,
    \"base_contagion_rate\": 0.1,
    \"incubation_rate\": 0.3,
    \"recovery_rate\": 0.05
}"

echo "Request payload:"
echo "$REQUEST_PAYLOAD" | jq .
echo

print_simulation "Starting risk propagation simulation..."
START_TIME=$(date +%s)
START_TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

print_status "Start time: $START_TIMESTAMP"
print_simulation "Simulating S-E-I-R epidemiological model..."

RESPONSE=$(curl -s -X POST "${API_BASE}/algorithms/apr" \
    -H "Content-Type: application/json" \
    -d "$REQUEST_PAYLOAD")

END_TIME=$(date +%s)
END_TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
EXECUTION_TIME=$(calculate_time $START_TIME $END_TIME)

print_status "End time: $END_TIMESTAMP"
print_status "Total simulation time: $EXECUTION_TIME"
echo

# Check if response is valid JSON
if echo "$RESPONSE" | jq . >/dev/null 2>&1; then
    ALGORITHM=$(echo "$RESPONSE" | jq -r '.algorithm // "N/A"')
    INITIAL_NODE=$(echo "$RESPONSE" | jq -r '.initial_node // "N/A"')
    TOTAL_AFFECTED=$(echo "$RESPONSE" | jq -r '.results.total_affected_nodes // 0')
    INFECTION_RATE=$(echo "$RESPONSE" | jq -r '.results.final_infection_rate // 0')
    TIME_TO_PEAK=$(echo "$RESPONSE" | jq -r '.results.time_to_peak // 0')
    RECOVERY_TIME=$(echo "$RESPONSE" | jq -r '.results.recovery_time // 0')
    
    print_status "Algorithm: $ALGORITHM"
    print_status "Initial infection node: $INITIAL_NODE"
    print_simulation "Total affected nodes: $TOTAL_AFFECTED"
    print_simulation "Final infection rate: $(echo "scale=2; $INFECTION_RATE * 100" | bc 2>/dev/null || echo $INFECTION_RATE)%"
    print_simulation "Time to peak infection: $TIME_TO_PEAK steps"
    print_simulation "Recovery time: $RECOVERY_TIME steps"
    
    # Show affected sectors
    echo
    print_header "Affected Sectors Analysis"
    AFFECTED_SECTORS=$(echo "$RESPONSE" | jq -r '.results.affected_sectors[]?' 2>/dev/null)
    if [ ! -z "$AFFECTED_SECTORS" ]; then
        echo "$AFFECTED_SECTORS" | while read sector; do
            print_simulation "Affected sector: $sector"
        done
    else
        print_warning "No sector information available"
    fi
    
    # Show cascade paths sample
    echo
    print_header "Cascade Propagation Paths (Top 3)"
    echo "$RESPONSE" | jq -r '
        .results.cascade_paths[]? | 
        select(. != null) |
        "Path: \(.)"
    ' 2>/dev/null | head -3 || print_warning "No cascade paths available"
    
    # Show simulation timeline sample
    echo
    print_header "Simulation Timeline (First 10 Steps)"
    echo "$RESPONSE" | jq '
        .results.simulation_timeline | 
        if type == "array" then 
            limit(10; .[])
        else 
            . 
        end
    ' 2>/dev/null || print_warning "Timeline data not available"
    
else
    print_error "Invalid response received"
    print_error "Raw response: $RESPONSE"
    
    # Check if node exists in graph
    print_warning "Testing if initial node exists in system..."
    NODE_CHECK=$(curl -s "${API_BASE}/health" 2>/dev/null)
    if echo "$NODE_CHECK" | jq . >/dev/null 2>&1; then
        print_status "API is responding correctly"
        print_warning "The node '$SAMPLE_NODE' may not exist in the graph"
        print_warning "Try using an actual domain from your Neo4j database"
    fi
fi

echo
echo "========================================="

# Test 2: High contagion simulation
print_header "Test 2: High Contagion Rate Simulation"

REQUEST_PAYLOAD_2="{
    \"initial_node\": \"$SAMPLE_NODE\",
    \"max_time\": 20,
    \"base_contagion_rate\": 0.3,
    \"incubation_rate\": 0.4,
    \"recovery_rate\": 0.02
}"

echo "Request payload (high contagion):"
echo "$REQUEST_PAYLOAD_2" | jq .
echo

print_simulation "Starting high contagion scenario..."
START_TIME_2=$(date +%s)

RESPONSE_2=$(curl -s -X POST "${API_BASE}/algorithms/apr" \
    -H "Content-Type: application/json" \
    -d "$REQUEST_PAYLOAD_2")

END_TIME_2=$(date +%s)
EXECUTION_TIME_2=$(calculate_time $START_TIME_2 $END_TIME_2)

print_status "High contagion simulation time: $EXECUTION_TIME_2"

if echo "$RESPONSE_2" | jq . >/dev/null 2>&1; then
    TOTAL_AFFECTED_2=$(echo "$RESPONSE_2" | jq -r '.results.total_affected_nodes // 0')
    INFECTION_RATE_2=$(echo "$RESPONSE_2" | jq -r '.results.final_infection_rate // 0')
    TIME_TO_PEAK_2=$(echo "$RESPONSE_2" | jq -r '.results.time_to_peak // 0')
    
    print_simulation "High contagion results:"
    print_simulation "• Total affected: $TOTAL_AFFECTED_2 nodes"
    print_simulation "• Final infection rate: $(echo "scale=2; $INFECTION_RATE_2 * 100" | bc 2>/dev/null || echo $INFECTION_RATE_2)%"
    print_simulation "• Time to peak: $TIME_TO_PEAK_2 steps"
    
    # Compare with first test
    if [ "$TOTAL_AFFECTED" -gt 0 ] && [ "$TOTAL_AFFECTED_2" -gt 0 ]; then
        if [ "$TOTAL_AFFECTED_2" -gt "$TOTAL_AFFECTED" ]; then
            INCREASE=$(echo "scale=1; ($TOTAL_AFFECTED_2 - $TOTAL_AFFECTED) * 100 / $TOTAL_AFFECTED" | bc 2>/dev/null || echo "N/A")
            print_warning "Higher contagion rate increased impact by $INCREASE%"
        else
            print_status "No significant difference detected"
        fi
    fi
else
    print_error "High contagion test failed"
fi

echo
echo "========================================="

# Test 3: Quick recovery simulation  
print_header "Test 3: Quick Recovery Scenario"

REQUEST_PAYLOAD_3="{
    \"initial_node\": \"$SAMPLE_NODE\",
    \"max_time\": 25,
    \"base_contagion_rate\": 0.15,
    \"incubation_rate\": 0.2,
    \"recovery_rate\": 0.15
}"

print_simulation "Testing quick recovery scenario (high recovery rate)..."
START_TIME_3=$(date +%s)

RESPONSE_3=$(curl -s -X POST "${API_BASE}/algorithms/apr" \
    -H "Content-Type: application/json" \
    -d "$REQUEST_PAYLOAD_3")

END_TIME_3=$(date +%s)
EXECUTION_TIME_3=$(calculate_time $START_TIME_3 $END_TIME_3)

if echo "$RESPONSE_3" | jq . >/dev/null 2>&1; then
    RECOVERY_TIME_3=$(echo "$RESPONSE_3" | jq -r '.results.recovery_time // 0')
    print_simulation "Quick recovery time: $RECOVERY_TIME_3 steps"
    print_status "Recovery simulation completed in: $EXECUTION_TIME_3"
fi

echo
echo "========================================="

# Performance and analysis summary
print_header "APR Performance Analysis"
print_status "Test 1 (Standard) execution time: $EXECUTION_TIME"
print_status "Test 2 (High contagion) execution time: $EXECUTION_TIME_2"
print_status "Test 3 (Quick recovery) execution time: $EXECUTION_TIME_3"

echo
print_header "Simulation Parameters Impact"
print_status "Parameter effects on propagation:"
print_status "• Base contagion rate: Higher = faster spread"
print_status "• Incubation rate: Higher = faster transition E→I"
print_status "• Recovery rate: Higher = faster transition I→R"
print_status "• Max time: Longer = more complete simulation"

echo
print_header "APR Algorithm Information"
print_status "Model: S-E-I-R (Susceptible-Exposed-Infected-Recovered)"
print_status "Purpose: Simulate how failures propagate through digital ecosystem"
print_status "Application: Business continuity, cascade failure analysis"
print_status "Chilean context: Critical for interconnected banking/telecom sectors"

echo
print_header "Risk Assessment Guidelines"
if [ "$TOTAL_AFFECTED" -gt 0 ]; then
    if [ "$TOTAL_AFFECTED" -gt 100 ]; then
        print_error "⚠️  HIGH SYSTEMIC RISK: >100 nodes affected"
    elif [ "$TOTAL_AFFECTED" -gt 50 ]; then
        print_warning "⚠️  MEDIUM RISK: 50-100 nodes affected"
    else
        print_status "✓ LOW RISK: <50 nodes affected"
    fi
else
    print_warning "No propagation detected - check initial node validity"
fi

echo
print_header "Recommended Actions"
print_status "1. Identify critical nodes with high propagation potential"
print_status "2. Implement circuit breakers in high-risk connections"
print_status "3. Plan recovery procedures for affected sectors"
print_status "4. Monitor cascade paths for early warning systems"

echo
print_status "APR algorithm test completed!"
echo -e "${BLUE}=========================================${NC}"