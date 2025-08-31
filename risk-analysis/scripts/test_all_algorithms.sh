#!/bin/bash

# Comprehensive test script for all Risk Analysis algorithms
# This script tests all algorithms from stats.md implementation

API_BASE="http://localhost:8002"
SCRIPT_NAME="Complete Risk Analysis Algorithm Test Suite"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}================================================${NC}"
echo -e "${CYAN}${SCRIPT_NAME}${NC}"
echo -e "${CYAN}================================================${NC}"
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

print_algorithm() {
    echo -e "${PURPLE}[ALGO]${NC} $1"
}

print_result() {
    echo -e "${CYAN}[RESULT]${NC} $1"
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

# Test API connectivity
print_header "Pre-flight Checks"
print_status "Testing API connectivity..."

HEALTH_CHECK=$(curl -s "$API_BASE/health" 2>/dev/null)
if echo "$HEALTH_CHECK" | jq . >/dev/null 2>&1; then
    STATUS=$(echo "$HEALTH_CHECK" | jq -r '.status')
    TOTAL_NODES=$(echo "$HEALTH_CHECK" | jq -r '.graph_stats.total_nodes')
    TOTAL_RELATIONSHIPS=$(echo "$HEALTH_CHECK" | jq -r '.graph_stats.total_relationships')
    
    print_status "✓ API Status: $STATUS"
    print_status "✓ Graph nodes: $TOTAL_NODES"
    print_status "✓ Graph relationships: $TOTAL_RELATIONSHIPS"
else
    print_error "✗ API connectivity failed"
    print_error "Please ensure Risk Analysis API is running on $API_BASE"
    exit 1
fi

# List available algorithms
print_status "Fetching available algorithms..."
ALGORITHMS_LIST=$(curl -s "$API_BASE/algorithms" 2>/dev/null)
if echo "$ALGORITHMS_LIST" | jq . >/dev/null 2>&1; then
    TOTAL_ALGORITHMS=$(echo "$ALGORITHMS_LIST" | jq -r '.total_algorithms')
    print_status "✓ Found $TOTAL_ALGORITHMS implemented algorithms"
else
    print_warning "Could not fetch algorithms list, continuing with known algorithms..."
fi

echo

# Global variables for summary
declare -A ALGORITHM_TIMES
declare -A ALGORITHM_STATUS
declare -A ALGORITHM_RESULTS

TOTAL_START_TIME=$(date +%s)

# Test 1: ACCS Algorithm
print_header "Test 1: ACCS - Algoritmo de Centralidad y Criticidad Sistémica"
print_algorithm "Testing Systemic Centrality and Criticality Algorithm..."

ACCS_START=$(date +%s)

ACCS_REQUEST='{
    "node_types": ["Organization", "Domain"],
    "sectors": ["banking", "telecommunications", "energy"],
    "include_critical_bonus": true
}'

ACCS_RESPONSE=$(curl -s -X POST "$API_BASE/algorithms/accs" \
    -H "Content-Type: application/json" \
    -d "$ACCS_REQUEST")

ACCS_END=$(date +%s)
ACCS_TIME=$(calculate_time $ACCS_START $ACCS_END)
ALGORITHM_TIMES["ACCS"]=$ACCS_TIME

if echo "$ACCS_RESPONSE" | jq . >/dev/null 2>&1; then
    ACCS_NODES=$(echo "$ACCS_RESPONSE" | jq -r '.total_nodes // 0')
    ACCS_CRITICAL=$(echo "$ACCS_RESPONSE" | jq -r '.summary.critical_nodes // 0')
    ACCS_AVG_ICS=$(echo "$ACCS_RESPONSE" | jq -r '.summary.average_ics // 0')
    
    ALGORITHM_STATUS["ACCS"]="SUCCESS"
    ALGORITHM_RESULTS["ACCS"]="$ACCS_NODES nodes, $ACCS_CRITICAL critical (avg ICS: $ACCS_AVG_ICS)"
    
    print_result "✓ ACCS completed: $ACCS_NODES nodes analyzed, $ACCS_CRITICAL critical nodes"
    print_status "⏱ ACCS execution time: $ACCS_TIME"
else
    ALGORITHM_STATUS["ACCS"]="FAILED"
    ALGORITHM_RESULTS["ACCS"]="API call failed"
    print_error "✗ ACCS test failed"
fi

echo

# Test 2: ACP Algorithm  
print_header "Test 2: ACP - Algoritmo de Concentración de Proveedores"
print_algorithm "Testing Provider Concentration Algorithm..."

ACP_START=$(date +%s)

ACP_REQUEST='{
    "provider_types": ["Provider"],
    "include_hhi_modified": true
}'

ACP_RESPONSE=$(curl -s -X POST "$API_BASE/algorithms/acp" \
    -H "Content-Type: application/json" \
    -d "$ACP_REQUEST")

ACP_END=$(date +%s)
ACP_TIME=$(calculate_time $ACP_START $ACP_END)
ALGORITHM_TIMES["ACP"]=$ACP_TIME

if echo "$ACP_RESPONSE" | jq . >/dev/null 2>&1; then
    ACP_HHI=$(echo "$ACP_RESPONSE" | jq -r '.hhi_modified // 0')
    ACP_LEVEL=$(echo "$ACP_RESPONSE" | jq -r '.concentration_level // "Unknown"')
    ACP_PROVIDERS=$(echo "$ACP_RESPONSE" | jq -r '.total_providers // 0')
    ACP_RISK=$(echo "$ACP_RESPONSE" | jq -r '.risk_assessment.concentration_risk // "Unknown"')
    
    ALGORITHM_STATUS["ACP"]="SUCCESS"
    ALGORITHM_RESULTS["ACP"]="HHI: $ACP_HHI ($ACP_LEVEL), $ACP_PROVIDERS providers, Risk: $ACP_RISK"
    
    print_result "✓ ACP completed: HHI-M = $ACP_HHI ($ACP_LEVEL)"
    print_result "  $ACP_PROVIDERS providers analyzed, concentration risk: $ACP_RISK"
    print_status "⏱ ACP execution time: $ACP_TIME"
else
    ALGORITHM_STATUS["ACP"]="FAILED"  
    ALGORITHM_RESULTS["ACP"]="API call failed"
    print_error "✗ ACP test failed"
fi

echo

# Test 3: APR Algorithm
print_header "Test 3: APR - Algoritmo de Propagación de Riesgo" 
print_algorithm "Testing Risk Propagation Algorithm..."

APR_START=$(date +%s)

# Use a common domain for testing
APR_REQUEST='{
    "initial_node": "bancochile.cl",
    "max_time": 20,
    "base_contagion_rate": 0.2,
    "incubation_rate": 0.3,
    "recovery_rate": 0.1
}'

APR_RESPONSE=$(curl -s -X POST "$API_BASE/algorithms/apr" \
    -H "Content-Type: application/json" \
    -d "$APR_REQUEST")

APR_END=$(date +%s)
APR_TIME=$(calculate_time $APR_START $APR_END)
ALGORITHM_TIMES["APR"]=$APR_TIME

if echo "$APR_RESPONSE" | jq . >/dev/null 2>&1; then
    APR_AFFECTED=$(echo "$APR_RESPONSE" | jq -r '.results.total_affected_nodes // 0')
    APR_INFECTION_RATE=$(echo "$APR_RESPONSE" | jq -r '.results.final_infection_rate // 0')
    APR_PEAK_TIME=$(echo "$APR_RESPONSE" | jq -r '.results.time_to_peak // 0')
    
    ALGORITHM_STATUS["APR"]="SUCCESS"
    ALGORITHM_RESULTS["APR"]="$APR_AFFECTED affected, ${APR_INFECTION_RATE}% infection, peak at ${APR_PEAK_TIME}t"
    
    print_result "✓ APR completed: $APR_AFFECTED nodes affected"
    print_result "  Final infection rate: $(echo "scale=2; $APR_INFECTION_RATE * 100" | bc 2>/dev/null || echo $APR_INFECTION_RATE)%"
    print_status "⏱ APR execution time: $APR_TIME"
else
    ALGORITHM_STATUS["APR"]="FAILED"
    ALGORITHM_RESULTS["APR"]="API call failed or node not found"
    print_warning "✗ APR test failed (possibly node not found in graph)"
fi

echo

# Test 4: AECS Algorithm
print_header "Test 4: AECS - Algoritmo de Evaluación de Cadena de Suministro"
print_algorithm "Testing Supply Chain Evaluation Algorithm..."

AECS_START=$(date +%s)

AECS_REQUEST='{
    "target_organization": "Banco de Chile",
    "max_levels": 3,
    "include_transitives": true
}'

AECS_RESPONSE=$(curl -s -X POST "$API_BASE/algorithms/aecs" \
    -H "Content-Type: application/json" \
    -d "$AECS_REQUEST")

AECS_END=$(date +%s)
AECS_TIME=$(calculate_time $AECS_START $AECS_END)
ALGORITHM_TIMES["AECS"]=$AECS_TIME

if echo "$AECS_RESPONSE" | jq . >/dev/null 2>&1; then
    AECS_IRC=$(echo "$AECS_RESPONSE" | jq -r '.resilience_metrics.irc // 0')
    AECS_CLASSIFICATION=$(echo "$AECS_RESPONSE" | jq -r '.resilience_metrics.irc_classification // "Unknown"')
    AECS_SUPPLIERS=$(echo "$AECS_RESPONSE" | jq -r '.supply_chain_map | length')
    
    ALGORITHM_STATUS["AECS"]="SUCCESS"
    ALGORITHM_RESULTS["AECS"]="IRC: $AECS_IRC ($AECS_CLASSIFICATION), $AECS_SUPPLIERS suppliers"
    
    print_result "✓ AECS completed: IRC = $AECS_IRC ($AECS_CLASSIFICATION)"
    print_result "  Supply chain analyzed: $AECS_SUPPLIERS suppliers found"
    print_status "⏱ AECS execution time: $AECS_TIME"
else
    ALGORITHM_STATUS["AECS"]="FAILED"
    ALGORITHM_RESULTS["AECS"]="API call failed or organization not found"
    print_warning "✗ AECS test failed (possibly organization not found)"
fi

echo

# Test 5: AEPC Algorithm
print_header "Test 5: AEPC - Algoritmo de Evaluación de Proveedores Críticos"
print_algorithm "Testing Critical Provider Evaluation Algorithm..."

AEPC_START=$(date +%s)

AEPC_REQUEST='{
    "include_iisp": true
}'

AEPC_RESPONSE=$(curl -s -X POST "$API_BASE/algorithms/aepc" \
    -H "Content-Type: application/json" \
    -d "$AEPC_REQUEST")

AEPC_END=$(date +%s)
AEPC_TIME=$(calculate_time $AEPC_START $AEPC_END)
ALGORITHM_TIMES["AEPC"]=$AEPC_TIME

if echo "$AEPC_RESPONSE" | jq . >/dev/null 2>&1; then
    AEPC_PROVIDERS=$(echo "$AEPC_RESPONSE" | jq -r '.total_providers_assessed // 0')
    AEPC_CRITICAL=$(echo "$AEPC_RESPONSE" | jq -r '.summary.systemically_critical // 0')
    AEPC_HIGH_RISK=$(echo "$AEPC_RESPONSE" | jq -r '.summary.high_risk // 0')
    AEPC_AVG_IISP=$(echo "$AEPC_RESPONSE" | jq -r '.summary.average_iisp // 0')
    
    ALGORITHM_STATUS["AEPC"]="SUCCESS"
    ALGORITHM_RESULTS["AEPC"]="$AEPC_PROVIDERS providers, $AEPC_CRITICAL critical, avg IISP: $AEPC_AVG_IISP"
    
    print_result "✓ AEPC completed: $AEPC_PROVIDERS providers assessed"
    print_result "  Critical providers: $AEPC_CRITICAL, High risk: $AEPC_HIGH_RISK"
    print_status "⏱ AEPC execution time: $AEPC_TIME"
else
    ALGORITHM_STATUS["AEPC"]="FAILED"
    ALGORITHM_RESULTS["AEPC"]="API call failed"
    print_error "✗ AEPC test failed"
fi

echo

# Test 6: APRN Algorithm
print_header "Test 6: APRN - Algoritmo de Priorización de Riesgos Nacionales"
print_algorithm "Testing National Risk Prioritization Algorithm..."

APRN_START=$(date +%s)

APRN_REQUEST='{
    "include_national_security": true
}'

APRN_RESPONSE=$(curl -s -X POST "$API_BASE/algorithms/aprn" \
    -H "Content-Type: application/json" \
    -d "$APRN_REQUEST")

APRN_END=$(date +%s)
APRN_TIME=$(calculate_time $APRN_START $APRN_END)
ALGORITHM_TIMES["APRN"]=$APRN_TIME

if echo "$APRN_RESPONSE" | jq . >/dev/null 2>&1; then
    APRN_ENTITIES=$(echo "$APRN_RESPONSE" | jq -r '.total_entities_assessed // 0')
    APRN_CRITICAL_RISKS=$(echo "$APRN_RESPONSE" | jq -r '.national_summary.critical_national_risks // 0')
    APRN_HIGH_RISKS=$(echo "$APRN_RESPONSE" | jq -r '.national_summary.high_national_risks // 0')
    APRN_FOREIGN_DEPS=$(echo "$APRN_RESPONSE" | jq -r '.national_summary.foreign_dependency_concerns // 0')
    APRN_AVG_IRN=$(echo "$APRN_RESPONSE" | jq -r '.national_summary.average_irn // 0')
    
    ALGORITHM_STATUS["APRN"]="SUCCESS"
    ALGORITHM_RESULTS["APRN"]="$APRN_ENTITIES entities, $APRN_CRITICAL_RISKS critical, $APRN_FOREIGN_DEPS foreign deps"
    
    print_result "✓ APRN completed: $APRN_ENTITIES entities assessed"
    print_result "  Critical national risks: $APRN_CRITICAL_RISKS, Foreign dependencies: $APRN_FOREIGN_DEPS"
    print_status "⏱ APRN execution time: $APRN_TIME"
else
    ALGORITHM_STATUS["APRN"]="FAILED"
    ALGORITHM_RESULTS["APRN"]="API call failed"
    print_error "✗ APRN test failed"
fi

TOTAL_END_TIME=$(date +%s)
TOTAL_EXECUTION_TIME=$(calculate_time $TOTAL_START_TIME $TOTAL_END_TIME)

echo
echo "=================================================="
print_header "COMPREHENSIVE TEST RESULTS SUMMARY"
echo

# Results table
print_result "Algorithm Performance Summary:"
echo
printf "%-8s %-10s %-15s %s\n" "ALGO" "STATUS" "EXEC_TIME" "RESULTS"
printf "%-8s %-10s %-15s %s\n" "----" "------" "---------" "-------"

for algo in ACCS ACP APR AECS AEPC APRN; do
    status=${ALGORITHM_STATUS[$algo]:-"UNKNOWN"}
    time=${ALGORITHM_TIMES[$algo]:-"N/A"}
    result=${ALGORITHM_RESULTS[$algo]:-"No data"}
    
    if [ "$status" = "SUCCESS" ]; then
        printf "%-8s ${GREEN}%-10s${NC} %-15s %s\n" "$algo" "$status" "$time" "$result"
    else
        printf "%-8s ${RED}%-10s${NC} %-15s %s\n" "$algo" "$status" "$time" "$result"
    fi
done

echo
print_header "Overall Performance Metrics"
print_status "Total test execution time: $TOTAL_EXECUTION_TIME"

# Count successes
SUCCESS_COUNT=0
TOTAL_COUNT=6

for algo in ACCS ACP APR AECS AEPC APRN; do
    if [ "${ALGORITHM_STATUS[$algo]}" = "SUCCESS" ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    fi
done

SUCCESS_RATE=$(echo "scale=1; $SUCCESS_COUNT * 100 / $TOTAL_COUNT" | bc 2>/dev/null || echo "N/A")
print_status "Success rate: $SUCCESS_COUNT/$TOTAL_COUNT ($SUCCESS_RATE%)"

# Fastest and slowest algorithms
FASTEST_TIME=9999
SLOWEST_TIME=0
FASTEST_ALGO=""
SLOWEST_ALGO=""

for algo in ACCS ACP APR AECS AEPC APRN; do
    time_str=${ALGORITHM_TIMES[$algo]:-"0s"}
    time_seconds=${time_str%s}
    
    if [ "$time_seconds" -gt 0 ]; then
        if [ "$time_seconds" -lt "$FASTEST_TIME" ]; then
            FASTEST_TIME=$time_seconds
            FASTEST_ALGO=$algo
        fi
        if [ "$time_seconds" -gt "$SLOWEST_TIME" ]; then
            SLOWEST_TIME=$time_seconds
            SLOWEST_ALGO=$algo
        fi
    fi
done

if [ ! -z "$FASTEST_ALGO" ]; then
    print_status "Fastest algorithm: $FASTEST_ALGO (${ALGORITHM_TIMES[$FASTEST_ALGO]})"
fi

if [ ! -z "$SLOWEST_ALGO" ]; then
    print_status "Slowest algorithm: $SLOWEST_ALGO (${ALGORITHM_TIMES[$SLOWEST_ALGO]})"
fi

echo
print_header "Risk Analysis Insights"

if [ "${ALGORITHM_STATUS[ACCS]}" = "SUCCESS" ] && [ "$ACCS_CRITICAL" -gt 0 ]; then
    print_warning "⚠️  Found $ACCS_CRITICAL nodes with critical systemic importance"
fi

if [ "${ALGORITHM_STATUS[ACP]}" = "SUCCESS" ] && [ "$ACP_RISK" = "High" ]; then
    print_warning "⚠️  High provider concentration risk detected (HHI: $ACP_HHI)"
fi

if [ "${ALGORITHM_STATUS[APR]}" = "SUCCESS" ] && [ "$APR_AFFECTED" -gt 50 ]; then
    print_warning "⚠️  Risk propagation affects $APR_AFFECTED nodes - consider mitigation"
fi

if [ "${ALGORITHM_STATUS[APRN]}" = "SUCCESS" ] && [ "$APRN_CRITICAL_RISKS" -gt 0 ]; then
    print_error "🔴 $APRN_CRITICAL_RISKS entities pose critical national security risks"
fi

echo
print_header "Next Steps & Recommendations"
print_status "1. Review critical entities identified by ACCS algorithm"
print_status "2. Monitor provider concentration levels (ACP results)"
print_status "3. Prepare contingency plans for propagation scenarios (APR)"
print_status "4. Assess supply chain resilience for key organizations (AECS)"
print_status "5. Evaluate critical provider dependencies (AEPC)"
print_status "6. Address national security concerns (APRN findings)"

echo
print_header "Algorithm Documentation"
print_status "📖 Full specifications: docs/stats.md"
print_status "🔍 API documentation: $API_BASE/docs"
print_status "📊 Health status: $API_BASE/health"
print_status "📋 Algorithm list: $API_BASE/algorithms"

echo
if [ "$SUCCESS_COUNT" -eq "$TOTAL_COUNT" ]; then
    print_status "🎉 All algorithms tested successfully!"
else
    FAILED_COUNT=$((TOTAL_COUNT - SUCCESS_COUNT))
    print_warning "⚠️  $FAILED_COUNT algorithm(s) failed - check individual results above"
fi

echo -e "${CYAN}================================================${NC}"
print_status "Risk Analysis Algorithm Test Suite completed!"
echo -e "${CYAN}================================================${NC}"