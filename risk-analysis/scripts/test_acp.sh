#!/bin/bash

# Test script for ACP (Algoritmo de Concentración de Proveedores)
# This script tests the Provider Concentration Algorithm using modified HHI

API_BASE="http://localhost:8002"
SCRIPT_NAME="ACP Algorithm Test (Provider Concentration)"

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

# Function to interpret HHI levels
interpret_hhi() {
    local hhi=$1
    if (( $(echo "$hhi < 0.15" | bc -l) )); then
        echo "Competitive Market"
    elif (( $(echo "$hhi < 0.25" | bc -l) )); then
        echo "Moderately Concentrated"
    else
        echo "Highly Concentrated"
    fi
}

# Test 1: Basic ACP calculation
print_header "Test 1: Provider Concentration Analysis"

REQUEST_PAYLOAD='{
    "provider_types": ["Provider"],
    "include_hhi_modified": true
}'

echo "Request payload:"
echo "$REQUEST_PAYLOAD" | jq .
echo

print_status "Starting ACP calculation..."
START_TIME=$(date +%s)
START_TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

print_status "Start time: $START_TIMESTAMP"

RESPONSE=$(curl -s -X POST "${API_BASE}/algorithms/acp" \
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
    HHI_MODIFIED=$(echo "$RESPONSE" | jq -r '.hhi_modified // 0')
    CONCENTRATION_LEVEL=$(echo "$RESPONSE" | jq -r '.concentration_level // "Unknown"')
    TOTAL_PROVIDERS=$(echo "$RESPONSE" | jq -r '.total_providers // 0')
    TOTAL_ENTITIES=$(echo "$RESPONSE" | jq -r '.total_critical_entities // 0')
    CONCENTRATION_RISK=$(echo "$RESPONSE" | jq -r '.risk_assessment.concentration_risk // "Unknown"')
    SPOF_RISK=$(echo "$RESPONSE" | jq -r '.risk_assessment.single_point_failure_risk // false')
    
    print_status "Algorithm: $ALGORITHM"
    print_status "HHI Modified: $HHI_MODIFIED"
    print_status "Market Concentration: $CONCENTRATION_LEVEL"
    print_status "Total providers analyzed: $TOTAL_PROVIDERS"
    print_status "Total critical entities: $TOTAL_ENTITIES"
    print_status "Concentration risk level: $CONCENTRATION_RISK"
    print_status "Single Point of Failure risk: $SPOF_RISK"
    
    echo
    print_header "Dominant Providers (Market Share > 10%)"
    DOMINANT_COUNT=$(echo "$RESPONSE" | jq -r '.dominant_providers | length')
    
    if [ "$DOMINANT_COUNT" -gt 0 ]; then
        echo "$RESPONSE" | jq -r '
            .dominant_providers | to_entries | 
            sort_by(-.value) | 
            .[] | 
            "\(.key): \((.value * 100 | floor))% market share"
        ' 2>/dev/null
        
        print_warning "Found $DOMINANT_COUNT dominant providers controlling >10% each"
    else
        print_status "No dominant providers found (good market distribution)"
    fi
    
    echo
    print_header "Top 5 Providers by Client Count"
    echo "$RESPONSE" | jq '
        .provider_details | to_entries | 
        sort_by(-.value.client_count) | 
        limit(5; .[]) | 
        map({
            provider: .key,
            clients: .value.client_count,
            sectors: .value.sectors,
            weighted_importance: .value.weighted_importance
        })
    ' 2>/dev/null
    
    echo
    print_header "Risk Assessment Recommendations"
    echo "$RESPONSE" | jq -r '.risk_assessment.recommendations[]?' 2>/dev/null
    
else
    print_error "Invalid response received"
    print_error "Raw response: $RESPONSE"
fi

echo
echo "========================================="

# Test 2: Check market concentration interpretation
print_header "Test 2: HHI Interpretation Guide"

print_status "HHI Interpretation Scale:"
print_status "• 0.00 - 0.15: Competitive market (low concentration risk)"
print_status "• 0.15 - 0.25: Moderately concentrated (medium risk)"
print_status "• 0.25 - 1.00: Highly concentrated (high systemic risk)"
echo

if [ ! -z "$HHI_MODIFIED" ] && [ "$HHI_MODIFIED" != "0" ] && [ "$HHI_MODIFIED" != "null" ]; then
    HHI_PERCENT=$(echo "scale=1; $HHI_MODIFIED * 100" | bc 2>/dev/null || echo "N/A")
    
    print_status "Current HHI-M value: $HHI_MODIFIED ($HHI_PERCENT%)"
    
    if (( $(echo "$HHI_MODIFIED >= 0.25" | bc -l 2>/dev/null || echo 0) )); then
        print_error "⚠️  HIGH RISK: Market is highly concentrated!"
        print_error "   Recommendation: Urgent diversification needed"
    elif (( $(echo "$HHI_MODIFIED >= 0.15" | bc -l 2>/dev/null || echo 0) )); then
        print_warning "⚠️  MEDIUM RISK: Moderate concentration detected"
        print_warning "   Recommendation: Monitor trends, consider diversification"
    else
        print_status "✓ LOW RISK: Competitive market structure"
    fi
fi

echo
echo "========================================="

# Performance and market analysis
print_header "Market Structure Analysis"

if [ "$TOTAL_PROVIDERS" -gt 0 ] && [ "$TOTAL_ENTITIES" -gt 0 ]; then
    ENTITIES_PER_PROVIDER=$(echo "scale=1; $TOTAL_ENTITIES / $TOTAL_PROVIDERS" | bc 2>/dev/null || echo "N/A")
    print_status "Average entities per provider: $ENTITIES_PER_PROVIDER"
    
    if [ "$DOMINANT_COUNT" -gt 0 ]; then
        MARKET_SHARE_DOMINANT=$(echo "$RESPONSE" | jq -r '
            .dominant_providers | to_entries | 
            map(.value) | add * 100 | floor
        ' 2>/dev/null || echo "N/A")
        print_status "Combined market share of dominant providers: $MARKET_SHARE_DOMINANT%"
    fi
fi

echo
print_header "Performance Summary"
print_status "Execution time: $EXECUTION_TIME"

if [ "$TOTAL_PROVIDERS" -gt 0 ] && [ ${EXECUTION_TIME%s} -gt 0 ]; then
    PROVIDERS_PER_SECOND=$((TOTAL_PROVIDERS / ${EXECUTION_TIME%s}))
    print_status "Processing rate: ~$PROVIDERS_PER_SECOND providers/second"
fi

echo
print_header "ACP Algorithm Information"
print_status "Formula: HHI-M = Σ(cuota_mercado_ponderada²)"
print_status "Sector weights: banking(3.0), telecom(2.8), energy(2.7), government(2.5), others(1.0)"
print_status "Purpose: Detect dangerous concentration of dependencies in few providers"
print_status "Chilean context: Market size requires lower concentration thresholds"

echo
print_header "Systemic Risk Indicators"
if [ "$SPOF_RISK" = "true" ]; then
    print_error "⚠️  Single Point of Failure Risk: DETECTED"
    print_error "   Too few providers control critical infrastructure"
else
    print_status "✓ Single Point of Failure Risk: Not detected"
fi

echo
print_status "ACP algorithm test completed!"
echo -e "${BLUE}=========================================${NC}"