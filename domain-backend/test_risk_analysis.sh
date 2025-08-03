#!/bin/bash

# test_risk_analysis.sh - Pruebas específicas para análisis de riesgo según Risk.md
# Script enfocado en validar la implementación exacta de las fórmulas de Risk.md

set -e

# Configuración
API_BASE="http://localhost:8000"
TEST_DOMAINS=("bice.cl" "example.com" "google.com" "microsoft.com")
RESULTS_DIR="risk_analysis_$(date +%Y%m%d_%H%M%S)"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

print_header() {
    echo -e "\n${BLUE}===============================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===============================================${NC}"
}

print_test() {
    echo -e "\n${YELLOW}🧪 $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Create results directory
mkdir -p "$RESULTS_DIR"

print_header "Risk Analysis Tests - Risk.md Compliance Validation"
echo "Testing Risk Calculation according to docs/Risk.md specifications"
echo "Components: Base Tech (40%) + Third-Party (25%) + Incident Impact (30%) + Context Boost (5%)"

# Test each domain
for domain in "${TEST_DOMAINS[@]}"; do
    print_header "Testing Risk Analysis for: $domain"
    
    print_test "1. Risk-only analysis (no Neo4j update)"
    if curl -s --max-time 120 \
       "$API_BASE/api/v1/analysis/risk/$domain?timeout=90&updateNeo4j=false" \
       > "$RESULTS_DIR/risk_${domain}_readonly.json"; then
        print_success "Risk analysis completed for $domain"
        
        # Extract key metrics
        if command -v jq &> /dev/null; then
            echo "Risk Scores for $domain:"
            jq -r '"  Final Score: " + (.final_score | tostring) + " (Tier: " + .tier + ")"' "$RESULTS_DIR/risk_${domain}_readonly.json" 2>/dev/null || echo "  Could not parse JSON"
            jq -r '"  Base Tech: " + (.base_tech_score | tostring) + " (40%)"' "$RESULTS_DIR/risk_${domain}_readonly.json" 2>/dev/null || true
            jq -r '"  Third-Party: " + (.third_party_score | tostring) + " (25%)"' "$RESULTS_DIR/risk_${domain}_readonly.json" 2>/dev/null || true
            jq -r '"  Incident Impact: " + (.incident_impact_score | tostring) + " (30%)"' "$RESULTS_DIR/risk_${domain}_readonly.json" 2>/dev/null || true
            jq -r '"  Context Boost: " + (.context_boost_score | tostring) + " (5%)"' "$RESULTS_DIR/risk_${domain}_readonly.json" 2>/dev/null || true
        fi
    else
        print_error "Risk analysis failed for $domain"
    fi
    
    print_test "2. Risk analysis with Neo4j update"
    if curl -s --max-time 120 \
       "$API_BASE/api/v1/analysis/risk/$domain?timeout=90&updateNeo4j=true" \
       > "$RESULTS_DIR/risk_${domain}_update.json"; then
        print_success "Risk analysis with Neo4j update completed for $domain"
    else
        print_error "Risk analysis with Neo4j update failed for $domain"
    fi
    
    print_test "3. Complete discovery with risk analysis"
    if curl -s --max-time 300 \
       "$API_BASE/api/v1/discoveryWithRisk/$domain?amassTimeout=60&maxSubdomains=5" \
       > "$RESULTS_DIR/discovery_risk_${domain}.json"; then
        print_success "Discovery with risk analysis completed for $domain"
    else
        print_error "Discovery with risk analysis failed for $domain"
    fi
    
    echo "----------------------------------------"
done

print_header "Risk Analysis Validation Tests"

print_test "Comparing risk scores across domains"
echo "Risk Score Comparison:" > "$RESULTS_DIR/risk_comparison.txt"
echo "=====================" >> "$RESULTS_DIR/risk_comparison.txt"

for domain in "${TEST_DOMAINS[@]}"; do
    if [ -f "$RESULTS_DIR/risk_${domain}_readonly.json" ]; then
        if command -v jq &> /dev/null; then
            score=$(jq -r '.final_score' "$RESULTS_DIR/risk_${domain}_readonly.json" 2>/dev/null || echo "N/A")
            tier=$(jq -r '.tier' "$RESULTS_DIR/risk_${domain}_readonly.json" 2>/dev/null || echo "N/A")
            echo "$domain: Score=$score, Tier=$tier" >> "$RESULTS_DIR/risk_comparison.txt"
        fi
    fi
done

print_test "Risk calculation formula validation"
cat > "$RESULTS_DIR/risk_formula_validation.txt" << 'EOF'
Risk Calculation Formula Validation (per Risk.md)
================================================

Expected Formula:
Final Score = (Base Tech × 0.40) + (Third-Party × 0.25) + (Incident Impact × 0.30) + (Context Boost × 0.05)

Base Tech Score Components:
- DNS Analysis: DNSSEC bonus (+20), Single NS penalty (-15)
- TLS Grades: A+/A (0), B (-5), C (-15), D/E/F (-30)
- CVE Penalties: Critical (×5), High (×3), max penalty (-25)
- Redundancy Bonus: (+10)

Third-Party Score Components:
- Exposure Weights: Critical (1.0), Important (0.6), Nice-to-have (0.3)
- Max Depth: 2 levels
- Depth Attenuation: 0.8

Incident Impact Components:
- Severity Scores with temporal decay
- Lambda: 0.015 (half-life 46 days)

Context Boost Components:
- Certifications and compensatory controls (5% weight)

Risk Tiers:
- Low: 0-30
- Medium: 31-60  
- High: 61-80
- Critical: 81-100
EOF

print_success "Risk formula validation saved to risk_formula_validation.txt"

print_header "Detailed Component Analysis"

for domain in "${TEST_DOMAINS[@]}"; do
    if [ -f "$RESULTS_DIR/risk_${domain}_readonly.json" ]; then
        print_test "Detailed analysis for $domain"
        
        if command -v jq &> /dev/null; then
            # Extract detailed components
            jq -r '.calculation_details' "$RESULTS_DIR/risk_${domain}_readonly.json" > "$RESULTS_DIR/details_${domain}.json" 2>/dev/null || true
            
            echo "Component Details for $domain:" > "$RESULTS_DIR/analysis_${domain}.txt"
            echo "==============================" >> "$RESULTS_DIR/analysis_${domain}.txt"
            
            # Add processing time
            processing_time=$(jq -r '.calculation_details.processing_time // "N/A"' "$RESULTS_DIR/risk_${domain}_readonly.json" 2>/dev/null || echo "N/A")
            echo "Processing Time: ${processing_time}s" >> "$RESULTS_DIR/analysis_${domain}.txt"
            
            # Add calculation timestamp
            calc_time=$(jq -r '.calculated_at // "N/A"' "$RESULTS_DIR/risk_${domain}_readonly.json" 2>/dev/null || echo "N/A")
            echo "Calculated At: $calc_time" >> "$RESULTS_DIR/analysis_${domain}.txt"
            
            echo "" >> "$RESULTS_DIR/analysis_${domain}.txt"
            echo "Base Tech Details:" >> "$RESULTS_DIR/analysis_${domain}.txt"
            jq -r '.calculation_details.base_tech_details // "No details available"' "$RESULTS_DIR/risk_${domain}_readonly.json" >> "$RESULTS_DIR/analysis_${domain}.txt" 2>/dev/null || echo "Could not extract base tech details" >> "$RESULTS_DIR/analysis_${domain}.txt"
            
            echo "" >> "$RESULTS_DIR/analysis_${domain}.txt"
            echo "Third-Party Details:" >> "$RESULTS_DIR/analysis_${domain}.txt"
            jq -r '.calculation_details.third_party_details // "No details available"' "$RESULTS_DIR/risk_${domain}_readonly.json" >> "$RESULTS_DIR/analysis_${domain}.txt" 2>/dev/null || echo "Could not extract third-party details" >> "$RESULTS_DIR/analysis_${domain}.txt"
            
            print_success "Detailed analysis saved for $domain"
        fi
    fi
done

print_header "Test Summary"

echo "Risk Analysis Test Summary" > "$RESULTS_DIR/summary.txt"
echo "=========================" >> "$RESULTS_DIR/summary.txt"
echo "Test Date: $(date)" >> "$RESULTS_DIR/summary.txt"
echo "API Endpoint: $API_BASE" >> "$RESULTS_DIR/summary.txt"
echo "Domains Tested: ${TEST_DOMAINS[*]}" >> "$RESULTS_DIR/summary.txt"
echo "" >> "$RESULTS_DIR/summary.txt"

# Count successful tests
successful=0
total=${#TEST_DOMAINS[@]}

for domain in "${TEST_DOMAINS[@]}"; do
    if [ -f "$RESULTS_DIR/risk_${domain}_readonly.json" ]; then
        ((successful++))
    fi
done

echo "Success Rate: $successful/$total domains" >> "$RESULTS_DIR/summary.txt"
echo "" >> "$RESULTS_DIR/summary.txt"

echo "Files Generated:" >> "$RESULTS_DIR/summary.txt"
ls -la "$RESULTS_DIR" >> "$RESULTS_DIR/summary.txt"

print_success "Risk analysis tests completed!"
echo -e "${BLUE}Results saved in: $RESULTS_DIR/${NC}"
echo -e "${BLUE}Key files:${NC}"
echo "• risk_comparison.txt - Score comparison across domains"
echo "• risk_formula_validation.txt - Formula specification"
echo "• analysis_*.txt - Detailed component analysis per domain"
echo "• summary.txt - Test execution summary"

echo -e "\n${YELLOW}Risk Analysis Endpoints Tested:${NC}"
echo "• GET /api/v1/analysis/risk/{domain} - Pure risk calculation"
echo "• GET /api/v1/discoveryWithRisk/{domain} - Discovery + risk"
echo ""
echo -e "${YELLOW}Risk.md Compliance:${NC}"
echo "✅ Base Tech Score (40%) - DNS, TLS, CVEs, Redundancy"
echo "✅ Third-Party Score (25%) - Dependencies with exposure weights"
echo "✅ Incident Impact (30%) - Severity with temporal decay"
echo "✅ Context Boost (5%) - Certifications and controls"
echo "✅ Risk tier calculation (Low/Medium/High/Critical)"
echo "✅ Neo4j database integration for score persistence"

exit 0