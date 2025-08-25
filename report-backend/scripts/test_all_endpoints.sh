#!/bin/bash

# Test script completo para todos los endpoints del report-backend
# Usage: ./test_all_endpoints.sh [domain]

DOMAIN=${1:-"bancochile.cl"}
BASE_URL="http://localhost:8083"
OUTPUT_DIR="./reports"

echo "=== Tsunami Report Backend - Complete API Test ==="
echo "Domain: $DOMAIN"
echo "API Base URL: $BASE_URL"
echo "Date: $(date)"
echo

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_section() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Test 1: Health Check
print_section "1. Health Check"
HEALTH_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" "$BASE_URL/q/health")
HTTP_CODE=$(echo $HEALTH_RESPONSE | tr -d '\n' | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')
RESPONSE_BODY=$(echo $HEALTH_RESPONSE | sed -E 's/HTTPSTATUS:[0-9]{3}$//')

if [ "$HTTP_CODE" = "200" ]; then
    print_success "Health check passed"
    echo "$RESPONSE_BODY" | jq . 2>/dev/null || echo "$RESPONSE_BODY"
else
    print_error "Health check failed (HTTP $HTTP_CODE)"
fi
echo

# Test 2: OpenAPI Documentation
print_section "2. OpenAPI Documentation"
OPENAPI_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" "$BASE_URL/q/openapi")
HTTP_CODE=$(echo $OPENAPI_RESPONSE | tr -d '\n' | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')

if [ "$HTTP_CODE" = "200" ]; then
    print_success "OpenAPI spec available at $BASE_URL/q/openapi"
else
    print_warning "OpenAPI spec not available (HTTP $HTTP_CODE)"
fi
echo

# Test 3: Digital Signature Service Info
print_section "3. Digital Signature Service Info"
SIGNATURE_INFO=$(curl -s -w "HTTPSTATUS:%{http_code}" "$BASE_URL/api/v1/signature/info")
HTTP_CODE=$(echo $SIGNATURE_INFO | tr -d '\n' | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')
RESPONSE_BODY=$(echo $SIGNATURE_INFO | sed -E 's/HTTPSTATUS:[0-9]{3}$//')

if [ "$HTTP_CODE" = "200" ]; then
    print_success "Digital signature service is available"
    echo "$RESPONSE_BODY" | jq . 2>/dev/null || echo "$RESPONSE_BODY"
else
    print_error "Digital signature service failed (HTTP $HTTP_CODE)"
fi
echo

# Test 4: Generate Basic Report
print_section "4. Generate Basic Report"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASIC_REPORT_FILE="$OUTPUT_DIR/basic_${DOMAIN}_${TIMESTAMP}.txt"

BASIC_REPORT_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST \
  "$BASE_URL/api/v1/reports" \
  -H "Content-Type: application/json" \
  -H "Accept: application/octet-stream" \
  -d "{
    \"clientId\": \"test-client-api\",
    \"domain\": \"$DOMAIN\",
    \"reportType\": \"BASIC\",
    \"requestNotes\": \"Generated via complete API test\"
  }" \
  -o "$BASIC_REPORT_FILE")

HTTP_CODE=$(echo $BASIC_REPORT_RESPONSE | tr -d '\n' | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')

if [ "$HTTP_CODE" = "200" ] && [ -f "$BASIC_REPORT_FILE" ] && [ -s "$BASIC_REPORT_FILE" ]; then
    print_success "Basic report generated successfully"
    echo "📁 File: $BASIC_REPORT_FILE"
    echo "📊 Size: $(wc -c < "$BASIC_REPORT_FILE") bytes"
else
    print_error "Basic report generation failed (HTTP $HTTP_CODE)"
    if [ -f "$BASIC_REPORT_FILE" ]; then
        echo "Response: $(head -3 "$BASIC_REPORT_FILE")"
    fi
fi
echo

# Test 5: Generate Signed Report
print_section "5. Generate Digitally Signed Report"
SIGNED_REPORT_FILE="$OUTPUT_DIR/signed_${DOMAIN}_${TIMESTAMP}.pdf"

SIGNED_REPORT_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST \
  "$BASE_URL/api/v1/signature/sign-report?domain=$DOMAIN&reportType=COMPREHENSIVE" \
  -H "Accept: application/octet-stream" \
  -o "$SIGNED_REPORT_FILE")

HTTP_CODE=$(echo $SIGNED_REPORT_RESPONSE | tr -d '\n' | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')

if [ "$HTTP_CODE" = "200" ] && [ -f "$SIGNED_REPORT_FILE" ] && [ -s "$SIGNED_REPORT_FILE" ]; then
    print_success "Signed report generated successfully"
    echo "📁 File: $SIGNED_REPORT_FILE"
    echo "📊 Size: $(wc -c < "$SIGNED_REPORT_FILE") bytes"
    echo "🔏 Digital signature: Applied with DSS"
    
    # Test 6: Validate Signature
    print_section "6. Validate Digital Signature"
    VALIDATION_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST \
      "$BASE_URL/api/v1/signature/validate" \
      -H "Content-Type: application/octet-stream" \
      -T "$SIGNED_REPORT_FILE")
    
    HTTP_CODE=$(echo $VALIDATION_RESPONSE | tr -d '\n' | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')
    RESPONSE_BODY=$(echo $VALIDATION_RESPONSE | sed -E 's/HTTPSTATUS:[0-9]{3}$//')
    
    if [ "$HTTP_CODE" = "200" ]; then
        print_success "Signature validation completed"
        echo "$RESPONSE_BODY" | jq . 2>/dev/null || echo "$RESPONSE_BODY"
    else
        print_error "Signature validation failed (HTTP $HTTP_CODE)"
    fi
else
    print_error "Signed report generation failed (HTTP $HTTP_CODE)"
    if [ -f "$SIGNED_REPORT_FILE" ]; then
        echo "Response: $(head -3 "$SIGNED_REPORT_FILE")"
    fi
fi
echo

# Test 7: Graph Analysis (if available)
print_section "7. Graph Analysis"
GRAPH_RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" "$BASE_URL/api/v1/graph/analysis")
HTTP_CODE=$(echo $GRAPH_RESPONSE | tr -d '\n' | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')

if [ "$HTTP_CODE" = "200" ]; then
    print_success "Graph analysis endpoint available"
else
    print_warning "Graph analysis endpoint not available (HTTP $HTTP_CODE)"
fi
echo

# Summary
print_section "Test Summary"
echo "🏠 Domain tested: $DOMAIN"
echo "🌐 API Base URL: $BASE_URL" 
echo "📂 Reports directory: $OUTPUT_DIR"
echo "📋 Generated files:"
ls -la "$OUTPUT_DIR"/ 2>/dev/null || echo "No files generated"
echo
print_success "Complete API test finished!"
echo
echo "💡 Next steps:"
echo "   - Check generated reports in: $OUTPUT_DIR/"
echo "   - View Swagger UI: $BASE_URL/swagger-ui"
echo "   - Check service logs: tail -f ../report-backend-java21-dev.log"