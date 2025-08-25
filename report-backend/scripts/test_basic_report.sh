#!/bin/bash

# Test script para generar reporte básico
# Usage: ./test_basic_report.sh [domain]

DOMAIN=${1:-"bancochile.cl"}
BASE_URL="http://localhost:8083"
OUTPUT_DIR="./reports"

echo "=== Tsunami Report Backend - Test Basic Report ==="
echo "Domain: $DOMAIN"
echo "API Base URL: $BASE_URL"
echo

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "1. Testing API Health..."
curl -s -X GET "$BASE_URL/q/health" | jq . 2>/dev/null || echo "Health check failed or jq not available"
echo

echo "2. Getting service info..."
curl -s -X GET "$BASE_URL/api/v1/signature/info" | jq . 2>/dev/null || echo "Service info request failed"
echo

echo "3. Generating basic report for domain: $DOMAIN"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="$OUTPUT_DIR/basic_report_${DOMAIN}_${TIMESTAMP}.txt"

curl -v -X POST \
  "$BASE_URL/api/v1/reports" \
  -H "Content-Type: application/json" \
  -H "Accept: application/octet-stream" \
  -d "{
    \"clientId\": \"test-client-001\",
    \"domain\": \"$DOMAIN\",
    \"reportType\": \"BASIC\",
    \"requestNotes\": \"Test report generated via curl script\"
  }" \
  -o "$OUTPUT_FILE"

if [ $? -eq 0 ]; then
    echo
    echo "✅ Report generated successfully!"
    echo "📁 Output file: $OUTPUT_FILE"
    echo "📊 File size: $(wc -c < "$OUTPUT_FILE") bytes"
    echo
    echo "Preview (first 20 lines):"
    echo "========================="
    head -20 "$OUTPUT_FILE"
    echo "========================="
else
    echo "❌ Failed to generate report"
    exit 1
fi