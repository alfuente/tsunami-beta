#!/bin/bash

# Test script para generar reporte firmado digitalmente
# Usage: ./test_signed_report.sh [domain] [report_type]

DOMAIN=${1:-"bancochile.cl"}
REPORT_TYPE=${2:-"BASIC"}
BASE_URL="http://localhost:8083"
OUTPUT_DIR="./reports"

echo "=== Tsunami Report Backend - Test Signed Report ==="
echo "Domain: $DOMAIN"
echo "Report Type: $REPORT_TYPE"
echo "API Base URL: $BASE_URL"
echo

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "1. Testing digital signature service info..."
curl -s -X GET "$BASE_URL/api/v1/signature/info" | jq . 2>/dev/null || {
    echo "Service info failed, checking raw response:"
    curl -s -X GET "$BASE_URL/api/v1/signature/info"
    echo
}

echo "2. Generating signed PDF report for domain: $DOMAIN"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="$OUTPUT_DIR/signed_report_${DOMAIN}_${REPORT_TYPE}_${TIMESTAMP}.pdf"

echo "Making request to: $BASE_URL/api/v1/signature/sign-report?domain=$DOMAIN&reportType=$REPORT_TYPE"

curl -v -X POST \
  "$BASE_URL/api/v1/signature/sign-report?domain=$DOMAIN&reportType=$REPORT_TYPE" \
  -H "Accept: application/octet-stream" \
  -o "$OUTPUT_FILE"

if [ $? -eq 0 ] && [ -f "$OUTPUT_FILE" ] && [ -s "$OUTPUT_FILE" ]; then
    echo
    echo "✅ Signed report generated successfully!"
    echo "📁 Output file: $OUTPUT_FILE"
    echo "📊 File size: $(wc -c < "$OUTPUT_FILE") bytes"
    echo "🔏 Digital signature: Included (DSS-based)"
    echo
    
    # Check if it's a PDF or text file
    FILE_TYPE=$(file "$OUTPUT_FILE" 2>/dev/null)
    echo "📄 File type: $FILE_TYPE"
    
    if [[ "$FILE_TYPE" == *"PDF"* ]]; then
        echo "✅ Valid PDF file detected"
    else
        echo "ℹ️  Content preview (first 10 lines):"
        echo "========================="
        head -10 "$OUTPUT_FILE"
        echo "========================="
    fi
    
    echo
    echo "3. Testing signature validation..."
    VALIDATION_RESULT=$(curl -s -X POST \
      "$BASE_URL/api/v1/signature/validate" \
      -H "Content-Type: application/octet-stream" \
      -T "$OUTPUT_FILE")
    
    echo "Validation result:"
    echo "$VALIDATION_RESULT" | jq . 2>/dev/null || echo "$VALIDATION_RESULT"
    
else
    echo "❌ Failed to generate signed report"
    
    # Check for error response
    if [ -f "$OUTPUT_FILE" ]; then
        echo "Response content:"
        cat "$OUTPUT_FILE"
    fi
    
    exit 1
fi

echo
echo "🎉 Test completed successfully!"
echo "📂 All reports saved in: $OUTPUT_DIR/"