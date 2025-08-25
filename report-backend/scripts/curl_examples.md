# Tsunami Report Backend - cURL Examples

This document contains examples of how to interact with the Tsunami Report Backend API using cURL.

## Base Configuration

```bash
BASE_URL="http://localhost:8083"
DOMAIN="bancochile.cl"
```

## 1. Health Check

```bash
# Check if the service is running
curl -X GET "$BASE_URL/q/health"
```

## 2. Service Information

```bash
# Get digital signature service information
curl -X GET "$BASE_URL/api/v1/signature/info" | jq .
```

## 3. Generate Basic Report

```bash
# Generate a basic security report
curl -X POST "$BASE_URL/api/v1/reports" \
  -H "Content-Type: application/json" \
  -H "Accept: application/octet-stream" \
  -d '{
    "clientId": "test-client-001",
    "domain": "bancochile.cl",
    "reportType": "BASIC",
    "requestNotes": "Security assessment for banking domain"
  }' \
  -o "report_bancochile_$(date +%Y%m%d_%H%M%S).txt"
```

## 4. Generate Digitally Signed Report

```bash
# Generate a PDF report with digital signature
curl -X POST "$BASE_URL/api/v1/signature/sign-report?domain=bancochile.cl&reportType=COMPREHENSIVE" \
  -H "Accept: application/octet-stream" \
  -o "signed_report_bancochile_$(date +%Y%m%d_%H%M%S).pdf"
```

## 5. Validate Digital Signature

```bash
# Validate the digital signature of a PDF report
curl -X POST "$BASE_URL/api/v1/signature/validate" \
  -H "Content-Type: application/octet-stream" \
  -T "signed_report_bancochile.pdf" | jq .
```

## 6. Graph Analysis

```bash
# Get Neo4j graph analysis
curl -X GET "$BASE_URL/api/v1/graph/analysis" | jq .

# Get graph analysis report
curl -X GET "$BASE_URL/api/v1/graph/report"
```

## 7. OpenAPI Documentation

```bash
# Get OpenAPI specification
curl -X GET "$BASE_URL/q/openapi" | jq .

# Access Swagger UI in browser:
# http://localhost:8083/swagger-ui
```

## Report Types Available

- `BASIC`: Basic security assessment
- `COMPREHENSIVE`: Complete security analysis
- `COMPLIANCE`: Compliance-focused report
- `TECHNICAL`: Technical deep-dive report

## Example Domains for Testing

```bash
# Chilean Banking
DOMAIN="bancochile.cl"

# Chilean Government
DOMAIN="gob.cl"

# Chilean University
DOMAIN="uchile.cl"

# International Examples
DOMAIN="example.com"
DOMAIN="google.com"
```

## Batch Testing Script

```bash
#!/bin/bash
# Test multiple domains
DOMAINS=("bancochile.cl" "bancoestado.cl" "santander.cl" "bci.cl")

for domain in "${DOMAINS[@]}"; do
    echo "Testing domain: $domain"
    
    # Generate signed report
    curl -X POST "$BASE_URL/api/v1/signature/sign-report?domain=$domain&reportType=BASIC" \
      -H "Accept: application/octet-stream" \
      -o "signed_${domain}_$(date +%Y%m%d_%H%M%S).pdf"
    
    sleep 2
done
```

## Error Handling

```bash
# Check HTTP status codes
curl -w "HTTP Status: %{http_code}\n" -X GET "$BASE_URL/api/v1/signature/info"

# Verbose output for debugging
curl -v -X POST "$BASE_URL/api/v1/signature/sign-report?domain=test.com"

# Save response headers
curl -D headers.txt -X GET "$BASE_URL/q/health"
```

## Advanced Examples

### Generate Report with Custom Configuration

```bash
curl -X POST "$BASE_URL/api/v1/reports" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "enterprise-client-001",
    "domain": "bancochile.cl",
    "reportType": "COMPREHENSIVE",
    "requestNotes": "Quarterly security assessment - Q4 2024",
    "priority": "HIGH",
    "includeSubdomains": true,
    "includeTechnologies": true,
    "includeVulnerabilities": true
  }' \
  -o "comprehensive_bancochile_q4_2024.pdf"
```

### Validate Multiple Reports

```bash
#!/bin/bash
for file in *.pdf; do
    echo "Validating: $file"
    result=$(curl -s -X POST "$BASE_URL/api/v1/signature/validate" \
      -H "Content-Type: application/octet-stream" \
      -T "$file")
    
    valid=$(echo "$result" | jq -r '.valid')
    echo "$file: $valid"
done
```

## Troubleshooting

### Check Service Status

```bash
# Check if Quarkus is running
curl -f "$BASE_URL/q/health" && echo "Service is UP" || echo "Service is DOWN"

# Check application metrics
curl "$BASE_URL/q/metrics" 2>/dev/null | head -20
```

### Common Issues

1. **Port 8083 not accessible**
   ```bash
   # Check if service is running on correct port
   lsof -i:8083
   ```

2. **Neo4j connection warnings**
   ```bash
   # Check Neo4j connectivity (optional for basic reports)
   curl -X GET "$BASE_URL/api/v1/graph/health" 2>/dev/null || echo "Neo4j not available"
   ```

3. **Large file handling**
   ```bash
   # For large PDFs, increase timeout
   curl --max-time 300 -X POST "$BASE_URL/api/v1/signature/validate" \
     -H "Content-Type: application/octet-stream" \
     -T "large_report.pdf"
   ```