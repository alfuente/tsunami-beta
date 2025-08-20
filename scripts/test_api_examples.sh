#!/bin/bash
# test_api_examples.sh - Quick examples and common usage patterns for the Async API
# 
# This script provides copy-paste curl examples for common operations
# Usage: ./test_api_examples.sh

set -e

API_BASE="http://localhost:8001/api/v1"
DOMAIN="ripley.cl"

echo "🚀 Async Domain Discovery API - Common Usage Examples"
echo "====================================================="
echo ""
echo "Base API URL: $API_BASE"
echo "Test Domain: $DOMAIN"
echo ""

echo "📋 BASIC OPERATIONS"
echo "==================="
echo ""

echo "1. Health Check:"
echo "curl -s $API_BASE/../health | jq ."
curl -s "$API_BASE/../health" | jq .
echo ""

echo "2. List all active tasks:"
echo "curl -s $API_BASE/tasks | jq ."
echo ""

echo "3. Get specific task status:"
echo "curl -s $API_BASE/tasks/TASK_ID | jq ."
echo ""

echo "🔍 DISCOVERY OPERATIONS"
echo "======================"
echo ""

echo "4. Start Amass discovery (with custom timeout):"
echo "curl -X POST '$API_BASE/discover/amass/$DOMAIN?timeout=300' | jq ."
echo ""

echo "5. Start service discovery on base domain:"
echo "curl -X POST '$API_BASE/discover/services/$DOMAIN' | jq ."
echo ""

echo "6. Start service discovery on specific subdomain:"
echo "curl -X POST '$API_BASE/discover/services/$DOMAIN?subdomain=www.$DOMAIN' | jq ."
echo ""

echo "7. Start DNS analysis:"
echo "curl -X POST '$API_BASE/discover/dns/$DOMAIN' | jq ."
echo ""

echo "8. Start MX/Email security analysis:"
echo "curl -X POST '$API_BASE/discover/mx/$DOMAIN' | jq ."
echo ""

echo "9. Start TLS certificate analysis:"
echo "curl -X POST '$API_BASE/discover/tls/$DOMAIN' | jq ."
echo ""

echo "10. Start web technology detection:"
echo "curl -X POST '$API_BASE/discover/tech/$DOMAIN' | jq ."
echo ""

echo "🔄 BATCH OPERATIONS"
echo "=================="
echo ""

echo "11. Analyze all subdomains for services:"
echo "curl -X POST '$API_BASE/discover/all-subdomains/$DOMAIN?analysis_type=services' | jq ."
echo ""

echo "12. Analyze all subdomains for DNS:"
echo "curl -X POST '$API_BASE/discover/all-subdomains/$DOMAIN?analysis_type=dns' | jq ."
echo ""

echo "13. Analyze all subdomains for TLS:"
echo "curl -X POST '$API_BASE/discover/all-subdomains/$DOMAIN?analysis_type=tls' | jq ."
echo ""

echo "14. Analyze all subdomains for technologies:"
echo "curl -X POST '$API_BASE/discover/all-subdomains/$DOMAIN?analysis_type=tech' | jq ."
echo ""

echo "🛠️ TASK MANAGEMENT"
echo "=================="
echo ""

echo "15. Delete completed task:"
echo "curl -X DELETE $API_BASE/tasks/TASK_ID | jq ."
echo ""

echo "📊 PRACTICAL WORKFLOW EXAMPLES"
echo "=============================="
echo ""

echo "Complete workflow for a new domain:"
echo "-----------------------------------"
echo "# Step 1: Discover subdomains and providers"
echo "AMASS_TASK=\$(curl -s -X POST '$API_BASE/discover/amass/$DOMAIN' | jq -r '.task_id')"
echo ""
echo "# Step 2: Wait and check status"
echo "curl -s $API_BASE/tasks/\$AMASS_TASK | jq '.status, .progress'"
echo ""
echo "# Step 3: Once completed, analyze email security"
echo "MX_TASK=\$(curl -s -X POST '$API_BASE/discover/mx/$DOMAIN' | jq -r '.task_id')"
echo ""
echo "# Step 4: Batch analyze all discovered subdomains for services"
echo "BATCH_TASK=\$(curl -s -X POST '$API_BASE/discover/all-subdomains/$DOMAIN?analysis_type=services' | jq -r '.task_ids[0]')"
echo ""
echo "# Step 5: Monitor progress"
echo "curl -s $API_BASE/tasks | jq '.tasks[] | {task_type, status, progress}'"
echo ""

echo "Analyzing a specific high-value subdomain:"
echo "-----------------------------------------"
echo "SUBDOMAIN='api.$DOMAIN'"
echo "# Service discovery"
echo "curl -X POST '$API_BASE/discover/services/$DOMAIN?subdomain=\$SUBDOMAIN'"
echo "# TLS analysis"  
echo "curl -X POST '$API_BASE/discover/tls/$DOMAIN?subdomain=\$SUBDOMAIN'"
echo "# Technology stack"
echo "curl -X POST '$API_BASE/discover/tech/$DOMAIN?subdomain=\$SUBDOMAIN'"
echo ""

echo "🔧 USEFUL ONE-LINERS"
echo "==================="
echo ""

echo "Count total active tasks:"
echo "curl -s $API_BASE/tasks | jq '.tasks | length'"
echo ""

echo "Get all completed task results:"
echo "curl -s $API_BASE/tasks | jq '.tasks[] | select(.status == \"completed\") | .result'"
echo ""

echo "Get all failed tasks with errors:"
echo "curl -s $API_BASE/tasks | jq '.tasks[] | select(.status == \"failed\") | {task_type, domain, error}'"
echo ""

echo "Monitor all running tasks:"
echo "curl -s $API_BASE/tasks | jq '.tasks[] | select(.status == \"running\") | {task_type, domain, progress}'"
echo ""

echo "Get Amass cache status (check if domain was recently scanned):"
echo "curl -s -X POST '$API_BASE/discover/amass/$DOMAIN?timeout=60' | jq '.cached'"
echo ""

echo "🚦 REAL-TIME MONITORING"
echo "======================"
echo ""

echo "Monitor specific task until completion:"
echo "---------------------------------------"
cat << 'EOF'
#!/bin/bash
TASK_ID=$1
while true; do
    STATUS=$(curl -s $API_BASE/tasks/$TASK_ID | jq -r '.status')
    PROGRESS=$(curl -s $API_BASE/tasks/$TASK_ID | jq -r '.progress')
    echo "Status: $STATUS, Progress: $PROGRESS%"
    [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ] && break
    sleep 5
done
EOF
echo ""

echo "Watch all tasks progress:"
echo "------------------------"
echo "watch 'curl -s $API_BASE/tasks | jq \".tasks[] | {task_type, domain, status, progress}\"'"
echo ""

echo "💡 TIPS"
echo "======"
echo "- Amass results are cached for 24 hours to improve performance"
echo "- Use ?subdomain= parameter to analyze specific subdomains"
echo "- Batch operations start multiple tasks simultaneously"
echo "- Check /docs endpoint for interactive API documentation"
echo "- MX analysis is domain-level only (not subdomain)"
echo "- All results are automatically saved to Neo4j graph database"
echo ""

echo "🔗 RELATED ENDPOINTS"
echo "==================="
echo "API Documentation: http://localhost:8001/docs"
echo "Health Check: http://localhost:8001/health"
echo "Task List: $API_BASE/tasks"
echo ""

echo "✅ Example commands ready to use!"
echo "Copy and paste any of the above curl commands to test the API."
