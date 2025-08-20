#!/bin/bash
# test_async_api.sh - Test script for Async Domain Discovery API
# 
# This script demonstrates the complete workflow of the async domain discovery API
# Usage: ./test_async_api.sh [domain]
#
# Examples:
#   ./test_async_api.sh example.com
#   ./test_async_api.sh bci.cl

set -e

# Configuration
API_BASE="http://localhost:8001/api/v1"
DOMAIN=${1:-"ripley.cl"}
SLEEP_TIME=5

echo "🚀 Testing Async Domain Discovery API with domain: $DOMAIN"
echo "API Base URL: $API_BASE"
echo "============================================================"

# Function to check task status and wait for completion
wait_for_task() {
    local task_id=$1
    local task_name=$2
    
    echo "⏳ Waiting for $task_name (Task ID: $task_id)"
    
    while true; do
        response=$(curl -s "$API_BASE/tasks/$task_id")
        status=$(echo "$response" | jq -r '.status')
        progress=$(echo "$response" | jq -r '.progress')
        
        echo "   Status: $status, Progress: $progress%"
        
        if [ "$status" = "completed" ]; then
            echo "✅ $task_name completed successfully"
            break
        elif [ "$status" = "failed" ]; then
            error=$(echo "$response" | jq -r '.error')
            echo "❌ $task_name failed: $error"
            break
        fi
        
        sleep $SLEEP_TIME
    done
    
    echo "$response"
}

# Function to pretty print JSON
pretty_json() {
    jq '.'
}

echo "1. 🏥 Health Check"
echo "===================="
curl -s "http://localhost:8001/health" | pretty_json
echo ""

echo "2. 📊 API Status"
echo "=================="
curl -s "$API_BASE/tasks" | pretty_json
echo ""

echo "3. 🔍 Starting Amass Discovery"
echo "==============================="
amass_response=$(curl -s -X POST "$API_BASE/discover/amass/$DOMAIN?timeout=180")
echo "$amass_response" | pretty_json
amass_task_id=$(echo "$amass_response" | jq -r '.task_id')
echo ""

# Wait for Amass to complete
amass_result=$(wait_for_task "$amass_task_id" "Amass Discovery")
echo "Amass Result Summary:"
echo "$amass_result" | jq '.result.metadata' | pretty_json
echo ""

echo "4. 🛠️ Starting Service Discovery on Base Domain"
echo "=============================================="
service_response=$(curl -s -X POST "$API_BASE/discover/services/$DOMAIN")
echo "$service_response" | pretty_json
service_task_id=$(echo "$service_response" | jq -r '.task_id')
echo ""

# Wait for service discovery to complete
service_result=$(wait_for_task "$service_task_id" "Service Discovery")
echo "Service Discovery Summary:"
echo "$service_result" | jq '.result.metadata' | pretty_json
echo ""

echo "5. 🌐 Starting DNS Analysis"
echo "============================"
dns_response=$(curl -s -X POST "$API_BASE/discover/dns/$DOMAIN")
echo "$dns_response" | pretty_json
dns_task_id=$(echo "$dns_response" | jq -r '.task_id')
echo ""

# Wait for DNS analysis to complete
dns_result=$(wait_for_task "$dns_task_id" "DNS Analysis")
echo "DNS Analysis Summary:"
echo "$dns_result" | jq '.result.metadata' | pretty_json
echo ""

echo "6. 📧 Starting MX Analysis"
echo "=========================="
mx_response=$(curl -s -X POST "$API_BASE/discover/mx/$DOMAIN")
echo "$mx_response" | pretty_json
mx_task_id=$(echo "$mx_response" | jq -r '.task_id')
echo ""

# Wait for MX analysis to complete
mx_result=$(wait_for_task "$mx_task_id" "MX Analysis")
echo "MX Analysis Summary:"
echo "$mx_result" | jq '.result.metadata' | pretty_json
echo ""

echo "7. 🔒 Starting TLS Analysis"
echo "=========================="
tls_response=$(curl -s -X POST "$API_BASE/discover/tls/$DOMAIN")
echo "$tls_response" | pretty_json
tls_task_id=$(echo "$tls_response" | jq -r '.task_id')
echo ""

# Wait for TLS analysis to complete
tls_result=$(wait_for_task "$tls_task_id" "TLS Analysis")
echo "TLS Analysis Summary:"
echo "$tls_result" | jq '.result.metadata' | pretty_json
echo ""

echo "8. 💻 Starting Technology Analysis"
echo "==================================="
tech_response=$(curl -s -X POST "$API_BASE/discover/tech/$DOMAIN")
echo "$tech_response" | pretty_json
tech_task_id=$(echo "$tech_response" | jq -r '.task_id')
echo ""

# Wait for tech analysis to complete
tech_result=$(wait_for_task "$tech_task_id" "Technology Analysis")
echo "Technology Analysis Summary:"
echo "$tech_result" | jq '.result.metadata' | pretty_json
echo ""

echo "9. 📋 Final Task Status Summary"
echo "==============================="
curl -s "$API_BASE/tasks" | jq '.tasks[] | {task_id: .task_id, task_type: .task_type, status: .status, progress: .progress}' | pretty_json
echo ""

echo "10. 🧹 Cleanup Completed Tasks (Optional)"
echo "=========================================="
completed_tasks=$(curl -s "$API_BASE/tasks" | jq -r '.tasks[] | select(.status == "completed") | .task_id')

for task_id in $completed_tasks; do
    echo "   Deleting task: $task_id"
    curl -s -X DELETE "$API_BASE/tasks/$task_id" | pretty_json
done

echo ""
echo "✅ Complete workflow test finished for domain: $DOMAIN"
echo "🗄️ Check your Neo4j database for the populated graph data"
echo "🌐 Visit http://localhost:8001/docs for API documentation"
