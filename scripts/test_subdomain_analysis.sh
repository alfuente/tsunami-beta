#!/bin/bash
# test_subdomain_analysis.sh - Test script for subdomain-specific analysis
# 
# This script demonstrates how to analyze specific subdomains after Amass discovery
# Usage: ./test_subdomain_analysis.sh [domain] [subdomain]
#
# Examples:
#   ./test_subdomain_analysis.sh example.com www.example.com
#   ./test_subdomain_analysis.sh bci.cl api.bci.cl

set -e

# Configuration
API_BASE="http://localhost:8001/api/v1"
DOMAIN=${1:-"ripley.cl"}
SUBDOMAIN=${2:-"www.$DOMAIN"}
SLEEP_TIME=3

echo "🎯 Testing Subdomain-Specific Analysis"
echo "Domain: $DOMAIN"
echo "Subdomain: $SUBDOMAIN"
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

echo "1. 🔍 First, run Amass discovery to populate subdomains"
echo "======================================================"
amass_response=$(curl -s -X POST "$API_BASE/discover/amass/$DOMAIN?timeout=120")
echo "$amass_response" | pretty_json
amass_task_id=$(echo "$amass_response" | jq -r '.task_id')

# Wait for Amass to complete
if [ "$amass_task_id" != "null" ] && [ -n "$amass_task_id" ]; then
    amass_result=$(wait_for_task "$amass_task_id" "Amass Discovery")
    echo "Discovered subdomains:"
    echo "$amass_result" | jq -r '.result.subdomains[0:10] // []' | head -10
else
    echo "❌ Failed to start Amass discovery task"
fi
echo ""

echo "2. 🛠️ Service Discovery on Specific Subdomain"
echo "============================================"
service_response=$(curl -s -X POST "$API_BASE/discover/services/$DOMAIN?subdomain=$SUBDOMAIN")
echo "$service_response" | pretty_json
service_task_id=$(echo "$service_response" | jq -r '.task_id')

if [ "$service_task_id" != "null" ] && [ -n "$service_task_id" ]; then
    service_result=$(wait_for_task "$service_task_id" "Service Discovery on $SUBDOMAIN")
    echo "Services found on $SUBDOMAIN:"
    echo "$service_result" | jq -r '.result.services // [] | length' 2>/dev/null || echo "No services data"
else
    echo "❌ Failed to start service discovery task"
fi
echo ""

echo "3. 🌐 DNS Analysis on Specific Subdomain"
echo "======================================="
dns_response=$(curl -s -X POST "$API_BASE/discover/dns/$DOMAIN?subdomain=$SUBDOMAIN")
echo "$dns_response" | pretty_json
dns_task_id=$(echo "$dns_response" | jq -r '.task_id')

if [ "$dns_task_id" != "null" ] && [ -n "$dns_task_id" ]; then
    dns_result=$(wait_for_task "$dns_task_id" "DNS Analysis on $SUBDOMAIN")
    echo "DNS records for $SUBDOMAIN:"
    echo "$dns_result" | jq -r '.result.records // {} | keys | length' 2>/dev/null || echo "No DNS data"
else
    echo "❌ Failed to start DNS analysis task"
fi
echo ""

echo "4. 🔒 TLS Analysis on Specific Subdomain"
echo "======================================="
tls_response=$(curl -s -X POST "$API_BASE/discover/tls/$DOMAIN?subdomain=$SUBDOMAIN")
echo "$tls_response" | pretty_json
tls_task_id=$(echo "$tls_response" | jq -r '.task_id')

if [ "$tls_task_id" != "null" ] && [ -n "$tls_task_id" ]; then
    tls_result=$(wait_for_task "$tls_task_id" "TLS Analysis on $SUBDOMAIN")
    echo "TLS certificate info for $SUBDOMAIN:"
    echo "$tls_result" | jq -r '.result.certificate_info.subject // "No certificate data"' 2>/dev/null || echo "No TLS data"
else
    echo "❌ Failed to start TLS analysis task"
fi
echo ""

echo "5. 💻 Technology Analysis on Specific Subdomain"
echo "==============================================="
tech_response=$(curl -s -X POST "$API_BASE/discover/tech/$DOMAIN?subdomain=$SUBDOMAIN")
echo "$tech_response" | pretty_json
tech_task_id=$(echo "$tech_response" | jq -r '.task_id')

if [ "$tech_task_id" != "null" ] && [ -n "$tech_task_id" ]; then
    tech_result=$(wait_for_task "$tech_task_id" "Technology Analysis on $SUBDOMAIN")
    echo "Technologies detected on $SUBDOMAIN:"
    echo "$tech_result" | jq -r '.result.technologies // [] | length' 2>/dev/null || echo "No technology data"
else
    echo "❌ Failed to start technology analysis task"
fi
echo ""

echo "6. 🔄 Batch Analysis: All Subdomains - Service Discovery"
echo "======================================================="
batch_response=$(curl -s -X POST "$API_BASE/discover/all-subdomains/$DOMAIN?analysis_type=services")
echo "$batch_response" | pretty_json
batch_task_ids=$(echo "$batch_response" | jq -r '.task_ids[]')

echo "Started batch analysis with task IDs:"
echo "$batch_task_ids"
echo ""

echo "7. 📊 Monitor Batch Progress"
echo "============================"
echo "Waiting for batch tasks to complete..."
sleep 10

echo "Current task status:"
curl -s "$API_BASE/tasks" | jq '.tasks[] | select(.task_type == "service_discovery") | {subdomain: .subdomain, status: .status, progress: .progress}' | pretty_json
echo ""

echo "8. 🔍 Get Individual Task Results"
echo "================================="
for task_id in $batch_task_ids; do
    if [ -n "$task_id" ]; then
        echo "Checking task: $task_id"
        task_result=$(curl -s "$API_BASE/tasks/$task_id")
        status=$(echo "$task_result" | jq -r '.status')
        subdomain=$(echo "$task_result" | jq -r '.subdomain')
        
        if [ "$status" = "completed" ]; then
            services_count=$(echo "$task_result" | jq '.result.services | length')
            echo "  ✅ $subdomain: $services_count services found"
        else
            echo "  ⏳ $subdomain: $status"
        fi
    fi
done
echo ""

echo "9. 📋 Final Summary"
echo "=================="
echo "All discovered subdomains and their analysis status:"
curl -s "$API_BASE/tasks" | jq '.tasks[] | {domain: .domain, subdomain: .subdomain, task_type: .task_type, status: .status}' | pretty_json
echo ""

echo "✅ Subdomain-specific analysis test completed!"
echo "🗄️ Check Neo4j for detailed subdomain relationships and properties"
echo "💡 Tip: Use different analysis_type values in batch operations:"
echo "   - services: Port scanning and service identification"  
echo "   - dns: DNS record analysis"
echo "   - tls: Certificate and TLS analysis"
echo "   - tech: Web technology detection"
