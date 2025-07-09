#!/bin/bash

# Simple test script to validate basic API functionality

GRAPH_SERVICE_URL="http://localhost:8000"
WAREHOUSE_SERVICE_URL="http://localhost:8001"

echo "🧪 Simple API Test Script"
echo "========================="

# Test graph service health
echo "Testing Graph Service Health..."
if curl -s "$GRAPH_SERVICE_URL/health" | grep -q "ok\|healthy\|status"; then
    echo "✅ Graph service is healthy"
else
    echo "❌ Graph service is not responding"
    exit 1
fi

# Test warehouse service health
echo "Testing Warehouse Service Health..."
if curl -s "$WAREHOUSE_SERVICE_URL/health" | grep -q "ok\|healthy\|status"; then
    echo "✅ Warehouse service is healthy"
else
    echo "❌ Warehouse service is not responding"
    exit 1
fi

# Test graph service domains endpoint
echo "Testing Graph Service Domains..."
DOMAINS_RESPONSE=$(curl -s "$GRAPH_SERVICE_URL/api/v1/domains?limit=5")
if [ $? -eq 0 ] && [ -n "$DOMAINS_RESPONSE" ]; then
    echo "✅ Domains endpoint is working"
    echo "Response: $DOMAINS_RESPONSE"
else
    echo "❌ Domains endpoint is not working"
fi

# Test warehouse service datasets endpoint
echo "Testing Warehouse Service Datasets..."
DATASETS_RESPONSE=$(curl -s "$WAREHOUSE_SERVICE_URL/api/v1/datasets")
if [ $? -eq 0 ] && [ -n "$DATASETS_RESPONSE" ]; then
    echo "✅ Datasets endpoint is working"
    echo "Response: $DATASETS_RESPONSE"
else
    echo "❌ Datasets endpoint is not working"
fi

echo "✅ Simple API tests completed!"