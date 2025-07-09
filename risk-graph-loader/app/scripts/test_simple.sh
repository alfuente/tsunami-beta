#\!/bin/bash

# Simple API test
echo "Testing Graph Service Health..."
curl -s http://localhost:8000/health || echo "Graph service not available"

echo "Testing Warehouse Service Health..."  
curl -s http://localhost:8001/health || echo "Warehouse service not available"

echo "Testing Graph Service Domains..."
curl -s "http://localhost:8000/api/v1/domains?limit=2" || echo "Domains endpoint not available"

echo "Testing complete"
EOF < /dev/null
