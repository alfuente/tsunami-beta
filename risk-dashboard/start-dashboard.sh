#!/bin/bash

echo "=== Risk Dashboard Startup Script ==="
echo

# Check if risk-graph-service is running
echo "Checking API connection..."
if curl -s http://localhost:8081/api/v1/domains/security-summary > /dev/null; then
    echo "✓ API is running on port 8081"
else
    echo "✗ API is not accessible on port 8081"
    echo "Please start the risk-graph-service first"
    exit 1
fi

# Check if port 3000 is available
if netstat -tlnp 2>/dev/null | grep -q :3000; then
    echo "Port 3000 is already in use. Killing existing processes..."
    pkill -f "react-scripts start" 2>/dev/null || true
    sleep 2
fi

echo
echo "Starting React development server..."
echo "The dashboard will be available at: http://localhost:3000"
echo
echo "Press Ctrl+C to stop the server"
echo

# Start the development server
npm start