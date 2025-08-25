#!/bin/bash
# Restart API with automatic stuck task cleanup

echo "🔄 Restarting API service with stuck task fixes..."

# Kill existing service
pkill -f async_domain_discovery_api.py
sleep 2

# Start service in background
cd /home/alf/dev/tsunami-beta/domain-backend
./venv/bin/python async_domain_discovery_api.py > api_with_fixes.log 2>&1 &

echo "⏳ Waiting for service to start..."
sleep 10

# Check if service is running
if curl -s http://localhost:8001/health > /dev/null; then
    echo "✅ API service restarted successfully"
    
    # Run the stuck task fix
    python3 final_stuck_task_fix.py --auto-fix
    
    echo "🎉 Service restarted with stuck task fixes applied"
else
    echo "❌ API service failed to start"
    exit 1
fi
