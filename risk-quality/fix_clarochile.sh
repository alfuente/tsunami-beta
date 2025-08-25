#!/bin/bash
# fix_clarochile.sh - Quick fix for clarochile.cl timeout issues
# Part of Tsunami Beta risk-quality module

set -e

DOMAIN="clarochile.cl"
DOMAIN_BACKEND_API="${DOMAIN_BACKEND_API:-http://localhost:8081}"
LOG_FILE="fix_clarochile_$(date +%Y%m%d_%H%M%S).log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "🚀 Starting emergency fix for clarochile.cl"
log "Domain Backend API: $DOMAIN_BACKEND_API"

# Step 1: Kill any stuck amass processes
log "Step 1: Cleaning up stuck processes..."
pkill -f "amass.*clarochile.cl" 2>/dev/null || true
sleep 2

# Step 2: Cancel any running tasks for this domain
log "Step 2: Cancelling existing tasks..."
running_tasks=$(curl -s "$DOMAIN_BACKEND_API/tasks?domain=clarochile.cl" 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    tasks = data.get('tasks', [])
    for task in tasks:
        if task.get('status') in ['running', 'pending']:
            print(task.get('task_id', ''))
except:
    pass
" 2>/dev/null || echo "")

for task_id in $running_tasks; do
    if [ -n "$task_id" ]; then
        log "Cancelling task: $task_id"
        curl -s -X DELETE "$DOMAIN_BACKEND_API/tasks/$task_id" > /dev/null || true
    fi
done

# Step 3: Wait a moment for cleanup
log "Step 3: Waiting for cleanup to complete..."
sleep 5

# Step 4: Start minimal discovery (DNS + Certificates only)
log "Step 4: Starting minimal discovery for clarochile.cl..."

# Start DNS analysis
log "Starting DNS analysis..."
dns_response=$(curl -s -X POST "$DOMAIN_BACKEND_API/analyze/dns" \
    -H "Content-Type: application/json" \
    -d '{"domain": "clarochile.cl"}')

dns_task_id=$(echo "$dns_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('task_id', ''))" 2>/dev/null || echo "")

if [ -n "$dns_task_id" ]; then
    log "✅ DNS analysis started (Task: $dns_task_id)"
else
    log "❌ Failed to start DNS analysis"
fi

# Start certificate analysis  
log "Starting certificate analysis..."
cert_response=$(curl -s -X POST "$DOMAIN_BACKEND_API/analyze/tls" \
    -H "Content-Type: application/json" \
    -d '{"domain": "clarochile.cl"}')

cert_task_id=$(echo "$cert_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('task_id', ''))" 2>/dev/null || echo "")

if [ -n "$cert_task_id" ]; then
    log "✅ Certificate analysis started (Task: $cert_task_id)"
else
    log "❌ Failed to start certificate analysis"
fi

# Monitor progress
monitor_task() {
    local task_id="$1"
    local name="$2"
    local max_wait=300  # 5 minutes
    local wait_time=0
    
    while [ $wait_time -lt $max_wait ]; do
        status_response=$(curl -s "$DOMAIN_BACKEND_API/tasks/$task_id/status" 2>/dev/null)
        
        if [ $? -ne 0 ]; then
            log "ERROR: Cannot check status for $name task"
            return 1
        fi
        
        status=$(echo "$status_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('status', ''))" 2>/dev/null || echo "")
        
        case "$status" in
            "completed")
                log "✅ $name completed successfully"
                return 0
                ;;
            "failed")
                log "❌ $name failed"
                return 1
                ;;
            "running")
                log "⏳ $name in progress... (${wait_time}s)"
                ;;
        esac
        
        sleep 15
        wait_time=$((wait_time + 15))
    done
    
    log "⏰ $name timed out after ${max_wait}s"
    return 1
}

# Monitor both tasks
dns_success=false
cert_success=false

if [ -n "$dns_task_id" ]; then
    if monitor_task "$dns_task_id" "DNS Analysis"; then
        dns_success=true
    fi
fi

if [ -n "$cert_task_id" ]; then
    if monitor_task "$cert_task_id" "Certificate Analysis"; then
        cert_success=true
    fi
fi

# Step 5: Try passive subdomain discovery if basic tasks succeeded
if [ "$dns_success" = true ] || [ "$cert_success" = true ]; then
    log "Step 5: Attempting passive subdomain discovery..."
    
    passive_response=$(curl -s -X POST "$DOMAIN_BACKEND_API/discover/passive" \
        -H "Content-Type: application/json" \
        -d '{
            "domain": "clarochile.cl",
            "options": {
                "timeout": 120,
                "sources": ["crtsh", "virustotal"],
                "passive_only": true
            }
        }')
    
    passive_task_id=$(echo "$passive_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('task_id', ''))" 2>/dev/null || echo "")
    
    if [ -n "$passive_task_id" ]; then
        log "✅ Passive discovery started (Task: $passive_task_id)"
        if monitor_task "$passive_task_id" "Passive Discovery"; then
            log "✅ Passive subdomain discovery completed!"
        fi
    fi
fi

# Step 6: Final summary
log "🏁 Emergency fix completed for clarochile.cl"
log "Results:"
log "  - DNS Analysis: $([ "$dns_success" = true ] && echo "✅ SUCCESS" || echo "❌ FAILED")"
log "  - Certificate Analysis: $([ "$cert_success" = true ] && echo "✅ SUCCESS" || echo "❌ FAILED")"
log "  - Log file: $LOG_FILE"

if [ "$dns_success" = true ] || [ "$cert_success" = true ]; then
    log "🎉 At least basic data was collected for clarochile.cl"
    exit 0
else
    log "⚠️ No data could be collected for clarochile.cl"
    exit 1
fi