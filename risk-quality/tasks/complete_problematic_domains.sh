#!/bin/bash
# complete_problematic_domains.sh - Handle domains that timeout or fail in subdomain discovery
# Part of Tsunami Beta risk-quality module

set -e

DOMAIN_BACKEND_API="${DOMAIN_BACKEND_API:-http://localhost:8081}"
LOG_FILE="problematic_domains_$(date +%Y%m%d_%H%M%S).log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    echo "Usage: $0 [OPTIONS] [DOMAIN]"
    echo ""
    echo "Handle problematic domains with optimized discovery strategies"
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN     Process specific problematic domain"
    echo "  -f, --file FILE         Process domains from file"
    echo "  -l, --list-failed       List recently failed domains"
    echo "  --fast-only             Use only passive/fast discovery methods"
    echo "  --incremental           Use incremental discovery approach"
    echo "  --minimal               Use minimal resource discovery"
    echo "  --api URL              Domain backend API URL"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Strategies:"
    echo "  fast-only    - Passive DNS only, no brute force"
    echo "  incremental  - Progressive timeout increases"
    echo "  minimal      - Basic DNS + certificate only"
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

check_health() {
    log "Checking domain-backend health..."
    if ! curl -f -s "$DOMAIN_BACKEND_API/health" > /dev/null; then
        log "ERROR: Domain backend is not available at $DOMAIN_BACKEND_API"
        exit 1
    fi
    log "Domain backend is healthy"
}

list_failed_domains() {
    log "Listing recently failed domains..."
    
    # Get failed tasks from the last 24 hours
    python3 - <<EOF
import sys
import json
import requests
from datetime import datetime, timedelta

try:
    response = requests.get('$DOMAIN_BACKEND_API/tasks?status=failed&limit=50')
    if response.status_code == 200:
        data = response.json()
        tasks = data.get('tasks', [])
        
        failed_domains = set()
        now = datetime.now()
        
        for task in tasks:
            # Check if task failed in last 24 hours
            created_at = task.get('created_at', '')
            if created_at:
                try:
                    task_time = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    if (now - task_time).total_seconds() < 86400:  # 24 hours
                        domain = task.get('domain', '')
                        task_type = task.get('task_type', '')
                        error = task.get('error', '')
                        
                        if domain and 'amass' in task_type.lower():
                            if 'timeout' in error.lower():
                                failed_domains.add(domain)
                                print(f"{domain} - {error}")
                except:
                    pass
        
        if not failed_domains:
            print("No failed domains found in the last 24 hours")
    else:
        print("Could not retrieve failed tasks")

except Exception as e:
    print(f"Error: {e}")
EOF
}

discover_with_fast_mode() {
    local domain="$1"
    
    log "Starting fast discovery for: $domain"
    
    # Use only passive DNS sources
    local request_data='{
        "domain": "'$domain'",
        "options": {
            "passive_only": true,
            "timeout": 180,
            "active": false,
            "brute": false,
            "resolvers": ["8.8.8.8", "1.1.1.1"],
            "datasources": ["crtsh", "virustotal", "dnsdumpster"]
        }
    }'
    
    local response=$(curl -s -X POST "$DOMAIN_BACKEND_API/discover/passive" \
        -H "Content-Type: application/json" \
        -d "$request_data")
    
    local task_id=$(echo "$response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('task_id', ''))" 2>/dev/null || echo "")
    
    if [ -n "$task_id" ]; then
        log "Fast discovery started for $domain (Task: $task_id)"
        monitor_task "$task_id" "$domain" 300  # 5 minutes timeout
    else
        log "ERROR: Failed to start fast discovery for $domain"
        return 1
    fi
}

discover_with_incremental_timeouts() {
    local domain="$1"
    local timeouts=(120 300 600)  # 2, 5, 10 minutes
    
    for timeout in "${timeouts[@]}"; do
        log "Trying incremental discovery for $domain with ${timeout}s timeout"
        
        local request_data='{
            "domain": "'$domain'",
            "options": {
                "timeout": '$timeout',
                "active": false,
                "brute": true,
                "max_dns_queries": '$((timeout * 10))',
                "resolvers": ["8.8.8.8", "1.1.1.1"]
            }
        }'
        
        local response=$(curl -s -X POST "$DOMAIN_BACKEND_API/discover/amass" \
            -H "Content-Type: application/json" \
            -d "$request_data")
        
        local task_id=$(echo "$response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('task_id', ''))" 2>/dev/null || echo "")
        
        if [ -n "$task_id" ]; then
            log "Incremental discovery started for $domain (Task: $task_id, Timeout: ${timeout}s)"
            
            if monitor_task "$task_id" "$domain" $((timeout + 60)); then
                log "✅ SUCCESS: Incremental discovery completed for $domain at ${timeout}s"
                return 0
            else
                log "⚠️ Failed at ${timeout}s timeout, trying next level"
            fi
        else
            log "ERROR: Failed to start incremental discovery for $domain"
        fi
        
        sleep 10  # Brief pause between attempts
    done
    
    log "❌ All incremental timeouts failed for $domain"
    return 1
}

minimal_discovery() {
    local domain="$1"
    
    log "Starting minimal discovery for: $domain"
    
    # Just get basic DNS and certificate info
    local dns_task_id=""
    local cert_task_id=""
    
    # Start DNS analysis
    local dns_response=$(curl -s -X POST "$DOMAIN_BACKEND_API/analyze/dns" \
        -H "Content-Type: application/json" \
        -d '{"domain": "'$domain'"}')
    
    dns_task_id=$(echo "$dns_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('task_id', ''))" 2>/dev/null || echo "")
    
    # Start certificate analysis
    local cert_response=$(curl -s -X POST "$DOMAIN_BACKEND_API/analyze/tls" \
        -H "Content-Type: application/json" \
        -d '{"domain": "'$domain'"}')
    
    cert_task_id=$(echo "$cert_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('task_id', ''))" 2>/dev/null || echo "")
    
    local success=true
    
    # Monitor DNS task
    if [ -n "$dns_task_id" ]; then
        log "DNS analysis started for $domain (Task: $dns_task_id)"
        if ! monitor_task "$dns_task_id" "$domain (DNS)" 180; then
            success=false
        fi
    fi
    
    # Monitor certificate task
    if [ -n "$cert_task_id" ]; then
        log "Certificate analysis started for $domain (Task: $cert_task_id)"
        if ! monitor_task "$cert_task_id" "$domain (TLS)" 180; then
            success=false
        fi
    fi
    
    if [ "$success" = true ]; then
        log "✅ SUCCESS: Minimal discovery completed for $domain"
        return 0
    else
        log "⚠️ WARNING: Minimal discovery partially completed for $domain"
        return 1
    fi
}

monitor_task() {
    local task_id="$1"
    local description="$2"
    local max_wait="$3"
    local wait_time=0
    local check_interval=15
    
    while [ $wait_time -lt $max_wait ]; do
        local status_response=$(curl -s "$DOMAIN_BACKEND_API/tasks/$task_id/status")
        
        if [ $? -ne 0 ]; then
            log "ERROR: Failed to check status for task $task_id"
            return 1
        fi
        
        local status=$(echo "$status_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('status', ''))" 2>/dev/null || echo "")
        local progress=$(echo "$status_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('progress', 0))" 2>/dev/null || echo "0")
        
        case "$status" in
            "completed")
                log "✅ SUCCESS: $description completed"
                return 0
                ;;
            "failed")
                local error_msg=$(echo "$status_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('error', 'Unknown error'))" 2>/dev/null || echo "Unknown error")
                log "❌ ERROR: $description failed - $error_msg"
                return 1
                ;;
            "running")
                log "⏳ PROGRESS: $description - ${progress}% (${wait_time}s/${max_wait}s)"
                ;;
            "timeout"|"cancelled")
                log "⚠️ WARNING: $description $status"
                return 1
                ;;
            *)
                log "📊 STATUS: $description - $status"
                ;;
        esac
        
        sleep $check_interval
        wait_time=$((wait_time + check_interval))
    done
    
    log "⏰ TIMEOUT: $description monitoring timed out after ${max_wait}s"
    
    # Try to cancel the stuck task
    curl -s -X DELETE "$DOMAIN_BACKEND_API/tasks/$task_id" > /dev/null || true
    
    return 1
}

process_problematic_domain() {
    local domain="$1"
    local strategy="$2"
    
    log "Processing problematic domain: $domain (Strategy: $strategy)"
    
    # First, clean up any stuck processes for this domain
    "$SCRIPT_DIR/fix_stuck_amass.sh" --kill-stuck --cleanup --domain "$domain"
    
    case "$strategy" in
        "fast")
            discover_with_fast_mode "$domain"
            ;;
        "incremental")
            discover_with_incremental_timeouts "$domain"
            ;;
        "minimal")
            minimal_discovery "$domain"
            ;;
        "progressive")
            # Try all strategies progressively
            log "Using progressive strategy for $domain"
            if discover_with_fast_mode "$domain"; then
                log "✅ Fast mode succeeded for $domain"
            elif minimal_discovery "$domain"; then
                log "✅ Minimal discovery succeeded for $domain"  
            elif discover_with_incremental_timeouts "$domain"; then
                log "✅ Incremental discovery succeeded for $domain"
            else
                log "❌ All strategies failed for $domain"
                return 1
            fi
            ;;
        *)
            log "ERROR: Unknown strategy: $strategy"
            return 1
            ;;
    esac
}

# Parse command line arguments
DOMAIN=""
FILE=""
LIST_FAILED=false
STRATEGY="progressive"

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -f|--file)
            FILE="$2"
            shift 2
            ;;
        -l|--list-failed)
            LIST_FAILED=true
            shift
            ;;
        --fast-only)
            STRATEGY="fast"
            shift
            ;;
        --incremental)
            STRATEGY="incremental"
            shift
            ;;
        --minimal)
            STRATEGY="minimal"
            shift
            ;;
        --api)
            DOMAIN_BACKEND_API="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            if [ -z "$DOMAIN" ]; then
                DOMAIN="$1"
            fi
            shift
            ;;
    esac
done

# Main execution
log "Starting problematic domains handler"
log "API: $DOMAIN_BACKEND_API"
log "Strategy: $STRATEGY"

if [ "$LIST_FAILED" = true ]; then
    list_failed_domains
    exit 0
fi

check_health

if [ -n "$DOMAIN" ]; then
    # Process single domain
    process_problematic_domain "$DOMAIN" "$STRATEGY"
    
elif [ -n "$FILE" ]; then
    # Process domains from file
    if [ ! -f "$FILE" ]; then
        log "ERROR: File not found: $FILE"
        exit 1
    fi
    
    log "Processing domains from file: $FILE"
    while IFS= read -r domain; do
        if [ -n "$domain" ] && [[ ! "$domain" =~ ^[[:space:]]*# ]]; then
            process_problematic_domain "$domain" "$STRATEGY"
            sleep 5  # Brief pause between domains
        fi
    done < "$FILE"
    
else
    log "ERROR: No domain or file specified"
    usage
    exit 1
fi

log "Problematic domains handler completed"
log "Log file: $LOG_FILE"