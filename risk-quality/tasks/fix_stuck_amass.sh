#!/bin/bash
# fix_stuck_amass.sh - Fix stuck amass tasks and optimize subdomain discovery
# Part of Tsunami Beta risk-quality module

set -e

DOMAIN_BACKEND_API="${DOMAIN_BACKEND_API:-http://localhost:8081}"
LOG_FILE="amass_fix_$(date +%Y%m%d_%H%M%S).log"

usage() {
    echo "Usage: $0 [OPTIONS] [DOMAIN]"
    echo ""
    echo "Fix stuck amass tasks and optimize subdomain discovery"
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN     Fix specific domain"
    echo "  -k, --kill-stuck        Kill all stuck amass processes"
    echo "  -c, --cleanup           Clean up temporary amass files"
    echo "  -r, --restart-domain    Restart domain discovery with optimized settings"
    echo "  -s, --status            Check status of running tasks"
    echo "  --fast-mode             Use faster amass configuration"
    echo "  --api URL              Domain backend API URL"
    echo "  -h, --help             Show this help message"
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

kill_stuck_amass_processes() {
    log "Checking for stuck amass processes..."
    
    # Find amass processes running longer than 30 minutes
    stuck_pids=$(ps -eo pid,etime,comm | grep amass | awk '
        function time_to_seconds(time) {
            split(time, parts, ":")
            if (length(parts) == 2) {
                return parts[1] * 60 + parts[2]
            } else if (length(parts) == 3) {
                return parts[1] * 3600 + parts[2] * 60 + parts[3]
            }
            return 0
        }
        {
            if (time_to_seconds($2) > 1800) print $1
        }
    ')
    
    if [ -n "$stuck_pids" ]; then
        log "Found stuck amass processes: $stuck_pids"
        for pid in $stuck_pids; do
            log "Killing stuck amass process: $pid"
            kill -TERM "$pid" 2>/dev/null || true
            sleep 2
            kill -KILL "$pid" 2>/dev/null || true
        done
    else
        log "No stuck amass processes found"
    fi
}

cleanup_amass_files() {
    log "Cleaning up temporary amass files..."
    
    # Remove old amass output files
    find /tmp -name "amass_output_*.txt" -mtime +1 -delete 2>/dev/null || true
    
    # Remove amass cache files older than 7 days
    if [ -d "$HOME/.config/amass" ]; then
        find "$HOME/.config/amass" -name "*.json" -mtime +7 -delete 2>/dev/null || true
    fi
    
    log "Cleanup completed"
}

check_task_status() {
    log "Checking domain-backend task status..."
    
    if ! curl -f -s "$DOMAIN_BACKEND_API/health" > /dev/null; then
        log "ERROR: Domain backend is not available"
        return 1
    fi
    
    # Get running tasks
    running_tasks=$(curl -s "$DOMAIN_BACKEND_API/tasks?status=running" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    tasks = data.get('tasks', [])
    for task in tasks:
        if 'amass' in task.get('task_type', '').lower():
            print(f\"{task.get('task_id', 'unknown')} - {task.get('domain', 'unknown')} - {task.get('status', 'unknown')}\")
except:
    pass
" 2>/dev/null || echo "No running tasks found")
    
    log "Running amass tasks:"
    log "$running_tasks"
}

cancel_stuck_task() {
    local task_id="$1"
    
    log "Cancelling stuck task: $task_id"
    
    if curl -s -X DELETE "$DOMAIN_BACKEND_API/tasks/$task_id" | grep -q "success"; then
        log "Successfully cancelled task: $task_id"
    else
        log "Failed to cancel task: $task_id"
    fi
}

restart_domain_discovery() {
    local domain="$1"
    local fast_mode="$2"
    
    log "Restarting domain discovery for: $domain"
    
    # Cancel any existing tasks for this domain
    existing_tasks=$(curl -s "$DOMAIN_BACKEND_API/tasks?domain=$domain" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    tasks = data.get('tasks', [])
    for task in tasks:
        if task.get('status') in ['running', 'pending']:
            print(task.get('task_id', ''))
except:
    pass
" 2>/dev/null)
    
    for task_id in $existing_tasks; do
        if [ -n "$task_id" ]; then
            cancel_stuck_task "$task_id"
        fi
    done
    
    # Wait a moment for cancellation to complete
    sleep 3
    
    # Start new discovery with optimized settings
    local request_data
    if [ "$fast_mode" = "true" ]; then
        request_data='{
            "domain": "'$domain'",
            "options": {
                "timeout": 300,
                "active": false,
                "brute": false,
                "passive_only": true,
                "max_dns_queries": 1000,
                "resolvers": ["8.8.8.8", "1.1.1.1"]
            }
        }'
        log "Using fast mode (passive only) for $domain"
    else
        request_data='{
            "domain": "'$domain'",
            "options": {
                "timeout": 600,
                "active": true,
                "brute": true,
                "max_dns_queries": 5000,
                "resolvers": ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
            }
        }'
        log "Using optimized mode for $domain"
    fi
    
    response=$(curl -s -X POST "$DOMAIN_BACKEND_API/discover/amass" \
        -H "Content-Type: application/json" \
        -d "$request_data")
    
    task_id=$(echo "$response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('task_id', ''))" 2>/dev/null || echo "")
    
    if [ -n "$task_id" ]; then
        log "New discovery task started: $task_id"
        monitor_task_progress "$task_id" "$domain"
    else
        log "ERROR: Failed to start new discovery task for $domain"
        log "Response: $response"
    fi
}

monitor_task_progress() {
    local task_id="$1"
    local domain="$2"
    local max_wait=1200  # 20 minutes
    local wait_time=0
    local check_interval=30
    
    log "Monitoring task progress for $domain (Task: $task_id)"
    
    while [ $wait_time -lt $max_wait ]; do
        status_response=$(curl -s "$DOMAIN_BACKEND_API/tasks/$task_id/status")
        
        if [ $? -ne 0 ]; then
            log "ERROR: Failed to check status for task $task_id"
            return 1
        fi
        
        status=$(echo "$status_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('status', ''))" 2>/dev/null || echo "")
        progress=$(echo "$status_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('progress', 0))" 2>/dev/null || echo "0")
        
        case "$status" in
            "completed")
                log "✅ SUCCESS: Discovery completed for $domain"
                
                # Get results
                result_response=$(curl -s "$DOMAIN_BACKEND_API/tasks/$task_id/result")
                subdomain_count=$(echo "$result_response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    subdomains = data.get('subdomains', [])
    print(len(subdomains))
except:
    print('0')
" 2>/dev/null || echo "0")
                
                log "Found $subdomain_count subdomains for $domain"
                return 0
                ;;
            "failed")
                log "❌ ERROR: Discovery failed for $domain"
                
                # Get error details
                error_msg=$(echo "$status_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('error', 'Unknown error'))" 2>/dev/null || echo "Unknown error")
                log "Error details: $error_msg"
                return 1
                ;;
            "running")
                log "⏳ PROGRESS: $domain - ${progress}% complete (${wait_time}s elapsed)"
                ;;
            "timeout"|"cancelled")
                log "⚠️  WARNING: Task $status for $domain"
                return 1
                ;;
            *)
                log "📊 STATUS: $domain - $status (${wait_time}s elapsed)"
                ;;
        esac
        
        sleep $check_interval
        wait_time=$((wait_time + check_interval))
    done
    
    log "⏰ TIMEOUT: Discovery monitoring timed out for $domain after ${max_wait}s"
    cancel_stuck_task "$task_id"
    return 1
}

create_amass_config() {
    local config_dir="$HOME/.config/amass"
    local config_file="$config_dir/config.yaml"
    
    mkdir -p "$config_dir"
    
    cat > "$config_file" <<EOF
# Optimized Amass configuration for Tsunami Beta
scope:
  ports: [80, 443, 8080, 8443]
  blacklisted: []

options:
  resolvers: [8.8.8.8, 1.1.1.1, 208.67.222.222, 9.9.9.9]
  
datasources:
  minimum_ttl: 1440 # 24 hours
  
bruteforce:
  enabled: true
  recursive: true
  min_for_recursive: 1
  wordlists:
    - /usr/share/amass/wordlists/all.txt
    - /usr/share/amass/wordlists/deepmagic.com-prefixes-top50000.txt

alterations:
  enabled: true
  minimum_word_size: 2
  edit_distance: 1

EOF

    log "Created optimized amass config: $config_file"
}

# Parse command line arguments
DOMAIN=""
KILL_STUCK=false
CLEANUP=false
RESTART_DOMAIN=false
STATUS_CHECK=false
FAST_MODE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -k|--kill-stuck)
            KILL_STUCK=true
            shift
            ;;
        -c|--cleanup)
            CLEANUP=true
            shift
            ;;
        -r|--restart-domain)
            RESTART_DOMAIN=true
            shift
            ;;
        -s|--status)
            STATUS_CHECK=true
            shift
            ;;
        --fast-mode)
            FAST_MODE=true
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
log "Starting amass fix script"
log "Domain Backend API: $DOMAIN_BACKEND_API"

# Create optimized amass configuration
create_amass_config

# Execute requested actions
if [ "$STATUS_CHECK" = true ]; then
    check_task_status
fi

if [ "$KILL_STUCK" = true ]; then
    kill_stuck_amass_processes
fi

if [ "$CLEANUP" = true ]; then
    cleanup_amass_files
fi

if [ "$RESTART_DOMAIN" = true ]; then
    if [ -z "$DOMAIN" ]; then
        log "ERROR: Domain required for restart operation"
        exit 1
    fi
    
    restart_domain_discovery "$DOMAIN" "$FAST_MODE"
fi

if [ -n "$DOMAIN" ] && [ "$RESTART_DOMAIN" != true ]; then
    # Default action: restart domain discovery
    log "Restarting discovery for domain: $DOMAIN"
    restart_domain_discovery "$DOMAIN" "$FAST_MODE"
fi

log "Amass fix script completed"
log "Log file: $LOG_FILE"