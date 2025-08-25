#!/bin/bash
# complete_subdomains.sh - Complete subdomain discovery for domains missing subdomains
# Part of Tsunami Beta risk-quality module

set -e

DOMAIN_BACKEND_API="${DOMAIN_BACKEND_API:-http://localhost:8081}"
LOG_FILE="subdomain_completion_$(date +%Y%m%d_%H%M%S).log"
MAX_CONCURRENT=5

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Complete subdomain discovery for domains missing subdomains"
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN     Process specific domain"
    echo "  -f, --file FILE         Process domains from file (one per line)"
    echo "  -a, --all              Process all domains missing subdomains"
    echo "  -c, --concurrent N      Max concurrent processes (default: $MAX_CONCURRENT)"
    echo "  --api URL              Domain backend API URL (default: $DOMAIN_BACKEND_API)"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  DOMAIN_BACKEND_API     Domain backend API URL"
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

discover_subdomains() {
    local domain="$1"
    local task_id
    
    log "Starting subdomain discovery for: $domain"
    
    # Start discovery task
    response=$(curl -s -X POST "$DOMAIN_BACKEND_API/discover/amass" \
        -H "Content-Type: application/json" \
        -d "{\"domain\": \"$domain\"}")
    
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to start subdomain discovery for $domain"
        return 1
    fi
    
    task_id=$(echo "$response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('task_id', ''))" 2>/dev/null || echo "")
    
    if [ -z "$task_id" ]; then
        log "ERROR: No task_id received for $domain"
        return 1
    fi
    
    log "Task started for $domain with ID: $task_id"
    
    # Monitor task progress
    max_wait=1800  # 30 minutes
    wait_time=0
    check_interval=30
    
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
                log "SUCCESS: Subdomain discovery completed for $domain"
                return 0
                ;;
            "failed")
                log "ERROR: Subdomain discovery failed for $domain"
                return 1
                ;;
            "running")
                log "PROGRESS: $domain - ${progress}% complete"
                ;;
            *)
                log "STATUS: $domain - $status"
                ;;
        esac
        
        sleep $check_interval
        wait_time=$((wait_time + check_interval))
    done
    
    log "TIMEOUT: Subdomain discovery timed out for $domain after ${max_wait}s"
    return 1
}

get_domains_missing_subdomains() {
    log "Querying domains missing subdomains..."
    
    python3 - <<EOF
import sys
try:
    from neo4j import GraphDatabase
    
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "neo4j"))
    
    with driver.session() as session:
        query = """
        MATCH (d:Domain)
        WHERE d.fqdn IS NOT NULL 
        AND NOT d.fqdn CONTAINS '.'
        AND NOT EXISTS {
            MATCH (sub:Domain) 
            WHERE sub.fqdn CONTAINS d.fqdn 
            AND sub.fqdn <> d.fqdn
        }
        RETURN d.fqdn as domain
        ORDER BY d.fqdn
        LIMIT 100
        """
        
        result = session.run(query)
        for record in result:
            print(record["domain"])
    
    driver.close()
    
except ImportError:
    print("ERROR: Neo4j driver not available", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
EOF
}

process_domain_list() {
    local domains=("$@")
    local pids=()
    local active_jobs=0
    
    for domain in "${domains[@]}"; do
        # Wait if we have too many concurrent jobs
        while [ $active_jobs -ge $MAX_CONCURRENT ]; do
            for i in "${!pids[@]}"; do
                if ! kill -0 "${pids[$i]}" 2>/dev/null; then
                    unset 'pids[$i]'
                    active_jobs=$((active_jobs - 1))
                fi
            done
            sleep 2
        done
        
        # Start subdomain discovery in background
        discover_subdomains "$domain" &
        pids+=($!)
        active_jobs=$((active_jobs + 1))
        
        log "Started background job for $domain (PID: $!, Active: $active_jobs)"
    done
    
    # Wait for all remaining jobs to complete
    for pid in "${pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            wait "$pid"
        fi
    done
    
    log "All subdomain discovery tasks completed"
}

# Parse command line arguments
DOMAIN=""
FILE=""
ALL_DOMAINS=false

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
        -a|--all)
            ALL_DOMAINS=true
            shift
            ;;
        -c|--concurrent)
            MAX_CONCURRENT="$2"
            shift 2
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
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Main execution
log "Starting subdomain completion script"
log "API: $DOMAIN_BACKEND_API"
log "Max concurrent: $MAX_CONCURRENT"

check_health

if [ -n "$DOMAIN" ]; then
    # Process single domain
    log "Processing single domain: $DOMAIN"
    discover_subdomains "$DOMAIN"
    
elif [ -n "$FILE" ]; then
    # Process domains from file
    if [ ! -f "$FILE" ]; then
        log "ERROR: File not found: $FILE"
        exit 1
    fi
    
    log "Processing domains from file: $FILE"
    mapfile -t domains < "$FILE"
    process_domain_list "${domains[@]}"
    
elif [ "$ALL_DOMAINS" = true ]; then
    # Process all domains missing subdomains
    log "Processing all domains missing subdomains"
    mapfile -t domains < <(get_domains_missing_subdomains)
    
    if [ ${#domains[@]} -eq 0 ]; then
        log "No domains found missing subdomains"
        exit 0
    fi
    
    log "Found ${#domains[@]} domains missing subdomains"
    process_domain_list "${domains[@]}"
    
else
    log "ERROR: No processing option specified"
    usage
    exit 1
fi

log "Subdomain completion script finished"
log "Log file: $LOG_FILE"