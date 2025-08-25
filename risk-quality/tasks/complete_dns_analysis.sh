#!/bin/bash
# complete_dns_analysis.sh - Complete DNS analysis for domains missing DNS data
# Part of Tsunami Beta risk-quality module

set -e

DOMAIN_BACKEND_API="${DOMAIN_BACKEND_API:-http://localhost:8081}"
LOG_FILE="dns_completion_$(date +%Y%m%d_%H%M%S).log"
BATCH_SIZE=50
MAX_CONCURRENT=3

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Complete DNS analysis for domains missing DNS resolution data"
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN     Process specific domain"
    echo "  -f, --file FILE         Process domains from file (one per line)"
    echo "  -a, --all              Process all domains missing DNS data"
    echo "  -b, --batch-size N      Batch size for processing (default: $BATCH_SIZE)"
    echo "  -c, --concurrent N      Max concurrent batches (default: $MAX_CONCURRENT)"
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

analyze_dns_batch() {
    local domains=("$@")
    local domain_json
    local task_id
    
    # Create JSON array of domains
    domain_json=$(printf '%s\n' "${domains[@]}" | jq -R . | jq -s .)
    
    log "Starting DNS analysis for batch of ${#domains[@]} domains"
    
    # Start DNS analysis task
    response=$(curl -s -X POST "$DOMAIN_BACKEND_API/analyze/dns/batch" \
        -H "Content-Type: application/json" \
        -d "{\"domains\": $domain_json}")
    
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to start DNS analysis for batch"
        return 1
    fi
    
    task_id=$(echo "$response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('task_id', ''))" 2>/dev/null || echo "")
    
    if [ -z "$task_id" ]; then
        log "ERROR: No task_id received for DNS batch"
        return 1
    fi
    
    log "DNS batch analysis started with task ID: $task_id"
    
    # Monitor task progress
    max_wait=900  # 15 minutes
    wait_time=0
    check_interval=20
    
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
                log "SUCCESS: DNS analysis completed for batch"
                return 0
                ;;
            "failed")
                log "ERROR: DNS analysis failed for batch"
                return 1
                ;;
            "running")
                log "PROGRESS: DNS batch - ${progress}% complete"
                ;;
            *)
                log "STATUS: DNS batch - $status"
                ;;
        esac
        
        sleep $check_interval
        wait_time=$((wait_time + check_interval))
    done
    
    log "TIMEOUT: DNS analysis timed out for batch after ${max_wait}s"
    return 1
}

analyze_single_domain() {
    local domain="$1"
    local task_id
    
    log "Starting DNS analysis for: $domain"
    
    # Start DNS analysis task
    response=$(curl -s -X POST "$DOMAIN_BACKEND_API/analyze/dns" \
        -H "Content-Type: application/json" \
        -d "{\"domain\": \"$domain\"}")
    
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to start DNS analysis for $domain"
        return 1
    fi
    
    task_id=$(echo "$response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('task_id', ''))" 2>/dev/null || echo "")
    
    if [ -z "$task_id" ]; then
        log "ERROR: No task_id received for $domain"
        return 1
    fi
    
    log "DNS analysis started for $domain with task ID: $task_id"
    
    # Monitor task progress
    max_wait=300  # 5 minutes
    wait_time=0
    check_interval=10
    
    while [ $wait_time -lt $max_wait ]; do
        status_response=$(curl -s "$DOMAIN_BACKEND_API/tasks/$task_id/status")
        
        if [ $? -ne 0 ]; then
            log "ERROR: Failed to check status for task $task_id"
            return 1
        fi
        
        status=$(echo "$status_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('status', ''))" 2>/dev/null || echo "")
        
        case "$status" in
            "completed")
                log "SUCCESS: DNS analysis completed for $domain"
                return 0
                ;;
            "failed")
                log "ERROR: DNS analysis failed for $domain"
                return 1
                ;;
            "running")
                log "PROGRESS: $domain - DNS analysis in progress"
                ;;
            *)
                log "STATUS: $domain - $status"
                ;;
        esac
        
        sleep $check_interval
        wait_time=$((wait_time + check_interval))
    done
    
    log "TIMEOUT: DNS analysis timed out for $domain after ${max_wait}s"
    return 1
}

get_domains_missing_dns() {
    log "Querying domains missing DNS resolution data..."
    
    python3 - <<EOF
import sys
try:
    from neo4j import GraphDatabase
    
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "neo4j"))
    
    with driver.session() as session:
        query = """
        MATCH (d:Domain)
        WHERE d.fqdn IS NOT NULL
        AND NOT EXISTS {(d)-[:RESOLVES_TO]->(:DNSServer)}
        RETURN d.fqdn as domain
        ORDER BY d.fqdn
        LIMIT 500
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

process_domains_in_batches() {
    local domains=("$@")
    local total_domains=${#domains[@]}
    local processed=0
    local pids=()
    local active_jobs=0
    
    log "Processing ${total_domains} domains in batches of ${BATCH_SIZE}"
    
    while [ $processed -lt $total_domains ]; do
        # Wait if we have too many concurrent jobs
        while [ $active_jobs -ge $MAX_CONCURRENT ]; do
            for i in "${!pids[@]}"; do
                if ! kill -0 "${pids[$i]}" 2>/dev/null; then
                    unset 'pids[$i]'
                    active_jobs=$((active_jobs - 1))
                fi
            done
            sleep 3
        done
        
        # Create batch
        local batch=()
        local batch_end=$((processed + BATCH_SIZE))
        if [ $batch_end -gt $total_domains ]; then
            batch_end=$total_domains
        fi
        
        for ((i=processed; i<batch_end; i++)); do
            batch+=("${domains[$i]}")
        done
        
        # Process batch in background
        analyze_dns_batch "${batch[@]}" &
        pids+=($!)
        active_jobs=$((active_jobs + 1))
        
        log "Started batch ${#pids[@]} with ${#batch[@]} domains (PID: $!, Active: $active_jobs)"
        
        processed=$batch_end
    done
    
    # Wait for all remaining jobs to complete
    for pid in "${pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            wait "$pid"
        fi
    done
    
    log "All DNS analysis batches completed"
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
        -b|--batch-size)
            BATCH_SIZE="$2"
            shift 2
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
log "Starting DNS analysis completion script"
log "API: $DOMAIN_BACKEND_API"
log "Batch size: $BATCH_SIZE"
log "Max concurrent: $MAX_CONCURRENT"

check_health

# Check for jq dependency
if ! command -v jq > /dev/null; then
    log "ERROR: jq is required but not installed"
    exit 1
fi

if [ -n "$DOMAIN" ]; then
    # Process single domain
    log "Processing single domain: $DOMAIN"
    analyze_single_domain "$DOMAIN"
    
elif [ -n "$FILE" ]; then
    # Process domains from file
    if [ ! -f "$FILE" ]; then
        log "ERROR: File not found: $FILE"
        exit 1
    fi
    
    log "Processing domains from file: $FILE"
    mapfile -t domains < "$FILE"
    
    if [ ${#domains[@]} -eq 0 ]; then
        log "ERROR: No domains found in file"
        exit 1
    fi
    
    process_domains_in_batches "${domains[@]}"
    
elif [ "$ALL_DOMAINS" = true ]; then
    # Process all domains missing DNS data
    log "Processing all domains missing DNS resolution data"
    mapfile -t domains < <(get_domains_missing_dns)
    
    if [ ${#domains[@]} -eq 0 ]; then
        log "No domains found missing DNS resolution data"
        exit 0
    fi
    
    log "Found ${#domains[@]} domains missing DNS data"
    process_domains_in_batches "${domains[@]}"
    
else
    log "ERROR: No processing option specified"
    usage
    exit 1
fi

log "DNS analysis completion script finished"
log "Log file: $LOG_FILE"