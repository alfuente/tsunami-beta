#!/bin/bash
# complete_certificates.sh - Complete SSL/TLS certificate analysis for domains
# Part of Tsunami Beta risk-quality module

set -e

DOMAIN_BACKEND_API="${DOMAIN_BACKEND_API:-http://localhost:8081}"
LOG_FILE="certificate_completion_$(date +%Y%m%d_%H%M%S).log"
BATCH_SIZE=25
MAX_CONCURRENT=2

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Complete SSL/TLS certificate analysis for domains missing certificate data"
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN     Process specific domain"
    echo "  -f, --file FILE         Process domains from file (one per line)"
    echo "  -a, --all              Process all domains missing certificate data"
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

analyze_tls_batch() {
    local domains=("$@")
    local domain_json
    local task_id
    
    # Create JSON array of domains
    domain_json=$(printf '%s\n' "${domains[@]}" | jq -R . | jq -s .)
    
    log "Starting TLS analysis for batch of ${#domains[@]} domains"
    
    # Start TLS analysis task
    response=$(curl -s -X POST "$DOMAIN_BACKEND_API/analyze/tls/batch" \
        -H "Content-Type: application/json" \
        -d "{\"domains\": $domain_json}")
    
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to start TLS analysis for batch"
        return 1
    fi
    
    task_id=$(echo "$response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('task_id', ''))" 2>/dev/null || echo "")
    
    if [ -z "$task_id" ]; then
        log "ERROR: No task_id received for TLS batch"
        return 1
    fi
    
    log "TLS batch analysis started with task ID: $task_id"
    
    # Monitor task progress
    max_wait=1200  # 20 minutes
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
                log "SUCCESS: TLS analysis completed for batch"
                return 0
                ;;
            "failed"|"partial")
                log "WARNING: TLS analysis completed with issues for batch (status: $status)"
                return 0  # Accept partial results
                ;;
            "running")
                log "PROGRESS: TLS batch - ${progress}% complete"
                ;;
            *)
                log "STATUS: TLS batch - $status"
                ;;
        esac
        
        sleep $check_interval
        wait_time=$((wait_time + check_interval))
    done
    
    log "TIMEOUT: TLS analysis timed out for batch after ${max_wait}s"
    return 1
}

analyze_single_domain() {
    local domain="$1"
    local task_id
    
    log "Starting TLS analysis for: $domain"
    
    # Start TLS analysis task
    response=$(curl -s -X POST "$DOMAIN_BACKEND_API/analyze/tls" \
        -H "Content-Type: application/json" \
        -d "{\"domain\": \"$domain\"}")
    
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to start TLS analysis for $domain"
        return 1
    fi
    
    task_id=$(echo "$response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('task_id', ''))" 2>/dev/null || echo "")
    
    if [ -z "$task_id" ]; then
        log "ERROR: No task_id received for $domain"
        return 1
    fi
    
    log "TLS analysis started for $domain with task ID: $task_id"
    
    # Monitor task progress
    max_wait=600  # 10 minutes
    wait_time=0
    check_interval=15
    
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
                log "SUCCESS: TLS analysis completed for $domain"
                return 0
                ;;
            "failed"|"partial")
                log "WARNING: TLS analysis completed with issues for $domain (status: $status)"
                return 0  # Accept partial results
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
    
    log "TIMEOUT: TLS analysis timed out for $domain after ${max_wait}s"
    return 1
}

get_domains_missing_certificates() {
    log "Querying domains missing SSL/TLS certificate data..."
    
    python3 - <<EOF
import sys
try:
    from neo4j import GraphDatabase
    
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "neo4j"))
    
    with driver.session() as session:
        query = """
        MATCH (d:Domain)
        WHERE d.fqdn IS NOT NULL
        AND NOT EXISTS {(d)-[:SECURED_BY]->(:Certificate)}
        AND d.fqdn =~ '.*\\\\.[a-zA-Z]{2,}$'
        RETURN d.fqdn as domain
        ORDER BY d.fqdn
        LIMIT 200
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

check_certificate_expiry() {
    log "Checking for expired certificates..."
    
    python3 - <<EOF
import sys
try:
    from neo4j import GraphDatabase
    from datetime import datetime, timedelta
    
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "neo4j"))
    
    with driver.session() as session:
        query = """
        MATCH (d:Domain)-[:SECURED_BY]->(c:Certificate)
        WHERE c.valid_to IS NOT NULL
        AND datetime(c.valid_to) < datetime() + duration({days: 30})
        RETURN d.fqdn as domain, c.subject_cn as certificate, c.valid_to as expiry
        ORDER BY c.valid_to
        LIMIT 50
        """
        
        result = session.run(query)
        expired_count = 0
        for record in result:
            print(f"WARNING: {record['domain']} certificate expires {record['expiry']}")
            expired_count += 1
        
        if expired_count == 0:
            print("INFO: No certificates expiring within 30 days found")
    
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
            sleep 5
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
        analyze_tls_batch "${batch[@]}" &
        pids+=($!)
        active_jobs=$((active_jobs + 1))
        
        log "Started batch ${#pids[@]} with ${#batch[@]} domains (PID: $!, Active: $active_jobs)"
        
        processed=$batch_end
        
        # Small delay between batches to avoid overwhelming the service
        sleep 2
    done
    
    # Wait for all remaining jobs to complete
    for pid in "${pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            wait "$pid"
        fi
    done
    
    log "All TLS analysis batches completed"
}

# Parse command line arguments
DOMAIN=""
FILE=""
ALL_DOMAINS=false
CHECK_EXPIRY=false

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
        --check-expiry)
            CHECK_EXPIRY=true
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
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Main execution
log "Starting SSL/TLS certificate completion script"
log "API: $DOMAIN_BACKEND_API"
log "Batch size: $BATCH_SIZE"
log "Max concurrent: $MAX_CONCURRENT"

check_health

# Check for jq dependency
if ! command -v jq > /dev/null; then
    log "ERROR: jq is required but not installed"
    exit 1
fi

# Check certificate expiry if requested
if [ "$CHECK_EXPIRY" = true ]; then
    check_certificate_expiry
    exit 0
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
    # Process all domains missing certificate data
    log "Processing all domains missing SSL/TLS certificate data"
    mapfile -t domains < <(get_domains_missing_certificates)
    
    if [ ${#domains[@]} -eq 0 ]; then
        log "No domains found missing certificate data"
        exit 0
    fi
    
    log "Found ${#domains[@]} domains missing certificate data"
    process_domains_in_batches "${domains[@]}"
    
else
    log "ERROR: No processing option specified"
    usage
    exit 1
fi

log "SSL/TLS certificate completion script finished"
log "Log file: $LOG_FILE"