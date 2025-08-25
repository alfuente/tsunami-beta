#!/bin/bash
# complete_risk_scores.sh - Complete risk score calculation for entities missing risk data
# Part of Tsunami Beta risk-quality module

set -e

DOMAIN_BACKEND_API="${DOMAIN_BACKEND_API:-http://localhost:8081}"
LOG_FILE="risk_completion_$(date +%Y%m%d_%H%M%S).log"
BATCH_SIZE=100
MAX_CONCURRENT=2

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Complete risk score calculation for entities missing risk scores"
    echo ""
    echo "Options:"
    echo "  -t, --type TYPE         Entity type to process (domain|service|provider|technology|all)"
    echo "  -d, --domain DOMAIN     Process specific domain"
    echo "  -f, --file FILE         Process domains from file (one per line)"
    echo "  -a, --all              Process all entities missing risk scores"
    echo "  -b, --batch-size N      Batch size for processing (default: $BATCH_SIZE)"
    echo "  -c, --concurrent N      Max concurrent batches (default: $MAX_CONCURRENT)"
    echo "  --api URL              Domain backend API URL (default: $DOMAIN_BACKEND_API)"
    echo "  --recalculate          Recalculate existing risk scores"
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

calculate_risk_batch() {
    local entity_type="$1"
    local entities=("${@:2}")
    local entity_json
    local task_id
    
    if [ ${#entities[@]} -eq 0 ]; then
        log "WARNING: Empty batch for $entity_type"
        return 0
    fi
    
    # Create JSON array of entities
    entity_json=$(printf '%s\n' "${entities[@]}" | jq -R . | jq -s .)
    
    log "Starting risk calculation for batch of ${#entities[@]} $entity_type entities"
    
    # Determine endpoint based on entity type
    local endpoint
    case "$entity_type" in
        "domain"|"domains")
            endpoint="/analyze/risk/domains"
            ;;
        "service"|"services")
            endpoint="/analyze/risk/services"
            ;;
        "provider"|"providers")
            endpoint="/analyze/risk/providers"
            ;;
        "technology"|"technologies")
            endpoint="/analyze/risk/technologies"
            ;;
        *)
            log "ERROR: Unknown entity type: $entity_type"
            return 1
            ;;
    esac
    
    # Start risk calculation task
    response=$(curl -s -X POST "$DOMAIN_BACKEND_API$endpoint" \
        -H "Content-Type: application/json" \
        -d "{\"${entity_type}s\": $entity_json}")
    
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to start risk calculation for $entity_type batch"
        return 1
    fi
    
    task_id=$(echo "$response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('task_id', ''))" 2>/dev/null || echo "")
    
    if [ -z "$task_id" ]; then
        log "ERROR: No task_id received for $entity_type batch"
        return 1
    fi
    
    log "Risk calculation started for $entity_type batch with task ID: $task_id"
    
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
                log "SUCCESS: Risk calculation completed for $entity_type batch"
                return 0
                ;;
            "failed"|"partial")
                log "WARNING: Risk calculation completed with issues for $entity_type batch (status: $status)"
                return 0  # Accept partial results
                ;;
            "running")
                log "PROGRESS: $entity_type batch - ${progress}% complete"
                ;;
            *)
                log "STATUS: $entity_type batch - $status"
                ;;
        esac
        
        sleep $check_interval
        wait_time=$((wait_time + check_interval))
    done
    
    log "TIMEOUT: Risk calculation timed out for $entity_type batch after ${max_wait}s"
    return 1
}

calculate_single_domain_risk() {
    local domain="$1"
    local task_id
    
    log "Starting risk calculation for domain: $domain"
    
    # Start risk calculation task
    response=$(curl -s -X POST "$DOMAIN_BACKEND_API/analyze/risk/domain" \
        -H "Content-Type: application/json" \
        -d "{\"domain\": \"$domain\"}")
    
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to start risk calculation for $domain"
        return 1
    fi
    
    task_id=$(echo "$response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('task_id', ''))" 2>/dev/null || echo "")
    
    if [ -z "$task_id" ]; then
        log "ERROR: No task_id received for $domain"
        return 1
    fi
    
    log "Risk calculation started for $domain with task ID: $task_id"
    
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
        
        case "$status" in
            "completed")
                log "SUCCESS: Risk calculation completed for $domain"
                return 0
                ;;
            "failed"|"partial")
                log "WARNING: Risk calculation completed with issues for $domain (status: $status)"
                return 0
                ;;
            "running")
                log "PROGRESS: $domain - risk calculation in progress"
                ;;
            *)
                log "STATUS: $domain - $status"
                ;;
        esac
        
        sleep $check_interval
        wait_time=$((wait_time + check_interval))
    done
    
    log "TIMEOUT: Risk calculation timed out for $domain after ${max_wait}s"
    return 1
}

get_entities_missing_risk_scores() {
    local entity_type="$1"
    local recalculate="$2"
    
    log "Querying $entity_type entities missing risk scores..."
    
    python3 - "$entity_type" "$recalculate" <<'EOF'
import sys
entity_type = sys.argv[1]
recalculate = sys.argv[2] == "true"

try:
    from neo4j import GraphDatabase
    
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "neo4j"))
    
    with driver.session() as session:
        # Map entity types to node labels
        node_labels = {
            "domain": "Domain",
            "service": "Service", 
            "provider": "Provider",
            "technology": "Technology"
        }
        
        if entity_type not in node_labels:
            print(f"ERROR: Unknown entity type: {entity_type}", file=sys.stderr)
            sys.exit(1)
        
        node_label = node_labels[entity_type]
        
        # Build query based on recalculate flag
        if recalculate:
            condition = ""
            limit = 500
        else:
            condition = "AND (n.risk_score IS NULL OR n.risk_score = 0)"
            limit = 1000
        
        if entity_type == "domain":
            identifier = "n.fqdn"
        else:
            identifier = "n.name"
        
        query = f"""
        MATCH (n:{node_label})
        WHERE {identifier} IS NOT NULL {condition}
        RETURN {identifier} as identifier
        ORDER BY {identifier}
        LIMIT {limit}
        """
        
        result = session.run(query)
        for record in result:
            print(record["identifier"])
    
    driver.close()
    
except ImportError:
    print("ERROR: Neo4j driver not available", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
EOF
}

get_risk_score_statistics() {
    log "Generating risk score statistics..."
    
    python3 - <<'EOF'
import sys
try:
    from neo4j import GraphDatabase
    
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "neo4j"))
    
    entity_types = ["Domain", "Service", "Provider", "Technology"]
    
    with driver.session() as session:
        for entity_type in entity_types:
            query = f"""
            MATCH (n:{entity_type})
            WITH count(n) as total,
                 count(CASE WHEN n.risk_score IS NOT NULL AND n.risk_score > 0 THEN 1 END) as with_risk,
                 avg(CASE WHEN n.risk_score IS NOT NULL AND n.risk_score > 0 THEN n.risk_score END) as avg_risk
            RETURN total, with_risk, (total - with_risk) as missing, avg_risk
            """
            
            result = session.run(query)
            record = result.single()
            
            if record:
                total = record["total"]
                with_risk = record["with_risk"]
                missing = record["missing"]
                avg_risk = record["avg_risk"] or 0
                
                if total > 0:
                    coverage_pct = (with_risk / total) * 100
                    print(f"{entity_type}: {with_risk}/{total} ({coverage_pct:.1f}%) have risk scores, avg: {avg_risk:.2f}")
                else:
                    print(f"{entity_type}: No entities found")
    
    driver.close()
    
except ImportError:
    print("ERROR: Neo4j driver not available", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
EOF
}

process_entities_in_batches() {
    local entity_type="$1"
    local entities=("${@:2}")
    local total_entities=${#entities[@]}
    local processed=0
    local pids=()
    local active_jobs=0
    
    log "Processing ${total_entities} $entity_type entities in batches of ${BATCH_SIZE}"
    
    while [ $processed -lt $total_entities ]; do
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
        if [ $batch_end -gt $total_entities ]; then
            batch_end=$total_entities
        fi
        
        for ((i=processed; i<batch_end; i++)); do
            batch+=("${entities[$i]}")
        done
        
        # Process batch in background
        calculate_risk_batch "$entity_type" "${batch[@]}" &
        pids+=($!)
        active_jobs=$((active_jobs + 1))
        
        log "Started batch ${#pids[@]} with ${#batch[@]} $entity_type entities (PID: $!, Active: $active_jobs)"
        
        processed=$batch_end
        
        # Small delay between batches
        sleep 1
    done
    
    # Wait for all remaining jobs to complete
    for pid in "${pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            wait "$pid"
        fi
    done
    
    log "All risk calculation batches completed for $entity_type"
}

# Parse command line arguments
ENTITY_TYPE=""
DOMAIN=""
FILE=""
ALL_ENTITIES=false
RECALCULATE=false
STATS_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--type)
            ENTITY_TYPE="$2"
            shift 2
            ;;
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -f|--file)
            FILE="$2"
            shift 2
            ;;
        -a|--all)
            ALL_ENTITIES=true
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
        --recalculate)
            RECALCULATE=true
            shift
            ;;
        --stats)
            STATS_ONLY=true
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
log "Starting risk score completion script"
log "API: $DOMAIN_BACKEND_API"
log "Batch size: $BATCH_SIZE"
log "Max concurrent: $MAX_CONCURRENT"
log "Recalculate: $RECALCULATE"

# Show statistics if requested
if [ "$STATS_ONLY" = true ]; then
    get_risk_score_statistics
    exit 0
fi

check_health

# Check for jq dependency
if ! command -v jq > /dev/null; then
    log "ERROR: jq is required but not installed"
    exit 1
fi

if [ -n "$DOMAIN" ]; then
    # Process single domain
    log "Processing single domain: $DOMAIN"
    calculate_single_domain_risk "$DOMAIN"
    
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
    
    process_entities_in_batches "domain" "${domains[@]}"
    
elif [ "$ALL_ENTITIES" = true ]; then
    # Process all entities missing risk scores
    entity_types=("domain" "service" "provider" "technology")
    
    if [ -n "$ENTITY_TYPE" ]; then
        case "$ENTITY_TYPE" in
            "all")
                # Keep all types
                ;;
            "domain"|"service"|"provider"|"technology")
                entity_types=("$ENTITY_TYPE")
                ;;
            *)
                log "ERROR: Invalid entity type: $ENTITY_TYPE"
                log "Valid types: domain, service, provider, technology, all"
                exit 1
                ;;
        esac
    fi
    
    for entity_type in "${entity_types[@]}"; do
        log "Processing $entity_type entities missing risk scores"
        mapfile -t entities < <(get_entities_missing_risk_scores "$entity_type" "$RECALCULATE")
        
        if [ ${#entities[@]} -eq 0 ]; then
            log "No $entity_type entities found missing risk scores"
            continue
        fi
        
        log "Found ${#entities[@]} $entity_type entities missing risk scores"
        process_entities_in_batches "$entity_type" "${entities[@]}"
    done
    
else
    log "ERROR: No processing option specified"
    usage
    exit 1
fi

# Show final statistics
log "Final risk score statistics:"
get_risk_score_statistics

log "Risk score completion script finished"
log "Log file: $LOG_FILE"