#!/bin/bash

# Standalone Amass Executor for Domain-Backend Cache Integration
# Version: 1.0
# Purpose: Execute amass independently and save results in domain-backend cache format

set -euo pipefail

# Configuration defaults (can be overridden by environment variables)
CACHE_DIR="${AMASS_CACHE_DIR:-./amass_cache}"
METADATA_DIR="${CACHE_DIR}/metadata"
DATA_DIR="${CACHE_DIR}/data"
CACHE_STATS_FILE="${CACHE_DIR}/cache_stats.json"
AMASS_BINARY="${AMASS_BINARY_PATH:-amass}"
DEFAULT_TIMEOUT=300
DEFAULT_MODE="active"
AMASS_VERSION="4.2.0"
CONFIG_HASH="1ec28f3f"
CACHE_VERSION="1.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

# Help function
show_help() {
    cat << EOF
Standalone Amass Executor for Domain-Backend Cache Integration

USAGE:
    $0 [OPTIONS] DOMAIN
    $0 [OPTIONS] --batch-file FILE
    $0 cleanup [OPTIONS]

ARGUMENTS:
    DOMAIN              Domain to scan (required, unless using other commands)
    --batch-file FILE   Process multiple domains from file (one per line)
    cleanup             Clean expired cache entries (no domain required)

OPTIONS:
    -t, --timeout SECONDS   Amass timeout in seconds (default: $DEFAULT_TIMEOUT)
    -m, --mode MODE         Amass mode: passive|active (default: $DEFAULT_MODE)
                            active mode includes brute force and zone transfers
    -c, --cache-dir DIR     Cache directory path (default: $CACHE_DIR)
    -f, --force             Force rescan even if cached results exist
    -v, --verbose           Enable verbose output
    -j, --jobs JOBS         Number of parallel jobs for batch processing (default: 5)
    --log-dir DIR           Directory for individual domain logs (default: ./logs)
    -h, --help              Show this help message

ENVIRONMENT VARIABLES:
    AMASS_CACHE_DIR         Override default cache directory
    AMASS_BINARY_PATH       Override amass binary path
    CACHE_DURATION_HOURS    Cache duration in hours (default: 168 = 1 week)

EXAMPLES:
    $0 example.com
    $0 -t 600 -m active example.com
    $0 --force --verbose subdomain.example.com
    $0 --batch-file domains.txt -j 3 --verbose
    $0 --batch-file /path/to/domains.txt -t 300 --log-dir /var/log/amass
    $0 cleanup --verbose
    $0 cleanup -c /path/to/cache

EOF
}

# Generate hash for domain (used for cache keys)
generate_hash() {
    local domain="$1"
    echo -n "$domain" | sha256sum | cut -d' ' -f1 | head -c16
}

# Check if cache entry exists and is valid
is_cache_valid() {
    local domain="$1"
    local cache_duration_hours="${CACHE_DURATION_HOURS:-168}"  # 1 week default
    local hash
    hash=$(generate_hash "$domain")
    local metadata_file="${METADATA_DIR}/${hash}.json"
    
    if [[ ! -f "$metadata_file" ]]; then
        return 1
    fi
    
    # Check if cache is expired
    local timestamp
    timestamp=$(jq -r '.timestamp' "$metadata_file" 2>/dev/null || echo "")
    if [[ -z "$timestamp" ]]; then
        return 1
    fi
    
    # Convert timestamp to epoch
    local cache_epoch
    cache_epoch=$(date -d "$timestamp" +%s 2>/dev/null || echo "0")
    local current_epoch
    current_epoch=$(date +%s)
    local cache_age_hours
    cache_age_hours=$(( (current_epoch - cache_epoch) / 3600 ))
    
    if [[ $cache_age_hours -gt $cache_duration_hours ]]; then
        log_info "Cache expired for $domain (age: ${cache_age_hours}h, max: ${cache_duration_hours}h)"
        return 1
    fi
    
    log_info "Valid cache found for $domain (age: ${cache_age_hours}h)"
    return 0
}

# Initialize cache directories
init_cache_dirs() {
    mkdir -p "$METADATA_DIR" "$DATA_DIR"
    
    # Initialize cache stats if not exists
    if [[ ! -f "$CACHE_STATS_FILE" ]]; then
        cat > "$CACHE_STATS_FILE" << EOF
{
  "hits": 0,
  "misses": 0,
  "evictions": 0,
  "total_domains_cached": 0
}
EOF
    fi
}

# Update cache statistics
update_cache_stats() {
    local operation="$1"  # hit, miss, evict, add
    
    if [[ ! -f "$CACHE_STATS_FILE" ]]; then
        init_cache_dirs
    fi
    
    local temp_file
    temp_file=$(mktemp)
    
    case "$operation" in
        hit)
            jq '.hits += 1' "$CACHE_STATS_FILE" > "$temp_file"
            ;;
        miss)
            jq '.misses += 1' "$CACHE_STATS_FILE" > "$temp_file"
            ;;
        evict)
            jq '.evictions += 1' "$CACHE_STATS_FILE" > "$temp_file"
            ;;
        add)
            jq '.total_domains_cached += 1' "$CACHE_STATS_FILE" > "$temp_file"
            ;;
        *)
            log_error "Unknown cache operation: $operation"
            rm -f "$temp_file"
            return 1
            ;;
    esac
    
    mv "$temp_file" "$CACHE_STATS_FILE"
}

# Get cached results
get_cached_results() {
    local domain="$1"
    local hash
    hash=$(generate_hash "$domain")
    local data_file="${DATA_DIR}/${hash}.json.gz"
    
    if [[ -f "$data_file" ]]; then
        update_cache_stats "hit"
        log_success "Retrieved cached results for $domain"
        gunzip -c "$data_file"
        return 0
    else
        update_cache_stats "miss"
        return 1
    fi
}

# Run amass and capture results
run_amass() {
    local domain="$1"
    local timeout="$2"
    local mode="$3"
    local verbose="$4"
    
    log_info "Running amass for domain: $domain (timeout: ${timeout}s, mode: $mode)"
    
    # Create temporary file for amass output
    local temp_output
    temp_output=$(mktemp)
    
    # Construct amass command with enhanced discovery
    local amass_cmd=("$AMASS_BINARY" "enum" "-d" "$domain")
    
    if [[ "$mode" == "active" ]]; then
        amass_cmd+=("-active" "-brute")
    fi
    
    # Add timeout (amass expects minutes) - minimum 5 minutes for active mode
    local timeout_minutes=$((timeout / 60))
    if [[ $timeout_minutes -lt 5 ]]; then
        timeout_minutes=5
    fi
    amass_cmd+=("-timeout" "$timeout_minutes")
    
    # Add output file
    amass_cmd+=("-o" "$temp_output")
    
    if [[ "$verbose" == "true" ]]; then
        log_info "Executing: ${amass_cmd[*]}"
    fi
    
    # Execute amass with timeout
    local start_time
    start_time=$(date +%s)
    
    if timeout $((timeout + 60)) "${amass_cmd[@]}" 2>/dev/null; then
        local end_time
        end_time=$(date +%s)
        local execution_time=$((end_time - start_time))
        
        # Read results from Amass structured output
        local subdomains=()
        if [[ -f "$temp_output" ]]; then
            # Extract subdomains using regex pattern for the domain
            local domain_pattern="[a-zA-Z0-9._-]+\.${domain//./\\.}"
            while read -r subdomain; do
                # Validate subdomain format and add to array
                if [[ -n "$subdomain" && "$subdomain" =~ ^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$ ]]; then
                    subdomains+=("$subdomain")
                fi
            done < <(grep -oE "$domain_pattern" "$temp_output" | sort -u)
        fi
        
        local subdomain_count=${#subdomains[@]}
        log_success "Amass completed in ${execution_time}s, found $subdomain_count subdomains"
        
        # Clean up temp file
        rm -f "$temp_output"
        
        # Return results as JSON array with proper escaping
        if [[ ${#subdomains[@]} -gt 0 ]]; then
            # Create JSON array manually to avoid jq parsing issues
            echo -n "["
            local first=true
            for subdomain in "${subdomains[@]}"; do
                if [[ "$first" == "true" ]]; then
                    first=false
                else
                    echo -n ","
                fi
                # Use jq to properly escape the individual subdomain
                echo -n "$(echo "$subdomain" | jq -R .)"
            done
            echo "]"
        else
            echo "[]"
        fi
        
        return 0
    else
        log_error "Amass execution failed or timed out"
        rm -f "$temp_output"
        return 1
    fi
}

# Save results to cache
save_to_cache() {
    local domain="$1"
    local subdomains_json="$2"
    local timeout="$3"
    local mode="$4"
    
    local hash
    hash=$(generate_hash "$domain")
    local metadata_file="${METADATA_DIR}/${hash}.json"
    local data_file="${DATA_DIR}/${hash}.json.gz"
    local timestamp
    timestamp=$(date -Iseconds)
    
    # Count subdomains
    local subdomain_count
    subdomain_count=$(echo "$subdomains_json" | jq '. | length')
    
    # Create metadata
    local metadata
    metadata=$(cat << EOF
{
  "domain": "$domain",
  "timestamp": "$timestamp",
  "mode": "$mode",
  "timeout": $timeout,
  "amass_version": "$AMASS_VERSION",
  "config_hash": "$CONFIG_HASH",
  "subdomain_count": $subdomain_count,
  "cache_version": "$CACHE_VERSION"
}
EOF
)
    
    # Save metadata
    echo "$metadata" > "$metadata_file"
    
    # Save compressed data
    echo "$subdomains_json" | gzip > "$data_file"
    
    # Update cache stats
    update_cache_stats "add"
    
    log_success "Cached results for $domain ($subdomain_count subdomains)"
}

# Clean expired cache entries (force version)
force_clean_expired_cache() {
    local cache_duration_hours="${CACHE_DURATION_HOURS:-168}"
    local current_epoch
    current_epoch=$(date +%s)
    local cleaned_count=0
    
    log_info "Force cleaning expired cache entries (older than ${cache_duration_hours}h)"
    
    # Process files in batches to avoid memory issues
    find "$METADATA_DIR" -name "*.json" -type f | while read -r metadata_file; do
        [[ ! -f "$metadata_file" ]] && continue
        
        local timestamp
        timestamp=$(jq -r '.timestamp' "$metadata_file" 2>/dev/null || echo "")
        [[ -z "$timestamp" ]] && continue
        
        local cache_epoch
        cache_epoch=$(date -d "$timestamp" +%s 2>/dev/null || echo "0")
        local cache_age_hours
        cache_age_hours=$(( (current_epoch - cache_epoch) / 3600 ))
        
        if [[ $cache_age_hours -gt $cache_duration_hours ]]; then
            local hash
            hash=$(basename "$metadata_file" .json)
            local data_file="${DATA_DIR}/${hash}.json.gz"
            
            rm -f "$metadata_file" "$data_file" 2>/dev/null
            echo "cleaned"
        fi
    done | wc -l | {
        read cleaned_count
        if [[ $cleaned_count -gt 0 ]]; then
            log_success "Force cleaned $cleaned_count expired cache entries"
            # Update cache stats
            for ((i=1; i<=cleaned_count; i++)); do
                update_cache_stats "evict"
            done
        else
            log_info "No expired cache entries found"
        fi
    }
}

# Clean expired cache entries (automatic version)
clean_expired_cache() {
    local cache_duration_hours="${CACHE_DURATION_HOURS:-168}"
    local current_epoch
    current_epoch=$(date +%s)
    local cleaned_count=0
    
    # Skip cleanup if there are too many files to avoid hanging
    local total_files
    total_files=$(find "$METADATA_DIR" -name "*.json" -type f | wc -l 2>/dev/null || echo "0")
    
    if [[ $total_files -gt 1000 ]]; then
        log_warn "Skipping automatic cache cleanup ($total_files files found). Use 'cleanup' command manually if needed."
        return 0
    fi
    
    log_info "Cleaning expired cache entries (older than ${cache_duration_hours}h, processing $total_files files)"
    
    # Use a more efficient approach with timeout protection
    timeout 30 bash -c "
        for metadata_file in \"$METADATA_DIR\"/*.json; do
            [[ ! -f \"\$metadata_file\" ]] && continue
            
            # Quick file age check using stat before parsing JSON
            if [[ \$(find \"\$metadata_file\" -mtime +$((cache_duration_hours/24)) 2>/dev/null | wc -l) -eq 0 ]]; then
                continue
            fi
            
            timestamp=\$(jq -r '.timestamp' \"\$metadata_file\" 2>/dev/null || echo \"\")
            [[ -z \"\$timestamp\" ]] && continue
            
            cache_epoch=\$(date -d \"\$timestamp\" +%s 2>/dev/null || echo \"0\")
            cache_age_hours=\$(( ($current_epoch - cache_epoch) / 3600 ))
            
            if [[ \$cache_age_hours -gt $cache_duration_hours ]]; then
                hash=\$(basename \"\$metadata_file\" .json)
                data_file=\"${DATA_DIR}/\${hash}.json.gz\"
                
                rm -f \"\$metadata_file\" \"\$data_file\" 2>/dev/null
                echo \"cleaned\"
            fi
        done
    " | wc -l | read cleaned_count
    
    if [[ $cleaned_count -gt 0 ]]; then
        log_info "Cleaned $cleaned_count expired cache entries"
        # Update cache stats only once
        for ((i=1; i<=cleaned_count; i++)); do
            update_cache_stats "evict"
        done
    fi
}

# Process a single domain (used for parallel execution)
process_single_domain() {
    local domain="$1"
    local timeout="$2"
    local mode="$3"
    local force="$4"
    local verbose="$5"
    local log_dir="$6"
    local job_id="$7"
    
    # Create domain-specific log file
    local domain_log="${log_dir}/amass_${domain//[^a-zA-Z0-9._-]/_}_${job_id}.log"
    local domain_error_log="${log_dir}/amass_${domain//[^a-zA-Z0-9._-]/_}_${job_id}.error"
    
    # Redirect output for this domain
    exec 3>&1 4>&2
    if [[ "$verbose" == "true" ]]; then
        exec 1> >(tee -a "$domain_log")
        exec 2> >(tee -a "$domain_error_log" >&2)
    else
        exec 1>>"$domain_log"
        exec 2>>"$domain_error_log"
    fi
    
    local start_time
    start_time=$(date '+%Y-%m-%d %H:%M:%S')
    
    log_info "[$job_id] Starting processing for domain: $domain at $start_time"
    
    # Process the domain
    local exit_code=0
    local result_count=0
    
    # Check if we should use cached results
    if [[ "$force" == "false" ]] && is_cache_valid "$domain"; then
        if cached_results=$(get_cached_results "$domain" 2>/dev/null); then
            result_count=$(echo "$cached_results" | jq '. | length' 2>/dev/null || echo "0")
            log_success "[$job_id] Used cached results for $domain ($result_count subdomains)"
            echo "$cached_results"
        else
            log_warn "[$job_id] Cache check failed for $domain, running amass"
            exit_code=2
        fi
    else
        # Run amass for this domain
        if results=$(run_amass "$domain" "$timeout" "$mode" "$verbose" 2>/dev/null); then
            result_count=$(echo "$results" | jq '. | length' 2>/dev/null || echo "0")
            
            # Save to cache
            save_to_cache "$domain" "$results" "$timeout" "$mode" 2>/dev/null
            
            log_success "[$job_id] Completed amass for $domain ($result_count subdomains)"
            echo "$results"
        else
            log_error "[$job_id] Failed to execute amass for domain: $domain"
            exit_code=1
        fi
    fi
    
    local end_time
    end_time=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Create summary for this domain
    local summary_file="${log_dir}/summary_${domain//[^a-zA-Z0-9._-]/_}_${job_id}.json"
    cat > "$summary_file" << EOF
{
    "domain": "$domain",
    "job_id": "$job_id",
    "start_time": "$start_time",
    "end_time": "$end_time",
    "timeout": $timeout,
    "mode": "$mode",
    "forced": $([[ "$force" == "true" ]] && echo "true" || echo "false"),
    "result_count": $result_count,
    "exit_code": $exit_code,
    "log_file": "$domain_log",
    "error_log": "$domain_error_log"
}
EOF
    
    # Restore stdout/stderr
    exec 1>&3 2>&4 3>&- 4>&-
    
    log_info "[$job_id] Finished processing $domain (exit: $exit_code, results: $result_count)"
    
    return $exit_code
}

# Process multiple domains in parallel
process_batch_domains() {
    local batch_file="$1"
    local timeout="$2"
    local mode="$3"
    local force="$4"
    local verbose="$5"
    local max_jobs="$6"
    local log_dir="$7"
    
    # Create log directory
    mkdir -p "$log_dir"
    
    # Create main batch log
    local batch_log="${log_dir}/batch_$(date '+%Y%m%d_%H%M%S').log"
    local batch_summary="${log_dir}/batch_summary_$(date '+%Y%m%d_%H%M%S').json"
    
    log_info "Starting batch processing of domains from $batch_file"
    log_info "Max parallel jobs: $max_jobs"
    log_info "Log directory: $log_dir"
    log_info "Batch log: $batch_log"
    
    # Read domains from file
    if [[ ! -f "$batch_file" ]]; then
        log_error "Batch file not found: $batch_file"
        return 1
    fi
    
    local domains=()
    while IFS= read -r line; do
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        # Clean domain (remove whitespace)
        domain=$(echo "$line" | tr -d '[:space:]')
        [[ -n "$domain" ]] && domains+=("$domain")
    done < "$batch_file"
    
    local total_domains=${#domains[@]}
    if [[ $total_domains -eq 0 ]]; then
        log_error "No valid domains found in $batch_file"
        return 1
    fi
    
    log_info "Found $total_domains domains to process"
    
    # Initialize batch tracking
    local batch_start_time
    batch_start_time=$(date '+%Y-%m-%d %H:%M:%S')
    local completed=0
    local failed=0
    local cached=0
    local pids=()
    local job_domains=()
    
    # Process domains with parallel limit
    for ((i=0; i<total_domains; i++)); do
        local domain="${domains[i]}"
        local job_id=$((i+1))
        
        # Wait if we've reached max parallel jobs
        while [[ ${#pids[@]} -ge $max_jobs ]]; do
            # Check for completed jobs
            local new_pids=()
            local new_job_domains=()
            
            for ((j=0; j<${#pids[@]}; j++)); do
                local pid="${pids[j]}"
                local job_domain="${job_domains[j]}"
                
                if kill -0 "$pid" 2>/dev/null; then
                    # Job still running
                    new_pids+=("$pid")
                    new_job_domains+=("$job_domain")
                else
                    # Job completed
                    wait "$pid"
                    local job_exit_code=$?
                    
                    case $job_exit_code in
                        0) ((completed++)); log_success "Job completed: $job_domain" ;;
                        1) ((failed++)); log_error "Job failed: $job_domain" ;;
                        2) ((cached++)); log_info "Job used cache: $job_domain" ;;
                        *) ((failed++)); log_error "Job unknown exit ($job_exit_code): $job_domain" ;;
                    esac
                fi
            done
            
            pids=("${new_pids[@]}")
            job_domains=("${new_job_domains[@]}")
            
            # Short sleep to avoid busy waiting
            [[ ${#pids[@]} -ge $max_jobs ]] && sleep 1
        done
        
        # Start new job
        log_info "Starting job $job_id/$total_domains for domain: $domain"
        
        (process_single_domain "$domain" "$timeout" "$mode" "$force" "$verbose" "$log_dir" "$job_id") &
        local new_pid=$!
        
        pids+=("$new_pid")
        job_domains+=("$domain")
        
        # Small delay between job starts to avoid overwhelming the system
        sleep 0.1
    done
    
    # Wait for all remaining jobs to complete
    log_info "Waiting for remaining $((${#pids[@]})) jobs to complete..."
    
    for ((j=0; j<${#pids[@]}; j++)); do
        local pid="${pids[j]}"
        local job_domain="${job_domains[j]}"
        
        wait "$pid"
        local job_exit_code=$?
        
        case $job_exit_code in
            0) ((completed++)); log_success "Job completed: $job_domain" ;;
            1) ((failed++)); log_error "Job failed: $job_domain" ;;
            2) ((cached++)); log_info "Job used cache: $job_domain" ;;
            *) ((failed++)); log_error "Job unknown exit ($job_exit_code): $job_domain" ;;
        esac
    done
    
    local batch_end_time
    batch_end_time=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Create batch summary
    cat > "$batch_summary" << EOF
{
    "batch_file": "$batch_file",
    "start_time": "$batch_start_time",
    "end_time": "$batch_end_time",
    "total_domains": $total_domains,
    "max_parallel_jobs": $max_jobs,
    "results": {
        "completed": $completed,
        "failed": $failed,
        "cached": $cached
    },
    "settings": {
        "timeout": $timeout,
        "mode": "$mode",
        "force": $([[ "$force" == "true" ]] && echo "true" || echo "false"),
        "log_dir": "$log_dir"
    }
}
EOF
    
    # Final summary
    log_success "Batch processing completed!"
    log_info "Total domains: $total_domains"
    log_info "Completed: $completed"
    log_info "Failed: $failed" 
    log_info "Used cache: $cached"
    log_info "Batch summary: $batch_summary"
    
    # Return non-zero if any jobs failed
    [[ $failed -eq 0 ]] && return 0 || return 1
}

# Main function
main() {
    local domain=""
    local batch_file=""
    local timeout="$DEFAULT_TIMEOUT"
    local mode="$DEFAULT_MODE"
    local force=false
    local verbose=false
    local max_jobs=5
    local log_dir="./logs"
    
    # Check for cleanup command first
    if [[ "$1" == "cleanup" ]]; then
        shift
        
        # Parse cleanup-specific arguments
        while [[ $# -gt 0 ]]; do
            case $1 in
                -c|--cache-dir)
                    CACHE_DIR="$2"
                    METADATA_DIR="${CACHE_DIR}/metadata"
                    DATA_DIR="${CACHE_DIR}/data"
                    CACHE_STATS_FILE="${CACHE_DIR}/cache_stats.json"
                    shift 2
                    ;;
                -v|--verbose)
                    verbose=true
                    shift
                    ;;
                -h|--help)
                    show_help
                    exit 0
                    ;;
                -*|--*)
                    log_error "Unknown option $1 for cleanup command"
                    show_help
                    exit 1
                    ;;
                *)
                    log_error "Cleanup command does not accept domain arguments"
                    show_help
                    exit 1
                    ;;
            esac
        done
        
        # Initialize cache and run force cleanup
        init_cache_dirs
        force_clean_expired_cache
        exit 0
    fi
    
    # Parse regular arguments for domain scanning
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--timeout)
                timeout="$2"
                shift 2
                ;;
            -m|--mode)
                mode="$2"
                shift 2
                ;;
            -c|--cache-dir)
                CACHE_DIR="$2"
                METADATA_DIR="${CACHE_DIR}/metadata"
                DATA_DIR="${CACHE_DIR}/data"
                CACHE_STATS_FILE="${CACHE_DIR}/cache_stats.json"
                shift 2
                ;;
            -f|--force)
                force=true
                shift
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -j|--jobs)
                max_jobs="$2"
                shift 2
                ;;
            --log-dir)
                log_dir="$2"
                shift 2
                ;;
            --batch-file)
                batch_file="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*|--*)
                log_error "Unknown option $1"
                show_help
                exit 1
                ;;
            *)
                if [[ -n "$domain" ]]; then
                    log_error "Multiple domains specified. Only one domain is allowed."
                    exit 1
                fi
                domain="$1"
                shift
                ;;
        esac
    done
    
    # Validate arguments
    if [[ -n "$batch_file" && -n "$domain" ]]; then
        log_error "Cannot specify both --batch-file and domain argument"
        show_help
        exit 1
    fi
    
    if [[ -z "$batch_file" && -z "$domain" ]]; then
        log_error "Either domain or --batch-file is required"
        show_help
        exit 1
    fi
    
    if ! [[ "$timeout" =~ ^[0-9]+$ ]] || [[ $timeout -lt 60 ]] || [[ $timeout -gt 3600 ]]; then
        log_error "Timeout must be between 60 and 3600 seconds"
        exit 1
    fi
    
    if [[ "$mode" != "passive" && "$mode" != "active" ]]; then
        log_error "Mode must be 'passive' or 'active'"
        exit 1
    fi
    
    if [[ -n "$batch_file" ]]; then
        if ! [[ "$max_jobs" =~ ^[0-9]+$ ]] || [[ $max_jobs -lt 1 ]] || [[ $max_jobs -gt 50 ]]; then
            log_error "Number of parallel jobs must be between 1 and 50"
            exit 1
        fi
    fi
    
    # Check if amass is available
    if ! command -v "$AMASS_BINARY" >/dev/null 2>&1; then
        log_error "Amass binary not found: $AMASS_BINARY"
        log_error "Please install amass or set AMASS_BINARY_PATH environment variable"
        exit 1
    fi
    
    # Initialize cache
    init_cache_dirs
    
    # Handle batch processing
    if [[ -n "$batch_file" ]]; then
        # Batch processing mode
        if process_batch_domains "$batch_file" "$timeout" "$mode" "$force" "$verbose" "$max_jobs" "$log_dir"; then
            exit 0
        else
            exit 1
        fi
    fi
    
    # Single domain processing mode
    # Clean expired cache entries
    clean_expired_cache
    
    # Check if we should use cached results
    if [[ "$force" == "false" ]] && is_cache_valid "$domain"; then
        if get_cached_results "$domain"; then
            exit 0
        fi
    fi
    
    # Run amass
    local results
    if results=$(run_amass "$domain" "$timeout" "$mode" "$verbose"); then
        # Save to cache
        save_to_cache "$domain" "$results" "$timeout" "$mode"
        
        # Output results
        echo "$results"
        exit 0
    else
        log_error "Failed to execute amass for domain: $domain"
        exit 1
    fi
}

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    for cmd in jq gzip gunzip date sha256sum; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        log_error "Please install the missing dependencies and try again"
        exit 1
    fi
}

# Run dependency check and main function
check_dependencies
main "$@"