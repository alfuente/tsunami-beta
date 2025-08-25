#!/bin/bash
# run_all_completions.sh - Master script to run all data completion tasks
# Part of Tsunami Beta risk-quality module

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOMAIN_BACKEND_API="${DOMAIN_BACKEND_API:-http://localhost:8081}"
LOG_FILE="completion_master_$(date +%Y%m%d_%H%M%S).log"

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Master script to run all data completion tasks for Tsunami Beta"
    echo ""
    echo "Options:"
    echo "  --skip-subdomains      Skip subdomain discovery"
    echo "  --skip-dns             Skip DNS analysis" 
    echo "  --skip-certificates    Skip certificate analysis"
    echo "  --skip-risk            Skip risk score calculation"
    echo "  --only TYPE            Only run specific completion type"
    echo "                         (subdomains|dns|certificates|risk)"
    echo "  --dry-run              Show what would be executed without running"
    echo "  --api URL              Domain backend API URL (default: $DOMAIN_BACKEND_API)"
    echo "  --parallel             Run tasks in parallel where possible"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  DOMAIN_BACKEND_API     Domain backend API URL"
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if scripts exist
    local scripts=(
        "$SCRIPT_DIR/complete_subdomains.sh"
        "$SCRIPT_DIR/complete_dns_analysis.sh"
        "$SCRIPT_DIR/complete_certificates.sh"
        "$SCRIPT_DIR/complete_risk_scores.sh"
    )
    
    for script in "${scripts[@]}"; do
        if [ ! -f "$script" ]; then
            log "ERROR: Required script not found: $script"
            exit 1
        fi
        
        if [ ! -x "$script" ]; then
            log "Making script executable: $script"
            chmod +x "$script"
        fi
    done
    
    # Check required tools
    local tools=("curl" "jq" "python3")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" > /dev/null; then
            log "ERROR: Required tool not found: $tool"
            exit 1
        fi
    done
    
    # Check domain-backend health
    log "Checking domain-backend health..."
    if ! curl -f -s "$DOMAIN_BACKEND_API/health" > /dev/null; then
        log "ERROR: Domain backend is not available at $DOMAIN_BACKEND_API"
        exit 1
    fi
    
    log "All prerequisites checked successfully"
}

run_validation() {
    log "Running graph validation before completion tasks..."
    
    local validator_script="$SCRIPT_DIR/../graph_validator.py"
    local validation_report="validation_report_$(date +%Y%m%d_%H%M%S).json"
    
    if [ -f "$validator_script" ]; then
        if python3 "$validator_script" --output "$validation_report" 2>/dev/null; then
            log "Validation completed successfully"
            log "Validation report saved to: $validation_report"
        else
            log "WARNING: Validation completed with errors"
        fi
    else
        log "WARNING: Graph validator not found, skipping validation"
    fi
}

run_completeness_analysis() {
    log "Running data completeness analysis..."
    
    local analyzer_script="$SCRIPT_DIR/../data_completeness_analyzer.py"
    local completeness_report="completeness_report_$(date +%Y%m%d_%H%M%S).json"
    local completion_script_dir="$(dirname "$LOG_FILE")"
    
    if [ -f "$analyzer_script" ]; then
        if python3 "$analyzer_script" \
            --domain-backend "$DOMAIN_BACKEND_API" \
            --output "$completeness_report" \
            --generate-script "$completion_script_dir" 2>/dev/null; then
            log "Completeness analysis completed successfully"
            log "Report saved to: $completeness_report"
        else
            log "WARNING: Completeness analysis completed with errors"
        fi
    else
        log "WARNING: Completeness analyzer not found, skipping analysis"
    fi
}

run_subdomain_completion() {
    if [ "$SKIP_SUBDOMAINS" = true ]; then
        log "Skipping subdomain completion (--skip-subdomains)"
        return 0
    fi
    
    log "=== Starting Subdomain Discovery Completion ==="
    
    if [ "$DRY_RUN" = true ]; then
        log "DRY RUN: Would execute: $SCRIPT_DIR/complete_subdomains.sh --all --api $DOMAIN_BACKEND_API"
        return 0
    fi
    
    if "$SCRIPT_DIR/complete_subdomains.sh" --all --api "$DOMAIN_BACKEND_API"; then
        log "Subdomain completion completed successfully"
    else
        log "WARNING: Subdomain completion completed with errors"
    fi
}

run_dns_completion() {
    if [ "$SKIP_DNS" = true ]; then
        log "Skipping DNS completion (--skip-dns)"
        return 0
    fi
    
    log "=== Starting DNS Analysis Completion ==="
    
    if [ "$DRY_RUN" = true ]; then
        log "DRY RUN: Would execute: $SCRIPT_DIR/complete_dns_analysis.sh --all --api $DOMAIN_BACKEND_API"
        return 0
    fi
    
    if "$SCRIPT_DIR/complete_dns_analysis.sh" --all --api "$DOMAIN_BACKEND_API"; then
        log "DNS completion completed successfully"
    else
        log "WARNING: DNS completion completed with errors"
    fi
}

run_certificate_completion() {
    if [ "$SKIP_CERTIFICATES" = true ]; then
        log "Skipping certificate completion (--skip-certificates)"
        return 0
    fi
    
    log "=== Starting Certificate Analysis Completion ==="
    
    if [ "$DRY_RUN" = true ]; then
        log "DRY RUN: Would execute: $SCRIPT_DIR/complete_certificates.sh --all --api $DOMAIN_BACKEND_API"
        return 0
    fi
    
    if "$SCRIPT_DIR/complete_certificates.sh" --all --api "$DOMAIN_BACKEND_API"; then
        log "Certificate completion completed successfully"
    else
        log "WARNING: Certificate completion completed with errors"
    fi
}

run_risk_completion() {
    if [ "$SKIP_RISK" = true ]; then
        log "Skipping risk completion (--skip-risk)"
        return 0
    fi
    
    log "=== Starting Risk Score Completion ==="
    
    if [ "$DRY_RUN" = true ]; then
        log "DRY RUN: Would execute: $SCRIPT_DIR/complete_risk_scores.sh --all --api $DOMAIN_BACKEND_API"
        return 0
    fi
    
    if "$SCRIPT_DIR/complete_risk_scores.sh" --all --api "$DOMAIN_BACKEND_API"; then
        log "Risk score completion completed successfully"
    else
        log "WARNING: Risk score completion completed with errors"
    fi
}

run_sequential() {
    log "Running completion tasks sequentially..."
    
    # Run in logical order: subdomains -> DNS -> certificates -> risk
    run_subdomain_completion
    run_dns_completion
    run_certificate_completion
    run_risk_completion
}

run_parallel() {
    log "Running completion tasks in parallel where possible..."
    
    local pids=()
    
    # Subdomain discovery can run independently
    if [ "$SKIP_SUBDOMAINS" != true ] && [ "$ONLY_TYPE" != "dns" ] && [ "$ONLY_TYPE" != "certificates" ] && [ "$ONLY_TYPE" != "risk" ]; then
        run_subdomain_completion &
        pids+=($!)
        log "Started subdomain completion in background (PID: $!)"
    fi
    
    # DNS and certificates can run in parallel
    if [ "$SKIP_DNS" != true ] && [ "$ONLY_TYPE" != "subdomains" ] && [ "$ONLY_TYPE" != "certificates" ] && [ "$ONLY_TYPE" != "risk" ]; then
        run_dns_completion &
        pids+=($!)
        log "Started DNS completion in background (PID: $!)"
    fi
    
    if [ "$SKIP_CERTIFICATES" != true ] && [ "$ONLY_TYPE" != "subdomains" ] && [ "$ONLY_TYPE" != "dns" ] && [ "$ONLY_TYPE" != "risk" ]; then
        run_certificate_completion &
        pids+=($!)
        log "Started certificate completion in background (PID: $!)"
    fi
    
    # Wait for prerequisites to complete before risk calculation
    for pid in "${pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            wait "$pid"
            log "Background task completed (PID: $pid)"
        fi
    done
    
    # Risk calculation should run last
    run_risk_completion
}

generate_final_report() {
    log "Generating final completion report..."
    
    local report_file="completion_summary_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" <<EOF
Tsunami Beta Data Completion Summary
Generated: $(date)
Log File: $LOG_FILE

=== Execution Parameters ===
Domain Backend API: $DOMAIN_BACKEND_API
Skip Subdomains: ${SKIP_SUBDOMAINS:-false}
Skip DNS: ${SKIP_DNS:-false}
Skip Certificates: ${SKIP_CERTIFICATES:-false}
Skip Risk: ${SKIP_RISK:-false}
Only Type: ${ONLY_TYPE:-none}
Parallel Execution: ${PARALLEL:-false}
Dry Run: ${DRY_RUN:-false}

=== Neo4j Statistics (After Completion) ===
EOF
    
    # Add Neo4j statistics if available
    if python3 "$SCRIPT_DIR/complete_risk_scores.sh" --stats >> "$report_file" 2>/dev/null; then
        log "Added final statistics to report"
    fi
    
    log "Final report saved to: $report_file"
}

# Parse command line arguments
SKIP_SUBDOMAINS=false
SKIP_DNS=false
SKIP_CERTIFICATES=false
SKIP_RISK=false
ONLY_TYPE=""
DRY_RUN=false
PARALLEL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-subdomains)
            SKIP_SUBDOMAINS=true
            shift
            ;;
        --skip-dns)
            SKIP_DNS=true
            shift
            ;;
        --skip-certificates)
            SKIP_CERTIFICATES=true
            shift
            ;;
        --skip-risk)
            SKIP_RISK=true
            shift
            ;;
        --only)
            ONLY_TYPE="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --parallel)
            PARALLEL=true
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

# Handle --only option
if [ -n "$ONLY_TYPE" ]; then
    case "$ONLY_TYPE" in
        subdomains)
            SKIP_DNS=true
            SKIP_CERTIFICATES=true
            SKIP_RISK=true
            ;;
        dns)
            SKIP_SUBDOMAINS=true
            SKIP_CERTIFICATES=true
            SKIP_RISK=true
            ;;
        certificates)
            SKIP_SUBDOMAINS=true
            SKIP_DNS=true
            SKIP_RISK=true
            ;;
        risk)
            SKIP_SUBDOMAINS=true
            SKIP_DNS=true
            SKIP_CERTIFICATES=true
            ;;
        *)
            log "ERROR: Invalid --only type: $ONLY_TYPE"
            log "Valid types: subdomains, dns, certificates, risk"
            exit 1
            ;;
    esac
fi

# Main execution
log "Starting Tsunami Beta data completion master script"
log "Configuration:"
log "  API: $DOMAIN_BACKEND_API"
log "  Skip Subdomains: $SKIP_SUBDOMAINS"
log "  Skip DNS: $SKIP_DNS"
log "  Skip Certificates: $SKIP_CERTIFICATES"
log "  Skip Risk: $SKIP_RISK"
log "  Only Type: ${ONLY_TYPE:-none}"
log "  Parallel: $PARALLEL"
log "  Dry Run: $DRY_RUN"

# Check prerequisites
check_prerequisites

# Run initial validation and analysis
run_validation
run_completeness_analysis

# Execute completion tasks
if [ "$PARALLEL" = true ]; then
    run_parallel
else
    run_sequential
fi

# Generate final report
if [ "$DRY_RUN" != true ]; then
    generate_final_report
fi

log "Data completion master script finished"
log "Total execution time: $SECONDS seconds"
log "Log file: $LOG_FILE"