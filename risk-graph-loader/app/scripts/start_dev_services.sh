#!/bin/bash

# Development startup script for risk-graph-service and risk-warehouse-service
# Usage: ./start_dev_services.sh [options]

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
RISK_GRAPH_SERVICE_DIR="$PROJECT_ROOT/risk-graph-service"
RISK_WAREHOUSE_SERVICE_DIR="$PROJECT_ROOT/risk-warehouse-service"
LOGS_DIR="$PROJECT_ROOT/logs"
PIDS_DIR="$PROJECT_ROOT/pids"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
GRAPH_SERVICE_PORT=8000
WAREHOUSE_SERVICE_PORT=8001
NEO4J_URI="bolt://localhost:7687"
NEO4J_USER="neo4j"
NEO4J_PASSWORD="test.password"
LOG_LEVEL="DEBUG"
RELOAD=true

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --graph-port)
            GRAPH_SERVICE_PORT="$2"
            shift 2
            ;;
        --warehouse-port)
            WAREHOUSE_SERVICE_PORT="$2"
            shift 2
            ;;
        --neo4j-uri)
            NEO4J_URI="$2"
            shift 2
            ;;
        --neo4j-user)
            NEO4J_USER="$2"
            shift 2
            ;;
        --neo4j-password)
            NEO4J_PASSWORD="$2"
            shift 2
            ;;
        --log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        --no-reload)
            RELOAD=false
            shift
            ;;
        --stop)
            stop_services
            exit 0
            ;;
        --status)
            check_services_status
            exit 0
            ;;
        --logs)
            tail_logs
            exit 0
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Create necessary directories
create_directories() {
    echo -e "${BLUE}Creating necessary directories...${NC}"
    mkdir -p "$LOGS_DIR"
    mkdir -p "$PIDS_DIR"
    echo -e "${GREEN}✓ Directories created${NC}"
}

# Check dependencies
check_dependencies() {
    echo -e "${BLUE}Checking dependencies...${NC}"
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}✗ Python 3 is required but not installed${NC}"
        exit 1
    fi
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        echo -e "${RED}✗ pip3 is required but not installed${NC}"
        exit 1
    fi
    
    # Check if service directories exist
    if [ ! -d "$RISK_GRAPH_SERVICE_DIR" ]; then
        echo -e "${RED}✗ Risk graph service directory not found: $RISK_GRAPH_SERVICE_DIR${NC}"
        exit 1
    fi
    
    if [ ! -d "$RISK_WAREHOUSE_SERVICE_DIR" ]; then
        echo -e "${RED}✗ Risk warehouse service directory not found: $RISK_WAREHOUSE_SERVICE_DIR${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Dependencies check passed${NC}"
}

# Check if Neo4j is running
check_neo4j() {
    echo -e "${BLUE}Checking Neo4j connection...${NC}"
    
    if ! python3 -c "
from neo4j import GraphDatabase
try:
    driver = GraphDatabase.driver('$NEO4J_URI', auth=('$NEO4J_USER', '$NEO4J_PASSWORD'))
    with driver.session() as session:
        session.run('RETURN 1')
    driver.close()
    print('Neo4j connection successful')
except Exception as e:
    print(f'Neo4j connection failed: {e}')
    exit(1)
" 2>/dev/null; then
        echo -e "${RED}✗ Cannot connect to Neo4j${NC}"
        echo "Please ensure Neo4j is running and accessible at $NEO4J_URI"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Neo4j connection successful${NC}"
}

# Install dependencies for services
install_dependencies() {
    echo -e "${BLUE}Installing service dependencies...${NC}"
    
    # Install risk-graph-service dependencies
    if [ -f "$RISK_GRAPH_SERVICE_DIR/requirements.txt" ]; then
        echo "Installing risk-graph-service dependencies..."
        cd "$RISK_GRAPH_SERVICE_DIR"
        pip3 install -r requirements.txt --break-system-packages
    else
        echo -e "${YELLOW}⚠ requirements.txt not found for risk-graph-service${NC}"
    fi
    
    # Install risk-warehouse-service dependencies
    if [ -f "$RISK_WAREHOUSE_SERVICE_DIR/requirements.txt" ]; then
        echo "Installing risk-warehouse-service dependencies..."
        cd "$RISK_WAREHOUSE_SERVICE_DIR"
        pip3 install -r requirements.txt --break-system-packages
    else
        echo -e "${YELLOW}⚠ requirements.txt not found for risk-warehouse-service${NC}"
    fi
    
    echo -e "${GREEN}✓ Dependencies installed${NC}"
}

# Setup environment variables
setup_environment() {
    echo -e "${BLUE}Setting up environment variables...${NC}"
    
    # Common environment variables
    export NEO4J_URI="$NEO4J_URI"
    export NEO4J_USER="$NEO4J_USER"
    export NEO4J_PASSWORD="$NEO4J_PASSWORD"
    export LOG_LEVEL="$LOG_LEVEL"
    export PYTHONPATH="$PROJECT_ROOT:$PYTHONPATH"
    
    # Risk graph service environment
    export GRAPH_SERVICE_PORT="$GRAPH_SERVICE_PORT"
    
    # Risk warehouse service environment
    export WAREHOUSE_SERVICE_PORT="$WAREHOUSE_SERVICE_PORT"
    export ICEBERG_CATALOG_URI="memory://"
    export SPARK_HOME="${SPARK_HOME:-/opt/spark}"
    
    echo -e "${GREEN}✓ Environment variables set${NC}"
}

# Start risk-graph-service
start_graph_service() {
    echo -e "${BLUE}Starting risk-graph-service...${NC}"
    
    cd "$RISK_GRAPH_SERVICE_DIR"
    
    local reload_flag=""
    if [ "$RELOAD" = true ]; then
        reload_flag="--reload"
    fi
    
    # Start the service
    nohup python3 -m uvicorn main:app \
        --host 0.0.0.0 \
        --port "$GRAPH_SERVICE_PORT" \
        --log-level "$LOG_LEVEL" \
        $reload_flag \
        > "$LOGS_DIR/risk-graph-service.log" 2>&1 &
    
    local pid=$!
    echo $pid > "$PIDS_DIR/risk-graph-service.pid"
    
    # Wait for service to start
    local retries=30
    while [ $retries -gt 0 ]; do
        if curl -s "http://localhost:$GRAPH_SERVICE_PORT/health" >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Risk-graph-service started successfully (PID: $pid, Port: $GRAPH_SERVICE_PORT)${NC}"
            return 0
        fi
        sleep 1
        ((retries--))
    done
    
    echo -e "${RED}✗ Failed to start risk-graph-service${NC}"
    return 1
}

# Start risk-warehouse-service
start_warehouse_service() {
    echo -e "${BLUE}Starting risk-warehouse-service...${NC}"
    
    cd "$RISK_WAREHOUSE_SERVICE_DIR"
    
    local reload_flag=""
    if [ "$RELOAD" = true ]; then
        reload_flag="--reload"
    fi
    
    # Start the service
    nohup python3 -m uvicorn main:app \
        --host 0.0.0.0 \
        --port "$WAREHOUSE_SERVICE_PORT" \
        --log-level "$LOG_LEVEL" \
        $reload_flag \
        > "$LOGS_DIR/risk-warehouse-service.log" 2>&1 &
    
    local pid=$!
    echo $pid > "$PIDS_DIR/risk-warehouse-service.pid"
    
    # Wait for service to start
    local retries=30
    while [ $retries -gt 0 ]; do
        if curl -s "http://localhost:$WAREHOUSE_SERVICE_PORT/health" >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Risk-warehouse-service started successfully (PID: $pid, Port: $WAREHOUSE_SERVICE_PORT)${NC}"
            return 0
        fi
        sleep 1
        ((retries--))
    done
    
    echo -e "${RED}✗ Failed to start risk-warehouse-service${NC}"
    return 1
}

# Stop services
stop_services() {
    echo -e "${BLUE}Stopping services...${NC}"
    
    # Stop risk-graph-service
    if [ -f "$PIDS_DIR/risk-graph-service.pid" ]; then
        local pid=$(cat "$PIDS_DIR/risk-graph-service.pid")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            echo -e "${GREEN}✓ Risk-graph-service stopped (PID: $pid)${NC}"
        fi
        rm -f "$PIDS_DIR/risk-graph-service.pid"
    fi
    
    # Stop risk-warehouse-service
    if [ -f "$PIDS_DIR/risk-warehouse-service.pid" ]; then
        local pid=$(cat "$PIDS_DIR/risk-warehouse-service.pid")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            echo -e "${GREEN}✓ Risk-warehouse-service stopped (PID: $pid)${NC}"
        fi
        rm -f "$PIDS_DIR/risk-warehouse-service.pid"
    fi
    
    # Kill any remaining processes
    pkill -f "risk-graph-service" 2>/dev/null || true
    pkill -f "risk-warehouse-service" 2>/dev/null || true
    
    echo -e "${GREEN}✓ All services stopped${NC}"
}

# Check services status
check_services_status() {
    echo -e "${BLUE}Checking services status...${NC}"
    
    # Check risk-graph-service
    if [ -f "$PIDS_DIR/risk-graph-service.pid" ]; then
        local pid=$(cat "$PIDS_DIR/risk-graph-service.pid")
        if kill -0 "$pid" 2>/dev/null; then
            if curl -s "http://localhost:$GRAPH_SERVICE_PORT/health" >/dev/null 2>&1; then
                echo -e "${GREEN}✓ Risk-graph-service: Running (PID: $pid, Port: $GRAPH_SERVICE_PORT)${NC}"
            else
                echo -e "${YELLOW}⚠ Risk-graph-service: Process running but not responding${NC}"
            fi
        else
            echo -e "${RED}✗ Risk-graph-service: Not running${NC}"
        fi
    else
        echo -e "${RED}✗ Risk-graph-service: Not started${NC}"
    fi
    
    # Check risk-warehouse-service
    if [ -f "$PIDS_DIR/risk-warehouse-service.pid" ]; then
        local pid=$(cat "$PIDS_DIR/risk-warehouse-service.pid")
        if kill -0 "$pid" 2>/dev/null; then
            if curl -s "http://localhost:$WAREHOUSE_SERVICE_PORT/health" >/dev/null 2>&1; then
                echo -e "${GREEN}✓ Risk-warehouse-service: Running (PID: $pid, Port: $WAREHOUSE_SERVICE_PORT)${NC}"
            else
                echo -e "${YELLOW}⚠ Risk-warehouse-service: Process running but not responding${NC}"
            fi
        else
            echo -e "${RED}✗ Risk-warehouse-service: Not running${NC}"
        fi
    else
        echo -e "${RED}✗ Risk-warehouse-service: Not started${NC}"
    fi
}

# Tail logs
tail_logs() {
    echo -e "${BLUE}Tailing service logs...${NC}"
    echo "Press Ctrl+C to exit"
    
    if [ -f "$LOGS_DIR/risk-graph-service.log" ] && [ -f "$LOGS_DIR/risk-warehouse-service.log" ]; then
        tail -f "$LOGS_DIR/risk-graph-service.log" "$LOGS_DIR/risk-warehouse-service.log"
    elif [ -f "$LOGS_DIR/risk-graph-service.log" ]; then
        tail -f "$LOGS_DIR/risk-graph-service.log"
    elif [ -f "$LOGS_DIR/risk-warehouse-service.log" ]; then
        tail -f "$LOGS_DIR/risk-warehouse-service.log"
    else
        echo -e "${YELLOW}No log files found${NC}"
    fi
}

# Show help
show_help() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Start risk-graph-service and risk-warehouse-service in development mode"
    echo ""
    echo "Options:"
    echo "  --graph-port PORT         Port for risk-graph-service (default: 8000)"
    echo "  --warehouse-port PORT     Port for risk-warehouse-service (default: 8001)"
    echo "  --neo4j-uri URI          Neo4j connection URI (default: bolt://localhost:7687)"
    echo "  --neo4j-user USER        Neo4j username (default: neo4j)"
    echo "  --neo4j-password PASS    Neo4j password (default: test.password)"
    echo "  --log-level LEVEL        Log level (default: DEBUG)"
    echo "  --no-reload              Disable auto-reload on code changes"
    echo "  --stop                   Stop running services"
    echo "  --status                 Check services status"
    echo "  --logs                   Tail service logs"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                       # Start both services with default settings"
    echo "  $0 --graph-port 8080     # Start with custom graph service port"
    echo "  $0 --stop                # Stop all services"
    echo "  $0 --status              # Check if services are running"
    echo "  $0 --logs                # View live logs"
}

# Main execution
main() {
    echo -e "${BLUE}Starting development services...${NC}"
    echo "Graph Service Port: $GRAPH_SERVICE_PORT"
    echo "Warehouse Service Port: $WAREHOUSE_SERVICE_PORT"
    echo "Neo4j URI: $NEO4J_URI"
    echo "Log Level: $LOG_LEVEL"
    echo "Auto-reload: $RELOAD"
    echo ""
    
    # Setup trap to cleanup on exit
    trap 'echo -e "\n${YELLOW}Shutting down services...${NC}"; stop_services' INT TERM
    
    # Execute setup steps
    create_directories
    check_dependencies
    check_neo4j
    install_dependencies
    setup_environment
    
    # Stop any existing services
    stop_services
    
    # Start services
    if start_graph_service && start_warehouse_service; then
        echo -e "\n${GREEN}🎉 All services started successfully!${NC}"
        echo ""
        echo "Service URLs:"
        echo "  Risk Graph Service:     http://localhost:$GRAPH_SERVICE_PORT"
        echo "  Risk Warehouse Service: http://localhost:$WAREHOUSE_SERVICE_PORT"
        echo ""
        echo "API Documentation:"
        echo "  Graph API Docs:         http://localhost:$GRAPH_SERVICE_PORT/docs"
        echo "  Warehouse API Docs:     http://localhost:$WAREHOUSE_SERVICE_PORT/docs"
        echo ""
        echo "Logs are available in: $LOGS_DIR"
        echo "PIDs are stored in: $PIDS_DIR"
        echo ""
        echo "Use '$0 --stop' to stop services"
        echo "Use '$0 --status' to check status"
        echo "Use '$0 --logs' to view logs"
        
        # Keep script running if in interactive mode
        if [ -t 0 ]; then
            echo ""
            echo "Press Ctrl+C to stop all services"
            wait
        fi
    else
        echo -e "\n${RED}❌ Failed to start some services${NC}"
        stop_services
        exit 1
    fi
}

# Run main function
main "$@"