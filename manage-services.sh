#!/bin/bash

# Tsunami Beta Services Management Script
# Manages risk-graph-service (Quarkus) and risk-dashboard (React) processes

RISK_GRAPH_DIR="risk-graph-service"
RISK_DASHBOARD_DIR="risk-dashboard"
RISK_QUERY_DIR="risk-query"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Function to check if Ollama is installed
check_ollama_installed() {
    if command -v ollama &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to start Ollama service
start_ollama() {
    print_header "Starting Ollama service"
    
    if ! check_ollama_installed; then
        print_error "Ollama is not installed. Please install it first:"
        print_error "curl -fsSL https://ollama.ai/install.sh | sh"
        return 1
    fi
    
    # Check if Ollama is already running
    if pgrep -x "ollama" > /dev/null; then
        print_status "Ollama is already running"
        return 0
    fi
    
    print_status "Starting Ollama service in background..."
    nohup ollama serve > ollama.log 2>&1 &
    OLLAMA_PID=$!
    echo $OLLAMA_PID > ollama.pid
    
    # Wait a moment for the service to start
    sleep 3
    
    if pgrep -x "ollama" > /dev/null; then
        print_status "Ollama started with PID: $OLLAMA_PID"
        print_status "Logs: tail -f ollama.log"
        
        # Check if default model is available
        print_status "Checking for default model (llama3.1)..."
        if ollama list | grep -q "llama3.1"; then
            print_status "Default model llama3.1 is available"
        else
            print_warning "Default model llama3.1 not found. Pulling it now..."
            ollama pull llama3.1
        fi
    else
        print_error "Failed to start Ollama service"
        return 1
    fi
}

# Function to stop Ollama service
stop_ollama() {
    print_header "Stopping Ollama service"
    
    OLLAMA_PIDS=$(pgrep -x "ollama")
    
    if [ -z "$OLLAMA_PIDS" ]; then
        print_status "No Ollama processes found running"
    else
        print_status "Found Ollama processes: $OLLAMA_PIDS"
        for PID in $OLLAMA_PIDS; do
            print_status "Killing Ollama process $PID"
            kill -15 $PID 2>/dev/null || kill -9 $PID 2>/dev/null
        done
        sleep 2
        
        # Verify processes are stopped
        REMAINING=$(pgrep -x "ollama")
        if [ -z "$REMAINING" ]; then
            print_status "All Ollama processes stopped successfully"
        else
            print_warning "Some processes may still be running: $REMAINING"
        fi
    fi
}

# Function to stop Maven Quarkus processes
stop_quarkus() {
    print_header "Stopping Quarkus processes"
    
    # Find and kill Maven processes running Quarkus
    QUARKUS_PIDS=$(ps aux | grep -E "mvn.*quarkus|quarkus:dev" | grep -v grep | awk '{print $2}')
    
    if [ -z "$QUARKUS_PIDS" ]; then
        print_status "No Quarkus processes found running"
    else
        print_status "Found Quarkus processes: $QUARKUS_PIDS"
        for PID in $QUARKUS_PIDS; do
            print_status "Killing Quarkus process $PID"
            kill -15 $PID 2>/dev/null || kill -9 $PID 2>/dev/null
        done
        sleep 2
        
        # Verify processes are stopped
        REMAINING=$(ps aux | grep -E "mvn.*quarkus|quarkus:dev" | grep -v grep | awk '{print $2}')
        if [ -z "$REMAINING" ]; then
            print_status "All Quarkus processes stopped successfully"
        else
            print_warning "Some processes may still be running: $REMAINING"
        fi
    fi
}

# Function to stop npm processes
stop_npm() {
    print_header "Stopping npm processes"
    
    # Find and kill npm start processes
    NPM_PIDS=$(ps aux | grep -E "npm.*start|node.*react-scripts" | grep -v grep | awk '{print $2}')
    
    if [ -z "$NPM_PIDS" ]; then
        print_status "No npm processes found running"
    else
        print_status "Found npm processes: $NPM_PIDS"
        for PID in $NPM_PIDS; do
            print_status "Killing npm process $PID"
            kill -15 $PID 2>/dev/null || kill -9 $PID 2>/dev/null
        done
        sleep 2
        
        # Verify processes are stopped
        REMAINING=$(ps aux | grep -E "npm.*start|node.*react-scripts" | grep -v grep | awk '{print $2}')
        if [ -z "$REMAINING" ]; then
            print_status "All npm processes stopped successfully"
        else
            print_warning "Some processes may still be running: $REMAINING"
        fi
    fi
}

# Function to stop risk-query Python processes
stop_risk_query() {
    print_header "Stopping Risk Query processes"
    
    # Method 1: Find processes by port 8003
    PORT_PIDS=$(lsof -ti:8003 2>/dev/null)
    
    # Method 2: Find Python processes related to risk-query (more comprehensive pattern)
    QUERY_PIDS=$(ps aux | grep -E "python.*main\.py|uvicorn.*main:app|fastapi" | grep -E "risk-query|app/main" | grep -v grep | awk '{print $2}')
    
    # Method 3: Find processes by PID file and validate they exist
    PID_FILE_PIDS=""
    if [ -f "risk-query-dev.pid" ]; then
        POTENTIAL_PID=$(cat risk-query-dev.pid 2>/dev/null)
        # Only include PID if the process actually exists
        if [ -n "$POTENTIAL_PID" ] && kill -0 $POTENTIAL_PID 2>/dev/null; then
            PID_FILE_PIDS=$POTENTIAL_PID
        else
            print_status "Removing stale PID file (process $POTENTIAL_PID no longer exists)"
            rm -f risk-query-dev.pid
        fi
    fi
    
    # Method 4: Find Python processes by command line pattern (broader search)
    PYTHON_PIDS=$(pgrep -f "python.*main\.py" 2>/dev/null)
    
    # Combine all PIDs
    ALL_PIDS="$PORT_PIDS $QUERY_PIDS $PID_FILE_PIDS $PYTHON_PIDS"
    
    # Remove duplicates and empty values
    UNIQUE_PIDS=$(echo $ALL_PIDS | tr ' ' '\n' | sort -u | grep -v '^$')
    
    if [ -z "$UNIQUE_PIDS" ]; then
        print_status "No Risk Query processes found running"
        # Clean up stale PID file if it exists
        if [ -f "risk-query-dev.pid" ]; then
            print_status "Cleaning up stale PID file"
            rm -f risk-query-dev.pid
        fi
    else
        print_status "Found Risk Query processes: $(echo $UNIQUE_PIDS | tr '\n' ' ')"
        for PID in $UNIQUE_PIDS; do
            if kill -0 $PID 2>/dev/null; then
                print_status "Killing Risk Query process $PID"
                kill -15 $PID 2>/dev/null
                sleep 1
                # Force kill if still running
                if kill -0 $PID 2>/dev/null; then
                    print_status "Force killing process $PID"
                    kill -9 $PID 2>/dev/null
                fi
            else
                print_status "Process $PID already terminated"
            fi
        done
        sleep 2
        
        # Verify processes are stopped
        REMAINING_PORT=$(lsof -ti:8003 2>/dev/null)
        if [ -z "$REMAINING_PORT" ]; then
            print_status "All Risk Query processes stopped successfully"
            # Clean up PID file
            rm -f risk-query-dev.pid
        else
            print_warning "Some processes may still be running on port 8003: $REMAINING_PORT"
            # Try to kill remaining processes on port 8003
            for PID in $REMAINING_PORT; do
                print_status "Force killing remaining process $PID on port 8003"
                kill -9 $PID 2>/dev/null
            done
            sleep 1
            rm -f risk-query-dev.pid
        fi
    fi
}

# Function to start risk-query service in development mode
start_risk_query_dev() {
    print_header "Starting Risk Query service in development mode"
    
    if [ ! -d "$RISK_QUERY_DIR" ]; then
        print_error "Directory $RISK_QUERY_DIR not found"
        return 1
    fi
    
    cd "$RISK_QUERY_DIR"
    
    # Check if already running
    if ps aux | grep -E "python.*main.py|uvicorn.*main:app" | grep risk-query | grep -v grep > /dev/null; then
        print_warning "Risk Query process already running. Stopping first..."
        stop_risk_query
        sleep 2
    fi
    
    # Check if virtual environment exists, create if not
    if [ ! -d "venv" ]; then
        print_status "Creating Python virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment and install dependencies
    source venv/bin/activate
    
    if [ ! -f "venv/installed.flag" ]; then
        print_status "Installing Python dependencies..."
        pip install -r requirements.txt
        touch venv/installed.flag
    fi
    
    print_status "Starting Risk Query service in background..."
    nohup python app/main.py > ../risk-query-dev.log 2>&1 &
    QUERY_PID=$!
    
    echo $QUERY_PID > ../risk-query-dev.pid
    print_status "Risk Query started with PID: $QUERY_PID"
    print_status "Logs: tail -f risk-query-dev.log"
    
    cd ..
}

# Function to start Quarkus in development mode (detached)
start_quarkus_dev() {
    print_header "Starting Quarkus in development mode"
    
    if [ ! -d "$RISK_GRAPH_DIR" ]; then
        print_error "Directory $RISK_GRAPH_DIR not found"
        return 1
    fi
    
    cd "$RISK_GRAPH_DIR"
    
    # Check if already running
    if ps aux | grep -E "mvn.*quarkus|quarkus:dev" | grep -v grep > /dev/null; then
        print_warning "Quarkus process already running. Stopping first..."
        stop_quarkus
        sleep 2
    fi
    
    print_status "Starting Quarkus development server in background..."
    nohup mvn quarkus:dev > ../quarkus-dev.log 2>&1 &
    QUARKUS_PID=$!
    
    echo $QUARKUS_PID > ../quarkus-dev.pid
    print_status "Quarkus started with PID: $QUARKUS_PID"
    print_status "Logs: tail -f quarkus-dev.log"
    
    cd ..
}

# Function to start npm in development mode (detached)
start_npm_dev() {
    print_header "Starting React Dashboard in development mode"
    
    if [ ! -d "$RISK_DASHBOARD_DIR" ]; then
        print_error "Directory $RISK_DASHBOARD_DIR not found"
        return 1
    fi
    
    cd "$RISK_DASHBOARD_DIR"
    
    # Check if already running
    if ps aux | grep -E "npm.*start|node.*react-scripts" | grep -v grep > /dev/null; then
        print_warning "npm process already running. Stopping first..."
        stop_npm
        sleep 2
    fi
    
    print_status "Starting React development server in background..."
    nohup npm start > ../react-dev.log 2>&1 &
    NPM_PID=$!
    
    echo $NPM_PID > ../react-dev.pid
    print_status "React started with PID: $NPM_PID"
    print_status "Logs: tail -f react-dev.log"
    
    cd ..
}

# Function to start Quarkus in test mode
start_quarkus_test() {
    print_header "Starting Quarkus in test mode"
    
    if [ ! -d "$RISK_GRAPH_DIR" ]; then
        print_error "Directory $RISK_GRAPH_DIR not found"
        return 1
    fi
    
    cd "$RISK_GRAPH_DIR"
    
    # Check if already running
    if ps aux | grep -E "mvn.*quarkus|quarkus:dev" | grep -v grep > /dev/null; then
        print_warning "Quarkus process already running. Stopping first..."
        stop_quarkus
        sleep 2
    fi
    
    print_status "Starting Quarkus test server in background..."
    nohup mvn quarkus:test > ../quarkus-test.log 2>&1 &
    QUARKUS_PID=$!
    
    echo $QUARKUS_PID > ../quarkus-test.pid
    print_status "Quarkus test started with PID: $QUARKUS_PID"
    print_status "Logs: tail -f quarkus-test.log"
    
    cd ..
}

# Function to start npm in test mode
start_npm_test() {
    print_header "Starting React Dashboard in test mode"
    
    if [ ! -d "$RISK_DASHBOARD_DIR" ]; then
        print_error "Directory $RISK_DASHBOARD_DIR not found"
        return 1
    fi
    
    cd "$RISK_DASHBOARD_DIR"
    
    # Check if already running
    if ps aux | grep -E "npm.*test|node.*react-scripts.*test" | grep -v grep > /dev/null; then
        print_warning "npm test process already running. Stopping first..."
        pkill -f "npm.*test"
        sleep 2
    fi
    
    print_status "Starting React test server in background..."
    nohup npm test -- --watchAll=false > ../react-test.log 2>&1 &
    NPM_PID=$!
    
    echo $NPM_PID > ../react-test.pid
    print_status "React test started with PID: $NPM_PID"
    print_status "Logs: tail -f react-test.log"
    
    cd ..
}

# Function to show status of services
show_status() {
    print_header "Service Status"
    
    # Check Ollama
    if pgrep -x "ollama" > /dev/null; then
        OLLAMA_PID=$(pgrep -x "ollama" | head -1)
        print_status "Ollama: RUNNING (PID: $OLLAMA_PID)"
    else
        print_warning "Ollama: STOPPED"
    fi
    
    # Check Quarkus
    if ps aux | grep -E "mvn.*quarkus|quarkus:dev" | grep -v grep > /dev/null; then
        QUARKUS_PID=$(ps aux | grep -E "mvn.*quarkus|quarkus:dev" | grep -v grep | awk '{print $2}' | head -1)
        print_status "Quarkus: RUNNING (PID: $QUARKUS_PID)"
    else
        print_warning "Quarkus: STOPPED"
    fi
    
    # Check React
    if ps aux | grep -E "npm.*start|node.*react-scripts" | grep -v grep > /dev/null; then
        NPM_PID=$(ps aux | grep -E "npm.*start|node.*react-scripts" | grep -v grep | awk '{print $2}' | head -1)
        print_status "React Dashboard: RUNNING (PID: $NPM_PID)"
    else
        print_warning "React Dashboard: STOPPED"
    fi
    
    # Check Risk Query (multiple methods)
    QUERY_PORT_PID=$(lsof -ti:8003 2>/dev/null | head -1)
    QUERY_PROCESS_PID=$(ps aux | grep -E "python.*app/main.py" | grep -v grep | awk '{print $2}' | head -1)
    
    if [ -n "$QUERY_PORT_PID" ] || [ -n "$QUERY_PROCESS_PID" ]; then
        ACTIVE_PID=${QUERY_PORT_PID:-$QUERY_PROCESS_PID}
        print_status "Risk Query: RUNNING (PID: $ACTIVE_PID, Port: 8003)"
    else
        print_warning "Risk Query: STOPPED"
    fi
}

# Function to show logs
show_logs() {
    case $1 in
        "quarkus"|"q")
            if [ -f "quarkus-dev.log" ]; then
                tail -f quarkus-dev.log
            elif [ -f "quarkus-test.log" ]; then
                tail -f quarkus-test.log
            else
                print_error "No Quarkus log files found"
            fi
            ;;
        "react"|"r")
            if [ -f "react-dev.log" ]; then
                tail -f react-dev.log
            elif [ -f "react-test.log" ]; then
                tail -f react-test.log
            else
                print_error "No React log files found"
            fi
            ;;
        "query"|"rq")
            if [ -f "risk-query-dev.log" ]; then
                tail -f risk-query-dev.log
            else
                print_error "No Risk Query log files found"
            fi
            ;;
        "ollama"|"o")
            if [ -f "ollama.log" ]; then
                tail -f ollama.log
            else
                print_error "No Ollama log files found"
            fi
            ;;
        *)
            print_error "Usage: $0 logs [quarkus|react|query|ollama]"
            ;;
    esac
}

# Main script logic
case $1 in
    "stop")
        stop_ollama
        stop_quarkus
        stop_npm
        stop_risk_query
        ;;
    "start-dev")
        start_ollama
        start_quarkus_dev
        start_npm_dev
        start_risk_query_dev
        ;;
    "start-test")
        start_ollama
        start_quarkus_test
        start_npm_test
        ;;
    "restart-dev")
        stop_ollama
        stop_quarkus
        stop_npm
        stop_risk_query
        sleep 2
        start_ollama
        start_quarkus_dev
        start_npm_dev
        start_risk_query_dev
        ;;
    "restart-test")
        stop_ollama
        stop_quarkus
        stop_npm
        stop_risk_query
        sleep 2
        start_ollama
        start_quarkus_test
        start_npm_test
        ;;
    "start-ollama")
        start_ollama
        ;;
    "stop-ollama")
        stop_ollama
        ;;
    "start-query")
        start_risk_query_dev
        ;;
    "stop-query")
        stop_risk_query
        ;;
    "status")
        show_status
        ;;
    "logs")
        show_logs $2
        ;;
    *)
        echo "Tsunami Beta Services Management Script"
        echo ""
        echo "Usage: $0 {stop|start-dev|start-test|restart-dev|restart-test|start-ollama|stop-ollama|start-query|stop-query|status|logs}"
        echo ""
        echo "Commands:"
        echo "  stop        - Stop all running services"
        echo "  start-dev   - Start all services in development mode (detached)"
        echo "  start-test  - Start services in test mode (detached)"  
        echo "  restart-dev - Restart all services in development mode"
        echo "  restart-test- Restart services in test mode"
        echo "  start-ollama- Start Ollama service only"
        echo "  stop-ollama - Stop Ollama service only"
        echo "  start-query - Start Risk Query service only"
        echo "  stop-query  - Stop Risk Query service only"
        echo "  status      - Show status of all services"
        echo "  logs [quarkus|react|query|ollama] - Show logs for specific service"
        echo ""
        echo "Examples:"
        echo "  $0 start-dev      # Start all services in development mode"
        echo "  $0 stop           # Stop all services"
        echo "  $0 status         # Check if services are running"
        echo "  $0 logs query     # View Risk Query logs"
        echo "  $0 start-ollama   # Start only Ollama service"
        exit 1
        ;;
esac