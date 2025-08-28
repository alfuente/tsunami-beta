#!/bin/bash

# Tsunami Beta Services Management Script
# Manages risk-graph-service (Quarkus) and risk-dashboard (React) processes

RISK_GRAPH_DIR="risk-graph-service"
RISK_DASHBOARD_DIR="risk-dashboard"
RISK_QUERY_DIR="risk-query"
DOMAIN_BACKEND_DIR="domain-backend"
REPORT_BACKEND_DIR="report-backend"
GRAPH_VIEW_DIR="graph-view"

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
        print_status "Checking for default model (llama3.2:1b)..."
        if ollama list | grep -q "llama3.2:1b"; then
            print_status "Default model llama3.2:1b is available"
        else
            print_warning "Default model llama3.2:1b not found. Pulling it now..."
            ollama pull llama3.2:1b
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

# Function to stop subdomain discovery API processes (legacy and async)
stop_discovery_api() {
    print_header "Stopping Subdomain Discovery API processes"
    
    # Method 1: Find processes by port 8000 (legacy API)
    PORT_8000_PIDS=$(lsof -ti:8000 2>/dev/null)
    
    # Method 2: Find processes by port 8001 (async API) 
    PORT_8001_PIDS=$(lsof -ti:8001 2>/dev/null)
    
    # Method 3: Find Python processes related to subdomain APIs
    API_PIDS=$(ps aux | grep -E "python.*subdomain_discovery_api|python.*async_domain_discovery_api|uvicorn.*subdomain_discovery_api|uvicorn.*async_domain_discovery_api" | grep -v grep | awk '{print $2}')
    
    # Method 4: Find processes by PID files and validate they exist
    PID_FILE_PIDS=""
    if [ -f "discovery-api-dev.pid" ]; then
        POTENTIAL_PID=$(cat discovery-api-dev.pid 2>/dev/null)
        # Only include PID if the process actually exists
        if [ -n "$POTENTIAL_PID" ] && kill -0 $POTENTIAL_PID 2>/dev/null; then
            PID_FILE_PIDS="$PID_FILE_PIDS $POTENTIAL_PID"
        else
            print_status "Removing stale PID file discovery-api-dev.pid (process $POTENTIAL_PID no longer exists)"
            rm -f discovery-api-dev.pid
        fi
    fi
    
    if [ -f "async-api-dev.pid" ]; then
        POTENTIAL_PID=$(cat async-api-dev.pid 2>/dev/null)
        # Only include PID if the process actually exists
        if [ -n "$POTENTIAL_PID" ] && kill -0 $POTENTIAL_PID 2>/dev/null; then
            PID_FILE_PIDS="$PID_FILE_PIDS $POTENTIAL_PID"
        else
            print_status "Removing stale PID file async-api-dev.pid (process $POTENTIAL_PID no longer exists)"
            rm -f async-api-dev.pid
        fi
    fi
    
    # Combine all PIDs
    ALL_PIDS="$PORT_8000_PIDS $PORT_8001_PIDS $API_PIDS $PID_FILE_PIDS"
    
    # Remove duplicates and empty values
    UNIQUE_PIDS=$(echo $ALL_PIDS | tr ' ' '\n' | sort -u | grep -v '^$')
    
    if [ -z "$UNIQUE_PIDS" ]; then
        print_status "No Subdomain Discovery API processes found running"
        # Clean up stale PID files if they exist
        if [ -f "discovery-api-dev.pid" ]; then
            print_status "Cleaning up stale PID file discovery-api-dev.pid"
            rm -f discovery-api-dev.pid
        fi
        if [ -f "async-api-dev.pid" ]; then
            print_status "Cleaning up stale PID file async-api-dev.pid"
            rm -f async-api-dev.pid
        fi
    else
        print_status "Found Subdomain Discovery API processes: $(echo $UNIQUE_PIDS | tr '\n' ' ')"
        for PID in $UNIQUE_PIDS; do
            if kill -0 $PID 2>/dev/null; then
                print_status "Killing Subdomain Discovery API process $PID"
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
        REMAINING_8000=$(lsof -ti:8000 2>/dev/null)
        REMAINING_8001=$(lsof -ti:8001 2>/dev/null)
        
        if [ -z "$REMAINING_8000" ] && [ -z "$REMAINING_8001" ]; then
            print_status "All Subdomain Discovery API processes stopped successfully"
            # Clean up PID files
            rm -f discovery-api-dev.pid async-api-dev.pid
        else
            if [ -n "$REMAINING_8000" ]; then
                print_warning "Some processes may still be running on port 8000: $REMAINING_8000"
                # Try to kill remaining processes on port 8000
                for PID in $REMAINING_8000; do
                    print_status "Force killing remaining process $PID on port 8000"
                    kill -9 $PID 2>/dev/null
                done
            fi
            if [ -n "$REMAINING_8001" ]; then
                print_warning "Some processes may still be running on port 8001: $REMAINING_8001"
                # Try to kill remaining processes on port 8001
                for PID in $REMAINING_8001; do
                    print_status "Force killing remaining process $PID on port 8001"
                    kill -9 $PID 2>/dev/null
                done
            fi
            sleep 1
            rm -f discovery-api-dev.pid async-api-dev.pid
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

# Function to start subdomain discovery API service in development mode (legacy)
start_discovery_api_dev() {
    print_header "Starting Subdomain Discovery API service in development mode"
    
    if [ ! -d "$DOMAIN_BACKEND_DIR" ]; then
        print_error "Directory $DOMAIN_BACKEND_DIR not found"
        return 1
    fi
    
    cd "$DOMAIN_BACKEND_DIR"
    
    # Check if already running
    if ps aux | grep -E "python.*subdomain_discovery_api|uvicorn.*subdomain_discovery_api" | grep -v grep > /dev/null; then
        print_warning "Subdomain Discovery API process already running. Stopping first..."
        stop_discovery_api
        sleep 2
    fi
    
    # Check if virtual environment exists, create if not
    if [ ! -d "venv" ]; then
        print_status "Creating Python virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment and install dependencies
    source venv/bin/activate
    
    if [ ! -f "venv/api_installed.flag" ]; then
        print_status "Installing API dependencies..."
        pip install -r requirements_api.txt
        touch venv/api_installed.flag
    fi
    
    # Set environment variables
    export NEO4J_URI=${NEO4J_URI:-"bolt://localhost:7687"}
    export NEO4J_USER=${NEO4J_USER:-"neo4j"}
    export NEO4J_PASS=${NEO4J_PASS:-"test.password"}
    
    print_status "Starting Legacy Discovery API service in background..."
    nohup python subdomain_discovery_api.py > ../discovery-api-dev.log 2>&1 &
    API_PID=$!
    
    echo $API_PID > ../discovery-api-dev.pid
    print_status "Legacy Discovery API started with PID: $API_PID"
    print_status "API available at: http://localhost:8000"
    print_status "Swagger docs at: http://localhost:8000/docs"
    print_status "Logs: tail -f discovery-api-dev.log"
    
    cd ..
}

# Function to start async domain discovery API service in development mode
start_async_api_dev() {
    print_header "Starting Async Domain Discovery API service in development mode"
    
    if [ ! -d "$DOMAIN_BACKEND_DIR" ]; then
        print_error "Directory $DOMAIN_BACKEND_DIR not found"
        return 1
    fi
    
    cd "$DOMAIN_BACKEND_DIR"
    
    # Check if already running on port 8001
    if ps aux | grep -E "python.*async_domain_discovery_api|uvicorn.*async_domain_discovery_api" | grep -v grep > /dev/null; then
        print_warning "Async Domain Discovery API process already running. Stopping first..."
        stop_discovery_api
        sleep 2
    fi
    
    # Check if virtual environment exists, create if not
    if [ ! -d "venv" ]; then
        print_status "Creating Python virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment and install dependencies
    source venv/bin/activate
    
    if [ ! -f "venv/async_api_installed.flag" ]; then
        print_status "Installing Async API dependencies..."
        pip install fastapi uvicorn redis neo4j requests dnspython
        touch venv/async_api_installed.flag
    fi
    
    # Set environment variables
    export NEO4J_URI=${NEO4J_URI:-"bolt://localhost:7687"}
    export NEO4J_USER=${NEO4J_USER:-"neo4j"}
    export NEO4J_PASS=${NEO4J_PASS:-"test.password"}
    export REDIS_HOST=${REDIS_HOST:-"localhost"}
    export REDIS_PORT=${REDIS_PORT:-"6379"}
    
    print_status "Starting Async Domain Discovery API service in background..."
    nohup python async_domain_discovery_api.py > ../async-api-dev.log 2>&1 &
    ASYNC_API_PID=$!
    
    echo $ASYNC_API_PID > ../async-api-dev.pid
    print_status "Async Domain Discovery API started with PID: $ASYNC_API_PID"
    print_status "API available at: http://localhost:8001"
    print_status "Swagger docs at: http://localhost:8001/docs"
    print_status "Health check at: http://localhost:8001/health"
    print_status "Logs: tail -f async-api-dev.log"
    
    cd ..
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
   
    export MISTRAL_API_KEY=$(cat ./test/api2.txt)  

    echo $MISTRAL_API_KEY
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

# Function to start Report Backend in development mode (Python FastAPI)
start_report_backend_dev() {
    print_header "Starting Report Backend in development mode (Python/FastAPI)"
    
    if [ ! -d "$REPORT_BACKEND_DIR" ]; then
        print_error "Directory $REPORT_BACKEND_DIR not found"
        return 1
    fi
    
    cd "$REPORT_BACKEND_DIR"
    
    # Check if already running on port 8082
    if lsof -ti:8082 > /dev/null 2>&1; then
        print_warning "Report Backend process already running on port 8082. Stopping first..."
        stop_report_backend
        sleep 2
    fi
    
    # Check if FastAPI dependencies are installed
    if ! python3 -c "import fastapi, uvicorn" 2>/dev/null; then
        print_status "Installing FastAPI dependencies..."
        pip3 install fastapi uvicorn neo4j
    fi
    
    print_status "Starting Report Backend (Python FastAPI) in background..."
    nohup python3 simple_graph_api.py > ../report-backend-dev.log 2>&1 &
    REPORT_BACKEND_PID=$!
    
    echo $REPORT_BACKEND_PID > ../report-backend-dev.pid
    print_status "Report Backend started with PID: $REPORT_BACKEND_PID"
    print_status "API Base: http://localhost:8082/api/v1"
    print_status "Swagger UI: http://localhost:8082/swagger-ui"
    print_status "OpenAPI Spec: http://localhost:8082/openapi"
    print_status "Graph Analysis: http://localhost:8082/api/v1/graph/analysis"
    print_status "Graph Health: http://localhost:8082/api/v1/graph/health"
    print_status "Logs: tail -f report-backend-dev.log"
    
    cd ..
}

# Function to start Report Backend in Quarkus mode (alternative)
start_report_backend_quarkus() {
    print_header "Starting Report Backend in Quarkus mode"
    
    if [ ! -d "$REPORT_BACKEND_DIR" ]; then
        print_error "Directory $REPORT_BACKEND_DIR not found"
        return 1
    fi
    
    cd "$REPORT_BACKEND_DIR"
    
    # Check if already running on port 8082
    if lsof -ti:8082 > /dev/null 2>&1; then
        print_warning "Report Backend process already running on port 8082. Stopping first..."
        stop_report_backend
        sleep 2
    fi
    
    print_status "Starting Report Backend (Quarkus) in background..."
    nohup mvn quarkus:dev -Dquarkus.http.port=8082 > ../report-backend-dev.log 2>&1 &
    REPORT_BACKEND_PID=$!
    
    echo $REPORT_BACKEND_PID > ../report-backend-dev.pid
    print_status "Report Backend (Quarkus) started with PID: $REPORT_BACKEND_PID"
    print_status "API Base: http://localhost:8082/api/v1"
    print_status "Swagger UI: http://localhost:8082/swagger-ui"
    print_status "OpenAPI Spec: http://localhost:8082/openapi"
    print_status "Logs: tail -f report-backend-dev.log"
    
    cd ..
}

# Function to start Report Backend in Java 21 Quarkus mode (port 8083)
start_report_backend_java21() {
    print_header "Starting Report Backend in Java 21 Quarkus mode (port 8083)"
    
    if [ ! -d "$REPORT_BACKEND_DIR" ]; then
        print_error "Directory $REPORT_BACKEND_DIR not found"
        return 1
    fi
    
    cd "$REPORT_BACKEND_DIR"
    
    # Check if already running on port 8083
    if lsof -ti:8083 > /dev/null 2>&1; then
        print_warning "Report Backend process already running on port 8083. Stopping first..."
        lsof -ti:8083 | xargs kill -15 2>/dev/null
        sleep 2
    fi
    
    print_status "Starting Report Backend (Java 21 Quarkus) in background..."
    nohup mvn quarkus:dev > ../report-backend-java21-dev.log 2>&1 &
    REPORT_BACKEND_PID=$!
    
    echo $REPORT_BACKEND_PID > ../report-backend-java21-dev.pid
    print_status "Report Backend (Java 21) started with PID: $REPORT_BACKEND_PID"
    print_status "API Base: http://localhost:8083"
    print_status "Swagger UI: http://localhost:8083/swagger-ui"
    print_status "OpenAPI Spec: http://localhost:8083/openapi"
    print_status "Logs: tail -f report-backend-java21-dev.log"
    
    cd ..
}

# Function to stop Graph View processes
stop_graph_view() {
    print_header "Stopping Graph View processes"
    
    # Method 1: Kill processes on port 8500 (backend)
    PORT_8500_PIDS=$(lsof -ti:8500 2>/dev/null)
    if [ ! -z "$PORT_8500_PIDS" ]; then
        print_status "Killing Graph View backend processes on port 8500: $PORT_8500_PIDS"
        echo $PORT_8500_PIDS | xargs kill -15 2>/dev/null
        sleep 2
        
        # Force kill if still running
        REMAINING_PORT=$(lsof -ti:8500 2>/dev/null)
        if [ ! -z "$REMAINING_PORT" ]; then
            print_status "Force killing remaining processes on port 8500: $REMAINING_PORT"
            echo $REMAINING_PORT | xargs kill -9 2>/dev/null
        fi
    fi
    
    # Method 2: Kill processes on port 8083 (frontend)
    PORT_8083_PIDS=$(lsof -ti:8083 2>/dev/null)
    if [ ! -z "$PORT_8083_PIDS" ]; then
        print_status "Killing Graph View frontend processes on port 8083: $PORT_8083_PIDS"
        echo $PORT_8083_PIDS | xargs kill -15 2>/dev/null
        sleep 2
        
        # Force kill if still running
        REMAINING_PORT=$(lsof -ti:8083 2>/dev/null)
        if [ ! -z "$REMAINING_PORT" ]; then
            print_status "Force killing remaining processes on port 8083: $REMAINING_PORT"
            echo $REMAINING_PORT | xargs kill -9 2>/dev/null
        fi
    fi
    
    # Method 3: Kill Graph View processes by pattern
    GRAPH_VIEW_PIDS=$(ps aux | grep -E "graph_visualization_api|python.*serve\.py" | grep -v grep | awk '{print $2}')
    if [ ! -z "$GRAPH_VIEW_PIDS" ]; then
        print_status "Killing Graph View processes: $GRAPH_VIEW_PIDS"
        echo $GRAPH_VIEW_PIDS | xargs kill -15 2>/dev/null
        sleep 2
        
        # Force kill if still running
        REMAINING_PIDS=$(ps aux | grep -E "graph_visualization_api|python.*serve\.py" | grep -v grep | awk '{print $2}')
        if [ ! -z "$REMAINING_PIDS" ]; then
            echo $REMAINING_PIDS | xargs kill -9 2>/dev/null
        fi
    fi
    
    # Clean up PID files
    rm -f graph-view-backend-dev.pid graph-view-frontend-dev.pid
    
    # Verify ports are free
    REMAINING_8500=$(lsof -ti:8500 2>/dev/null)
    REMAINING_8083=$(lsof -ti:8083 2>/dev/null)
    
    if [ -z "$REMAINING_8500" ] && [ -z "$REMAINING_8083" ]; then
        print_status "Graph View services stopped successfully - ports 8500 and 8083 are free"
    else
        if [ -n "$REMAINING_8500" ]; then
            print_warning "Port 8500 may still be in use: $REMAINING_8500"
        fi
        if [ -n "$REMAINING_8083" ]; then
            print_warning "Port 8083 may still be in use: $REMAINING_8083"
        fi
    fi
}

# Function to stop Report Backend
stop_report_backend() {
    print_header "Stopping Report Backend processes"
    
    # Method 1: Kill by PID if exists
    if [ -f "report-backend-dev.pid" ]; then
        PID=$(cat report-backend-dev.pid)
        if ps -p $PID > /dev/null 2>&1; then
            print_status "Stopping Report Backend with PID: $PID"
            kill $PID
            sleep 2
            
            if ps -p $PID > /dev/null 2>&1; then
                print_warning "Process still running, force killing..."
                kill -9 $PID
            fi
        else
            print_status "Removing stale PID file report-backend-dev.pid (process $PID no longer exists)"
        fi
        rm -f report-backend-dev.pid
    fi
    
    # Method 2: Kill processes on port 8082
    PORT_PIDS=$(lsof -ti:8082 2>/dev/null)
    if [ ! -z "$PORT_PIDS" ]; then
        print_status "Killing processes on port 8082: $PORT_PIDS"
        echo $PORT_PIDS | xargs kill -15 2>/dev/null
        sleep 2
        
        # Force kill if still running
        REMAINING_PORT=$(lsof -ti:8082 2>/dev/null)
        if [ ! -z "$REMAINING_PORT" ]; then
            print_status "Force killing remaining processes on port 8082: $REMAINING_PORT"
            echo $REMAINING_PORT | xargs kill -9 2>/dev/null
        fi
    fi
    
    # Method 3: Kill any remaining Report Backend processes by pattern
    PIDS=$(ps aux | grep -E "mvn.*quarkus.*8082|report-backend" | grep -v grep | awk '{print $2}')
    if [ ! -z "$PIDS" ]; then
        print_status "Killing remaining Report Backend processes: $PIDS"
        echo $PIDS | xargs kill -15 2>/dev/null
        sleep 2
        
        # Force kill if still running
        PIDS=$(ps aux | grep -E "mvn.*quarkus.*8082|report-backend" | grep -v grep | awk '{print $2}')
        if [ ! -z "$PIDS" ]; then
            echo $PIDS | xargs kill -9 2>/dev/null
        fi
    fi
    
    # Verify port is free
    if lsof -ti:8082 > /dev/null 2>&1; then
        print_warning "Port 8082 may still be in use"
    else
        print_status "Report Backend stopped successfully - port 8082 is free"
    fi
}

# Function to clear React cache
clear_react_cache() {
    print_header "Clearing React cache"
    
    if [ ! -d "$RISK_DASHBOARD_DIR" ]; then
        print_error "Directory $RISK_DASHBOARD_DIR not found"
        return 1
    fi
    
    cd "$RISK_DASHBOARD_DIR"
    
    print_status "Clearing React development cache..."
    
    # Clear npm cache
    if command -v npm &> /dev/null; then
        print_status "Clearing npm cache..."
        npm cache clean --force
    fi
    
    # Remove node_modules cache directories
    if [ -d "node_modules/.cache" ]; then
        print_status "Removing node_modules/.cache..."
        rm -rf node_modules/.cache
    fi
    
    # Remove React build cache
    if [ -d "build" ]; then
        print_status "Removing build directory..."
        rm -rf build
    fi
    
    # Remove webpack cache (if exists)
    if [ -d ".cache" ]; then
        print_status "Removing .cache directory..."
        rm -rf .cache
    fi
    
    # Clear environment variable cache by touching .env file
    if [ -f ".env" ]; then
        print_status "Refreshing .env file timestamp..."
        touch .env
    fi
    
    print_status "React cache cleared successfully"
    cd ..
}

# Function to start Graph View services in development mode
start_graph_view_dev() {
    print_header "Starting Graph View services in development mode"
    
    if [ ! -d "$GRAPH_VIEW_DIR" ]; then
        print_error "Directory $GRAPH_VIEW_DIR not found"
        return 1
    fi
    
    # Check if already running
    if lsof -ti:8500 > /dev/null 2>&1 || lsof -ti:8083 > /dev/null 2>&1; then
        print_warning "Graph View processes already running. Stopping first..."
        stop_graph_view
        sleep 2
    fi
    
    # Start Backend (Python FastAPI)
    cd "$GRAPH_VIEW_DIR/backend"
    print_status "Starting Graph View Backend API in background..."
    
    # Check if virtual environment exists, create if not
    if [ ! -d "venv" ]; then
        print_status "Creating Python virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment and install dependencies
    source venv/bin/activate
    
    if [ ! -f "venv/graph_api_installed.flag" ]; then
        print_status "Installing Graph API dependencies..."
        pip install -r requirements.txt
        touch venv/graph_api_installed.flag
    fi
    
    # Set environment variables
    export NEO4J_URI=${NEO4J_URI:-"bolt://localhost:7687"}
    export NEO4J_USER=${NEO4J_USER:-"neo4j"}
    export NEO4J_PASS=${NEO4J_PASS:-"test.password"}
    
    nohup python3 graph_visualization_api.py > ../../graph-view-backend-dev.log 2>&1 &
    BACKEND_PID=$!
    echo $BACKEND_PID > ../../graph-view-backend-dev.pid
    
    cd ../..
    
    # Start Frontend (Simple HTTP Server)
    cd "$GRAPH_VIEW_DIR/frontend"
    print_status "Starting Graph View Frontend server in background..."
    nohup python3 serve.py > ../../graph-view-frontend-dev.log 2>&1 &
    FRONTEND_PID=$!
    echo $FRONTEND_PID > ../../graph-view-frontend-dev.pid
    
    cd ../..
    
    print_status "Graph View Backend started with PID: $BACKEND_PID (Port: 8500)"
    print_status "Graph View Frontend started with PID: $FRONTEND_PID (Port: 8083)"
    print_status "Backend API: http://localhost:8500"
    print_status "Frontend UI: http://localhost:8083"
    print_status "API Docs: http://localhost:8500/docs"
    print_status "Backend logs: tail -f graph-view-backend-dev.log"
    print_status "Frontend logs: tail -f graph-view-frontend-dev.log"
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
    
    # Check Legacy Subdomain Discovery API (Port 8000)
    API_PORT_PID=$(lsof -ti:8000 2>/dev/null | head -1)
    API_PROCESS_PID=$(ps aux | grep -E "python.*subdomain_discovery_api" | grep -v grep | awk '{print $2}' | head -1)
    
    if [ -n "$API_PORT_PID" ] || [ -n "$API_PROCESS_PID" ]; then
        ACTIVE_PID=${API_PORT_PID:-$API_PROCESS_PID}
        print_status "Legacy Discovery API: RUNNING (PID: $ACTIVE_PID, Port: 8000)"
    else
        print_warning "Legacy Discovery API: STOPPED"
    fi
    
    # Check Async Domain Discovery API (Port 8001)
    ASYNC_PORT_PID=$(lsof -ti:8001 2>/dev/null | head -1)
    ASYNC_PROCESS_PID=$(ps aux | grep -E "python.*async_domain_discovery_api" | grep -v grep | awk '{print $2}' | head -1)
    
    if [ -n "$ASYNC_PORT_PID" ] || [ -n "$ASYNC_PROCESS_PID" ]; then
        ACTIVE_PID=${ASYNC_PORT_PID:-$ASYNC_PROCESS_PID}
        print_status "Async Discovery API: RUNNING (PID: $ACTIVE_PID, Port: 8001)"
    else
        print_warning "Async Discovery API: STOPPED"
    fi
    
    # Check Graph View Backend (Port 8500)
    GRAPH_BACKEND_PORT_PID=$(lsof -ti:8500 2>/dev/null | head -1)
    GRAPH_BACKEND_PROCESS_PID=$(ps aux | grep -E "graph_visualization_api" | grep -v grep | awk '{print $2}' | head -1)
    
    if [ -n "$GRAPH_BACKEND_PORT_PID" ] || [ -n "$GRAPH_BACKEND_PROCESS_PID" ]; then
        ACTIVE_PID=${GRAPH_BACKEND_PORT_PID:-$GRAPH_BACKEND_PROCESS_PID}
        print_status "Graph View Backend: RUNNING (PID: $ACTIVE_PID, Port: 8500)"
        print_status "  ↳ API Docs: http://localhost:8500/docs"
        print_status "  ↳ Graph Stats: http://localhost:8500/stats"
    else
        print_warning "Graph View Backend: STOPPED"
    fi
    
    # Check Graph View Frontend (Port 8083)
    GRAPH_FRONTEND_PORT_PID=$(lsof -ti:8083 2>/dev/null | head -1)
    GRAPH_FRONTEND_PROCESS_PID=$(ps aux | grep -E "python.*serve\.py" | grep -v grep | awk '{print $2}' | head -1)
    
    if [ -n "$GRAPH_FRONTEND_PORT_PID" ] || [ -n "$GRAPH_FRONTEND_PROCESS_PID" ]; then
        ACTIVE_PID=${GRAPH_FRONTEND_PORT_PID:-$GRAPH_FRONTEND_PROCESS_PID}
        print_status "Graph View Frontend: RUNNING (PID: $ACTIVE_PID, Port: 8083)"
        print_status "  ↳ 3D Visualization: http://localhost:8083"
    else
        print_warning "Graph View Frontend: STOPPED"
    fi
    
    # Check Report Backend (Alternative ports)
    REPORT_PORT_PID=$(lsof -ti:8084 2>/dev/null | head -1)
    REPORT_PROCESS_PID=$(ps aux | grep -E "mvn.*quarkus.*8084|report-backend" | grep -v grep | awk '{print $2}' | head -1)
    
    if [ -n "$REPORT_PORT_PID" ] || [ -n "$REPORT_PROCESS_PID" ]; then
        ACTIVE_PID=${REPORT_PORT_PID:-$REPORT_PROCESS_PID}
        print_status "Report Backend: RUNNING (PID: $ACTIVE_PID, Port: 8084)"
        print_status "  ↳ Swagger UI: http://localhost:8084/swagger-ui"
        print_status "  ↳ Graph Analysis: http://localhost:8084/api/v1/graph/analysis"
    else
        print_warning "Report Backend: STOPPED"
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
        "discovery"|"api"|"da")
            if [ -f "discovery-api-dev.log" ]; then
                tail -f discovery-api-dev.log
            else
                print_error "No Legacy Discovery API log files found"
            fi
            ;;
        "async"|"async-api"|"aa")
            if [ -f "async-api-dev.log" ]; then
                tail -f async-api-dev.log
            else
                print_error "No Async Discovery API log files found"
            fi
            ;;
        "ollama"|"o")
            if [ -f "ollama.log" ]; then
                tail -f ollama.log
            else
                print_error "No Ollama log files found"
            fi
            ;;
        "graph"|"gv")
            if [ -f "graph-view-backend-dev.log" ]; then
                tail -f graph-view-backend-dev.log
            else
                print_error "No Graph View Backend log files found"
            fi
            ;;
        "graph-frontend"|"gvf")
            if [ -f "graph-view-frontend-dev.log" ]; then
                tail -f graph-view-frontend-dev.log
            else
                print_error "No Graph View Frontend log files found"
            fi
            ;;
        "report"|"rb")
            if [ -f "report-backend-dev.log" ]; then
                tail -f report-backend-dev.log
            else
                print_error "No Report Backend log files found"
            fi
            ;;
        *)
            print_error "Usage: $0 logs [quarkus|react|query|discovery|async|ollama|graph|graph-frontend|report]"
            print_error "Available log types:"
            print_error "  quarkus|q    - Risk Graph Service logs"
            print_error "  react|r      - Risk Dashboard logs"
            print_error "  query|rq     - Risk Query Service logs" 
            print_error "  discovery|api|da - Legacy Discovery API logs (port 8000)"
            print_error "  async|async-api|aa - Async Discovery API logs (port 8001)"
            print_error "  ollama|o     - Ollama Service logs"
            print_error "  graph|gv     - Graph View Backend logs (port 8500)"
            print_error "  graph-frontend|gvf - Graph View Frontend logs (port 8083)"
            print_error "  report|rb    - Report Backend Service logs (port 8084)"
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
        stop_discovery_api
        stop_report_backend
        stop_graph_view
        ;;
    "start-dev")
       # start_ollama
        start_quarkus_dev
        start_npm_dev
        start_risk_query_dev
        start_async_api_dev
        start_graph_view_dev
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
        stop_discovery_api
        stop_report_backend
        stop_graph_view
        sleep 2
        start_ollama
        start_quarkus_dev
        start_npm_dev
        start_risk_query_dev
        start_async_api_dev
        start_graph_view_dev
        ;;
    "restart-test")
        stop_ollama
        stop_quarkus
        stop_npm
        stop_risk_query
        stop_discovery_api
        stop_report_backend
        stop_graph_view
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
    "start-discovery")
        start_discovery_api_dev
        ;;
    "start-async")
        start_async_api_dev
        ;;
    "start-discovery-legacy")
        start_discovery_api_dev
        ;;
    "stop-discovery")
        stop_discovery_api
        ;;
    "stop-async")
        stop_discovery_api
        ;;
    "start-report")
        start_report_backend_dev
        ;;
    "start-report-quarkus")
        start_report_backend_quarkus
        ;;
    "start-report-java21")
        start_report_backend_java21
        ;;
    "stop-report")
        stop_report_backend
        ;;
    "start-graph")
        start_graph_view_dev
        ;;
    "stop-graph")
        stop_graph_view
        ;;
    "restart-graph")
        stop_graph_view
        sleep 2
        start_graph_view_dev
        ;;
    "clear-cache")
        clear_react_cache
        ;;
    "restart-react")
        stop_npm
        clear_react_cache
        start_npm_dev
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
        echo "Usage: $0 {stop|start-dev|start-test|restart-dev|restart-test|start-ollama|stop-ollama|start-query|stop-query|start-discovery|start-async|start-discovery-legacy|stop-discovery|stop-async|start-report|stop-report|start-graph|stop-graph|restart-graph|clear-cache|restart-react|status|logs}"
        echo ""
        echo "Commands:"
        echo "  stop        - Stop all running services"
        echo "  start-dev   - Start all services in development mode (detached) - includes Graph View"
        echo "  start-test  - Start services in test mode (detached)"  
        echo "  restart-dev - Restart all services in development mode - includes Graph View"
        echo "  restart-test- Restart services in test mode"
        echo "  start-ollama- Start Ollama service only"
        echo "  stop-ollama - Stop Ollama service only"
        echo "  start-query - Start Risk Query service only"
        echo "  stop-query  - Stop Risk Query service only"
        echo "  start-async - Start NEW Async Domain Discovery API service (port 8001)"
        echo "  start-discovery-legacy - Start Legacy Subdomain Discovery API (port 8000)"
        echo "  start-discovery - Alias for start-discovery-legacy"
        echo "  stop-discovery  - Stop all Discovery API services (legacy + async)"
        echo "  stop-async  - Stop all Discovery API services (legacy + async)"
        echo "  start-report- Start Report Backend service only (Python/FastAPI, port 8084)"
        echo "  start-report-quarkus - Start Report Backend in Quarkus mode (port 8084)"
        echo "  stop-report - Stop Report Backend service only"
        echo "  start-graph - Start Graph View service only (Backend: 8500, Frontend: 8083)"
        echo "  stop-graph  - Stop Graph View service only"
        echo "  restart-graph - Restart Graph View service"
        echo "  clear-cache - Clear React development cache"
        echo "  restart-react- Stop React, clear cache, and restart React"
        echo "  status      - Show status of all services"
        echo "  logs [quarkus|react|query|discovery|async|ollama|graph|graph-frontend|report] - Show logs for specific service"
        echo ""
        echo "Examples:"
        echo "  $0 start-dev      # Start all services (includes Graph View on ports 8082/8083)"
        echo "  $0 stop           # Stop all services"
        echo "  $0 status         # Check if services are running"
        echo "  $0 logs query     # View Risk Query logs"
        echo "  $0 logs async     # View Async Discovery API logs"
        echo "  $0 logs discovery # View Legacy Discovery API logs"
        echo "  $0 logs graph     # View Graph View Backend logs"
        echo "  $0 logs graph-frontend # View Graph View Frontend logs"
        echo "  $0 start-ollama   # Start only Ollama service"
        echo "  $0 start-async    # Start only NEW Async Discovery API (port 8001)"
        echo "  $0 start-discovery-legacy # Start only Legacy Discovery API (port 8000)"
        echo "  $0 start-graph    # Start only Graph View (Backend: 8082, Frontend: 8083)"
        echo "  $0 start-report   # Start only Report Backend service (Python/FastAPI, port 8084)"
        echo "  $0 start-report-quarkus # Start Report Backend in Quarkus mode (port 8084)"
        echo "  $0 restart-graph  # Restart Graph View services"
        echo "  $0 logs report    # View Report Backend logs"
        echo "  $0 clear-cache    # Clear React cache (useful when env vars don't update)"
        echo "  $0 restart-react  # Restart React with cache clearing"
        echo ""
        echo "🆕 NEW: Async Domain Discovery API"
        echo "  - Available at: http://localhost:8001"  
        echo "  - Swagger docs: http://localhost:8001/docs"
        echo "  - Features: Incremental analysis, Redis caching, progress tracking"
        echo "  - Test scripts: ./scripts/test_async_api.sh"
        echo ""
        echo "🌊 NEW: Graph View 3D Visualization"
        echo "  - Backend API: http://localhost:8082"
        echo "  - Frontend UI: http://localhost:8083"
        echo "  - API Docs: http://localhost:8082/docs"
        echo "  - Graph Stats: http://localhost:8082/stats"
        echo "  - Features: Interactive 3D graph visualization, risk-based coloring"
        echo "  - Views: Complete graph, domain-focused, provider analysis, risk filtering"
        echo ""
        echo "📊 Report Backend Service"
        echo "  - Available at: http://localhost:8084 (moved to avoid port conflicts)"
        echo "  - Swagger UI: http://localhost:8084/swagger-ui"
        echo "  - OpenAPI Spec: http://localhost:8084/openapi"
        echo "  - Graph Analysis: http://localhost:8084/api/v1/graph/analysis"
        echo "  - Graph Health: http://localhost:8084/api/v1/graph/health"
        echo "  - Features: Neo4j graph analysis, domain risk assessment, PDF reports"
        echo "  - Default: Python/FastAPI mode (faster startup)"
        echo "  - Alternative: Quarkus mode (use 'start-report-quarkus')"
        exit 1
        ;;
esac
