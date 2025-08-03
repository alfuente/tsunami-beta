#!/bin/bash

# setup_api.sh - Script de instalación y configuración para Subdomain Discovery API v6.0

set -e

echo "🚀 Subdomain Discovery API v6.0 - Setup Script"
echo "============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [[ ! -f "subdomain_discovery_api.py" ]]; then
    print_error "subdomain_discovery_api.py not found. Please run this script from the correct directory."
    exit 1
fi

print_status "Starting setup process..."

# 1. Check Python version
print_status "Checking Python version..."
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.8"

if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
    print_success "Python $PYTHON_VERSION detected (>= $REQUIRED_VERSION required)"
else
    print_error "Python $REQUIRED_VERSION or higher is required. Current version: $PYTHON_VERSION"
    exit 1
fi

# 2. Check if Neo4j is running
print_status "Checking Neo4j connection..."
if docker ps | grep -q neo4j; then
    NEO4J_CONTAINER=$(docker ps --format "table {{.Names}}" | grep neo4j | head -1)
    print_success "Neo4j container found: $NEO4J_CONTAINER"
    
    # Test connection
    if docker exec $NEO4J_CONTAINER cypher-shell -u neo4j -p test.password "RETURN 1" >/dev/null 2>&1; then
        print_success "Neo4j connection test successful"
    else
        print_warning "Neo4j connection test failed. Please check credentials."
    fi
else
    print_warning "No Neo4j container found. Please ensure Neo4j is running."
fi

# 3. Install dependencies
print_status "Installing Python dependencies..."
if pip3 install -r requirements_api.txt; then
    print_success "Dependencies installed successfully"
else
    print_error "Failed to install dependencies"
    exit 1
fi

# 4. Create environment configuration
print_status "Creating environment configuration..."
if [[ ! -f ".env" ]]; then
    cat > .env << EOF
# Subdomain Discovery API Configuration
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASS=test.password
IPINFO_TOKEN=
MAX_CONCURRENT_JOBS=10
DEFAULT_AMASS_TIMEOUT=300
DEFAULT_MAX_SUBDOMAINS=1000
EOF
    print_success "Environment configuration created (.env)"
    print_warning "Please edit .env file to configure IPINFO_TOKEN if needed"
else
    print_success "Environment configuration already exists (.env)"
fi

# 5. Create startup script
print_status "Creating startup script..."
cat > start_api.sh << 'EOF'
#!/bin/bash

# Load environment variables
if [[ -f ".env" ]]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

echo "🚀 Starting Subdomain Discovery API..."
echo "======================================"

# Check if port 8000 is available
if lsof -Pi :8000 -sTCP:LISTEN -t >/dev/null ; then
    echo "⚠️  Port 8000 is already in use. Stopping existing service..."
    pkill -f "subdomain_discovery_api"
    sleep 2
fi

# Start the API server
echo "🌐 Starting API server on http://localhost:8000"
echo "📖 Swagger documentation: http://localhost:8000/docs"
echo "📚 ReDoc documentation: http://localhost:8000/redoc"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python3 subdomain_discovery_api.py
EOF

chmod +x start_api.sh
print_success "Startup script created (start_api.sh)"

# 6. Create test script
print_status "Creating test script..."
cat > test_api.sh << 'EOF'
#!/bin/bash

# test_api.sh - Test script for Subdomain Discovery API

API_BASE="http://localhost:8000"
TEST_DOMAIN="bice.cl"

echo "🧪 Testing Subdomain Discovery API"
echo "=================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

test_endpoint() {
    local endpoint="$1"
    local description="$2"
    local timeout="${3:-30}"
    
    echo -e "\n${BLUE}Testing:${NC} $description"
    echo -e "${YELLOW}Endpoint:${NC} $endpoint"
    
    if curl -s --max-time $timeout "$endpoint" | jq . >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Success${NC}"
        return 0
    else
        echo -e "${RED}❌ Failed${NC}"
        return 1
    fi
}

# Check if API is running
echo "Checking if API is running..."
if ! curl -s "$API_BASE/health" >/dev/null; then
    echo -e "${RED}❌ API is not running. Please start it first with: ./start_api.sh${NC}"
    exit 1
fi

echo -e "${GREEN}✅ API is running${NC}"

# Test endpoints
echo -e "\n${BLUE}Running endpoint tests...${NC}"

test_endpoint "$API_BASE/health" "Health check" 5
test_endpoint "$API_BASE/api/v1/status" "API status" 5
test_endpoint "$API_BASE/api/v1/analysis/providers/$TEST_DOMAIN?includeMx=true" "Provider analysis" 60
test_endpoint "$API_BASE/api/v1/analysis/services/$TEST_DOMAIN" "Service analysis" 30
test_endpoint "$API_BASE/api/v1/analysis/tls/$TEST_DOMAIN" "TLS analysis" 30

echo -e "\n${BLUE}Testing basic discovery (this may take a few minutes)...${NC}"
test_endpoint "$API_BASE/api/v1/discovery/$TEST_DOMAIN?amassTimeout=60&maxSubdomains=10" "Basic discovery" 120

echo -e "\n${BLUE}Testing discovery with providers...${NC}"
test_endpoint "$API_BASE/api/v1/discoveryWithProviders/$TEST_DOMAIN?amassTimeout=60&maxSubdomains=5" "Discovery with providers" 120

echo -e "\n${GREEN}🎉 API testing completed!${NC}"
echo -e "\n${YELLOW}💡 To explore more endpoints, visit:${NC}"
echo -e "   📖 Swagger UI: $API_BASE/docs"
echo -e "   📚 ReDoc: $API_BASE/redoc"
EOF

chmod +x test_api.sh
print_success "Test script created (test_api.sh)"

# 7. Create Docker Compose file for easy deployment
print_status "Creating Docker Compose configuration..."
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  subdomain-api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - NEO4J_URI=bolt://neo4j:7687
      - NEO4J_USER=neo4j
      - NEO4J_PASS=test.password
    depends_on:
      - neo4j
    volumes:
      - .:/app
    working_dir: /app
    command: python3 subdomain_discovery_api.py

  neo4j:
    image: neo4j:5.13.0
    ports:
      - "7474:7474"
      - "7687:7687"
    environment:
      - NEO4J_AUTH=neo4j/test.password
      - NEO4J_PLUGINS=["apoc"]
    volumes:
      - neo4j_data:/data
      - neo4j_logs:/logs

volumes:
  neo4j_data:
  neo4j_logs:
EOF

# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements_api.txt .
RUN pip install -r requirements_api.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 8000

# Run the application
CMD ["python3", "subdomain_discovery_api.py"]
EOF

print_success "Docker configuration created (docker-compose.yml, Dockerfile)"

# 8. Final validation
print_status "Running final validation..."

# Check if unified discovery engine exists
if [[ -f "subdomain_relationship_discovery_unified.py" ]]; then
    print_success "Unified discovery engine found"
else
    print_warning "Unified discovery engine not found - some features may not work"
fi

# Check if provider detection exists
if [[ -f "provider_detection.py" ]]; then
    print_success "Provider detection module found"
else
    print_warning "Provider detection module not found - MX analysis may not work"
fi

# Check if domain risk calculator exists
if [[ -f "domain_risk_calculator.py" ]]; then
    print_success "Domain risk calculator found"
else
    print_warning "Domain risk calculator not found - risk analysis may not work"
fi

echo ""
print_success "🎉 Setup completed successfully!"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "1. Edit .env file to configure IPINFO_TOKEN if needed"
echo "2. Start the API server: ${GREEN}./start_api.sh${NC}"
echo "3. Test the API: ${GREEN}./test_api.sh${NC}"
echo "4. Open Swagger UI: ${GREEN}http://localhost:8000/docs${NC}"
echo ""
echo -e "${BLUE}Alternative Docker deployment:${NC}"
echo "1. Start with Docker: ${GREEN}docker-compose up -d${NC}"
echo "2. View logs: ${GREEN}docker-compose logs -f${NC}"
echo "3. Stop: ${GREEN}docker-compose down${NC}"
echo ""
echo -e "${YELLOW}📚 For detailed documentation, see: REFACTORING_DOCUMENTATION.md${NC}"
EOF