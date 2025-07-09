# Risk Analysis Platform - Test & Development Scripts

This directory contains comprehensive testing and development scripts for the Risk Analysis Platform.

## 📋 Scripts Overview

### 🚀 **Development Scripts**

#### `start_dev_services.sh`
Starts both risk-graph-service and risk-warehouse-service in development mode.

**Usage:**
```bash
# Start both services with default settings
./start_dev_services.sh

# Start with custom ports
./start_dev_services.sh --graph-port 8080 --warehouse-port 8081

# Start without auto-reload
./start_dev_services.sh --no-reload

# Stop services
./start_dev_services.sh --stop

# Check services status
./start_dev_services.sh --status

# View live logs
./start_dev_services.sh --logs
```

**Features:**
- Automatic dependency installation
- Neo4j connection validation
- Environment variable setup
- Process management (start/stop/status)
- Live log monitoring
- Auto-reload on code changes

---

### 🧪 **API Testing Scripts**

#### `test_api.sh`
Comprehensive API testing for risk-graph-service.

**Usage:**
```bash
# Test local service
./test_api.sh

# Test remote service
./test_api.sh https://api.example.com

# Test specific port
./test_api.sh http://localhost:8080
```

**Test Coverage:**
- Health check endpoints
- Domain CRUD operations
- Subdomain management
- IP address queries
- Provider information
- Search functionality
- Analytics endpoints
- Graph traversal
- Data export
- Error handling

#### `test_warehouse_api.sh`
Comprehensive API testing for risk-warehouse-service.

**Usage:**
```bash
# Test local service
./test_warehouse_api.sh

# Test remote service
./test_warehouse_api.sh https://warehouse.example.com

# Test specific port
./test_warehouse_api.sh http://localhost:8001
```

**Test Coverage:**
- Dataset management
- ETL operations
- Data quality checks
- Analytics and reporting
- Data lineage
- Data catalog
- Export functionality
- Batch processing
- Configuration management
- Monitoring endpoints
- SQL interface
- Streaming data

---

### 🔄 **Integration Testing**

#### `integration_test.sh`
End-to-end integration testing for the complete platform.

**Usage:**
```bash
# Run full integration test
./integration_test.sh
```

**Test Flow:**
1. Service availability check
2. Data loading with risk_loader_two_phase.py
3. Data validation via graph-service API
4. Data processing via warehouse-service API
5. Analytics and export testing
6. Complete data flow validation

**Features:**
- Automatic test data generation
- Service dependency validation
- Data flow testing
- HTML report generation
- Comprehensive logging

---

### ⚡ **Performance Testing**

#### `performance_test.sh`
Load and performance testing for both services.

**Usage:**
```bash
# Default performance test
./performance_test.sh

# Heavy load test
./performance_test.sh --concurrent-users 50 --test-duration 300

# Light load test  
./performance_test.sh --concurrent-users 5 --test-duration 30

# Custom configuration
./performance_test.sh \
  --concurrent-users 20 \
  --test-duration 120 \
  --graph-service-url http://localhost:8000 \
  --warehouse-service-url http://localhost:8001
```

**Test Types:**
- Concurrent user simulation
- Response time measurement
- Throughput testing
- Stress testing scenarios
- Response time distribution
- Load balancing validation

**Tools Used:**
- Apache Bench (ab) - primary load testing
- wrk - advanced HTTP benchmarking (optional)
- Custom response time measurement

---

## 🚀 **Quick Start Guide**

### 1. **Setup Development Environment**
```bash
# Start development services
./start_dev_services.sh

# Verify services are running
./start_dev_services.sh --status
```

### 2. **Run Basic API Tests**
```bash
# Test graph service
./test_api.sh

# Test warehouse service
./test_warehouse_api.sh
```

### 3. **Run Integration Tests**
```bash
# Full platform integration test
./integration_test.sh
```

### 4. **Run Performance Tests**
```bash
# Performance and load testing
./performance_test.sh
```

---

## 📊 **Test Results**

All scripts generate results in the `test_results/` directory:

```
test_results/
├── api_test_YYYYMMDD_HHMMSS.log
├── warehouse_test_YYYYMMDD_HHMMSS.log
├── integration_test_YYYYMMDD_HHMMSS.log
├── integration_report_YYYYMMDD_HHMMSS.html
├── performance_test_YYYYMMDD_HHMMSS.log
├── performance_report_YYYYMMDD_HHMMSS.html
└── response_time_distribution_YYYYMMDD_HHMMSS.csv
```

### **Report Types:**
- **Text logs**: Detailed execution logs
- **HTML reports**: Visual summaries and metrics
- **CSV files**: Raw performance data
- **Gnuplot data**: Performance visualization data

---

## 🔧 **Configuration**

### **Environment Variables**
```bash
# Neo4j Configuration
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="test.password"

# Service Configuration
export GRAPH_SERVICE_PORT=8000
export WAREHOUSE_SERVICE_PORT=8001
export LOG_LEVEL="DEBUG"

# Performance Test Configuration
export CONCURRENT_USERS=10
export TEST_DURATION=60
```

### **Prerequisites**
- Python 3.8+
- Neo4j database running
- curl (for API testing)
- jq (for JSON parsing)
- Apache Bench (for performance testing)
- wrk (optional, for advanced load testing)

---

## 🛠️ **Troubleshooting**

### **Common Issues:**

#### **Services Not Starting**
```bash
# Check Neo4j connection
python3 -c "from neo4j import GraphDatabase; print('Neo4j OK')"

# Check port availability
netstat -tulpn | grep :8000
netstat -tulpn | grep :8001

# Check dependencies
pip list | grep -E "(fastapi|uvicorn|neo4j)"
```

#### **API Tests Failing**
```bash
# Verify service health
curl http://localhost:8000/health
curl http://localhost:8001/health

# Check service logs
./start_dev_services.sh --logs
```

#### **Performance Test Issues**
```bash
# Install Apache Bench
sudo apt-get install apache2-utils

# Install wrk (optional)
git clone https://github.com/wg/wrk.git
cd wrk && make && sudo cp wrk /usr/local/bin/
```

---

## 📈 **Performance Benchmarks**

### **Expected Performance (Reference)**
- **Graph Service**: ~1000 requests/second (simple queries)
- **Warehouse Service**: ~500 requests/second (complex analytics)
- **Response Time**: <100ms (95th percentile)
- **Concurrent Users**: 50+ (without degradation)

### **Monitoring Metrics**
- Request throughput (RPS)
- Response time distribution
- Error rates
- Resource utilization
- Database connection pool

---

## 🤝 **Contributing**

### **Adding New Tests**
1. Create test function in appropriate script
2. Add to test suite array
3. Update documentation
4. Test with different scenarios

### **Script Structure**
```bash
# Standard script structure
check_dependencies()    # Verify prerequisites
show_help()            # Display usage info
main()                 # Main execution logic
log()                  # Logging function
```

### **Best Practices**
- Use colored output for better UX
- Implement retry logic for flaky tests
- Generate structured reports
- Log all important events
- Handle errors gracefully

---

## 📚 **Additional Resources**

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Neo4j Documentation](https://neo4j.com/docs/)
- [Apache Bench Manual](https://httpd.apache.org/docs/2.4/programs/ab.html)
- [wrk GitHub Repository](https://github.com/wg/wrk)

---

## 📝 **License**

These scripts are part of the Risk Analysis Platform and follow the same license terms as the main project.