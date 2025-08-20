# Async Domain Discovery API

## Overview

The `async_domain_discovery_api.py` file contains a comprehensive refactoring of the original `subdomain_relationship_discovery_v5.py` into a FastAPI-based asynchronous service. This service provides incremental graph building with independent task execution for different types of domain analysis.

## Architecture

### Core Components

1. **AsyncDomainDiscoveryService** - Main service class that orchestrates all discovery operations
2. **Task Management System** - Tracks async operations with progress monitoring
3. **Redis Caching Layer** - Caches Amass results for 24 hours to optimize performance
4. **Neo4j Graph Integration** - Incrementally builds the knowledge graph
5. **FastAPI Web Service** - RESTful API endpoints for all operations

### File Location
```
/home/alf/dev/tsunami-beta/domain-backend/async_domain_discovery_api.py
```

## Key Features Implemented

### 1. Amass Discovery with Caching (`lines 356-522`)
- **Purpose**: Discover subdomains and providers using Amass with intelligent caching
- **Caching**: Redis-based 24-hour cache to avoid re-running expensive Amass scans
- **Provider Resolution**: Uses enhanced provider resolver from v5 for better accuracy
- **Graph Integration**: Automatically saves results to Neo4j with relationships

**Key Methods**:
- `run_amass_discovery()` - Main async entry point
- `_run_amass_sync()` - Synchronous Amass execution in thread pool
- `_cache_amass_results()` - Redis caching implementation
- `_save_amass_to_neo4j()` - Graph persistence

### 2. Service Discovery (`lines 524-620`)
- **Purpose**: Port scanning and service identification
- **Scope**: Works on base domains OR specific subdomains
- **Ports Scanned**: Common ports (21, 22, 25, 80, 443, 3306, etc.)
- **Service Mapping**: Automatic service identification by port

**Key Methods**:
- `run_service_discovery()` - Async service scanning
- `_run_service_scan_sync()` - TCP connect scanning
- `_identify_service()` - Port-to-service mapping

### 3. DNS Analysis (`lines 622-729`)
- **Purpose**: Comprehensive DNS record analysis
- **Record Types**: A, AAAA, CNAME, MX, NS, TXT, SOA
- **Nameserver Detection**: Automatic NS record extraction
- **Flexibility**: Supports both domains and subdomains

**Key Methods**:
- `run_dns_analysis()` - Async DNS queries
- `_run_dns_analysis_sync()` - DNS resolution logic
- `_save_dns_to_neo4j()` - Graph updates

### 4. MX Analysis with Email Security (`lines 731-850`)
- **Purpose**: Email infrastructure and security analysis
- **Components**:
  - MX record discovery with priority
  - SPF record validation
  - DMARC policy detection
  - DKIM key discovery (common selectors)
- **Scope**: Base domain focused (as requested)

**Key Methods**:
- `run_mx_analysis()` - Complete email security analysis
- `_run_mx_analysis_sync()` - Email record queries

### 5. TLS Analysis (`lines 852-958`)
- **Purpose**: SSL/TLS certificate and security analysis
- **Features**:
  - Certificate information extraction
  - Subject Alternative Names (SAN)
  - TLS version detection
  - Cipher suite identification
  - Validity period analysis

**Key Methods**:
- `run_tls_analysis()` - Async TLS connection
- `_run_tls_analysis_sync()` - Certificate extraction

### 6. Web Technology Detection (`lines 960-1109`)
- **Purpose**: Web stack and technology identification
- **Detection Methods**:
  - HTTP header analysis
  - Content inspection for frameworks
  - CMS identification (WordPress, Drupal, Joomla)
  - JavaScript library detection (jQuery, React, Vue)

**Key Methods**:
- `run_tech_analysis()` - Technology stack analysis
- `_run_tech_analysis_sync()` - HTTP analysis and content parsing

### 7. Task Management System (`lines 77-153`)
- **Purpose**: Async task lifecycle management
- **Features**:
  - Task status tracking (pending, running, completed, failed)
  - Progress monitoring (0-100%)
  - Result storage and retrieval
  - Task metadata and error handling

**Data Models**:
- `TaskInfo` - Task metadata and status
- `TaskStatus` - Status enumeration
- `TaskType` - Analysis type classification

### 8. Graph Integration
Each analysis type includes dedicated Neo4j integration:
- `_save_amass_to_neo4j()` - Domain/subdomain/provider relationships
- `_save_services_to_neo4j()` - Service nodes and relationships
- `_save_dns_to_neo4j()` - DNS record storage
- `_save_mx_to_neo4j()` - Email configuration storage
- `_save_tls_to_neo4j()` - Certificate information
- `_save_tech_to_neo4j()` - Technology stack data

## API Endpoints

### Discovery Operations
- `POST /api/v1/discover/amass/{domain}` - Start Amass subdomain discovery
- `POST /api/v1/discover/services/{domain}` - Service discovery (domain or subdomain)
- `POST /api/v1/discover/dns/{domain}` - DNS analysis (domain or subdomain)
- `POST /api/v1/discover/mx/{domain}` - MX/email security analysis (domain only)
- `POST /api/v1/discover/tls/{domain}` - TLS certificate analysis (domain or subdomain)
- `POST /api/v1/discover/tech/{domain}` - Web technology detection (domain or subdomain)

### Batch Operations
- `POST /api/v1/discover/all-subdomains/{domain}` - Analyze all subdomains with specified analysis type

### Task Management
- `GET /api/v1/tasks` - List all tasks
- `GET /api/v1/tasks/{task_id}` - Get task status and results
- `DELETE /api/v1/tasks/{task_id}` - Delete completed task

### System
- `GET /health` - Health check
- `GET /docs` - Swagger/OpenAPI documentation

## Configuration

### Environment Variables
```bash
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASS=tsunami123
REDIS_HOST=localhost
REDIS_PORT=6379
```

### Dependencies
- FastAPI for web framework
- Redis for caching
- Neo4j for graph database
- Docker for Amass execution
- DNS libraries for resolution
- SSL/TLS libraries for certificate analysis

## Usage Flow

1. **Start Amass Discovery**: Creates base subdomain and provider inventory
2. **Run Targeted Analysis**: Execute specific analysis types on discovered assets
3. **Monitor Progress**: Track task status and progress via API
4. **Retrieve Results**: Get detailed results when tasks complete
5. **Graph Exploration**: Query Neo4j for relationships and insights

## Key Improvements Over v5

1. **Asynchronous Operations**: All analysis runs in background with progress tracking
2. **Incremental Updates**: Graph builds progressively rather than batch processing
3. **Intelligent Caching**: Amass results cached to prevent unnecessary re-scanning
4. **Flexible Scope**: Analysis can target base domains or specific subdomains
5. **API-Driven**: RESTful interface for integration with other tools
6. **Task Management**: Complete lifecycle management of analysis operations
7. **Error Resilience**: Individual task failures don't impact other operations

## Performance Considerations

- **Caching Strategy**: 24-hour cache for Amass results significantly reduces scan time
- **Thread Pool**: CPU-intensive operations run in thread pool to prevent blocking
- **Connection Pooling**: Neo4j connections managed efficiently
- **Progress Tracking**: Real-time progress updates for long-running operations
- **Resource Management**: Automatic cleanup of completed tasks and connections

## Security Features

- **Input Validation**: Domain name validation prevents injection attacks
- **Timeout Controls**: Prevents runaway operations from consuming resources
- **Error Handling**: Comprehensive error capture and logging
- **Access Control**: Ready for authentication/authorization layers

This refactored service provides a robust, scalable foundation for comprehensive domain analysis with the flexibility to extend functionality and integrate with larger security platforms.