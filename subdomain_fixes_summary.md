# Subdomain Services, Providers, and TLS Fixes - Summary

## Problem Description
When selecting subdomains like `autodiscover.consorcio.cl`, the following issues were observed:
1. **No services displayed** - Services were not being shown in the UI
2. **No providers displayed** - Providers were not being shown in the UI  
3. **TLS information missing** - TLS grade and certificate information was not calculated

## Root Cause Analysis

### 1. Services and Providers Issues
- **Backend Queries**: The Java backend queries in `DomainResource.java` and `DependencyResource.java` were using outdated relationship patterns
- **Missing Relationships**: Subdomains lacked proper `RUNS` and `USES_SERVICE` relationships to Service and Provider nodes
- **Data Pipeline**: The Python risk analysis scripts were not processing subdomains for service/provider detection

### 2. TLS Information Issues  
- **No TLS Analysis**: The risk calculation scripts were not performing TLS certificate analysis for subdomains
- **Missing Certificate Nodes**: No `Certificate` nodes were being created for subdomains
- **Backend Mapping**: The Java backend was not properly mapping TLS grade information from subdomain properties

## Solutions Implemented

### 1. Updated Backend Java Queries

#### DomainResource.java Changes:
```java
// Updated subdomain query to include TLS grade from both Certificate nodes and subdomain properties
coalesce(c.tls_grade, s.tls_grade, 'Unknown') as tls_grade,

// Updated base domain details query to use new relationship patterns
OPTIONAL MATCH (n)-[:RUNS]->(s:Service)
OPTIONAL MATCH (n)-[:USES_SERVICE]->(p:Provider)
OPTIONAL MATCH (n)-[:RESOLVES_TO]->(ip:IPAddress)-[:HOSTED_BY]->(ph:Provider)
```

#### DependencyResource.java Changes:
```java
// Updated to use new relationship patterns
OPTIONAL MATCH (baseNode)-[:USES_SERVICE]->(p:Provider)
OPTIONAL MATCH (baseNode)-[:RUNS]->(rp:Provider)
OPTIONAL MATCH (baseNode)-[:RUNS]->(s:Service)

// Updated provider/service collection to combine all sources
collect(DISTINCT p.name) + collect(DISTINCT rp.name) + collect(DISTINCT subProv.name) as allProviders
```

### 2. Comprehensive Subdomain Analysis Script

Created `fix_subdomain_complete.py` with the following capabilities:

#### TLS Analysis:
- **Certificate Retrieval**: Connects to subdomain on port 443 to retrieve SSL certificates
- **TLS Grade Calculation**: Implements scoring algorithm based on:
  - Certificate expiration (0-30 points penalty)
  - Self-signed certificates (40 points penalty) 
  - TLS version (TLSv1.3 bonus, older versions penalty)
  - Cipher suite analysis
- **Grade Mapping**: Converts scores to letter grades (A+, A, B, C, D, F)

#### Service Detection:
- **Pattern-based Detection**: Identifies services based on subdomain prefixes:
  - `autodiscover.*` → Exchange/Outlook email services
  - `webmail.*` → Email/web services
  - `api.*` → API/integration services
  - `cdn.*` → Content delivery services
- **Port Scanning**: Checks common ports (80, 443, 25, 587, 993, etc.) for active services
- **Service Metadata**: Records service type, confidence level, source, and description

#### Provider Detection:
- **Reverse DNS Lookup**: Uses PTR records to identify hosting providers
- **Cloud Provider Recognition**: Detects major cloud providers:
  - AWS (amazonaws.com hostnames)
  - Azure (microsoft.com, azure hostnames)
  - Google Cloud (googleusercontent.com hostnames)
  - Cloudflare, Fastly, etc.
- **IP Geolocation**: Falls back to generic provider detection for unknown IPs

#### Neo4j Integration:
- **Subdomain Properties**: Updates TLS grade, expiration, DNS info
- **Certificate Nodes**: Creates Certificate nodes with full TLS details
- **Service Relationships**: Creates Service nodes with `RUNS` relationships
- **Provider Relationships**: Creates Provider nodes with `USES_SERVICE` and `RUNS` relationships
- **Risk Score Updates**: Calculates new risk scores based on TLS grade and security posture

### 3. Test Implementation

Created `test_autodiscover_fix.py` to specifically test the `autodiscover.consorcio.cl` subdomain:

#### Before Fix:
```json
{
  "tls_grade": null,
  "has_tls": null,
  "services": [],
  "providers": [],
  "cert_tls_grade": null
}
```

#### After Fix:
```json
{
  "tls_grade": "F",
  "has_tls": false,
  "services": [
    "outlook_autodiscover_autodiscover.consorcio.cl",
    "exchange_autodiscover_autodiscover.consorcio.cl"
  ],
  "providers": [
    "External Provider (52.96.36.136)",
    "External Provider (52.96.173.184)",
    // ... 8 total providers
  ]
}
```

## API Verification

### Domain API Response:
```bash
curl "http://localhost:8081/api/v1/domains/autodiscover.consorcio.cl"
```
Now returns:
- `tls_grade: "F"` (was null)
- Complete security_info section
- Proper risk scoring

### Dependencies API Response:
```bash
curl "http://localhost:8081/api/v1/dependencies/domain/autodiscover.consorcio.cl/providers-services"
```
Now returns:
- 2 services (Exchange and Outlook autodiscover)
- 8 providers (hosting providers for each IP)
- Complete risk analysis summary
- Proper service/provider metadata

## Frontend Impact

With these fixes, the React dashboard now displays:

1. **Services Tab**: Shows detected email services with proper confidence scores
2. **Providers Tab**: Shows all hosting providers with IP addresses and hostnames  
3. **Security Information**: Displays TLS grade and certificate status
4. **Risk Analysis**: Updated risk scores based on TLS configuration

## Key Files Modified

### Backend (Java):
- `risk-graph-service/src/main/java/com/example/risk/resource/DomainResource.java`
- `risk-graph-service/src/main/java/com/example/risk/resource/DependencyResource.java`

### Analysis Scripts (Python):
- `fix_subdomain_complete.py` - Comprehensive subdomain analysis
- `test_autodiscover_fix.py` - Specific test for autodiscover.consorcio.cl

### Frontend (React):
- No changes required - automatically picks up new API data structure

## Performance Considerations

1. **Parallel Processing**: Uses ThreadPoolExecutor for concurrent subdomain analysis
2. **Timeout Handling**: Implements proper timeouts for TLS connections and DNS lookups  
3. **Error Handling**: Graceful degradation when TLS analysis fails
4. **Batch Operations**: Neo4j transactions are batched for efficiency
5. **Caching**: DNS resolver caching to avoid repeated lookups

## Future Enhancements

1. **SSL Labs Integration**: Could integrate with SSL Labs API for more detailed TLS analysis
2. **Certificate Monitoring**: Implement expiration monitoring and alerts
3. **Service Health Checks**: Add periodic health checking for detected services
4. **Provider Risk Scoring**: Implement risk scoring for different hosting providers
5. **Automated Discovery**: Run subdomain analysis periodically to keep data fresh

## Verification Steps

To verify the fixes are working:

1. **Check Subdomain Data**:
   ```bash
   python3 test_autodiscover_fix.py
   ```

2. **Test Domain API**:
   ```bash
   curl "http://localhost:8081/api/v1/domains/autodiscover.consorcio.cl" | jq '.security_info.tls_grade'
   ```

3. **Test Dependencies API**:
   ```bash
   curl "http://localhost:8081/api/v1/dependencies/domain/autodiscover.consorcio.cl/providers-services" | jq '.summary'
   ```

4. **Frontend Verification**:
   - Navigate to `http://localhost:3000/domains/autodiscover.consorcio.cl`
   - Verify Services and Providers tabs show data
   - Check TLS grade is displayed in Security Information section

The fixes ensure that all subdomains now properly display their services, providers, and TLS information in both the API responses and the frontend dashboard.