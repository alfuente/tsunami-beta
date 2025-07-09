# Enhanced Risk Graph Loader

This enhanced implementation provides proper TLD/subdomain distinction, timestamp tracking, and graph-based queue management to replace the SQLite dependency.

## Key Improvements

### 1. Proper TLD/Subdomain Distinction
- **TLD nodes**: Represent top-level domains (e.g., ".cl", ".com")
- **Domain nodes**: Represent actual domains (e.g., "bci.cl", "google.com")
- **Subdomain nodes**: Represent subdomains (e.g., "www.bci.cl", "api.bci.cl")

### 2. Parallel Processing with Multiple Threads
- **Multi-threaded domain processing**: Configurable worker threads (default: 4)
- **Parallel Amass execution**: Concurrent subdomain discovery (default: 2 workers)
- **Thread-safe operations**: Safe concurrent graph updates
- **Auto-detection**: Automatically chooses optimal processing mode
- **Performance monitoring**: Real-time progress tracking and statistics

### 3. Enhanced Graph Model
```
TLD ----[:CONTAINS_DOMAIN]----> Domain ----[:HAS_SUBDOMAIN]----> Subdomain
 |                                 |                                 |
 |                                 |                                 |
 v                                 v                                 v
"cl"                          "bci.cl"                        "www.bci.cl"
```

### 3. Timestamp Tracking
- `last_analyzed`: When the domain/subdomain was last analyzed
- `last_risk_scoring`: When risk scoring was last performed
- Enables automatic stale node discovery

### 4. Graph-based Queue Management
- No more SQLite dependency
- Query-based node discovery for maintenance
- Automatic identification of stale nodes

### 5. Enhanced Provider Discovery
- Configurable depth to ensure provider relationships are discovered
- Automatic depth expansion if providers are not found
- Better provider association with domains and subdomains

## Files

### Core Implementation
- `risk_loader_improved.py` - Enhanced domain processing with new model
- `migrate_to_enhanced_model.py` - Migration script for existing graphs
- `update_stale_nodes.py` - Graph-based stale node management

### Backend Updates
- `main.py` - Updated API with new endpoints
- `GraphQueries.java` - Updated Java queries for new model

### Testing
- `test_enhanced_implementation.py` - Comprehensive test suite

## Usage

### 1. Migration (First Time Setup)
```bash
# Migrate existing graph to enhanced model
python3 migrate_to_enhanced_model.py --password YOUR_PASSWORD

# Validate migration
python3 migrate_to_enhanced_model.py --password YOUR_PASSWORD --validate-only
```

### 2. Domain Processing

#### Sequential Processing (Legacy Mode)
```bash
python3 risk_loader_improved.py \
  --domains domains.txt \
  --sequential \
  --depth 2 \
  --max-depth 4 \
  --password YOUR_PASSWORD \
  --ipinfo-token YOUR_TOKEN
```

#### Parallel Processing (Recommended)
```bash
# Auto-detect mode (chooses best option based on domain count)
python3 risk_loader_improved.py \
  --domains domains.txt \
  --depth 2 \
  --max-depth 4 \
  --workers 4 \
  --password YOUR_PASSWORD \
  --ipinfo-token YOUR_TOKEN

# Force parallel processing
python3 risk_loader_improved.py \
  --domains domains.txt \
  --parallel \
  --workers 6 \
  --depth 2 \
  --max-depth 4 \
  --password YOUR_PASSWORD \
  --ipinfo-token YOUR_TOKEN

# Parallel with parallel Amass (fastest for many domains)
python3 risk_loader_improved.py \
  --domains domains.txt \
  --parallel-amass \
  --workers 8 \
  --amass-workers 4 \
  --depth 2 \
  --max-depth 4 \
  --password YOUR_PASSWORD \
  --ipinfo-token YOUR_TOKEN
```

#### Stale Node Management
```bash
# Update stale nodes (replaces SQLite queue)
python3 update_stale_nodes.py \
  --password YOUR_PASSWORD \
  --analysis-days 7 \
  --risk-days 7
```

### 3. Stale Node Management
```bash
# Show graph statistics
python3 update_stale_nodes.py --password YOUR_PASSWORD --stats-only

# Update analysis for stale nodes
python3 update_stale_nodes.py --password YOUR_PASSWORD --analysis-only

# Update risk scoring for stale nodes
python3 update_stale_nodes.py --password YOUR_PASSWORD --risk-only

# Ensure provider discovery
python3 update_stale_nodes.py --password YOUR_PASSWORD --providers-only
```

### 4. API Usage
```bash
# Start the API server
uvicorn main:app --host 0.0.0.0 --port 8000
```

#### New API Endpoints

**Migration Task**
```json
POST /tasks/migration
{
  "validate_only": false,
  "bolt": "bolt://localhost:7687",
  "user": "neo4j",
  "password": "test"
}
```

**Stale Node Update Task**
```json
POST /tasks/stale-update
{
  "analysis_days": 7,
  "risk_days": 7,
  "depth": 2,
  "max_depth": 4,
  "stats_only": false,
  "ipinfo_token": "YOUR_TOKEN",
  "bolt": "bolt://localhost:7687",
  "user": "neo4j",
  "password": "test"
}
```

**Enhanced Bulk Load**
```json
POST /tasks/bulk
{
  "domains": ["bci.cl", "google.com"],
  "depth": 2,
  "max_depth": 4,
  "ipinfo_token": "YOUR_TOKEN",
  "bolt": "bolt://localhost:7687",
  "user": "neo4j",
  "password": "test"
}
```

## Configuration

### Environment Variables
```bash
export LOADER_SCRIPT="/path/to/risk_loader_improved.py"
export STALE_UPDATER_SCRIPT="/path/to/update_stale_nodes.py"
export IPINFO_TOKEN="your_ipinfo_token"
```

### Neo4j Configuration
The enhanced model creates these constraints:
- `tld_name` - Unique constraint on TLD names
- `domain_fqdn` - Unique constraint on Domain FQDNs
- `subdomain_fqdn` - Unique constraint on Subdomain FQDNs

## Graph Queries

### Find Stale Nodes
```cypher
// Domains not analyzed in 7 days
MATCH (d:Domain)
WHERE d.last_analyzed IS NULL OR d.last_analyzed < datetime() - duration({days: 7})
RETURN d.fqdn ORDER BY coalesce(d.last_analyzed, '1970-01-01')

// Subdomains not analyzed in 7 days
MATCH (s:Subdomain)
WHERE s.last_analyzed IS NULL OR s.last_analyzed < datetime() - duration({days: 7})
RETURN s.fqdn ORDER BY coalesce(s.last_analyzed, '1970-01-01')
```

### Find Nodes Without Providers
```cypher
MATCH (n) WHERE (n:Domain OR n:Subdomain)
AND NOT EXISTS((n)-[:RESOLVES_TO]->(:IPAddress)-[:HOSTED_BY]->(:Service))
RETURN n.fqdn ORDER BY n.fqdn
```

### Domain Hierarchy
```cypher
// Get all subdomains for a domain
MATCH (d:Domain {fqdn: 'bci.cl'})-[:HAS_SUBDOMAIN]->(s:Subdomain)
RETURN s.fqdn

// Get parent domain for a subdomain
MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain {fqdn: 'www.bci.cl'})
RETURN d.fqdn
```

### Graph Statistics
```cypher
// Count by node type
MATCH (t:TLD) RETURN 'TLD' as type, COUNT(t) as count
UNION
MATCH (d:Domain) RETURN 'Domain' as type, COUNT(d) as count
UNION
MATCH (s:Subdomain) RETURN 'Subdomain' as type, COUNT(s) as count
```

## Problem Resolution

### Issue: TLD Parsing
**Problem**: Using `fqdn.split('.')[-1]` incorrectly treats last part as TLD
**Solution**: Enhanced implementation uses `tldextract` library for proper TLD extraction

### Issue: No Domain/Subdomain Distinction
**Problem**: All domains treated the same, no hierarchy
**Solution**: Separate node types (TLD, Domain, Subdomain) with proper relationships

### Issue: No Timestamp Tracking
**Problem**: No way to identify stale nodes
**Solution**: Added `last_analyzed` and `last_risk_scoring` timestamps

### Issue: SQLite Queue Dependency
**Problem**: External SQLite database for queue management
**Solution**: Graph-based queries to identify nodes needing processing

### Issue: Insufficient Provider Discovery
**Problem**: depth=2 may not reach providers
**Solution**: Configurable `max_depth` with automatic expansion if providers not found

## Troubleshooting

### Common Issues

1. **Migration Fails**
   - Check Neo4j connection
   - Verify existing data structure
   - Use `--validate-only` to check current state

2. **Stale Node Discovery Returns No Results**
   - Check if timestamps exist: `MATCH (n:Domain) RETURN n.last_analyzed LIMIT 5`
   - Run migration if timestamps are missing

3. **Provider Discovery Issues**
   - Increase `max_depth` parameter
   - Check IPInfo token validity
   - Verify IP resolution is working

4. **API Endpoint Failures**
   - Check script paths in environment variables
   - Verify Neo4j credentials in requests
   - Check logs for specific errors

### Testing
```bash
# Run comprehensive test suite
python3 test_enhanced_implementation.py

# Test specific components
python3 -c "from risk_loader_improved import DomainInfo; print(DomainInfo.from_fqdn('www.bci.cl'))"
```

## Migration Path

1. **Backup Current Graph**
   ```bash
   # Use your backup script
   ./scripts/neo4j-backup.sh
   ```

2. **Run Migration**
   ```bash
   python3 migrate_to_enhanced_model.py --password YOUR_PASSWORD
   ```

3. **Validate Migration**
   ```bash
   python3 migrate_to_enhanced_model.py --password YOUR_PASSWORD --validate-only
   ```

4. **Update Application**
   - Deploy updated API (`main.py`)
   - Update Java services with new queries
   - Switch to new loader script

5. **Schedule Maintenance**
   ```bash
   # Add to cron for regular stale node updates
   0 2 * * * /path/to/update_stale_nodes.py --password YOUR_PASSWORD
   ```

## Benefits

1. **Proper Domain Structure**: Clear distinction between TLDs, domains, and subdomains
2. **Automatic Maintenance**: Graph-based discovery of stale nodes
3. **No External Dependencies**: Eliminated SQLite queue system
4. **Better Provider Discovery**: Configurable depth ensures providers are found
5. **Timestamp Tracking**: Enables smart maintenance and updates
6. **Backward Compatibility**: Migration preserves existing data

This enhanced implementation solves the core issues identified in the original request while maintaining compatibility with existing systems.