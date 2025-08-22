# Amass Cache Integration for Domain-Backend

## Overview

This implementation decouples the execution of amass from domain-backend by providing:

1. **Standalone Amass Executor**: A bash script that can run amass independently and store results in the domain-backend cache format
2. **Cache-First Domain Backend**: Modified domain-backend that always checks the cache before executing amass
3. **Configurable Cache Duration**: Cache duration can be configured as a parameter

## Components

### 1. Standalone Amass Executor (`standalone_amass_executor.sh`)

A bash script that:
- Executes amass with the same parameters as domain-backend
- Stores results in the exact cache format used by domain-backend
- Can be run on different servers independently
- Supports cache validation and expiration
- Provides comprehensive logging and error handling

**Usage:**
```bash
# Basic usage
./standalone_amass_executor.sh example.com

# With custom timeout and active mode
./standalone_amass_executor.sh -t 600 -m active example.com

# Force rescan (ignore cache)
./standalone_amass_executor.sh --force example.com

# Custom cache directory
./standalone_amass_executor.sh -c /path/to/cache example.com
```

**Environment Variables:**
- `AMASS_CACHE_DIR`: Override default cache directory
- `AMASS_BINARY_PATH`: Override amass binary path
- `CACHE_DURATION_HOURS`: Cache duration in hours (default: 168 = 1 week)

### 2. Modified Domain-Backend

Enhanced `subdomain_relationship_discovery_unified.py` with:

#### New ProcessingConfig Parameters:
```python
@dataclass
class ProcessingConfig:
    # ... existing parameters ...
    
    # Cache options
    amass_cache_duration_hours: int = 168  # 1 week default
    amass_cache_dir: str = "./amass_cache"
    enable_cache_check: bool = True
```

#### New Methods:
- `_generate_cache_hash(domain)`: Generate cache key for domain
- `_check_amass_cache(domain)`: Check if valid cached results exist
- Modified `_run_amass(domain)`: Cache-first execution with fallback

#### Cache Logic:
1. Check if valid cache exists for domain
2. If cache is valid and not expired, return cached results
3. If cache is invalid/expired, execute amass (using standalone script if available)
4. Store results in cache for future use

### 3. API Enhancements

Enhanced `subdomain_discovery_api.py` with:

#### New Configuration Parameters:
```python
class APIConfig(BaseModel):
    # ... existing parameters ...
    amass_cache_dir: str = "./amass_cache"
    amass_cache_duration_hours: int = 168  # 1 week default
```

#### New Cache Management Endpoints:

- `GET /api/v1/cache/stats` - Get cache statistics
- `DELETE /api/v1/cache/clear` - Clear all cache entries  
- `DELETE /api/v1/cache/{domain}` - Clear cache for specific domain
- `POST /api/v1/cache/cleanup` - Clean up expired cache entries

## Cache Format

The cache uses the existing domain-backend format:

### Directory Structure:
```
amass_cache/
├── cache_stats.json          # Cache statistics
├── metadata/                 # Metadata files
│   └── {hash}.json          # Domain metadata
└── data/                     # Compressed data files
    └── {hash}.json.gz       # Subdomain lists (gzipped JSON)
```

### Metadata Format:
```json
{
  "domain": "example.com",
  "timestamp": "2025-08-21T10:30:00",
  "mode": "passive",
  "timeout": 300,
  "amass_version": "4.2.0",
  "config_hash": "1ec28f3f",
  "subdomain_count": 42,
  "cache_version": "1.0"
}
```

### Data Format:
```json
[
  "subdomain1.example.com",
  "subdomain2.example.com",
  "subdomain3.example.com"
]
```

## Usage Scenarios

### Scenario 1: Distributed Execution

1. **Server A**: Run standalone executor for multiple domains
```bash
# Run amass for multiple domains on Server A
./standalone_amass_executor.sh -t 600 domain1.com
./standalone_amass_executor.sh -t 600 domain2.com
./standalone_amass_executor.sh -t 600 domain3.com
```

2. **Server B**: Copy cache and use domain-backend
```bash
# Copy cache from Server A
rsync -av serverA:/path/to/amass_cache/ ./amass_cache/

# Run domain-backend - will use cached results
python subdomain_relationship_discovery_unified.py domain1.com
```

### Scenario 2: Scheduled Cache Updates

```bash
#!/bin/bash
# scheduled_amass_update.sh

DOMAINS_FILE="domains.txt"
CACHE_DIR="/shared/amass_cache"

# Set cache duration to 7 days
export CACHE_DURATION_HOURS=168
export AMASS_CACHE_DIR="$CACHE_DIR"

# Update cache for all domains
while read -r domain; do
    echo "Updating cache for $domain"
    ./standalone_amass_executor.sh -t 600 "$domain"
done < "$DOMAINS_FILE"

# Cleanup expired entries
./standalone_amass_executor.sh --help  # Triggers cleanup
```

### Scenario 3: API Usage with Cache Management

```python
import requests

# Configure cache settings
config_update = {
    "amass_cache_duration_hours": 72,  # 3 days
    "amass_cache_dir": "/shared/cache"
}
requests.post("http://localhost:8000/api/v1/config", json=config_update)

# Run discovery (will check cache first)
response = requests.get("http://localhost:8000/api/v1/discovery/example.com")

# Check cache statistics
stats = requests.get("http://localhost:8000/api/v1/cache/stats").json()
print(f"Cache hits: {stats['hits']}, misses: {stats['misses']}")

# Clean up expired cache
requests.post("http://localhost:8000/api/v1/cache/cleanup")
```

## Configuration

### Command Line Options:

```bash
python subdomain_relationship_discovery_unified.py \
    --cache-dir ./custom_cache \
    --cache-duration 72 \
    --no-cache \
    example.com
```

### Environment Variables:

```bash
export AMASS_CACHE_DIR="/shared/cache"
export CACHE_DURATION_HOURS=168
export AMASS_BINARY_PATH="/usr/local/bin/amass"
```

### API Configuration:

```bash
# Update via API
curl -X POST "http://localhost:8000/api/v1/config" \
    -H "Content-Type: application/json" \
    -d '{
        "amass_cache_dir": "/shared/cache",
        "amass_cache_duration_hours": 72
    }'
```

## Testing

Run the provided test script to verify the implementation:

```bash
python test_amass_cache.py
```

The test script verifies:
- Cache creation and validation
- Cache-first execution logic
- Standalone script functionality
- Cache expiration handling

## Benefits

1. **Decoupled Execution**: Amass can run independently on different servers
2. **Performance**: Cached results eliminate redundant amass executions
3. **Scalability**: Distribute amass workload across multiple servers
4. **Flexibility**: Configurable cache duration per deployment
5. **Compatibility**: Uses existing cache format, no data migration needed
6. **Monitoring**: Cache statistics and management endpoints

## Migration

No migration is required. The implementation:
- Uses existing cache format and structure
- Is backward compatible with existing cached data
- Provides new configuration options with sensible defaults
- Maintains existing API endpoints while adding new cache management endpoints

## Dependencies

### Required Tools:
- `amass` (version 4.2.0 or compatible)
- `jq` (for JSON processing)
- `gzip`/`gunzip` (for compression)
- `sha256sum` (for hash generation)

### Python Dependencies:
- All existing domain-backend dependencies
- No new Python packages required

## Troubleshooting

### Common Issues:

1. **Cache not being used**:
   - Check `enable_cache_check` is `True`
   - Verify cache directory exists and is readable
   - Check cache expiration settings

2. **Standalone script fails**:
   - Verify amass is installed and in PATH
   - Check script permissions (`chmod +x standalone_amass_executor.sh`)
   - Verify all dependencies are installed

3. **Permission errors**:
   - Ensure cache directory is writable
   - Check file permissions on cache files

### Debug Mode:

```bash
# Enable verbose logging in standalone script
./standalone_amass_executor.sh --verbose example.com

# Check cache manually
ls -la amass_cache/metadata/
ls -la amass_cache/data/
```

### Cache Statistics:

```bash
# View cache stats
cat amass_cache/cache_stats.json

# Or via API
curl http://localhost:8000/api/v1/cache/stats
```