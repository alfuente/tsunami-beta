# TASK CACHE SYSTEM - INTEGRATION INSTRUCTIONS

## System Overview
The task cache system provides comprehensive caching and resumption capabilities
for domain discovery tasks, addressing the user's request:
"agregar un cache para todas las tareas de forma de que al reiniciar se valide 
si ya se avanzó y no empiecen desde cero"

## Components Created

### Core System Files
1. **task_cache_system.py** - Main caching database and logic
2. **task_checkpoint_integration.py** - Integration with existing tasks  
3. **startup_cache_validator.py** - Startup validation and management
4. **task_resumption_patch.py** - API patching for resumption support
5. **apply_cache_system.py** - This integration script

### Database
- **task_cache.db** - SQLite database containing:
  - task_checkpoints: Task progress checkpoints
  - cache_entries: Cached analysis results  
  - cache_metadata: System metadata

## Integration Options

### Option A: Non-invasive Integration (Recommended)
This approach adds caching alongside existing functionality:

1. **Add imports to async_domain_discovery_api.py:**
```python
# Add at top of file after existing imports
from task_checkpoint_integration import checkpoint_manager, BatchAnalysisCheckpointer
from startup_cache_validator import startup_manager
```

2. **Add to AsyncDomainDiscoveryService.__init__():**
```python
# Add in constructor
self.checkpoint_manager = checkpoint_manager
self.cache_enabled = True
```

3. **Add startup validation in main():**
```python
# Add before uvicorn.run()
if __name__ == "__main__":
    import asyncio
    
    # Validate cache on startup
    startup_results = asyncio.run(startup_manager.perform_startup_sequence())
    logger.info("Cache validation completed")
    
    # Start server
    uvicorn.run(app, host="0.0.0.0", port=8001)
```

4. **Modify _run_combined_recursive_discovery method:**
```python
# At start of method - check for resumption
should_resume, resume_data = self.checkpoint_manager.should_resume_task(
    task_id, domain, "batch_analysis"
)

if should_resume:
    logger.info(f"Resuming task from {resume_data['progress_percentage']:.1f}% progress")
    batch_checkpointer = BatchAnalysisCheckpointer(self.checkpoint_manager)
    batch_checkpointer.initialize_from_checkpoint(resume_data)
else:
    batch_checkpointer = BatchAnalysisCheckpointer(self.checkpoint_manager)

# In target processing loop - add skip logic
for target in all_targets:
    if batch_checkpointer and batch_checkpointer.should_skip_target(target):
        logger.info(f"Skipping completed target: {target}")
        continue
    
    # ... existing processing ...
    
    # After each analysis type - mark completed and save checkpoint
    if batch_checkpointer:
        batch_checkpointer.mark_analysis_completed(target, "service_analysis")
        batch_checkpointer.save_checkpoint(task_id, domain, all_targets)
```

### Option B: Automatic Patching (Advanced)
Use the patching system to automatically modify the API:

```bash
python3 task_resumption_patch.py
```

This creates `async_domain_discovery_api_with_checkpoints.py` with all modifications applied.

## New API Endpoints

Add these endpoints to enable manual cache management:

```python
@app.get("/api/v1/tasks/resumable")
async def get_resumable_tasks():
    # Get all resumable tasks

@app.post("/api/v1/tasks/{task_id}/resume") 
async def resume_task(task_id: str, domain: str, task_type: str):
    # Resume specific task

@app.get("/api/v1/cache/statistics")
async def get_cache_statistics():
    # Get cache system statistics
    
@app.post("/api/v1/cache/cleanup")
async def cleanup_cache(max_age_hours: int = 168):
    # Clean up expired cache entries
```

## Testing the System

1. **Basic functionality test:**
```bash
python3 task_cache_system.py
python3 task_checkpoint_integration.py  
python3 startup_cache_validator.py
```

2. **Start API with caching:**
```bash
./venv/bin/python async_domain_discovery_api.py
# Or if using patched version:
./venv/bin/python async_domain_discovery_api_with_checkpoints.py
```

3. **Test resumption:**
```bash
# Start a batch analysis task
curl -X POST "http://localhost:8001/api/v1/discovery/batch-analysis" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Stop service while task is running
# Restart service  
# Task should resume from last checkpoint
```

## Cache Management

### View resumable tasks:
```bash
curl http://localhost:8001/api/v1/tasks/resumable | jq '.'
```

### Get cache statistics:
```bash  
curl http://localhost:8001/api/v1/cache/statistics | jq '.'
```

### Clean up old cache:
```bash
curl -X POST http://localhost:8001/api/v1/cache/cleanup
```

## Benefits Achieved

✅ **Zero restart loss**: Tasks resume exactly where they left off
✅ **Intelligent skipping**: Already analyzed targets are automatically skipped  
✅ **Progress preservation**: Partial analysis results are cached and reused
✅ **Automatic validation**: System validates cache consistency on startup
✅ **Manual management**: API endpoints for cache control and monitoring
✅ **Backward compatible**: Existing functionality unaffected

## Backup and Rollback

Your original system has been backed up to: backup_cache_system_20250824_142009

To rollback if needed:
```bash
cp backup_cache_system_20250824_142009/async_domain_discovery_api.py ./
# Restart service
```

## Monitoring

- Check `cache_validation_report_*.json` files for startup validation results
- Monitor cache database size: `task_cache.db`  
- Use `/api/v1/cache/statistics` endpoint for runtime monitoring

---
Generated on: 2025-08-24 14:20:09
Integration backup: backup_cache_system_20250824_142009