# UI Database Integration - Task Display Updates

## Changes Made

### 🔧 **Backend API Updates (`async_domain_discovery_api.py`)**

#### New Database Query Functions
- `get_all_tasks_from_db(limit, status_filter)` - Retrieves tasks from PostgreSQL with filtering
- `get_task_from_db(task_id)` - Gets specific task by ID from database

#### Updated API Endpoints
1. **GET /api/v1/tasks**
   - Now queries PostgreSQL database instead of in-memory tasks
   - Added `limit` parameter (default: 100)
   - Added `status` filter parameter (pending, running, completed, failed)
   - Returns tasks ordered by creation date (newest first)

2. **GET /api/v1/tasks/{task_id}**
   - First checks in-memory tasks (for running tasks)
   - Falls back to database lookup for completed/failed tasks
   - Ensures hybrid approach for current and historical tasks

3. **GET /api/v1/tasks/{task_id}/logs**
   - Supports both in-memory and database task logs
   - Returns formatted logs for database tasks

### 🎨 **Frontend UI Updates (`risk-dashboard/src/`)**

#### API Configuration (`services/api.ts`)
- Updated `ASYNC_API_URL` from `localhost:8001` to `localhost:8081`
- Now points to the domain-backend service instead of separate async API

#### Task Monitor Component (`pages/TasksMonitor.tsx`)
- Added new task type display names:
  - `combined_discovery` → "Combined Discovery" 
  - `combined_recursive` → "Combined Recursive Analysis"
  - `risk_calculation` → "Risk Calculation"
  - `risk_tree_calculation` → "Risk Tree Calculation"
  - `full_analysis` → "Full Analysis"
- Enhanced task type formatting with fallback logic

## 📊 **Database Schema**

The tasks are stored in the `async_tasks` table with the following structure:
```sql
CREATE TABLE async_tasks (
    task_id VARCHAR(255) PRIMARY KEY,
    task_type VARCHAR(50) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    subdomain VARCHAR(255),
    status VARCHAR(20) NOT NULL,
    progress INTEGER DEFAULT 0,
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    metadata JSONB,
    logs TEXT,
    error TEXT,
    result JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 🚀 **Testing**

### Test Scripts Available:
1. `test_task_endpoints.py` - Tests the updated database-backed endpoints
2. `test_combined_endpoints.py` - Tests the new combined discovery methods

### Manual Testing:
1. Start the domain-backend API:
   ```bash
   cd domain-backend
   ./venv/bin/python async_domain_discovery_api.py
   ```

2. Start the React dashboard:
   ```bash
   cd risk-dashboard
   npm start
   ```

3. Navigate to the "Tasks Monitor" page to see database tasks

## 🔍 **Benefits**

1. **Persistent Task History**: Tasks are now stored permanently in PostgreSQL
2. **Better Performance**: Database queries are optimized with indexes
3. **Filtering Capabilities**: UI can filter tasks by status
4. **Scalability**: No memory limitations for task storage
5. **Reliability**: Tasks survive server restarts
6. **Audit Trail**: Complete history of all analysis tasks

## 📝 **API Usage Examples**

```bash
# Get all tasks
curl http://localhost:8081/api/v1/tasks

# Get only running tasks
curl "http://localhost:8081/api/v1/tasks?status=running"

# Get limited number of tasks
curl "http://localhost:8081/api/v1/tasks?limit=10"

# Get specific task
curl http://localhost:8081/api/v1/tasks/{task_id}

# Get task logs
curl http://localhost:8081/api/v1/tasks/{task_id}/logs
```

## 🎯 **Next Steps**

The UI is now configured to display tasks from the PostgreSQL database. Users can:
- View all historical tasks (not just currently running ones)
- Filter tasks by status
- See detailed task information and logs
- Monitor real-time progress of running tasks

The system maintains backward compatibility while providing enhanced functionality through database storage.