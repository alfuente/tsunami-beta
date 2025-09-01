"""
Task Manager for Risk Analysis async operations
"""

import asyncio
import logging
import uuid
import json
from datetime import datetime
from typing import Dict, Optional, Any, List
from contextlib import contextmanager
import psycopg2
import psycopg2.extras

from task_models import RiskTaskInfo, RiskTaskStatus, RiskTaskType

logger = logging.getLogger(__name__)

class RiskTaskManager:
    """Manages async risk analysis tasks with PostgreSQL persistence"""
    
    def __init__(self, db_config: Dict[str, Any]):
        self.db_config = db_config
        self.active_tasks: Dict[str, RiskTaskInfo] = {}
        self._init_task_db()
        self._load_tasks_from_db()
    
    @contextmanager
    def _get_db_connection(self):
        """Get PostgreSQL connection with context management"""
        conn = None
        try:
            conn = psycopg2.connect(
                host=self.db_config['host'],
                port=self.db_config['port'],
                database=self.db_config['database'],
                user=self.db_config['user'],
                password=self.db_config['password']
            )
            yield conn
        finally:
            if conn:
                conn.close()
    
    def _init_task_db(self):
        """Initialize PostgreSQL database for risk analysis tasks"""
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS risk_analysis_tasks (
                            task_id VARCHAR(255) PRIMARY KEY,
                            task_type VARCHAR(100) NOT NULL,
                            parameters JSONB DEFAULT '{}',
                            status VARCHAR(50) DEFAULT 'pending',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            started_at TIMESTAMP,
                            completed_at TIMESTAMP,
                            progress INTEGER DEFAULT 0,
                            logs TEXT DEFAULT '',
                            error TEXT,
                            result JSONB,
                            execution_time REAL
                        );
                        
                        CREATE INDEX IF NOT EXISTS idx_risk_tasks_status ON risk_analysis_tasks(status);
                        CREATE INDEX IF NOT EXISTS idx_risk_tasks_type ON risk_analysis_tasks(task_type);
                        CREATE INDEX IF NOT EXISTS idx_risk_tasks_created ON risk_analysis_tasks(created_at DESC);
                    """)
                    conn.commit()
                    logger.info("Risk analysis tasks database initialized")
        except Exception as e:
            logger.error(f"Failed to initialize task database: {e}")
            raise
    
    def _load_tasks_from_db(self):
        """Load existing tasks from PostgreSQL database"""
        try:
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                    cur.execute("""
                        SELECT * FROM risk_analysis_tasks 
                        WHERE status IN ('pending', 'running')
                        ORDER BY created_at DESC
                    """)
                    
                    for row in cur.fetchall():
                        task_info = RiskTaskInfo(
                            task_id=row['task_id'],
                            task_type=RiskTaskType(row['task_type']),
                            parameters=row['parameters'] or {},
                            status=RiskTaskStatus(row['status']),
                            created_at=row['created_at'],
                            started_at=row['started_at'],
                            completed_at=row['completed_at'],
                            progress=row['progress'] or 0,
                            logs=row['logs'] or "",
                            error=row['error'],
                            result=row['result'],
                            execution_time=row['execution_time']
                        )
                        self.active_tasks[task_info.task_id] = task_info
                        
                    logger.info(f"Loaded {len(self.active_tasks)} active risk analysis tasks from database")
        except Exception as e:
            logger.error(f"Error loading tasks from database: {e}")
    
    def _save_task_to_db(self, task_info: RiskTaskInfo):
        """Save task to PostgreSQL database"""
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO risk_analysis_tasks 
                        (task_id, task_type, parameters, status, created_at, started_at, 
                         completed_at, progress, logs, error, result, execution_time)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (task_id) DO UPDATE SET
                            task_type = EXCLUDED.task_type,
                            parameters = EXCLUDED.parameters,
                            status = EXCLUDED.status,
                            started_at = EXCLUDED.started_at,
                            completed_at = EXCLUDED.completed_at,
                            progress = EXCLUDED.progress,
                            logs = EXCLUDED.logs,
                            error = EXCLUDED.error,
                            result = EXCLUDED.result,
                            execution_time = EXCLUDED.execution_time
                    """, (
                        task_info.task_id,
                        task_info.task_type.value,
                        json.dumps(task_info.parameters, default=str) if task_info.parameters else '{}',
                        task_info.status.value,
                        task_info.created_at,
                        task_info.started_at,
                        task_info.completed_at,
                        task_info.progress,
                        task_info.logs,
                        task_info.error,
                        json.dumps(task_info.result, default=str) if task_info.result else None,
                        task_info.execution_time
                    ))
                    conn.commit()
        except Exception as e:
            logger.error(f"Error saving task to database: {e}")
            if task_info.result:
                logger.error(f"Task result preview: {str(task_info.result)[:500]}...")
    
    def create_task(self, task_type: RiskTaskType, parameters: Dict[str, Any]) -> str:
        """Create a new risk analysis task"""
        task_id = str(uuid.uuid4())
        
        task_info = RiskTaskInfo(
            task_id=task_id,
            task_type=task_type,
            parameters=parameters,
            status=RiskTaskStatus.PENDING,
            created_at=datetime.now()
        )
        
        self.active_tasks[task_id] = task_info
        self._save_task_to_db(task_info)
        
        logger.info(f"Created risk analysis task {task_id} of type {task_type.value}")
        return task_id
    
    def update_task_status(self, task_id: str, status: RiskTaskStatus, 
                          started_at: Optional[datetime] = None,
                          completed_at: Optional[datetime] = None,
                          error: Optional[str] = None, 
                          result: Optional[Dict[str, Any]] = None, 
                          progress: Optional[int] = None,
                          execution_time: Optional[float] = None):
        """Update task status and automatically save to database"""
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            task.status = status
            
            if started_at:
                task.started_at = started_at
            if completed_at:
                task.completed_at = completed_at
            if error:
                task.error = error
            if result:
                task.result = result
            if progress is not None:
                task.progress = progress
            if execution_time is not None:
                task.execution_time = execution_time
            
            self._save_task_to_db(task)
            logger.debug(f"Updated risk analysis task {task_id} with status {status}")
    
    def add_task_log(self, task_id: str, log_message: str):
        """Add log message to task"""
        if task_id in self.active_tasks:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            new_log = f"[{timestamp}] {log_message}\n"
            self.active_tasks[task_id].logs += new_log
            
            self._save_task_to_db(self.active_tasks[task_id])
    
    def get_task(self, task_id: str) -> Optional[RiskTaskInfo]:
        """Get task by ID from memory or database"""
        # First check active tasks
        if task_id in self.active_tasks:
            return self.active_tasks[task_id]
        
        # Check database
        return self.get_task_from_db(task_id)
    
    def get_task_from_db(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get specific task from database"""
        try:
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                    cur.execute("""
                        SELECT * FROM risk_analysis_tasks 
                        WHERE task_id = %s
                    """, (task_id,))
                    
                    row = cur.fetchone()
                    if row:
                        return {
                            'task_id': row['task_id'],
                            'task_type': row['task_type'],
                            'parameters': row['parameters'] or {},
                            'status': row['status'],
                            'created_at': row['created_at'].isoformat() if row['created_at'] else None,
                            'started_at': row['started_at'].isoformat() if row['started_at'] else None,
                            'completed_at': row['completed_at'].isoformat() if row['completed_at'] else None,
                            'progress': row['progress'] or 0,
                            'logs': row['logs'] or "",
                            'error': row['error'],
                            'result': row['result'],
                            'execution_time': row['execution_time']
                        }
                    return None
        except Exception as e:
            logger.error(f"Error fetching task {task_id} from database: {e}")
            return None
    
    def get_all_tasks(self, limit: int = 1000, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all tasks from database with optional status filter"""
        try:
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                    if status_filter:
                        cur.execute("""
                            SELECT * FROM risk_analysis_tasks 
                            WHERE status = %s
                            ORDER BY created_at DESC 
                            LIMIT %s
                        """, (status_filter, limit))
                    else:
                        cur.execute("""
                            SELECT * FROM risk_analysis_tasks 
                            ORDER BY created_at DESC 
                            LIMIT %s
                        """, (limit,))
                    
                    tasks = []
                    for row in cur.fetchall():
                        tasks.append({
                            'task_id': row['task_id'],
                            'task_type': row['task_type'],
                            'parameters': row['parameters'] or {},
                            'status': row['status'],
                            'created_at': row['created_at'].isoformat() if row['created_at'] else None,
                            'started_at': row['started_at'].isoformat() if row['started_at'] else None,
                            'completed_at': row['completed_at'].isoformat() if row['completed_at'] else None,
                            'progress': row['progress'] or 0,
                            'logs': row['logs'] or "",
                            'error': row['error'],
                            'result': row['result'],
                            'execution_time': row['execution_time']
                        })
                    
                    return tasks
        except Exception as e:
            logger.error(f"Error fetching tasks from database: {e}")
            return []
    
    def cleanup_completed_tasks(self, days_old: int = 7):
        """Clean up old completed tasks"""
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        DELETE FROM risk_analysis_tasks 
                        WHERE status IN ('completed', 'failed') 
                        AND completed_at < NOW() - INTERVAL '%s days'
                    """, (days_old,))
                    
                    deleted_count = cur.rowcount
                    conn.commit()
                    logger.info(f"Cleaned up {deleted_count} old risk analysis tasks")
                    return deleted_count
        except Exception as e:
            logger.error(f"Error cleaning up tasks: {e}")
            return 0