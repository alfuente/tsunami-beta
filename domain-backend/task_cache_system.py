#!/usr/bin/env python3
"""
Task Cache System - Comprehensive caching and resumption for domain discovery tasks

This system ensures that when the API restarts, tasks can resume from their last
checkpoint rather than starting from zero, addressing the user's specific request:
"agregar un cache para todas las tareas de forma de que al reiniciar se valide 
si ya se avanzó y no empiecen desde cero"
"""

import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from dataclasses import dataclass, asdict
import hashlib
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TaskType(Enum):
    BATCH_ANALYSIS = "batch_analysis"
    WEB_SCRAPING = "web_scraping"
    DNS_ANALYSIS = "dns_analysis"
    SERVICE_DISCOVERY = "service_discovery"

class CacheEntryType(Enum):
    SUBDOMAIN_DISCOVERY = "subdomain_discovery"
    SERVICE_ANALYSIS = "service_analysis"
    DNS_ANALYSIS = "dns_analysis"
    MX_ANALYSIS = "mx_analysis"
    TLS_ANALYSIS = "tls_analysis"
    TECH_ANALYSIS = "tech_analysis"
    WEB_SCRAPING = "web_scraping"

@dataclass
class TaskCheckpoint:
    """Represents a checkpoint in task execution"""
    task_id: str
    checkpoint_id: str
    task_type: str
    domain: str
    completed_targets: List[str]  # List of completed subdomains/targets
    completed_analysis_types: Dict[str, List[str]]  # type -> list of completed targets
    total_targets: int
    progress_percentage: float
    metadata: Dict[str, Any]
    created_at: datetime
    updated_at: datetime

@dataclass
class CacheEntry:
    """Represents a cached analysis result for a specific target"""
    cache_key: str
    entry_type: str  # CacheEntryType
    domain: str
    target: str  # subdomain or specific target
    result_data: Dict[str, Any]
    analysis_timestamp: datetime
    expiry_hours: int = 24  # How long the cache entry is valid

class TaskCacheSystem:
    """Main cache system for task management and resumption"""
    
    def __init__(self, cache_db_path: str = "task_cache.db"):
        self.cache_db_path = cache_db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize cache database with required tables"""
        conn = sqlite3.connect(self.cache_db_path)
        cursor = conn.cursor()
        
        # Task checkpoints table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS task_checkpoints (
                task_id TEXT PRIMARY KEY,
                checkpoint_id TEXT,
                task_type TEXT,
                domain TEXT,
                completed_targets TEXT,  -- JSON array
                completed_analysis_types TEXT,  -- JSON object
                total_targets INTEGER,
                progress_percentage REAL,
                metadata TEXT,  -- JSON object
                created_at TEXT,
                updated_at TEXT
            )
        """)
        
        # Cache entries table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cache_entries (
                cache_key TEXT PRIMARY KEY,
                entry_type TEXT,
                domain TEXT,
                target TEXT,
                result_data TEXT,  -- JSON object
                analysis_timestamp TEXT,
                expiry_hours INTEGER
            )
        """)
        
        # Create indexes separately
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cache_domain ON cache_entries(domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cache_target ON cache_entries(target)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cache_type ON cache_entries(entry_type)")
        
        # Cache metadata table for system information
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cache_metadata (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT
            )
        """)
        
        conn.commit()
        conn.close()
        logger.info(f"Initialized task cache database: {self.cache_db_path}")
    
    def _generate_cache_key(self, entry_type: str, domain: str, target: str, analysis_params: Dict = None) -> str:
        """Generate unique cache key for analysis results"""
        base_key = f"{entry_type}:{domain}:{target}"
        if analysis_params:
            params_str = json.dumps(analysis_params, sort_keys=True)
            base_key += f":{hashlib.md5(params_str.encode()).hexdigest()[:8]}"
        return base_key
    
    def save_checkpoint(self, checkpoint: TaskCheckpoint) -> bool:
        """Save task checkpoint to database"""
        try:
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO task_checkpoints 
                (task_id, checkpoint_id, task_type, domain, completed_targets,
                 completed_analysis_types, total_targets, progress_percentage,
                 metadata, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                checkpoint.task_id,
                checkpoint.checkpoint_id,
                checkpoint.task_type,
                checkpoint.domain,
                json.dumps(checkpoint.completed_targets),
                json.dumps(checkpoint.completed_analysis_types),
                checkpoint.total_targets,
                checkpoint.progress_percentage,
                json.dumps(checkpoint.metadata),
                checkpoint.created_at.isoformat(),
                checkpoint.updated_at.isoformat()
            ))
            
            conn.commit()
            conn.close()
            
            logger.debug(f"Saved checkpoint for task {checkpoint.task_id}: {checkpoint.progress_percentage:.1f}%")
            return True
            
        except Exception as e:
            logger.error(f"Error saving checkpoint for {checkpoint.task_id}: {e}")
            return False
    
    def get_checkpoint(self, task_id: str) -> Optional[TaskCheckpoint]:
        """Retrieve task checkpoint from database"""
        try:
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT task_id, checkpoint_id, task_type, domain, completed_targets,
                       completed_analysis_types, total_targets, progress_percentage,
                       metadata, created_at, updated_at
                FROM task_checkpoints WHERE task_id = ?
            """, (task_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return TaskCheckpoint(
                    task_id=row[0],
                    checkpoint_id=row[1],
                    task_type=row[2],
                    domain=row[3],
                    completed_targets=json.loads(row[4]) if row[4] else [],
                    completed_analysis_types=json.loads(row[5]) if row[5] else {},
                    total_targets=row[6],
                    progress_percentage=row[7],
                    metadata=json.loads(row[8]) if row[8] else {},
                    created_at=datetime.fromisoformat(row[9]),
                    updated_at=datetime.fromisoformat(row[10])
                )
            return None
            
        except Exception as e:
            logger.error(f"Error getting checkpoint for {task_id}: {e}")
            return None
    
    def save_cache_entry(self, entry: CacheEntry) -> bool:
        """Save analysis result to cache"""
        try:
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO cache_entries
                (cache_key, entry_type, domain, target, result_data,
                 analysis_timestamp, expiry_hours)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                entry.cache_key,
                entry.entry_type,
                entry.domain,
                entry.target,
                json.dumps(entry.result_data),
                entry.analysis_timestamp.isoformat(),
                entry.expiry_hours
            ))
            
            conn.commit()
            conn.close()
            
            logger.debug(f"Cached {entry.entry_type} result for {entry.target}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving cache entry {entry.cache_key}: {e}")
            return False
    
    def get_cache_entry(self, cache_key: str) -> Optional[CacheEntry]:
        """Retrieve cached analysis result"""
        try:
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT cache_key, entry_type, domain, target, result_data,
                       analysis_timestamp, expiry_hours
                FROM cache_entries WHERE cache_key = ?
            """, (cache_key,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                entry = CacheEntry(
                    cache_key=row[0],
                    entry_type=row[1],
                    domain=row[2],
                    target=row[3],
                    result_data=json.loads(row[4]) if row[4] else {},
                    analysis_timestamp=datetime.fromisoformat(row[5]),
                    expiry_hours=row[6]
                )
                
                # Check if entry is still valid
                if self._is_cache_entry_valid(entry):
                    return entry
                else:
                    # Entry expired, remove it
                    self._remove_cache_entry(cache_key)
                    
            return None
            
        except Exception as e:
            logger.error(f"Error getting cache entry {cache_key}: {e}")
            return None
    
    def _is_cache_entry_valid(self, entry: CacheEntry) -> bool:
        """Check if cache entry is still valid"""
        expiry_time = entry.analysis_timestamp + timedelta(hours=entry.expiry_hours)
        return datetime.now() < expiry_time
    
    def _remove_cache_entry(self, cache_key: str):
        """Remove expired cache entry"""
        try:
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cache_entries WHERE cache_key = ?", (cache_key,))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error removing cache entry {cache_key}: {e}")
    
    def can_resume_task(self, task_id: str, domain: str, task_type: str) -> Tuple[bool, Optional[TaskCheckpoint]]:
        """Check if a task can be resumed from cache"""
        checkpoint = self.get_checkpoint(task_id)
        
        if not checkpoint:
            return False, None
        
        # Verify the checkpoint matches the current task parameters
        if checkpoint.domain != domain or checkpoint.task_type != task_type:
            logger.warning(f"Checkpoint mismatch for task {task_id}")
            return False, None
        
        # Check if checkpoint is recent (within last 7 days)
        age_hours = (datetime.now() - checkpoint.updated_at).total_seconds() / 3600
        if age_hours > 168:  # 7 days
            logger.info(f"Checkpoint too old for task {task_id} ({age_hours:.1f}h)")
            return False, None
        
        # Check if we have meaningful progress (at least 10%)
        if checkpoint.progress_percentage < 10:
            return False, None
        
        logger.info(f"Task {task_id} can resume from {checkpoint.progress_percentage:.1f}% progress")
        return True, checkpoint
    
    def get_cached_analysis_result(self, entry_type: str, domain: str, target: str, 
                                 analysis_params: Dict = None) -> Optional[Dict[str, Any]]:
        """Get cached analysis result for specific target"""
        cache_key = self._generate_cache_key(entry_type, domain, target, analysis_params)
        entry = self.get_cache_entry(cache_key)
        return entry.result_data if entry else None
    
    def cache_analysis_result(self, entry_type: str, domain: str, target: str,
                            result_data: Dict[str, Any], analysis_params: Dict = None,
                            expiry_hours: int = 24) -> bool:
        """Cache analysis result for specific target"""
        cache_key = self._generate_cache_key(entry_type, domain, target, analysis_params)
        
        entry = CacheEntry(
            cache_key=cache_key,
            entry_type=entry_type,
            domain=domain,
            target=target,
            result_data=result_data,
            analysis_timestamp=datetime.now(),
            expiry_hours=expiry_hours
        )
        
        return self.save_cache_entry(entry)
    
    def get_resumable_tasks(self) -> List[Dict[str, Any]]:
        """Get all tasks that can potentially be resumed"""
        try:
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT task_id, domain, task_type, progress_percentage, updated_at
                FROM task_checkpoints 
                WHERE progress_percentage > 10 AND progress_percentage < 100
                ORDER BY updated_at DESC
            """)
            
            rows = cursor.fetchall()
            conn.close()
            
            resumable = []
            for row in rows:
                updated_at = datetime.fromisoformat(row[4])
                age_hours = (datetime.now() - updated_at).total_seconds() / 3600
                
                if age_hours <= 168:  # Within last 7 days
                    resumable.append({
                        "task_id": row[0],
                        "domain": row[1],
                        "task_type": row[2],
                        "progress_percentage": row[3],
                        "updated_at": row[4],
                        "age_hours": age_hours
                    })
            
            return resumable
            
        except Exception as e:
            logger.error(f"Error getting resumable tasks: {e}")
            return []
    
    def cleanup_expired_cache(self, max_age_hours: int = 168) -> int:
        """Clean up expired cache entries and old checkpoints"""
        try:
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()
            
            cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
            cutoff_str = cutoff_time.isoformat()
            
            # Clean expired cache entries
            cursor.execute("""
                DELETE FROM cache_entries 
                WHERE datetime(analysis_timestamp) < datetime(?)
            """, (cutoff_str,))
            
            cache_deleted = cursor.rowcount
            
            # Clean old checkpoints
            cursor.execute("""
                DELETE FROM task_checkpoints 
                WHERE datetime(updated_at) < datetime(?)
            """, (cutoff_str,))
            
            checkpoints_deleted = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            total_deleted = cache_deleted + checkpoints_deleted
            if total_deleted > 0:
                logger.info(f"Cleaned up {cache_deleted} cache entries and {checkpoints_deleted} checkpoints")
            
            return total_deleted
            
        except Exception as e:
            logger.error(f"Error cleaning up cache: {e}")
            return 0
    
    def get_cache_statistics(self) -> Dict[str, Any]:
        """Get cache system statistics"""
        try:
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()
            
            # Count cache entries by type
            cursor.execute("""
                SELECT entry_type, COUNT(*) 
                FROM cache_entries 
                GROUP BY entry_type
            """)
            cache_by_type = dict(cursor.fetchall())
            
            # Count total cache entries
            cursor.execute("SELECT COUNT(*) FROM cache_entries")
            total_cache_entries = cursor.fetchone()[0]
            
            # Count checkpoints
            cursor.execute("SELECT COUNT(*) FROM task_checkpoints")
            total_checkpoints = cursor.fetchone()[0]
            
            # Count resumable tasks
            cursor.execute("""
                SELECT COUNT(*) FROM task_checkpoints 
                WHERE progress_percentage > 10 AND progress_percentage < 100
            """)
            resumable_tasks = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                "total_cache_entries": total_cache_entries,
                "cache_entries_by_type": cache_by_type,
                "total_checkpoints": total_checkpoints,
                "resumable_tasks": resumable_tasks,
                "cache_db_path": self.cache_db_path,
                "cache_db_size_mb": round(os.path.getsize(self.cache_db_path) / (1024*1024), 2) if os.path.exists(self.cache_db_path) else 0
            }
            
        except Exception as e:
            logger.error(f"Error getting cache statistics: {e}")
            return {}

# Global cache system instance
task_cache = TaskCacheSystem()

def create_task_checkpoint(task_id: str, task_type: str, domain: str,
                          completed_targets: List[str], 
                          completed_analysis_types: Dict[str, List[str]],
                          total_targets: int, 
                          metadata: Dict[str, Any] = None) -> TaskCheckpoint:
    """Helper function to create a task checkpoint"""
    progress = (len(completed_targets) / total_targets * 100) if total_targets > 0 else 0
    
    return TaskCheckpoint(
        task_id=task_id,
        checkpoint_id=f"{task_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        task_type=task_type,
        domain=domain,
        completed_targets=completed_targets,
        completed_analysis_types=completed_analysis_types,
        total_targets=total_targets,
        progress_percentage=progress,
        metadata=metadata or {},
        created_at=datetime.now(),
        updated_at=datetime.now()
    )

if __name__ == "__main__":
    # Test the cache system
    cache = TaskCacheSystem()
    
    # Example usage
    print("Task Cache System initialized")
    print(f"Cache statistics: {cache.get_cache_statistics()}")
    
    # Example checkpoint
    checkpoint = create_task_checkpoint(
        task_id="test_123",
        task_type="batch_analysis", 
        domain="example.com",
        completed_targets=["example.com", "www.example.com"],
        completed_analysis_types={
            "service_analysis": ["example.com"],
            "dns_analysis": ["example.com", "www.example.com"]
        },
        total_targets=5,
        metadata={"test": True}
    )
    
    cache.save_checkpoint(checkpoint)
    print(f"Saved test checkpoint with {checkpoint.progress_percentage:.1f}% progress")
    
    # Test resumability
    can_resume, saved_checkpoint = cache.can_resume_task("test_123", "example.com", "batch_analysis")
    print(f"Can resume: {can_resume}")
    if can_resume and saved_checkpoint:
        print(f"Resumable progress: {saved_checkpoint.progress_percentage:.1f}%")