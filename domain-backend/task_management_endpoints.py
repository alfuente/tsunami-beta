#!/usr/bin/env python3
"""
Task Management API Endpoints

New endpoints for manual task management and monitoring:
- PATCH /api/v1/tasks/{task_id} - Update task status manually
- POST /api/v1/tasks/{task_id}/force-complete - Force complete a stuck task
- GET /api/v1/tasks/stuck - Get information about stuck tasks
- POST /api/v1/tasks/health-check - Run manual health check
- GET /api/v1/tasks/statistics - Get task system statistics
"""

from fastapi import APIRouter, HTTPException, Path, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Pydantic models for request/response
class TaskStatusUpdate(BaseModel):
    status: str = Field(..., description="New task status (pending, running, completed, failed)")
    progress: Optional[int] = Field(None, ge=0, le=100, description="Task progress percentage")
    completed_at: Optional[datetime] = Field(None, description="Task completion timestamp")
    error: Optional[str] = Field(None, description="Error message if task failed")

class TaskHealthResponse(BaseModel):
    health_check_completed: bool
    stuck_tasks_found: int
    fixed_tasks: List[str]
    timestamp: datetime

class StuckTaskInfo(BaseModel):
    task_id: str
    domain: str
    task_type: str
    progress: int
    duration_hours: float
    started_at: str
    appears_complete: bool
    last_log_entry: Optional[str]

class TaskStatistics(BaseModel):
    total_active_tasks: int
    running_tasks: int
    completed_tasks: int
    failed_tasks: int
    stuck_tasks: int
    average_completion_time_hours: float
    oldest_running_task_hours: float

def create_task_management_router(discovery_service):
    """Create router with task management endpoints"""
    router = APIRouter(prefix="/api/v1/tasks", tags=["Task Management"])
    
    @router.patch("/{task_id}")
    async def update_task_status(
        task_id: str = Path(..., description="Task ID to update"),
        update_data: TaskStatusUpdate = None
    ):
        """
        Manually update task status and progress
        
        Useful for fixing stuck tasks or correcting task states
        """
        try:
            if not hasattr(discovery_service, 'improvements'):
                raise HTTPException(
                    status_code=503,
                    detail="Task improvements not available. Service needs to be updated."
                )
            
            if task_id not in discovery_service.active_tasks:
                raise HTTPException(
                    status_code=404,
                    detail=f"Task {task_id} not found in active tasks"
                )
            
            # Validate status
            valid_statuses = ['pending', 'running', 'completed', 'failed', 'partial']
            if update_data.status not in valid_statuses:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid status. Must be one of: {valid_statuses}"
                )
            
            # Update task
            success = discovery_service.update_task_status_manual(
                task_id=task_id,
                status=update_data.status,
                progress=update_data.progress
            )
            
            if not success:
                raise HTTPException(
                    status_code=500,
                    detail="Failed to update task status"
                )
            
            # Get updated task info
            updated_task = discovery_service.active_tasks[task_id]
            
            return {
                "success": True,
                "task_id": task_id,
                "updated_status": updated_task.status.value,
                "updated_progress": updated_task.progress,
                "message": f"Task {task_id} updated successfully",
                "timestamp": datetime.now().isoformat()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error updating task {task_id}: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @router.post("/{task_id}/force-complete")
    async def force_complete_task(
        task_id: str = Path(..., description="Task ID to force complete")
    ):
        """
        Force complete a stuck task
        
        This endpoint will mark a task as completed even if it appears stuck.
        Use with caution - only for tasks that have clearly finished their work.
        """
        try:
            if not hasattr(discovery_service, 'improvements'):
                raise HTTPException(
                    status_code=503,
                    detail="Task improvements not available. Service needs to be updated."
                )
            
            if task_id not in discovery_service.active_tasks:
                raise HTTPException(
                    status_code=404,
                    detail=f"Task {task_id} not found in active tasks"
                )
            
            task = discovery_service.active_tasks[task_id]
            
            # Check if task is eligible for force completion
            if task.status.value == 'completed':
                return {
                    "success": False,
                    "message": "Task is already completed",
                    "current_status": task.status.value
                }
            
            # Force complete the task
            success = discovery_service.force_complete_task_by_id(task_id)
            
            if not success:
                raise HTTPException(
                    status_code=500,
                    detail="Failed to force complete task"
                )
            
            return {
                "success": True,
                "task_id": task_id,
                "message": f"Task {task_id} force completed successfully",
                "completed_at": datetime.now().isoformat()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error force completing task {task_id}: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @router.get("/stuck")
    async def get_stuck_tasks():
        """
        Get information about tasks that appear to be stuck
        
        Returns tasks that have been running at 90%+ progress for an extended period
        """
        try:
            if not hasattr(discovery_service, 'improvements'):
                raise HTTPException(
                    status_code=503,
                    detail="Task improvements not available. Service needs to be updated."
                )
            
            stuck_tasks = discovery_service.get_stuck_tasks_info()
            
            return {
                "stuck_tasks": stuck_tasks,
                "count": len(stuck_tasks),
                "timestamp": datetime.now().isoformat(),
                "threshold_hours": discovery_service.improvements.stuck_task_threshold_hours
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error getting stuck tasks: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @router.post("/health-check")
    async def run_health_check():
        """
        Run manual health check to detect and fix stuck tasks
        
        This will automatically fix tasks that are clearly stuck and completed
        """
        try:
            if not hasattr(discovery_service, 'improvements'):
                raise HTTPException(
                    status_code=503,
                    detail="Task improvements not available. Service needs to be updated."
                )
            
            fixed_tasks = discovery_service.detect_and_fix_stuck_tasks()
            
            return TaskHealthResponse(
                health_check_completed=True,
                stuck_tasks_found=len(fixed_tasks),
                fixed_tasks=fixed_tasks,
                timestamp=datetime.now()
            )
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error running health check: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @router.get("/statistics")
    async def get_task_statistics():
        """
        Get comprehensive task system statistics
        """
        try:
            active_tasks = discovery_service.active_tasks
            current_time = datetime.now()
            
            # Calculate statistics
            total_active = len(active_tasks)
            running_count = sum(1 for t in active_tasks.values() if t.status.value == 'running')
            completed_count = sum(1 for t in active_tasks.values() if t.status.value == 'completed')
            failed_count = sum(1 for t in active_tasks.values() if t.status.value == 'failed')
            
            # Calculate stuck tasks
            stuck_count = 0
            running_durations = []
            
            for task in active_tasks.values():
                if task.status.value == 'running':
                    duration = (current_time - task.started_at).total_seconds() / 3600
                    running_durations.append(duration)
                    
                    if task.progress >= 90 and duration > 2:
                        stuck_count += 1
            
            avg_completion_time = sum(running_durations) / len(running_durations) if running_durations else 0
            oldest_running = max(running_durations) if running_durations else 0
            
            return TaskStatistics(
                total_active_tasks=total_active,
                running_tasks=running_count,
                completed_tasks=completed_count,
                failed_tasks=failed_count,
                stuck_tasks=stuck_count,
                average_completion_time_hours=round(avg_completion_time, 2),
                oldest_running_task_hours=round(oldest_running, 2)
            )
            
        except Exception as e:
            logger.error(f"Error getting task statistics: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @router.delete("/{task_id}")
    async def cancel_task(
        task_id: str = Path(..., description="Task ID to cancel"),
        force: bool = Query(False, description="Force cancel even if task is running")
    ):
        """
        Cancel a running task
        
        This will stop a task and mark it as failed. Use force=true for stuck tasks.
        """
        try:
            if task_id not in discovery_service.active_tasks:
                raise HTTPException(
                    status_code=404,
                    detail=f"Task {task_id} not found in active tasks"
                )
            
            task = discovery_service.active_tasks[task_id]
            
            # Check if task can be cancelled
            if task.status.value == 'completed' and not force:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot cancel completed task. Use force=true to override."
                )
            
            # Cancel the task
            task.status = discovery_service.TaskStatus.FAILED
            task.error = f"Task cancelled manually at {datetime.now().isoformat()}"
            task.completed_at = datetime.now()
            
            # Add cancellation log
            cancel_log = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Task cancelled manually\\n"
            task.logs += cancel_log
            
            # Save to database if improvements available
            if hasattr(discovery_service, 'improvements'):
                discovery_service.improvements._save_task_to_db_robust(task)
            
            return {
                "success": True,
                "task_id": task_id,
                "message": f"Task {task_id} cancelled successfully",
                "cancelled_at": datetime.now().isoformat()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error cancelling task {task_id}: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    return router