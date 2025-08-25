#!/usr/bin/env python3
"""
Task Resumption Patch - Modifications to integrate caching into existing API

This script creates patches for the async_domain_discovery_api.py to add
checkpoint-based task resumption without breaking existing functionality.
"""

import os
import shutil
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TaskResumptionPatcher:
    """Patches the main API to add task resumption capabilities"""
    
    def __init__(self, api_file_path: str = "async_domain_discovery_api.py"):
        self.api_file_path = api_file_path
        self.backup_file_path = f"{api_file_path}.checkpoint_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
    def create_backup(self) -> bool:
        """Create backup of the original API file"""
        try:
            if os.path.exists(self.api_file_path):
                shutil.copy2(self.api_file_path, self.backup_file_path)
                logger.info(f"Created backup: {self.backup_file_path}")
                return True
            else:
                logger.error(f"Original API file not found: {self.api_file_path}")
                return False
        except Exception as e:
            logger.error(f"Error creating backup: {e}")
            return False
    
    def get_checkpoint_imports(self) -> str:
        """Get the import statements needed for checkpointing"""
        return """
# Task Checkpoint System Imports
try:
    from task_checkpoint_integration import (
        TaskCheckpointManager, BatchAnalysisCheckpointer, 
        checkpoint_manager, get_checkpoint_manager
    )
    CHECKPOINT_SYSTEM_AVAILABLE = True
    logger.info("Task checkpoint system loaded successfully")
except ImportError as e:
    CHECKPOINT_SYSTEM_AVAILABLE = False
    logger.warning(f"Task checkpoint system not available: {e}")
"""
    
    def get_checkpoint_initialization(self) -> str:
        """Get code to initialize checkpoint system in the service"""
        return """
        # Initialize checkpoint system
        self.checkpoint_system_enabled = CHECKPOINT_SYSTEM_AVAILABLE
        if self.checkpoint_system_enabled:
            self.checkpoint_manager = get_checkpoint_manager()
            logger.info("Checkpoint system initialized")
        else:
            self.checkpoint_manager = None
            logger.info("Running without checkpoint system")
"""
    
    def get_task_resumption_check(self) -> str:
        """Get code to check for task resumption at task start"""
        return """
        # Check if task can be resumed from checkpoint
        resume_data = None
        if self.checkpoint_system_enabled and self.checkpoint_manager:
            should_resume, resume_data = self.checkpoint_manager.should_resume_task(
                task_id, domain, task_type
            )
            if should_resume:
                logger.info(f"Resuming task {task_id} from {resume_data['progress_percentage']:.1f}% progress")
                task_info.progress = int(resume_data['progress_percentage'])
                # Update task logs
                resume_log = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Task resumed from checkpoint ({resume_data['progress_percentage']:.1f}%)\\n"
                task_info.logs = getattr(task_info, 'logs', '') + resume_log
                self._update_task_status(task_info)
"""
    
    def get_batch_analysis_resumption(self) -> str:
        """Get code to modify batch analysis for resumption"""
        return """
        # Initialize checkpoint system for batch analysis
        batch_checkpointer = None
        resume_from_checkpoint = False
        
        if self.checkpoint_system_enabled and self.checkpoint_manager and resume_data:
            batch_checkpointer = BatchAnalysisCheckpointer(self.checkpoint_manager)
            batch_checkpointer.initialize_from_checkpoint(resume_data)
            resume_from_checkpoint = True
            
            logger.info(f"Batch analysis resuming with {len(resume_data.get('completed_targets', []))} completed targets")
        elif self.checkpoint_system_enabled and self.checkpoint_manager:
            batch_checkpointer = BatchAnalysisCheckpointer(self.checkpoint_manager)
            logger.info("Batch analysis starting fresh with checkpoint system")
"""
    
    def get_target_processing_logic(self) -> str:
        """Get code to modify target processing loop"""
        return """
            # Check if target should be skipped (already completed)
            if batch_checkpointer and batch_checkpointer.should_skip_target(target):
                logger.info(f"Skipping already completed target: {target}")
                continue
            
            logger.info(f"Processing target: {target}")
            target_start_time = datetime.now()
"""
    
    def get_analysis_skip_logic(self) -> str:
        """Get code to check if individual analysis should be skipped"""
        return """
                # Check if this analysis type should be skipped for this target
                if batch_checkpointer and batch_checkpointer.should_skip_analysis_for_target(target, "{analysis_type}"):
                    logger.debug(f"Skipping {analysis_type} analysis for {target} (already completed)")
                    continue
"""
    
    def get_checkpoint_save_logic(self) -> str:
        """Get code to save checkpoints during processing"""
        return """
                    # Mark analysis as completed and save checkpoint
                    if batch_checkpointer:
                        batch_checkpointer.mark_analysis_completed(target, "{analysis_type}")
                        
                        # Save checkpoint every few completed analyses
                        if len(batch_checkpointer.completed_analysis_per_target.get(target, [])) % 2 == 0:
                            batch_checkpointer.save_checkpoint(task_id, domain, all_targets, {
                                "last_checkpoint": datetime.now().isoformat(),
                                "current_target": target,
                                "completed_analysis": "{analysis_type}"
                            })
"""
    
    def get_target_completion_logic(self) -> str:
        """Get code to mark targets as completed"""
        return """
            # Mark target as fully completed
            if batch_checkpointer:
                batch_checkpointer.mark_target_completed(target)
                
                # Save checkpoint after each completed target
                checkpoint_saved = batch_checkpointer.save_checkpoint(task_id, domain, all_targets, {
                    "last_completed_target": target,
                    "completed_at": datetime.now().isoformat(),
                    "targets_remaining": len([t for t in all_targets if not batch_checkpointer.should_skip_target(t)])
                })
                
                if checkpoint_saved:
                    logger.debug(f"Checkpoint saved after completing target: {target}")
"""
    
    def get_task_completion_logic(self) -> str:
        """Get code to handle final task completion"""
        return """
        # Mark task as fully completed in checkpoint system
        if self.checkpoint_system_enabled and self.checkpoint_manager:
            self.checkpoint_manager.mark_task_completed(task_id)
            self.checkpoint_manager.cleanup_completed_task_cache(task_id)
            logger.info(f"Task {task_id} marked as completed in checkpoint system")
"""
    
    def apply_patches(self) -> bool:
        """Apply all patches to the API file"""
        try:
            # Read original file
            with open(self.api_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Apply patches in order
            content = self._patch_imports(content)
            content = self._patch_service_initialization(content)
            content = self._patch_task_start_method(content)
            content = self._patch_batch_analysis_method(content)
            
            # Write patched file
            patched_file = self.api_file_path.replace('.py', '_with_checkpoints.py')
            with open(patched_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logger.info(f"Created patched API file: {patched_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error applying patches: {e}")
            return False
    
    def _patch_imports(self, content: str) -> str:
        """Add checkpoint imports to the file"""
        import_location = content.find("import logging")
        if import_location != -1:
            # Insert after the logging import
            lines = content.split('\\n')
            for i, line in enumerate(lines):
                if "import logging" in line:
                    lines.insert(i + 1, self.get_checkpoint_imports())
                    break
            content = '\\n'.join(lines)
        
        return content
    
    def _patch_service_initialization(self, content: str) -> str:
        """Add checkpoint system initialization"""
        # Find the __init__ method of AsyncDomainDiscoveryService
        init_pattern = "def __init__(self):"
        if init_pattern in content:
            content = content.replace(
                init_pattern + "\\n        self.active_tasks: Dict[str, TaskInfo] = {}",
                init_pattern + "\\n        self.active_tasks: Dict[str, TaskInfo] = {}" + 
                self.get_checkpoint_initialization()
            )
        
        return content
    
    def _patch_task_start_method(self, content: str) -> str:
        """Add resumption check to task start"""
        # Find where tasks are started and add resumption check
        pattern = "task_info = TaskInfo("
        if pattern in content:
            # Add resumption logic after TaskInfo creation
            lines = content.split('\\n')
            for i, line in enumerate(lines):
                if pattern in line:
                    # Find the end of TaskInfo creation (look for next non-indented line or specific pattern)
                    j = i + 1
                    while j < len(lines) and (lines[j].startswith('            ') or lines[j].strip() == ''):
                        j += 1
                    
                    # Insert resumption check
                    resumption_lines = self.get_task_resumption_check().split('\\n')
                    for k, resume_line in enumerate(resumption_lines):
                        lines.insert(j + k, resume_line)
                    break
            
            content = '\\n'.join(lines)
        
        return content
    
    def _patch_batch_analysis_method(self, content: str) -> str:
        """Add checkpoint logic to batch analysis method"""
        # Find the start of _run_combined_recursive_discovery method
        method_pattern = "async def _run_combined_recursive_discovery"
        if method_pattern in content:
            lines = content.split('\\n')
            
            # Find method start and add checkpoint initialization
            for i, line in enumerate(lines):
                if method_pattern in line:
                    # Add checkpoint setup after the method declaration and initial setup
                    # Look for the first query to Neo4j (subdomains query)
                    for j in range(i, min(i + 50, len(lines))):
                        if "MATCH (d:Domain)" in lines[j] and "subdomains" in lines[j]:
                            # Insert checkpoint initialization before subdomain query
                            checkpoint_lines = self.get_batch_analysis_resumption().split('\\n')
                            for k, checkpoint_line in enumerate(checkpoint_lines):
                                lines.insert(j + k, checkpoint_line)
                            break
                    break
            
            content = '\\n'.join(lines)
        
        return content

def create_resumption_endpoints() -> str:
    """Create new API endpoints for task resumption management"""
    return '''

# ========== TASK RESUMPTION ENDPOINTS ==========

@app.get("/api/v1/tasks/resumable")
async def get_resumable_tasks():
    """Get all tasks that can be resumed"""
    try:
        if not hasattr(discovery_service, 'checkpoint_system_enabled') or not discovery_service.checkpoint_system_enabled:
            return {"message": "Checkpoint system not available", "resumable_tasks": []}
        
        resumable = discovery_service.checkpoint_manager.cache.get_resumable_tasks()
        return {
            "resumable_tasks": resumable,
            "count": len(resumable),
            "checkpoint_system_enabled": True
        }
        
    except Exception as e:
        logger.error(f"Error getting resumable tasks: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/tasks/{task_id}/resume")
async def resume_task(task_id: str, domain: str, task_type: str):
    """Resume a specific task from checkpoint"""
    try:
        if not hasattr(discovery_service, 'checkpoint_system_enabled') or not discovery_service.checkpoint_system_enabled:
            raise HTTPException(status_code=503, detail="Checkpoint system not available")
        
        # Check if task can be resumed
        should_resume, resume_data = discovery_service.checkpoint_manager.should_resume_task(
            task_id, domain, task_type
        )
        
        if not should_resume:
            raise HTTPException(status_code=400, detail="Task cannot be resumed")
        
        # Check if task is already running
        if task_id in discovery_service.active_tasks:
            raise HTTPException(status_code=409, detail="Task is already running")
        
        # Start the task (it will automatically resume from checkpoint)
        if task_type == "batch_analysis":
            task = asyncio.create_task(
                discovery_service._run_combined_recursive_discovery(task_id, domain)
            )
            discovery_service.active_tasks[task_id] = task
        elif task_type == "web_scraping":
            # Add web scraping resumption if needed
            raise HTTPException(status_code=501, detail="Web scraping resumption not implemented yet")
        else:
            raise HTTPException(status_code=400, detail=f"Unknown task type: {task_type}")
        
        return {
            "success": True,
            "task_id": task_id,
            "resumed_from_progress": resume_data["progress_percentage"],
            "message": f"Task resumed from {resume_data['progress_percentage']:.1f}% progress"
        }
        
    except Exception as e:
        logger.error(f"Error resuming task {task_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/cache/statistics")
async def get_cache_statistics():
    """Get cache system statistics"""
    try:
        if not hasattr(discovery_service, 'checkpoint_system_enabled') or not discovery_service.checkpoint_system_enabled:
            return {"message": "Checkpoint system not available", "statistics": {}}
        
        stats = discovery_service.checkpoint_manager.cache.get_cache_statistics()
        return {
            "cache_statistics": stats,
            "checkpoint_system_enabled": True
        }
        
    except Exception as e:
        logger.error(f"Error getting cache statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/cache/cleanup")
async def cleanup_cache(max_age_hours: int = 168):
    """Clean up expired cache entries"""
    try:
        if not hasattr(discovery_service, 'checkpoint_system_enabled') or not discovery_service.checkpoint_system_enabled:
            raise HTTPException(status_code=503, detail="Checkpoint system not available")
        
        deleted_count = discovery_service.checkpoint_manager.cache.cleanup_expired_cache(max_age_hours)
        return {
            "success": True,
            "deleted_entries": deleted_count,
            "max_age_hours": max_age_hours
        }
        
    except Exception as e:
        logger.error(f"Error cleaning up cache: {e}")
        raise HTTPException(status_code=500, detail=str(e))

'''

def main():
    """Main function to create the resumption patch"""
    logger.info("🔧 CREATING TASK RESUMPTION PATCH")
    logger.info("=" * 50)
    
    # Create patcher
    patcher = TaskResumptionPatcher()
    
    # Create backup
    if patcher.create_backup():
        logger.info("✅ Original file backed up")
    else:
        logger.error("❌ Failed to create backup")
        return False
    
    # Apply patches
    if patcher.apply_patches():
        logger.info("✅ Patches applied successfully")
        
        # Create endpoint additions file
        with open("resumption_endpoints.py", "w") as f:
            f.write(create_resumption_endpoints())
        
        logger.info("✅ Created resumption endpoints file")
        logger.info("🎉 TASK RESUMPTION PATCH COMPLETED!")
        logger.info("=" * 50)
        logger.info("📋 CREATED FILES:")
        logger.info(f"✅ {patcher.backup_file_path} - Original backup")
        logger.info(f"✅ async_domain_discovery_api_with_checkpoints.py - Patched API")
        logger.info("✅ resumption_endpoints.py - New API endpoints")
        
        logger.info("🚀 USAGE:")
        logger.info("1. Replace the original API file with the patched version")
        logger.info("2. Add the resumption endpoints to your API")
        logger.info("3. Restart the service to enable checkpoint system")
        
        return True
    else:
        logger.error("❌ Failed to apply patches")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)