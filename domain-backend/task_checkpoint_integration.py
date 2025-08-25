#!/usr/bin/env python3
"""
Task Checkpoint Integration - Integrate caching into the main API

This module provides the integration layer between the existing async_domain_discovery_api.py
and the new task cache system, allowing tasks to be resumed from checkpoints.
"""

import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
import logging

# Add the current directory to Python path to import the cache system
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from task_cache_system import (
    TaskCacheSystem, TaskCheckpoint, CacheEntry, CacheEntryType,
    create_task_checkpoint, task_cache
)

logger = logging.getLogger(__name__)

class TaskCheckpointManager:
    """Manages checkpointing integration with existing task system"""
    
    def __init__(self, cache_system: TaskCacheSystem = None):
        self.cache = cache_system or task_cache
        
    def should_resume_task(self, task_id: str, domain: str, task_type: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Check if a task should be resumed from cache.
        Returns (should_resume, resume_data)
        """
        can_resume, checkpoint = self.cache.can_resume_task(task_id, domain, task_type)
        
        if can_resume and checkpoint:
            resume_data = {
                "checkpoint": checkpoint,
                "completed_targets": checkpoint.completed_targets,
                "completed_analysis_types": checkpoint.completed_analysis_types,
                "progress_percentage": checkpoint.progress_percentage,
                "skip_targets": checkpoint.completed_targets,  # Targets to skip
                "resume_from": checkpoint.progress_percentage
            }
            
            logger.info(f"Task {task_id} will resume from {checkpoint.progress_percentage:.1f}% progress")
            logger.info(f"Skipping {len(checkpoint.completed_targets)} already completed targets")
            
            return True, resume_data
        
        return False, None
    
    def save_checkpoint_for_batch_analysis(self, task_id: str, domain: str, 
                                         all_targets: List[str],
                                         completed_targets: List[str],
                                         completed_analysis_per_target: Dict[str, List[str]],
                                         metadata: Dict[str, Any] = None) -> bool:
        """
        Save checkpoint specifically for batch analysis tasks.
        
        Args:
            task_id: Unique task identifier
            domain: Main domain being analyzed
            all_targets: Complete list of targets (domain + subdomains)
            completed_targets: List of fully completed targets
            completed_analysis_per_target: Dict mapping target -> list of completed analysis types
            metadata: Additional metadata
        """
        
        # Reorganize completed_analysis_per_target to analysis_type -> targets format
        completed_analysis_types = {}
        for target, analysis_list in completed_analysis_per_target.items():
            for analysis_type in analysis_list:
                if analysis_type not in completed_analysis_types:
                    completed_analysis_types[analysis_type] = []
                completed_analysis_types[analysis_type].append(target)
        
        checkpoint = create_task_checkpoint(
            task_id=task_id,
            task_type="batch_analysis",
            domain=domain,
            completed_targets=completed_targets,
            completed_analysis_types=completed_analysis_types,
            total_targets=len(all_targets),
            metadata=metadata or {}
        )
        
        success = self.cache.save_checkpoint(checkpoint)
        
        if success:
            logger.debug(f"Batch analysis checkpoint saved: {checkpoint.progress_percentage:.1f}% complete")
        
        return success
    
    def save_checkpoint_for_web_scraping(self, task_id: str, domain: str,
                                       pages_to_scrape: List[str],
                                       completed_pages: List[str],
                                       metadata: Dict[str, Any] = None) -> bool:
        """Save checkpoint for web scraping tasks"""
        
        completed_analysis_types = {
            "web_scraping": completed_pages
        }
        
        checkpoint = create_task_checkpoint(
            task_id=task_id,
            task_type="web_scraping", 
            domain=domain,
            completed_targets=completed_pages,
            completed_analysis_types=completed_analysis_types,
            total_targets=len(pages_to_scrape),
            metadata=metadata or {}
        )
        
        return self.cache.save_checkpoint(checkpoint)
    
    def get_cached_subdomain_results(self, domain: str) -> Optional[List[str]]:
        """Get cached subdomain discovery results"""
        cache_key = f"subdomain_discovery:{domain}:all"
        entry = self.cache.get_cache_entry(cache_key)
        
        if entry and entry.result_data:
            return entry.result_data.get('subdomains', [])
        
        return None
    
    def cache_subdomain_results(self, domain: str, subdomains: List[str],
                              expiry_hours: int = 24) -> bool:
        """Cache subdomain discovery results"""
        result_data = {
            'subdomains': subdomains,
            'count': len(subdomains),
            'discovery_timestamp': datetime.now().isoformat()
        }
        
        return self.cache.cache_analysis_result(
            entry_type=CacheEntryType.SUBDOMAIN_DISCOVERY.value,
            domain=domain,
            target="all",
            result_data=result_data,
            expiry_hours=expiry_hours
        )
    
    def get_cached_analysis_result(self, analysis_type: str, domain: str, target: str) -> Optional[Dict[str, Any]]:
        """Get cached analysis result for specific target and type"""
        return self.cache.get_cached_analysis_result(analysis_type, domain, target)
    
    def cache_analysis_result(self, analysis_type: str, domain: str, target: str,
                            result: Dict[str, Any], expiry_hours: int = 24) -> bool:
        """Cache analysis result for specific target and type"""
        return self.cache.cache_analysis_result(analysis_type, domain, target, result, expiry_hours=expiry_hours)
    
    def get_resume_instructions_for_batch_analysis(self, checkpoint: TaskCheckpoint) -> Dict[str, Any]:
        """
        Generate resume instructions for batch analysis tasks.
        This provides the data needed to resume a batch analysis from where it left off.
        """
        
        instructions = {
            "task_id": checkpoint.task_id,
            "domain": checkpoint.domain, 
            "resume_from_progress": checkpoint.progress_percentage,
            "skip_completed_targets": checkpoint.completed_targets,
            "completed_analysis_types": checkpoint.completed_analysis_types,
            "checkpoint_metadata": checkpoint.metadata,
            "resume_timestamp": datetime.now().isoformat(),
            
            # Instructions for the task executor
            "execution_hints": {
                "skip_subdomain_discovery": len(checkpoint.completed_targets) > 1,  # If we have multiple targets, subdomains were found
                "partial_analysis_per_target": {},  # Will be filled below
                "start_from_target_index": len(checkpoint.completed_targets)
            }
        }
        
        # Build partial analysis map - which analysis types are complete for each target
        for analysis_type, completed_targets in checkpoint.completed_analysis_types.items():
            for target in completed_targets:
                if target not in instructions["execution_hints"]["partial_analysis_per_target"]:
                    instructions["execution_hints"]["partial_analysis_per_target"][target] = []
                instructions["execution_hints"]["partial_analysis_per_target"][target].append(analysis_type)
        
        return instructions
    
    def mark_task_completed(self, task_id: str) -> bool:
        """Mark a task as 100% completed in the cache"""
        checkpoint = self.cache.get_checkpoint(task_id)
        if checkpoint:
            checkpoint.progress_percentage = 100.0
            checkpoint.updated_at = datetime.now()
            return self.cache.save_checkpoint(checkpoint)
        return False
    
    def cleanup_completed_task_cache(self, task_id: str) -> bool:
        """Clean up cache entries for a completed task to save space"""
        # For now, we keep the checkpoint but could add logic to remove
        # individual cache entries if needed
        logger.debug(f"Task {task_id} completed - cache cleanup not implemented yet")
        return True


class BatchAnalysisCheckpointer:
    """Specialized checkpointing for batch analysis tasks"""
    
    def __init__(self, checkpoint_manager: TaskCheckpointManager):
        self.checkpoint_manager = checkpoint_manager
        self.completed_targets = []
        self.completed_analysis_per_target = {}  # target -> [analysis_types]
        
    def initialize_from_checkpoint(self, resume_data: Dict[str, Any]):
        """Initialize from existing checkpoint data"""
        if resume_data:
            self.completed_targets = resume_data.get("completed_targets", [])
            
            # Convert from analysis_type -> targets format to target -> analysis_types
            completed_analysis_types = resume_data.get("completed_analysis_types", {})
            self.completed_analysis_per_target = {}
            
            for analysis_type, targets in completed_analysis_types.items():
                for target in targets:
                    if target not in self.completed_analysis_per_target:
                        self.completed_analysis_per_target[target] = []
                    self.completed_analysis_per_target[target].append(analysis_type)
    
    def should_skip_target(self, target: str) -> bool:
        """Check if a target should be completely skipped"""
        return target in self.completed_targets
    
    def should_skip_analysis_for_target(self, target: str, analysis_type: str) -> bool:
        """Check if specific analysis should be skipped for a target"""
        if target in self.completed_analysis_per_target:
            return analysis_type in self.completed_analysis_per_target[target]
        return False
    
    def mark_analysis_completed(self, target: str, analysis_type: str):
        """Mark a specific analysis as completed for a target"""
        if target not in self.completed_analysis_per_target:
            self.completed_analysis_per_target[target] = []
        
        if analysis_type not in self.completed_analysis_per_target[target]:
            self.completed_analysis_per_target[target].append(analysis_type)
    
    def mark_target_completed(self, target: str):
        """Mark a target as fully completed"""
        if target not in self.completed_targets:
            self.completed_targets.append(target)
    
    def save_checkpoint(self, task_id: str, domain: str, all_targets: List[str], 
                       metadata: Dict[str, Any] = None) -> bool:
        """Save current checkpoint state"""
        return self.checkpoint_manager.save_checkpoint_for_batch_analysis(
            task_id=task_id,
            domain=domain,
            all_targets=all_targets,
            completed_targets=self.completed_targets,
            completed_analysis_per_target=self.completed_analysis_per_target,
            metadata=metadata
        )

# Global checkpoint manager instance
checkpoint_manager = TaskCheckpointManager()

def get_checkpoint_manager() -> TaskCheckpointManager:
    """Get the global checkpoint manager instance"""
    return checkpoint_manager

if __name__ == "__main__":
    # Test the checkpoint integration
    manager = TaskCheckpointManager()
    
    print("Task Checkpoint Integration Test")
    print("=" * 40)
    
    # Test saving a batch analysis checkpoint
    success = manager.save_checkpoint_for_batch_analysis(
        task_id="test_batch_123",
        domain="example.com",
        all_targets=["example.com", "www.example.com", "api.example.com", "mail.example.com", "admin.example.com"],
        completed_targets=["example.com", "www.example.com"],
        completed_analysis_per_target={
            "example.com": ["service_analysis", "dns_analysis", "mx_analysis"],
            "www.example.com": ["service_analysis", "dns_analysis"],
            "api.example.com": ["service_analysis"]  # Partially completed
        },
        metadata={"test_run": True, "started_at": datetime.now().isoformat()}
    )
    
    print(f"Checkpoint save success: {success}")
    
    # Test resumption check
    should_resume, resume_data = manager.should_resume_task(
        "test_batch_123", "example.com", "batch_analysis"
    )
    
    print(f"Should resume: {should_resume}")
    if should_resume:
        print(f"Resume progress: {resume_data['progress_percentage']:.1f}%")
        print(f"Skip targets: {resume_data['skip_targets']}")
        
        # Test resume instructions
        checkpoint = resume_data["checkpoint"]
        instructions = manager.get_resume_instructions_for_batch_analysis(checkpoint)
        print(f"Resume instructions: {instructions['execution_hints']}")
    
    # Test cache statistics
    print(f"\nCache statistics: {manager.cache.get_cache_statistics()}")