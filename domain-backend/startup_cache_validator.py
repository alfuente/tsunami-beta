#!/usr/bin/env python3
"""
Startup Cache Validator - Validates and manages task cache on service startup

This module ensures that when the API service starts, it properly validates
existing cache data and resumes any appropriate tasks automatically.
"""

import os
import sys
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import json

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from task_cache_system import TaskCacheSystem, task_cache
from task_checkpoint_integration import TaskCheckpointManager, checkpoint_manager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class StartupCacheValidator:
    """Handles cache validation and task resumption on service startup"""
    
    def __init__(self, cache_system: TaskCacheSystem = None, checkpoint_manager: TaskCheckpointManager = None):
        self.cache = cache_system or task_cache
        self.checkpoint_manager = checkpoint_manager or globals()['checkpoint_manager']
        self.validation_results = {}
        
    def validate_cache_on_startup(self) -> Dict[str, Any]:
        """
        Comprehensive cache validation on service startup.
        Returns validation results and recommendations.
        """
        logger.info("🔍 Starting cache validation on service startup...")
        
        validation_results = {
            "validation_timestamp": datetime.now().isoformat(),
            "cache_statistics": {},
            "resumable_tasks": [],
            "expired_entries_cleaned": 0,
            "validation_errors": [],
            "recommendations": []
        }
        
        try:
            # Step 1: Get cache statistics
            validation_results["cache_statistics"] = self.cache.get_cache_statistics()
            logger.info(f"Cache contains {validation_results['cache_statistics'].get('total_cache_entries', 0)} entries")
            
            # Step 2: Clean up expired cache entries
            expired_cleaned = self.cache.cleanup_expired_cache(max_age_hours=168)  # 7 days
            validation_results["expired_entries_cleaned"] = expired_cleaned
            
            if expired_cleaned > 0:
                logger.info(f"Cleaned up {expired_cleaned} expired cache entries")
            
            # Step 3: Find resumable tasks
            resumable_tasks = self.cache.get_resumable_tasks()
            validation_results["resumable_tasks"] = resumable_tasks
            
            if resumable_tasks:
                logger.info(f"Found {len(resumable_tasks)} tasks that can be resumed:")
                for task in resumable_tasks:
                    logger.info(f"  - {task['task_id'][:8]}... ({task['domain']}) - {task['progress_percentage']:.1f}% - {task['age_hours']:.1f}h old")
            
            # Step 4: Validate task checkpoint consistency
            self._validate_checkpoint_consistency(validation_results)
            
            # Step 5: Generate recommendations
            self._generate_startup_recommendations(validation_results)
            
            # Step 6: Auto-resume logic (if enabled)
            auto_resumed = self._auto_resume_eligible_tasks(validation_results)
            validation_results["auto_resumed_tasks"] = auto_resumed
            
            logger.info("✅ Cache validation completed successfully")
            self.validation_results = validation_results
            
        except Exception as e:
            logger.error(f"Error during cache validation: {e}")
            validation_results["validation_errors"].append(str(e))
        
        return validation_results
    
    def _validate_checkpoint_consistency(self, validation_results: Dict[str, Any]):
        """Validate that checkpoints are consistent and not corrupted"""
        logger.debug("Validating checkpoint consistency...")
        
        consistency_issues = []
        
        for task in validation_results.get("resumable_tasks", []):
            try:
                task_id = task["task_id"]
                checkpoint = self.cache.get_checkpoint(task_id)
                
                if not checkpoint:
                    consistency_issues.append(f"Task {task_id[:8]}... listed as resumable but no checkpoint found")
                    continue
                
                # Validate checkpoint data integrity
                if not checkpoint.completed_targets or not isinstance(checkpoint.completed_targets, list):
                    consistency_issues.append(f"Task {task_id[:8]}... has invalid completed_targets")
                
                if checkpoint.progress_percentage < 0 or checkpoint.progress_percentage > 100:
                    consistency_issues.append(f"Task {task_id[:8]}... has invalid progress percentage: {checkpoint.progress_percentage}")
                
                if checkpoint.total_targets <= 0:
                    consistency_issues.append(f"Task {task_id[:8]}... has invalid total_targets: {checkpoint.total_targets}")
                
                # Check progress calculation consistency
                expected_progress = (len(checkpoint.completed_targets) / checkpoint.total_targets * 100) if checkpoint.total_targets > 0 else 0
                if abs(checkpoint.progress_percentage - expected_progress) > 5:  # Allow 5% deviation
                    consistency_issues.append(f"Task {task_id[:8]}... progress calculation inconsistent: {checkpoint.progress_percentage:.1f}% vs expected {expected_progress:.1f}%")
                
            except Exception as e:
                consistency_issues.append(f"Error validating task {task.get('task_id', 'unknown')[:8]}...: {e}")
        
        validation_results["consistency_issues"] = consistency_issues
        
        if consistency_issues:
            logger.warning(f"Found {len(consistency_issues)} checkpoint consistency issues:")
            for issue in consistency_issues[:5]:  # Show first 5 issues
                logger.warning(f"  - {issue}")
            if len(consistency_issues) > 5:
                logger.warning(f"  ... and {len(consistency_issues) - 5} more issues")
        else:
            logger.info("✅ All checkpoints are consistent")
    
    def _generate_startup_recommendations(self, validation_results: Dict[str, Any]):
        """Generate recommendations for startup based on cache state"""
        recommendations = []
        
        # Cache size recommendations
        cache_stats = validation_results.get("cache_statistics", {})
        cache_size_mb = cache_stats.get("cache_db_size_mb", 0)
        
        if cache_size_mb > 100:  # More than 100MB
            recommendations.append(f"Cache database is large ({cache_size_mb:.1f}MB) - consider running cleanup")
        
        # Resumable tasks recommendations
        resumable_tasks = validation_results.get("resumable_tasks", [])
        
        if resumable_tasks:
            high_progress_tasks = [t for t in resumable_tasks if t["progress_percentage"] > 50]
            recent_tasks = [t for t in resumable_tasks if t["age_hours"] < 24]
            
            if high_progress_tasks:
                recommendations.append(f"{len(high_progress_tasks)} tasks with >50% progress can be resumed to save time")
            
            if recent_tasks:
                recommendations.append(f"{len(recent_tasks)} recent tasks (< 24h old) available for resumption")
        
        # Consistency issue recommendations
        consistency_issues = validation_results.get("consistency_issues", [])
        if consistency_issues:
            recommendations.append(f"{len(consistency_issues)} checkpoint consistency issues found - review and clean up")
        
        # Performance recommendations
        total_entries = cache_stats.get("total_cache_entries", 0)
        if total_entries > 10000:
            recommendations.append("Large number of cache entries may impact performance - consider periodic cleanup")
        
        validation_results["recommendations"] = recommendations
    
    def _auto_resume_eligible_tasks(self, validation_results: Dict[str, Any]) -> List[str]:
        """Automatically resume eligible tasks (if auto-resume is enabled)"""
        # For now, we don't auto-resume to avoid unexpected behavior
        # This can be enabled with configuration in the future
        
        auto_resume_enabled = False  # Could be read from config file
        
        if not auto_resume_enabled:
            return []
        
        resumed_task_ids = []
        resumable_tasks = validation_results.get("resumable_tasks", [])
        
        # Criteria for auto-resume:
        # - Task is less than 24 hours old
        # - Task has more than 50% progress
        # - Task type is batch_analysis (safer to resume)
        
        for task in resumable_tasks:
            if (task["age_hours"] < 24 and 
                task["progress_percentage"] > 50 and 
                task["task_type"] == "batch_analysis"):
                
                try:
                    # This would require integration with the main service
                    # For now, just log the intention
                    logger.info(f"Would auto-resume task {task['task_id'][:8]}... ({task['progress_percentage']:.1f}%)")
                    resumed_task_ids.append(task["task_id"])
                    
                except Exception as e:
                    logger.error(f"Failed to auto-resume task {task['task_id'][:8]}...: {e}")
        
        return resumed_task_ids
    
    def get_startup_summary(self) -> str:
        """Get a human-readable startup summary"""
        if not self.validation_results:
            return "Cache validation has not been run yet"
        
        results = self.validation_results
        cache_stats = results.get("cache_statistics", {})
        resumable_count = len(results.get("resumable_tasks", []))
        cleaned_count = results.get("expired_entries_cleaned", 0)
        
        summary_lines = [
            "🔍 CACHE VALIDATION SUMMARY",
            "=" * 40,
            f"Cache entries: {cache_stats.get('total_cache_entries', 0)}",
            f"Checkpoints: {cache_stats.get('total_checkpoints', 0)}",
            f"Resumable tasks: {resumable_count}",
            f"Cleaned expired entries: {cleaned_count}",
            f"Database size: {cache_stats.get('cache_db_size_mb', 0):.1f} MB"
        ]
        
        if resumable_count > 0:
            summary_lines.extend([
                "",
                "📋 RESUMABLE TASKS:",
                "-" * 20
            ])
            
            for task in results.get("resumable_tasks", [])[:5]:  # Show first 5
                age_str = f"{task['age_hours']:.1f}h"
                summary_lines.append(f"• {task['domain']} - {task['progress_percentage']:.1f}% ({age_str} old)")
            
            if resumable_count > 5:
                summary_lines.append(f"• ... and {resumable_count - 5} more tasks")
        
        recommendations = results.get("recommendations", [])
        if recommendations:
            summary_lines.extend([
                "",
                "💡 RECOMMENDATIONS:",
                "-" * 20
            ])
            for rec in recommendations[:3]:  # Show first 3 recommendations
                summary_lines.append(f"• {rec}")
            
            if len(recommendations) > 3:
                summary_lines.append(f"• ... and {len(recommendations) - 3} more recommendations")
        
        return "\\n".join(summary_lines)
    
    def save_validation_report(self, filename: str = None) -> str:
        """Save detailed validation report to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cache_validation_report_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.validation_results, f, indent=2, default=str)
            
            logger.info(f"Validation report saved to: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Error saving validation report: {e}")
            return ""

class ServiceStartupManager:
    """Manages the complete service startup process with cache validation"""
    
    def __init__(self):
        self.validator = StartupCacheValidator()
        self.startup_time = datetime.now()
        
    async def perform_startup_sequence(self) -> Dict[str, Any]:
        """Perform complete startup sequence with cache validation"""
        logger.info("🚀 Starting service startup sequence...")
        
        startup_results = {
            "startup_time": self.startup_time.isoformat(),
            "sequence_completed": False,
            "cache_validation_results": {},
            "service_status": "starting",
            "errors": []
        }
        
        try:
            # Step 1: Validate cache
            logger.info("Step 1: Validating task cache...")
            cache_results = self.validator.validate_cache_on_startup()
            startup_results["cache_validation_results"] = cache_results
            
            # Step 2: Log startup summary
            summary = self.validator.get_startup_summary()
            logger.info("\\n" + summary)
            
            # Step 3: Save validation report
            report_file = self.validator.save_validation_report()
            if report_file:
                startup_results["validation_report_file"] = report_file
            
            # Step 4: Initialize service components (placeholder)
            logger.info("Step 2: Initializing service components...")
            await asyncio.sleep(0.1)  # Simulate initialization
            
            # Step 5: Ready to serve
            startup_results["service_status"] = "ready"
            startup_results["sequence_completed"] = True
            
            startup_duration = (datetime.now() - self.startup_time).total_seconds()
            logger.info(f"✅ Service startup completed in {startup_duration:.2f}s")
            
        except Exception as e:
            logger.error(f"Error during startup sequence: {e}")
            startup_results["errors"].append(str(e))
            startup_results["service_status"] = "error"
        
        return startup_results

# Global startup manager
startup_manager = ServiceStartupManager()

async def main():
    """Test the startup cache validator"""
    logger.info("Testing Startup Cache Validator")
    logger.info("=" * 50)
    
    # Run startup sequence
    results = await startup_manager.perform_startup_sequence()
    
    print("\\nStartup Results:")
    print(json.dumps(results, indent=2, default=str))
    
    # Display summary
    print("\\n" + startup_manager.validator.get_startup_summary())

if __name__ == "__main__":
    asyncio.run(main())