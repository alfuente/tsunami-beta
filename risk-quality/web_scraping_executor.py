#!/usr/bin/env python3
"""
web_scraping_executor.py - Execute web scraping for subdomains

Takes a CSV file with subdomains (from extract_web_subdomains.py) and executes 
web scraping API calls for each subdomain. Monitors task progress and collects
information about related sites discovered during scraping.

Usage:
    python3 web_scraping_executor.py --input web_subdomains.csv
    python3 web_scraping_executor.py --input web_subdomains.csv --dry-run
    python3 web_scraping_executor.py --input web_subdomains.csv --limit 10 --delay 2.0
"""

import json
import logging
import requests
import time
import sys
import os
import csv
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import argparse
import signal
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f'web_scraping_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class WebScrapingTask:
    subdomain: str
    base_domain: str
    web_ports: List[int]
    task_id: Optional[str] = None
    status: str = "pending"
    response_code: Optional[int] = None
    error_message: Optional[str] = None
    execution_time: Optional[float] = None
    related_sites_count: int = 0
    related_sites: List[str] = None
    
    def __post_init__(self):
        if self.related_sites is None:
            self.related_sites = []

@dataclass
class ScrapingResults:
    timestamp: datetime
    total_tasks: int
    successful_tasks: int
    failed_tasks: int
    total_related_sites: int
    execution_time: float
    tasks: List[WebScrapingTask]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "total_tasks": self.total_tasks,
            "successful_tasks": self.successful_tasks,
            "failed_tasks": self.failed_tasks,
            "success_rate": round(self.successful_tasks / max(self.total_tasks, 1) * 100, 2),
            "total_related_sites": self.total_related_sites,
            "execution_time": self.execution_time,
            "tasks": [
                {
                    "subdomain": t.subdomain,
                    "base_domain": t.base_domain,
                    "web_ports": t.web_ports,
                    "task_id": t.task_id,
                    "status": t.status,
                    "response_code": t.response_code,
                    "error_message": t.error_message,
                    "execution_time": t.execution_time,
                    "related_sites_count": t.related_sites_count,
                    "related_sites": t.related_sites
                }
                for t in self.tasks
            ]
        }

class WebScrapingExecutor:
    """Execute web scraping API calls for subdomains"""
    
    def __init__(self, domain_backend_api: str = "http://localhost:8001", 
                 timeout: int = 30, max_retries: int = 3):
        self.domain_backend_api = domain_backend_api.rstrip('/')
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.timeout = timeout
        self.tasks: List[WebScrapingTask] = []
        self.interrupted = False
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle interruption signals gracefully"""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.interrupted = True

    def check_backend_health(self) -> bool:
        """Check if the domain-backend service is available"""
        logger.info(f"🏥 Checking backend health: {self.domain_backend_api}/health")
        try:
            response = self.session.get(f"{self.domain_backend_api}/health", timeout=5)
            logger.info(f"   📡 Health check response: HTTP {response.status_code}")
            if response.status_code == 200:
                logger.info("   ✅ Domain backend is healthy")
                return True
            else:
                logger.warning(f"   ⚠️  Domain backend health check failed: HTTP {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"   ❌ Cannot reach domain backend: {e}")
            return False

    def load_subdomains_csv(self, input_file: str) -> List[Dict[str, Any]]:
        """Load subdomains from CSV file"""
        try:
            subdomains = []
            with open(input_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Parse web_ports from string
                    web_ports_str = row.get('web_ports', '')
                    web_ports = []
                    if web_ports_str:
                        try:
                            web_ports = [int(p.strip()) for p in web_ports_str.split(',') if p.strip()]
                        except ValueError:
                            web_ports = []
                    
                    subdomains.append({
                        'subdomain': row.get('subdomain', ''),
                        'base_domain': row.get('base_domain', ''),
                        'web_ports': web_ports,
                        'services_count': int(row.get('services_count', 0)),
                        'has_http': row.get('has_http', '').lower() == 'true',
                        'has_https': row.get('has_https', '').lower() == 'true'
                    })
            
            logger.info(f"Loaded {len(subdomains)} subdomains from {input_file}")
            return subdomains
        
        except FileNotFoundError:
            logger.error(f"Input file not found: {input_file}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error loading CSV file: {e}")
            sys.exit(1)

    def execute_web_scraping(self, subdomain: str, base_domain: str, dry_run: bool = False) -> WebScrapingTask:
        """Execute web scraping for a single subdomain"""
        task = WebScrapingTask(
            subdomain=subdomain,
            base_domain=base_domain,
            web_ports=[],  # Will be filled from CSV data
            status="pending"
        )
        
        start_time = time.time()
        
        if dry_run:
            task.status = "skipped"
            task.execution_time = 0
            return task
        
        # Construct API URL
        api_url = f"{self.domain_backend_api}/api/v1/discover/web-scraping/{base_domain}?subdomain={subdomain}"
        
        logger.info(f"🔍 Scraping: {subdomain}")
        logger.info(f"   Base domain: {base_domain}")
        logger.info(f"   API URL: {api_url}")
        
        try:
            # Execute web scraping request
            headers = {'accept': 'application/json'}
            response = self.session.post(api_url, headers=headers, data='', timeout=self.timeout)
            
            execution_time = time.time() - start_time
            task.execution_time = execution_time
            task.response_code = response.status_code
            
            logger.info(f"   📡 Response: HTTP {response.status_code} in {execution_time:.2f}s")
            
            if response.status_code in [200, 201, 202]:
                try:
                    response_data = response.json()
                    task.task_id = response_data.get('task_id') or response_data.get('id')
                    task.status = "submitted"
                    
                    if task.task_id:
                        logger.info(f"   🆔 Task ID: {task.task_id}")
                    else:
                        logger.info(f"   📄 Response: {json.dumps(response_data, separators=(',', ':'))[:200]}")
                    
                    logger.info(f"   ✅ Success: {subdomain}")
                    
                except json.JSONDecodeError:
                    task.status = "submitted"
                    logger.info(f"   ✅ Success: {subdomain} (non-JSON response)")
                
            else:
                task.status = "failed"
                task.error_message = f"HTTP {response.status_code}: {response.text[:200]}"
                logger.warning(f"   ⚠️  HTTP {response.status_code}: {subdomain}")
                logger.warning(f"   📄 Response: {response.text[:200]}")
        
        except requests.exceptions.RequestException as e:
            task.status = "failed"
            task.error_message = f"Network error: {e}"
            task.execution_time = time.time() - start_time
            logger.error(f"   ❌ Network error: {e}")
        
        except Exception as e:
            task.status = "failed"
            task.error_message = f"Unexpected error: {e}"
            task.execution_time = time.time() - start_time
            logger.error(f"   💥 Unexpected error: {e}")
        
        return task

    def check_task_status(self, task_id: str) -> Dict[str, Any]:
        """Check the status of a web scraping task"""
        try:
            response = self.session.get(f"{self.domain_backend_api}/api/v1/tasks/{task_id}", timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Failed to check task {task_id}: HTTP {response.status_code}")
                return {}
        except Exception as e:
            logger.warning(f"Error checking task {task_id}: {e}")
            return {}

    def wait_for_tasks_completion(self, max_wait_minutes: int = 30) -> None:
        """Wait for submitted tasks to complete and collect results"""
        submitted_tasks = [t for t in self.tasks if t.status == "submitted" and t.task_id]
        
        if not submitted_tasks:
            logger.info("No tasks to monitor")
            return
        
        logger.info(f"🕐 Monitoring {len(submitted_tasks)} tasks for up to {max_wait_minutes} minutes...")
        
        start_time = time.time()
        max_wait_seconds = max_wait_minutes * 60
        
        while submitted_tasks and (time.time() - start_time) < max_wait_seconds:
            if self.interrupted:
                logger.info("Task monitoring interrupted")
                break
            
            completed_tasks = []
            
            for task in submitted_tasks:
                task_status = self.check_task_status(task.task_id)
                
                if task_status:
                    status = task_status.get('status', 'unknown')
                    
                    if status in ['completed', 'failed', 'error']:
                        logger.info(f"   📋 Task {task.task_id} ({task.subdomain}): {status}")
                        
                        # Update task with results
                        if status == 'completed':
                            task.status = 'completed'
                            # Look for related sites in the results
                            results = task_status.get('results', {})
                            related_sites = results.get('related_sites', [])
                            if related_sites:
                                task.related_sites = related_sites
                                task.related_sites_count = len(related_sites)
                                logger.info(f"   🔗 Found {len(related_sites)} related sites for {task.subdomain}")
                        else:
                            task.status = 'failed'
                            task.error_message = task_status.get('error', 'Task failed')
                        
                        completed_tasks.append(task)
            
            # Remove completed tasks from monitoring
            for task in completed_tasks:
                submitted_tasks.remove(task)
            
            if submitted_tasks:
                logger.info(f"   ⏳ {len(submitted_tasks)} tasks still running...")
                time.sleep(30)  # Check every 30 seconds
        
        # Mark remaining tasks as timeout
        for task in submitted_tasks:
            task.status = 'timeout'
            task.error_message = f'Task did not complete within {max_wait_minutes} minutes'
            logger.warning(f"   ⏰ Task {task.task_id} ({task.subdomain}) timed out")

    def execute_batch_scraping(self, subdomains_data: List[Dict[str, Any]], 
                              dry_run: bool = False, limit: Optional[int] = None,
                              delay_seconds: float = 1.0, 
                              wait_for_completion: bool = True) -> ScrapingResults:
        """Execute web scraping for all subdomains"""
        
        if limit:
            subdomains_data = subdomains_data[:limit]
        
        total_subdomains = len(subdomains_data)
        logger.info(f"🚀 Starting web scraping for {total_subdomains} subdomains")
        logger.info(f"   Dry run: {dry_run}")
        logger.info(f"   Delay between requests: {delay_seconds}s")
        
        start_time = time.time()
        
        for i, subdomain_data in enumerate(subdomains_data, 1):
            if self.interrupted:
                logger.info("Batch execution interrupted")
                break
            
            subdomain = subdomain_data.get('subdomain', '')
            base_domain = subdomain_data.get('base_domain', '')
            web_ports = subdomain_data.get('web_ports', [])
            
            print(f"\n{'='*80}")
            logger.info(f"📋 [{i}/{total_subdomains}] Processing: {subdomain}")
            logger.info(f"   Base domain: {base_domain}")
            logger.info(f"   Web ports: {web_ports}")
            
            if not subdomain or not base_domain:
                logger.warning(f"   ⚠️  Skipping invalid entry: {subdomain_data}")
                continue
            
            # Execute scraping
            task = self.execute_web_scraping(subdomain, base_domain, dry_run)
            task.web_ports = web_ports
            self.tasks.append(task)
            
            # Add delay between requests
            if i < total_subdomains and delay_seconds > 0:
                logger.info(f"   ⏳ Waiting {delay_seconds}s before next request...")
                time.sleep(delay_seconds)
        
        execution_time = time.time() - start_time
        
        # Wait for tasks to complete if requested
        if wait_for_completion and not dry_run:
            self.wait_for_tasks_completion()
        
        # Calculate results
        successful_tasks = len([t for t in self.tasks if t.status in ['completed', 'submitted']])
        failed_tasks = len([t for t in self.tasks if t.status == 'failed'])
        total_related_sites = sum(t.related_sites_count for t in self.tasks)
        
        logger.info(f"\n{'='*80}")
        logger.info(f"🏁 BATCH SCRAPING COMPLETED in {execution_time:.2f}s")
        logger.info(f"📊 RESULTS:")
        logger.info(f"   ✅ Successful: {successful_tasks}")
        logger.info(f"   ❌ Failed: {failed_tasks}")
        logger.info(f"   🔗 Total related sites found: {total_related_sites}")
        logger.info(f"   📈 Success rate: {(successful_tasks/max(len(self.tasks),1)*100):.1f}%")
        
        return ScrapingResults(
            timestamp=datetime.now(),
            total_tasks=len(self.tasks),
            successful_tasks=successful_tasks,
            failed_tasks=failed_tasks,
            total_related_sites=total_related_sites,
            execution_time=execution_time,
            tasks=self.tasks
        )

def main():
    parser = argparse.ArgumentParser(description="Execute web scraping for subdomains")
    parser.add_argument('--input', '-i', required=True,
                       help='Input CSV file with subdomains (from extract_web_subdomains.py)')
    parser.add_argument('--domain-backend-api', default='http://localhost:8001',
                       help='Domain backend API URL (default: http://localhost:8001)')
    parser.add_argument('--output', '-o',
                       help='Output JSON file for results (default: web_scraping_results_TIMESTAMP.json)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be executed without actually doing it')
    parser.add_argument('--limit', type=int,
                       help='Limit number of subdomains to process')
    parser.add_argument('--delay', type=float, default=1.0,
                       help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Request timeout in seconds (default: 30)')
    parser.add_argument('--max-retries', type=int, default=3,
                       help='Maximum retry attempts (default: 3)')
    parser.add_argument('--no-wait', action='store_true',
                       help='Do not wait for task completion')
    parser.add_argument('--max-wait', type=int, default=30,
                       help='Maximum minutes to wait for task completion (default: 30)')
    parser.add_argument('--no-health-check', action='store_true',
                       help='Skip backend health check')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize executor
    executor = WebScrapingExecutor(
        domain_backend_api=args.domain_backend_api,
        timeout=args.timeout,
        max_retries=args.max_retries
    )
    
    try:
        # Health check
        if not args.no_health_check:
            if not executor.check_backend_health():
                logger.error("Domain backend is not available. Use --no-health-check to skip.")
                sys.exit(1)
        
        # Load subdomains
        subdomains_data = executor.load_subdomains_csv(args.input)
        
        if not subdomains_data:
            logger.error("No subdomains found in input file")
            sys.exit(1)
        
        # Execute scraping
        results = executor.execute_batch_scraping(
            subdomains_data=subdomains_data,
            dry_run=args.dry_run,
            limit=args.limit,
            delay_seconds=args.delay,
            wait_for_completion=not args.no_wait
        )
        
        # Save results
        output_file = args.output or f"web_scraping_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results.to_dict(), f, indent=2, ensure_ascii=False)
        
        logger.info(f"📄 Results saved to: {output_file}")
        
        # Print related sites summary
        if results.total_related_sites > 0:
            print(f"\n{'='*80}")
            print("RELATED SITES DISCOVERED:")
            print(f"{'='*80}")
            for task in results.tasks:
                if task.related_sites:
                    print(f"\n{task.subdomain} ({len(task.related_sites)} related sites):")
                    for site in task.related_sites[:5]:  # Show first 5
                        print(f"  - {site}")
                    if len(task.related_sites) > 5:
                        print(f"  ... and {len(task.related_sites) - 5} more")
        
        # Exit with appropriate code
        if results.failed_tasks > 0:
            sys.exit(1)
        else:
            sys.exit(0)
    
    except KeyboardInterrupt:
        logger.info("Execution interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Execution failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()