#!/usr/bin/env python3
"""
data_completion_executor.py - Tsunami Beta Data Completion Executor

Takes the output from data_completeness_analyzer.py and executes the completion commands
by making API calls to the domain-backend service. Supports batch processing, progress tracking,
error handling, and retry mechanisms.

Usage:
    python3 data_completion_executor.py --input completeness_report.json
    python3 data_completion_executor.py --input completeness_report.json --dry-run
    python3 data_completion_executor.py --input completeness_report.json --priority critical,high
"""

import json
import logging
import requests
import time
import sys
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import argparse
import subprocess
import asyncio
import aiohttp
from urllib.parse import urlparse
import signal

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f'data_completion_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ExecutionResult:
    gap_id: str
    data_type: str
    priority: str
    domain: str
    success: bool
    response_code: Optional[int] = None
    response_data: Optional[Dict] = None
    error_message: Optional[str] = None
    execution_time_seconds: Optional[float] = None
    task_id: Optional[str] = None

@dataclass
class ExecutionSummary:
    timestamp: datetime
    total_gaps: int
    executed_gaps: int
    successful_executions: int
    failed_executions: int
    skipped_executions: int
    total_execution_time: float
    results: List[ExecutionResult]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "total_gaps": self.total_gaps,
            "executed_gaps": self.executed_gaps,
            "successful_executions": self.successful_executions,
            "failed_executions": self.failed_executions,
            "skipped_executions": self.skipped_executions,
            "total_execution_time": self.total_execution_time,
            "success_rate": round(self.successful_executions / max(self.executed_gaps, 1) * 100, 2),
            "results": [
                {
                    "gap_id": r.gap_id,
                    "data_type": r.data_type,
                    "priority": r.priority,
                    "domain": r.domain,
                    "success": r.success,
                    "response_code": r.response_code,
                    "error_message": r.error_message,
                    "execution_time_seconds": r.execution_time_seconds,
                    "task_id": r.task_id
                }
                for r in self.results
            ]
        }

class DataCompletionExecutor:
    """Executes data completion tasks from completeness analyzer output"""
    
    def __init__(self, domain_backend_api: str = "http://localhost:8001", 
                 timeout: int = 30, max_retries: int = 3):
        self.domain_backend_api = domain_backend_api.rstrip('/')
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.timeout = timeout
        self.results: List[ExecutionResult] = []
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
                try:
                    health_data = response.json()
                    logger.info(f"   📄 Health data: {json.dumps(health_data, separators=(',', ':'))}")
                except:
                    logger.info(f"   📄 Health response: {response.text}")
                return True
            else:
                logger.warning(f"   ⚠️  Domain backend health check failed: HTTP {response.status_code}")
                logger.warning(f"   📄 Response: {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"   ❌ Cannot reach domain backend: {e}")
            return False

    def load_completeness_report(self, input_file: str) -> Dict[str, Any]:
        """Load the completeness report from JSON file"""
        try:
            with open(input_file, 'r') as f:
                report = json.load(f)
            logger.info(f"Loaded completeness report with {len(report.get('data_gaps', []))} gaps")
            return report
        except FileNotFoundError:
            logger.error(f"Input file not found: {input_file}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in input file: {e}")
            sys.exit(1)

    def filter_gaps_by_priority(self, gaps: List[Dict], priorities: List[str]) -> List[Dict]:
        """Filter gaps by priority levels"""
        if not priorities:
            return gaps
            
        filtered = [gap for gap in gaps if gap.get('priority', '').lower() in priorities]
        logger.info(f"Filtered {len(filtered)} gaps from {len(gaps)} total gaps by priority: {priorities}")
        return filtered

    def filter_gaps_by_type(self, gaps: List[Dict], data_types: List[str]) -> List[Dict]:
        """Filter gaps by data types"""
        if not data_types:
            return gaps
            
        filtered = [gap for gap in gaps if gap.get('data_type', '').lower() in data_types]
        logger.info(f"Filtered {len(filtered)} gaps from {len(gaps)} total gaps by type: {data_types}")
        return filtered

    def parse_curl_command(self, curl_command: str) -> Tuple[str, str, Optional[Dict], Optional[Dict]]:
        """Parse curl command to extract method, URL, headers, and data"""
        import shlex
        try:
            # Use shlex to properly handle quoted arguments
            parts = shlex.split(curl_command)
        except ValueError:
            # Fallback to simple split if shlex fails
            parts = curl_command.split()
        
        method = "GET"
        url = ""
        headers = {}
        data = None
        
        i = 0
        while i < len(parts):
            part = parts[i]
            if part == "curl":
                i += 1
                continue
            elif part == "-X":
                i += 1
                if i < len(parts):
                    method = parts[i].strip("'\"")
            elif part == "-H":
                i += 1
                if i < len(parts):
                    header_str = parts[i].strip("'\"")
                    if ": " in header_str:
                        key, value = header_str.split(": ", 1)
                        headers[key] = value
            elif part == "-d":
                i += 1
                if i < len(parts):
                    data_str = parts[i].strip("'\"")
                    if data_str == "":
                        data = None  # Empty data
                    else:
                        try:
                            data = json.loads(data_str)
                        except json.JSONDecodeError:
                            data = {"raw": data_str}
            elif part.startswith("http"):
                url = part.strip("'\"")
            i += 1
        
        return method, url, headers, data

    def execute_curl_command(self, curl_command: str, gap_info: Dict) -> ExecutionResult:
        """Execute a single curl command with retry logic"""
        gap_id = f"{gap_info.get('data_type', 'unknown')}_{gap_info.get('domain', 'unknown')}"
        start_time = time.time()
        
        logger.info(f"🚀 Executing: {gap_id}")
        logger.info(f"   Command: {curl_command}")
        
        try:
            method, url, headers, data = self.parse_curl_command(curl_command)
            logger.info(f"   Parsed - Method: {method}, URL: {url}")
            if headers:
                logger.info(f"   Headers: {headers}")
            if data:
                logger.info(f"   Data: {json.dumps(data, separators=(',', ':'))}")
            
            if not url:
                logger.error(f"   ❌ Could not parse URL from command")
                return ExecutionResult(
                    gap_id=gap_id,
                    data_type=gap_info.get('data_type', 'unknown'),
                    priority=gap_info.get('priority', 'unknown'),
                    domain=gap_info.get('domain', 'unknown'),
                    success=False,
                    error_message="Could not parse URL from curl command",
                    execution_time_seconds=time.time() - start_time
                )
            
            # Attempt execution with retries
            last_exception = None
            for attempt in range(self.max_retries):
                if self.interrupted:
                    return ExecutionResult(
                        gap_id=gap_id,
                        data_type=gap_info.get('data_type', 'unknown'),
                        priority=gap_info.get('priority', 'unknown'),
                        domain=gap_info.get('domain', 'unknown'),
                        success=False,
                        error_message="Execution interrupted by user",
                        execution_time_seconds=time.time() - start_time
                    )
                
                try:
                    logger.info(f"   🔄 Attempt {attempt + 1}/{self.max_retries}: {method} {url}")
                    
                    if method.upper() == "POST":
                        response = self.session.post(url, headers=headers, json=data, timeout=self.timeout)
                    elif method.upper() == "GET":
                        response = self.session.get(url, headers=headers, timeout=self.timeout)
                    elif method.upper() == "PUT":
                        response = self.session.put(url, headers=headers, json=data, timeout=self.timeout)
                    else:
                        logger.error(f"   ❌ Unsupported HTTP method: {method}")
                        return ExecutionResult(
                            gap_id=gap_id,
                            data_type=gap_info.get('data_type', 'unknown'),
                            priority=gap_info.get('priority', 'unknown'),
                            domain=gap_info.get('domain', 'unknown'),
                            success=False,
                            error_message=f"Unsupported HTTP method: {method}",
                            execution_time_seconds=time.time() - start_time
                        )
                    
                    execution_time = time.time() - start_time
                    
                    logger.info(f"   📡 Response: HTTP {response.status_code} ({len(response.text)} bytes)")
                    
                    # Parse response
                    response_data = None
                    task_id = None
                    try:
                        response_data = response.json()
                        task_id = response_data.get('task_id') or response_data.get('id')
                        if task_id:
                            logger.info(f"   🆔 Task ID: {task_id}")
                        else:
                            logger.info(f"   📄 Response data: {json.dumps(response_data, separators=(',', ':'))[:200]}...")
                    except (json.JSONDecodeError, AttributeError):
                        response_data = {"raw_response": response.text[:500]}
                        logger.info(f"   📄 Raw response: {response.text[:200]}...")
                    
                    if response.status_code in [200, 201, 202]:
                        logger.info(f"   ✅ Success: {gap_id} - HTTP {response.status_code} in {execution_time:.2f}s")
                        return ExecutionResult(
                            gap_id=gap_id,
                            data_type=gap_info.get('data_type', 'unknown'),
                            priority=gap_info.get('priority', 'unknown'),
                            domain=gap_info.get('domain', 'unknown'),
                            success=True,
                            response_code=response.status_code,
                            response_data=response_data,
                            execution_time_seconds=execution_time,
                            task_id=task_id
                        )
                    else:
                        logger.warning(f"   ⚠️  HTTP {response.status_code}: {gap_id} - {response.text[:100]}...")
                        if attempt == self.max_retries - 1:  # Last attempt
                            logger.error(f"   ❌ Final failure after {self.max_retries} attempts: {gap_id}")
                            return ExecutionResult(
                                gap_id=gap_id,
                                data_type=gap_info.get('data_type', 'unknown'),
                                priority=gap_info.get('priority', 'unknown'),
                                domain=gap_info.get('domain', 'unknown'),
                                success=False,
                                response_code=response.status_code,
                                response_data=response_data,
                                error_message=f"HTTP {response.status_code}: {response.text}",
                                execution_time_seconds=execution_time
                            )
                        wait_time = 2 ** attempt
                        logger.info(f"   ⏳ Retrying in {wait_time}s...")
                        time.sleep(wait_time)  # Exponential backoff
                
                except requests.exceptions.RequestException as e:
                    last_exception = e
                    logger.warning(f"   🔥 Network error on attempt {attempt + 1}: {e}")
                    if attempt < self.max_retries - 1:
                        wait_time = 2 ** attempt
                        logger.info(f"   ⏳ Retrying in {wait_time}s due to network error...")
                        time.sleep(wait_time)  # Exponential backoff
            
            # All retries failed
            logger.error(f"   💀 All {self.max_retries} attempts failed for {gap_id}: {last_exception}")
            return ExecutionResult(
                gap_id=gap_id,
                data_type=gap_info.get('data_type', 'unknown'),
                priority=gap_info.get('priority', 'unknown'),
                domain=gap_info.get('domain', 'unknown'),
                success=False,
                error_message=f"All {self.max_retries} attempts failed. Last error: {last_exception}",
                execution_time_seconds=time.time() - start_time
            )
        
        except Exception as e:
            logger.error(f"   💥 Unexpected error for {gap_id}: {e}")
            return ExecutionResult(
                gap_id=gap_id,
                data_type=gap_info.get('data_type', 'unknown'),
                priority=gap_info.get('priority', 'unknown'),
                domain=gap_info.get('domain', 'unknown'),
                success=False,
                error_message=f"Unexpected error: {e}",
                execution_time_seconds=time.time() - start_time
            )

    def execute_data_completion(self, report: Dict[str, Any], dry_run: bool = False,
                              priority_filter: List[str] = None,
                              type_filter: List[str] = None,
                              delay_seconds: float = 1.0) -> ExecutionSummary:
        """Execute all data completion tasks from the report"""
        data_gaps = report.get('data_gaps', [])
        
        # Apply filters
        if priority_filter:
            data_gaps = self.filter_gaps_by_priority(data_gaps, priority_filter)
        if type_filter:
            data_gaps = self.filter_gaps_by_type(data_gaps, type_filter)
        
        if not data_gaps:
            logger.warning("No gaps to execute after filtering")
            return ExecutionSummary(
                timestamp=datetime.now(),
                total_gaps=len(report.get('data_gaps', [])),
                executed_gaps=0,
                successful_executions=0,
                failed_executions=0,
                skipped_executions=0,
                total_execution_time=0,
                results=[]
            )
        
        logger.info(f"Starting execution of {len(data_gaps)} data completion tasks")
        logger.info(f"Dry run: {dry_run}, Delay: {delay_seconds}s between requests")
        
        start_time = time.time()
        successful = 0
        failed = 0
        skipped = 0
        
        for i, gap in enumerate(data_gaps, 1):
            if self.interrupted:
                logger.info("Execution interrupted by user")
                break
                
            print(f"\n{'='*80}")
            logger.info(f"📋 [{i}/{len(data_gaps)}] Processing {gap.get('data_type', 'unknown').upper()} gap")
            logger.info(f"   Domain: {gap.get('domain', 'unknown')}")
            logger.info(f"   Priority: {gap.get('priority', 'unknown').upper()}")
            logger.info(f"   Description: {gap.get('description', 'N/A')}")
            
            if dry_run:
                logger.info(f"   🔍 DRY RUN - Would execute: {gap.get('completion_command', 'N/A')}")
                result = ExecutionResult(
                    gap_id=f"dry_run_{i}",
                    data_type=gap.get('data_type', 'unknown'),
                    priority=gap.get('priority', 'unknown'),
                    domain=gap.get('domain', 'unknown'),
                    success=True,
                    response_code=200,
                    execution_time_seconds=0
                )
                skipped += 1
            else:
                result = self.execute_curl_command(gap.get('completion_command', ''), gap)
                if result.success:
                    successful += 1
                    logger.info(f"✅ COMPLETED: {result.gap_id}")
                else:
                    failed += 1
                    logger.error(f"❌ FAILED: {result.gap_id} - {result.error_message}")
                
                # Add delay between requests to avoid overwhelming the backend
                if i < len(data_gaps) and delay_seconds > 0:
                    logger.info(f"⏳ Waiting {delay_seconds}s before next request...")
                    time.sleep(delay_seconds)
            
            self.results.append(result)
        
        total_time = time.time() - start_time
        executed_gaps = successful + failed
        
        print(f"\n{'='*80}")
        logger.info(f"🏁 EXECUTION COMPLETED in {total_time:.2f} seconds")
        logger.info(f"📊 RESULTS SUMMARY:")
        logger.info(f"   ✅ Successful: {successful}")
        logger.info(f"   ❌ Failed: {failed}")
        logger.info(f"   ⏭️  Skipped: {skipped}")
        logger.info(f"   📈 Success Rate: {(successful/max(executed_gaps,1)*100):.1f}%")
        print(f"{'='*80}")
        
        return ExecutionSummary(
            timestamp=datetime.now(),
            total_gaps=len(report.get('data_gaps', [])),
            executed_gaps=executed_gaps,
            successful_executions=successful,
            failed_executions=failed,
            skipped_executions=skipped,
            total_execution_time=total_time,
            results=self.results
        )

def main():
    parser = argparse.ArgumentParser(description="Execute data completion tasks from completeness analyzer")
    parser.add_argument('--input', '-i', required=True,
                       help='Input JSON file from data_completeness_analyzer.py')
    parser.add_argument('--domain-backend-api', default='http://localhost:8081',
                       help='Domain backend API URL (default: http://localhost:8081)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be executed without actually doing it')
    parser.add_argument('--priority', 
                       help='Filter by priority levels (comma-separated: critical,high,medium,low)')
    parser.add_argument('--type',
                       help='Filter by data types (comma-separated: dns,certificate,technology,service,risk,etc.)')
    parser.add_argument('--output', '-o',
                       help='Output file for execution results (default: execution_results_TIMESTAMP.json)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Request timeout in seconds (default: 30)')
    parser.add_argument('--max-retries', type=int, default=3,
                       help='Maximum retry attempts (default: 3)')
    parser.add_argument('--delay', type=float, default=1.0,
                       help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('--no-health-check', action='store_true',
                       help='Skip backend health check')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize executor
    executor = DataCompletionExecutor(
        domain_backend_api=args.domain_backend_api,
        timeout=args.timeout,
        max_retries=args.max_retries
    )
    
    try:
        # Health check
        if not args.no_health_check:
            logger.info("Checking domain backend health...")
            if not executor.check_backend_health():
                logger.error("Domain backend is not available. Use --no-health-check to skip this check.")
                sys.exit(1)
        
        # Load report
        logger.info(f"Loading completeness report from {args.input}")
        report = executor.load_completeness_report(args.input)
        
        # Parse filters
        priority_filter = None
        if args.priority:
            priority_filter = [p.strip().lower() for p in args.priority.split(',')]
            logger.info(f"Priority filter: {priority_filter}")
        
        type_filter = None
        if args.type:
            type_filter = [t.strip().lower() for t in args.type.split(',')]
            logger.info(f"Type filter: {type_filter}")
        
        # Execute completion tasks
        summary = executor.execute_data_completion(
            report=report,
            dry_run=args.dry_run,
            priority_filter=priority_filter,
            type_filter=type_filter,
            delay_seconds=args.delay
        )
        
        # Save results
        output_file = args.output or f"execution_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(summary.to_dict(), f, indent=2)
        
        logger.info(f"Results saved to {output_file}")
        
        # Print summary
        print("\n=== Execution Summary ===")
        print(f"Total gaps in report: {summary.total_gaps}")
        print(f"Executed gaps: {summary.executed_gaps}")
        print(f"Successful: {summary.successful_executions}")
        print(f"Failed: {summary.failed_executions}")
        print(f"Skipped: {summary.skipped_executions}")
        print(f"Success rate: {summary.to_dict()['success_rate']}%")
        print(f"Total execution time: {summary.total_execution_time:.2f} seconds")
        
        # Exit with appropriate code
        if summary.failed_executions > 0:
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
