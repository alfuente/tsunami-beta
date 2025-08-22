#!/usr/bin/env python3
"""
Script para recargar dominios usando el domain-backend API con soporte para cache local

Este script toma una lista de dominios y los procesa usando:
1. Cache local de amass (standalone_amass_executor.sh) cuando está disponible
2. API de domain-backend para análisis completo cuando no hay cache
3. Timeouts configurables para evitar fallos por timeout en amass
4. Inserción automática en Neo4j de todos los resultados

Características:
- Integración con cache local de amass
- Timeouts configurables (amass, task monitoring, subdomain analysis)
- Modo cache-only para usar solo datos cached
- Procesamiento concurrente con límites configurables
- Manejo robusto de errores y reintentos
"""

import sys
import json
import asyncio
import aiohttp
import time
import logging
import argparse
from datetime import datetime
import os
from typing import List, Dict, Any
import signal
import gzip
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DomainReloader:
    def __init__(self, api_base_url="http://localhost:8001", max_concurrent=3, delay_between_requests=5, 
                 cache_dir="../amass_cache", cache_duration_hours=168, cache_only=False,
                 amass_timeout=1200, task_timeout=1800, subdomain_timeout=120):
        """Initialize domain reloader"""
        self.api_base_url = api_base_url.rstrip('/')
        self.max_concurrent = max_concurrent
        self.delay_between_requests = delay_between_requests
        self.session = None
        self.results = {
            'success': [],
            'failed': [],
            'skipped': [],
            'in_progress': []
        }
        self.start_time = None
        self.stop_requested = False
        
        # Amass cache configuration
        self.cache_dir = cache_dir
        self.cache_duration_hours = cache_duration_hours
        self.metadata_dir = os.path.join(cache_dir, "metadata")
        self.data_dir = os.path.join(cache_dir, "data")
        self.cache_only = cache_only
        
        # Timeout configuration
        self.amass_timeout = amass_timeout
        self.task_timeout = task_timeout
        self.subdomain_timeout = subdomain_timeout
        
        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"Received signal {signum}, stopping gracefully...")
        self.stop_requested = True
    
    def _generate_hash(self, domain: str) -> str:
        """Generate hash for domain (same as standalone_amass_executor.sh)"""
        return hashlib.sha256(domain.encode()).hexdigest()[:16]
    
    def _is_cache_valid(self, domain: str) -> bool:
        """Check if cache entry exists and is valid"""
        print(self.metadata_dir) 
        if not os.path.exists(self.metadata_dir):
            return False
        
        domain_hash = self._generate_hash(domain)
        metadata_file = os.path.join(self.metadata_dir, f"{domain_hash}.json")
        
        if not os.path.exists(metadata_file):
            return False
        
        try:
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            # Check if metadata is complete
            if 'timestamp' not in metadata or 'subdomain_count' not in metadata:
                logger.debug(f"Invalid metadata for {domain}, cache miss")
                return False
            
            # Check if cache is expired
            timestamp_str = metadata['timestamp']
            cache_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            current_time = datetime.now()
            age_hours = (current_time - cache_time.replace(tzinfo=None)).total_seconds() / 3600
            
            if age_hours > self.cache_duration_hours:
                logger.debug(f"Cache expired for {domain} (age: {age_hours:.1f}h)")
                return False
            
            logger.info(f"✅ Valid cache found for {domain} (age: {age_hours:.1f}h)")
            return True
            
        except Exception as e:
            logger.debug(f"Error checking cache for {domain}: {e}")
            return False
    
    def _get_cached_subdomains(self, domain: str) -> List[str]:
        """Get cached subdomains from local cache"""
        try:
            domain_hash = self._generate_hash(domain)
            data_file = os.path.join(self.data_dir, f"{domain_hash}.json.gz")
            
            if not os.path.exists(data_file):
                return []
            
            with gzip.open(data_file, 'rt', encoding='utf-8') as f:
                subdomains = json.load(f)
            
            if isinstance(subdomains, list):
                logger.info(f"📂 Retrieved {len(subdomains)} subdomains from cache for {domain}")
                return subdomains
            else:
                logger.warning(f"Invalid cache format for {domain}")
                return []
                
        except Exception as e:
            logger.error(f"Error reading cache for {domain}: {e}")
            return []
    
    async def _upload_cached_subdomains_to_api(self, domain: str, subdomains: List[str]) -> dict:
        """Upload cached subdomains to the API for graph insertion"""
        try:
            # Create a payload that mimics the API expected format
            cache_result = {
                "domain": domain,
                "subdomains": subdomains,
                "cached": True,
                "discovered_at": datetime.now().isoformat(),
                "metadata": {
                    "total_subdomains": len(subdomains),
                    "source": "local_cache"
                }
            }
            
            # Since we have the subdomains, we can directly call the complete analysis
            # but inform the API that amass results are already available
            logger.info(f"🔄 Uploading {len(subdomains)} cached subdomains for {domain} to graph")
            
            # Use the complete analysis endpoint to ensure providers and services are analyzed
            url = f"{self.api_base_url}/api/v1/discover/all-subdomains/{domain}"
            params = {
                "amass_timeout": 60,  # Minimal timeout since we have cached data
                "max_subdomains": len(subdomains),
                "max_workers": 20,  # More workers since we have the subdomain list
                "timeout_per_subdomain": max(30, self.subdomain_timeout // 8),  # Much reduced for cached data
                "save_to_neo4j": "true"
            }
            
            async with self.session.post(url, params=params) as response:
                if response.status == 200:
                    result = await response.json()
                    
                    if 'task_id' in result:
                        # Monitor the task with extended timeout for cached data processing
                        task_result = await self.monitor_task(result['task_id'], timeout=self.task_timeout // 2)
                        if task_result['status'] == 'success':
                            return {
                                'status': 'success',
                                'source': 'cached_data',
                                'subdomains_count': len(subdomains),
                                'duration': task_result['duration'],
                                'result': task_result['result']
                            }
                        else:
                            return {
                                'status': 'failed',
                                'source': 'cached_data',
                                'error': task_result.get('error', 'Task failed'),
                                'duration': task_result['duration']
                            }
                    else:
                        return {
                            'status': 'success',
                            'source': 'cached_data',
                            'subdomains_count': len(subdomains),
                            'result': result
                        }
                else:
                    error_text = await response.text()
                    return {
                        'status': 'failed',
                        'source': 'cached_data',
                        'error': f"API error: {response.status} - {error_text}"
                    }
                    
        except Exception as e:
            return {
                'status': 'failed',
                'source': 'cached_data',
                'error': f"Upload error: {str(e)}"
            }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=3600)  # 60 minute timeout (increased from 30)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def check_api_status(self):
        """Check if the domain-backend API is available"""
        try:
            async with self.session.get(f"{self.api_base_url}/health") as response:
                if response.status == 200:
                    status_data = await response.json()
                    logger.info(f"API Status: {status_data}")
                    return True
                else:
                    logger.error(f"API status check failed: HTTP {response.status}")
                    return False
        except Exception as e:
            logger.error(f"Failed to connect to API: {e}")
            return False
    
    async def estimate_domain_duration(self, domain: str, task_type: str = "complete_discovery"):
        """Get time estimation for domain analysis (simplified for async API)"""
        # Async API doesn't have estimation endpoint, use configured task timeout
        return self.task_timeout // 2  # Use half of configured task timeout as estimate
    
    async def monitor_task(self, task_id: str, timeout: int = None) -> dict:
        """Monitor a task until completion or timeout"""
        if timeout is None:
            timeout = self.task_timeout
            
        start_time = time.time()
        check_interval = 5  # Check every 5 seconds
        
        while (time.time() - start_time) < timeout:
            try:
                task_url = f"{self.api_base_url}/api/v1/tasks/{task_id}"
                async with self.session.get(task_url) as response:
                    if response.status == 200:
                        task_info = await response.json()
                        status = task_info.get('status', 'unknown')
                        
                        if status == 'completed':
                            return {
                                'status': 'success',
                                'result': task_info.get('result', {}),
                                'duration': time.time() - start_time
                            }
                        elif status == 'failed':
                            return {
                                'status': 'failed',
                                'error': task_info.get('error', 'Unknown error'),
                                'duration': time.time() - start_time
                            }
                        # Task still running, continue monitoring
                        
                    await asyncio.sleep(check_interval)
            except Exception as e:
                print(f"   ⚠️  Error monitoring task {task_id}: {e}")
                await asyncio.sleep(check_interval)
        
        return {
            'status': 'timeout',
            'error': f'Task monitoring timed out after {timeout} seconds',
            'duration': timeout
        }

    async def analyze_domain(self, domain: str, analysis_type: str = "complete", retries: int = 2, 
                           use_cache: bool = True):
        """Analyze a single domain using cache first, then API if needed"""
        
        # Check local cache first for complete analysis and amass
        if use_cache and analysis_type in ["complete", "amass"]:
            if self._is_cache_valid(domain):
                cached_subdomains = self._get_cached_subdomains(domain)
                if cached_subdomains:
                    logger.info(f"🚀 Using cached data for {domain} ({len(cached_subdomains)} subdomains)")
                    
                    # Upload cached data to API for graph insertion
                    cache_result = await self._upload_cached_subdomains_to_api(domain, cached_subdomains)
                    
                    if cache_result['status'] == 'success':
                        # Extract actual results from the cache processing
                        result_data = cache_result.get('result', {})
                        return {
                            'domain': domain,
                            'analysis_type': analysis_type,
                            'status': 'success',
                            'timestamp': datetime.now().isoformat(),
                            'duration_seconds': cache_result.get('duration', 0),
                            'estimated_duration': 60,  # Cached operations are fast
                            'accuracy': 1.0,  # Cache is always accurate
                            'subdomains_found': len(cached_subdomains),
                            'providers_found': len(result_data.get('providers', [])),
                            'services_found': len(result_data.get('services', [])),
                            'certificates_found': len(result_data.get('certificates', [])),
                            'risks_found': len(result_data.get('risks', [])),
                            'processing_time': cache_result.get('duration', 0),
                            'source': 'local_cache',
                            'cached': True,
                            'errors': [],
                            'attempt': 1
                        }
                    else:
                        logger.warning(f"⚠️  Failed to upload cached data for {domain}: {cache_result.get('error', 'Unknown error')}")
                        # Fall through to API call if not cache_only
                else:
                    logger.info(f"📂 No cached subdomains found for {domain}")
            else:
                logger.info(f"❌ Cache invalid or expired for {domain}")
        
        # Check if cache-only mode is enabled
        if hasattr(self, 'cache_only') and self.cache_only:
            return {
                'domain': domain,
                'analysis_type': analysis_type,
                'status': 'failed',
                'timestamp': datetime.now().isoformat(),
                'duration_seconds': 0,
                'error': 'No valid cache available and cache-only mode enabled',
                'source': 'cache_only_mode',
                'cached': False,
                'errors': ['No valid cache in cache-only mode'],
                'attempt': 1
            }
        
        # Proceed with API call if no cache or cache failed
        logger.info(f"🔄 No valid cache for {domain}, using API")
        
        endpoint_map = {
            "basic": f"{self.api_base_url}/api/v1/discover/dns/{domain}",
            "amass": f"{self.api_base_url}/api/v1/discover/amass/{domain}",
            "services": f"{self.api_base_url}/api/v1/discover/services/{domain}",
            "tls": f"{self.api_base_url}/api/v1/discover/tls/{domain}",
            "mx": f"{self.api_base_url}/api/v1/discover/mx/{domain}",
            "tech": f"{self.api_base_url}/api/v1/discover/tech/{domain}",
            "complete": f"{self.api_base_url}/api/v1/discover/all-subdomains/{domain}"
        }
        
        url = endpoint_map.get(analysis_type, endpoint_map["complete"])
        
        # Common parameters for comprehensive analysis
        params = {
            "amass_timeout": self.amass_timeout,  # Configurable amass timeout
            "max_subdomains": 2000,
            "max_workers": 10,
            "timeout_per_subdomain": self.subdomain_timeout,  # Configurable subdomain timeout
            "save_to_neo4j": "true"  # String instead of boolean
        }
        
        for attempt in range(retries + 1):
            try:
                # Show attempt info only for retries
                if attempt > 0:
                    print(f"   🔄 Retry {attempt + 1}/{retries + 1} for {domain}")
                
                # Get time estimation (only on first attempt to avoid spam)
                if attempt == 0:
                    estimated_duration = await self.estimate_domain_duration(domain)
                    print(f"   ⏱️  Estimated duration: {estimated_duration // 60}m {estimated_duration % 60}s")
                else:
                    estimated_duration = 300  # Default for retries
                
                start_time = time.time()
                
                # Use POST for async API endpoints
                async with self.session.post(url, params=params) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        # Check if this is an async task (all-subdomains endpoint)
                        if analysis_type == "complete" and "task_id" in result:
                            task_id = result["task_id"]
                            print(f"   🔄 Task started: {task_id}, monitoring progress...")
                            
                            # Monitor the task with configurable timeout for comprehensive analysis
                            actual_timeout = max(estimated_duration, self.task_timeout)
                            task_result = await self.monitor_task(task_id, timeout=actual_timeout)
                            
                            if task_result['status'] == 'success':
                                task_data = task_result.get('result', {})
                                analysis_result = {
                                    'domain': domain,
                                    'analysis_type': analysis_type,
                                    'status': 'success',
                                    'timestamp': datetime.now().isoformat(),
                                    'duration_seconds': round(task_result['duration'], 2),
                                    'estimated_duration': estimated_duration,
                                    'accuracy': abs(estimated_duration - task_result['duration']) / estimated_duration if estimated_duration > 0 else 0,
                                    'subdomains_found': task_data.get('subdomains_found', 0),
                                    'providers_found': len(task_data.get('providers', [])),
                                    'services_found': len(task_data.get('services', [])),
                                    'certificates_found': len(task_data.get('certificates', [])),
                                    'risks_found': len(task_data.get('risks', [])),
                                    'processing_time': task_result['duration'],
                                    'task_id': task_id,
                                    'errors': [],
                                    'attempt': attempt + 1
                                }
                            else:
                                # Task failed or timed out
                                raise Exception(f"Task failed: {task_result.get('error', 'Unknown error')}")
                        else:
                            # Direct response (non-async endpoints)
                            actual_duration = time.time() - start_time
                            
                            # Extract key metrics
                            analysis_result = {
                                'domain': domain,
                                'analysis_type': analysis_type,
                                'status': 'success',
                                'timestamp': datetime.now().isoformat(),
                                'duration_seconds': round(actual_duration, 2),
                                'estimated_duration': estimated_duration,
                                'accuracy': abs(estimated_duration - actual_duration) / estimated_duration if estimated_duration > 0 else 0,
                                'subdomains_found': len(result.get('subdomains', [])),
                                'providers_found': len(result.get('providers', [])),
                                'services_found': len(result.get('services', [])),
                                'certificates_found': len(result.get('certificates', [])),
                                'risks_found': len(result.get('risks', [])),
                                'processing_time': result.get('processing_time', 0),
                            'errors': result.get('errors', []),
                            'attempt': attempt + 1
                        }
                        
                        return analysis_result
                    
                    else:
                        error_text = await response.text()
                        error_msg = f"HTTP {response.status}: {error_text[:200]}"
                        
                        if attempt < retries:
                            wait_time = (attempt + 1) * 30  # Increasing wait time
                            print(f"   ⚠️  Failed (HTTP {response.status}), retrying in {wait_time}s...")
                            await asyncio.sleep(wait_time)
                        else:
                            print(f"   ❌ Final failure: {error_msg}")
                        
            except asyncio.TimeoutError:
                actual_duration = time.time() - start_time
                if attempt < retries:
                    print(f"   ⏰ Timeout after {actual_duration:.1f}s, retrying...")
                    await asyncio.sleep(60)  # Wait longer for timeouts
                else:
                    print(f"   ❌ Final timeout after {actual_duration:.1f}s")
                    
            except Exception as e:
                if attempt < retries:
                    print(f"   ⚠️  Error: {str(e)[:100]}, retrying...")
                    await asyncio.sleep(30)
                else:
                    print(f"   ❌ Final error: {str(e)[:100]}")
        
        # All attempts failed
        return {
            'domain': domain,
            'analysis_type': analysis_type,
            'status': 'failed',
            'timestamp': datetime.now().isoformat(),
            'attempts': retries + 1,
            'error': 'Max retries exceeded'
        }
    
    async def reload_domains_batch(self, domains: List[str], analysis_type: str = "complete", use_cache: bool = True):
        """Reload a batch of domains with concurrent processing and real-time progress"""
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        # Progress tracking
        self.completed_count = 0
        self.total_domains = len(domains)
        
        async def process_domain(domain_index, domain):
            if self.stop_requested:
                return None
                
            async with semaphore:
                try:
                    # Show start of processing
                    print(f"🔄 [{domain_index + 1:3d}/{self.total_domains}] Starting: {domain}")
                    
                    result = await self.analyze_domain(domain, analysis_type, use_cache=use_cache)
                    
                    # Update results
                    if result['status'] == 'success':
                        self.results['success'].append(result)
                        status_emoji = "✅"
                        status_color = "SUCCESS"
                        details = f"({result.get('subdomains_found', 0)} subdomains, {result.get('duration_seconds', 0):.1f}s)"
                    else:
                        self.results['failed'].append(result)
                        status_emoji = "❌"
                        status_color = "FAILED"
                        details = f"({result.get('error', 'Unknown error')})"
                    
                    # Update progress counter
                    self.completed_count += 1
                    
                    # Calculate progress stats
                    elapsed_time = time.time() - self.start_time
                    progress_pct = (self.completed_count / self.total_domains) * 100
                    rate = self.completed_count / elapsed_time * 60 if elapsed_time > 0 else 0
                    
                    # Estimate remaining time
                    if rate > 0:
                        remaining_domains = self.total_domains - self.completed_count
                        eta_minutes = remaining_domains / rate
                        eta_str = f", ETA: {eta_minutes:.1f}m"
                    else:
                        eta_str = ""
                    
                    # Show completion status with progress
                    print(f"{status_emoji} [{domain_index + 1:3d}/{self.total_domains}] {status_color}: {domain} {details}")
                    print(f"📊 Progress: {self.completed_count}/{self.total_domains} ({progress_pct:.1f}%) "
                          f"| ✅ {len(self.results['success'])} | ❌ {len(self.results['failed'])} "
                          f"| Rate: {rate:.1f}/min{eta_str}")
                    print("-" * 80)
                    
                    # Add delay between requests to avoid overwhelming the API
                    if not self.stop_requested and self.delay_between_requests > 0:
                        await asyncio.sleep(self.delay_between_requests)
                    
                    return result
                    
                except Exception as e:
                    self.completed_count += 1
                    error_msg = str(e)
                    logger.error(f"❌ [{domain_index + 1:3d}/{self.total_domains}] ERROR: {domain} - {error_msg}")
                    
                    self.results['failed'].append({
                        'domain': domain,
                        'status': 'failed',
                        'error': error_msg,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    # Show error progress
                    progress_pct = (self.completed_count / self.total_domains) * 100
                    print(f"📊 Progress: {self.completed_count}/{self.total_domains} ({progress_pct:.1f}%) "
                          f"| ✅ {len(self.results['success'])} | ❌ {len(self.results['failed'])}")
                    print("-" * 80)
                    
                    return None
        
        self.start_time = time.time()
        
        # Header
        print("\n" + "=" * 80)
        print(f"🚀 STARTING DOMAIN ANALYSIS: {len(domains)} domains")
        print(f"📊 Analysis type: {analysis_type}")
        print(f"🔧 Max concurrent: {self.max_concurrent}")
        print(f"⏱️  Delay between requests: {self.delay_between_requests}s")
        print("=" * 80)
        
        # Process domains with index for better tracking
        tasks = [process_domain(i, domain) for i, domain in enumerate(domains)]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        total_time = time.time() - self.start_time
        
        # Final summary
        print("\n" + "=" * 80)
        print("🏁 BATCH PROCESSING COMPLETED")
        print("=" * 80)
        print(f"⏱️  Total time: {total_time/60:.1f} minutes")
        print(f"📊 Total processed: {len(self.results['success']) + len(self.results['failed'])}")
        print(f"✅ Successful: {len(self.results['success'])}")
        print(f"❌ Failed: {len(self.results['failed'])}")
        print(f"📈 Success rate: {len(self.results['success']) / self.total_domains * 100:.1f}%")
        print(f"🚀 Average rate: {self.total_domains / (total_time / 60):.1f} domains/minute")
        
        if self.results['failed']:
            print(f"\n❌ Failed domains ({len(self.results['failed'])}):")
            for i, failed in enumerate(self.results['failed'][:10], 1):
                print(f"   {i:2d}. {failed['domain']}: {failed.get('error', 'Unknown error')}")
            if len(self.results['failed']) > 10:
                print(f"   ... and {len(self.results['failed']) - 10} more")
        
        print("=" * 80)
        
        return self.results
    
    def save_results(self, output_dir: str):
        """Save processing results to files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save detailed results
        results_file = os.path.join(output_dir, f'reload_results_{timestamp}.json')
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump({
                'summary': {
                    'total_domains': len(self.results['success']) + len(self.results['failed']),
                    'successful': len(self.results['success']),
                    'failed': len(self.results['failed']),
                    'success_rate': len(self.results['success']) / (len(self.results['success']) + len(self.results['failed'])) * 100 if self.results['success'] or self.results['failed'] else 0,
                    'total_time_minutes': (time.time() - self.start_time) / 60 if self.start_time else 0,
                    'timestamp': datetime.now().isoformat()
                },
                'results': self.results
            }, f, indent=2, ensure_ascii=False, default=str)
        
        # Save failed domains list for retry
        if self.results['failed']:
            failed_domains = [result['domain'] for result in self.results['failed']]
            failed_file = os.path.join(output_dir, f'failed_domains_{timestamp}.json')
            with open(failed_file, 'w', encoding='utf-8') as f:
                json.dump(failed_domains, f, indent=2)
        
        # Save successful domains list
        if self.results['success']:
            success_domains = [result['domain'] for result in self.results['success']]
            success_file = os.path.join(output_dir, f'successful_domains_{timestamp}.json')
            with open(success_file, 'w', encoding='utf-8') as f:
                json.dump(success_domains, f, indent=2)
        
        logger.info(f"📄 Results saved to {results_file}")
        return results_file

def load_domains_from_file(file_path: str) -> List[str]:
    """Load domains from various file formats"""
    domains = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            if file_path.endswith('.json'):
                data = json.load(f)
                
                if isinstance(data, list):
                    # Simple list of domains
                    domains = [d for d in data if isinstance(d, str)]
                elif isinstance(data, dict):
                    # Check various possible structures
                    if 'base_domains' in data:
                        domains = [d['base_domain'] for d in data['base_domains'] if 'base_domain' in d]
                    elif 'domains' in data:
                        domains = data['domains']
                    else:
                        # Try to extract domains from any domain-like field
                        for key, value in data.items():
                            if 'domain' in key.lower() and isinstance(value, list):
                                domains.extend(value)
                                break
            else:
                # Assume text file with one domain per line
                domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        # Clean and validate domains
        cleaned_domains = []
        for domain in domains:
            if isinstance(domain, str):
                domain = domain.strip().lower()
                if '.' in domain and len(domain) > 3:  # Basic domain validation
                    cleaned_domains.append(domain)
        
        logger.info(f"Loaded {len(cleaned_domains)} domains from {file_path}")
        return cleaned_domains
        
    except Exception as e:
        logger.error(f"Error loading domains from {file_path}: {e}")
        return []

async def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Reload domains using domain-backend API with local cache support')
    parser.add_argument('domains_file', help='File containing domains to reload (JSON or text)')
    parser.add_argument('--api-url', default='http://localhost:8001', help='Domain-backend API URL')
    parser.add_argument('--analysis-type', default='complete', 
                       choices=['basic', 'amass', 'services', 'tls', 'mx', 'tech', 'complete'],
                       help='Type of analysis to perform')
    parser.add_argument('--max-concurrent', type=int, default=3, help='Maximum concurrent requests')
    parser.add_argument('--delay', type=int, default=5, help='Delay between requests in seconds')
    parser.add_argument('--output-dir', default='.', help='Output directory for results')
    parser.add_argument('--cache-dir', default='../amass_cache', help='Path to amass cache directory')
    parser.add_argument('--cache-duration', type=int, default=168, help='Cache duration in hours')
    parser.add_argument('--no-cache', action='store_true', help='Skip local cache, always use API')
    parser.add_argument('--cache-only', action='store_true', help='Only use cache, do not call API')
    parser.add_argument('--limit', type=int, help='Limit number of domains to process (for testing)')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without executing')
    parser.add_argument('--amass-timeout', type=int, default=1200, help='Amass timeout in seconds (default: 1200 = 20 minutes)')
    parser.add_argument('--task-timeout', type=int, default=1800, help='Task monitoring timeout in seconds (default: 1800 = 30 minutes)')
    parser.add_argument('--subdomain-timeout', type=int, default=120, help='Timeout per subdomain analysis in seconds (default: 120 = 2 minutes)')
    
    args = parser.parse_args()
    
    # Load domains
    domains = load_domains_from_file(args.domains_file)
    if not domains:
        logger.error("No valid domains found in input file")
        sys.exit(1)
    
    # Apply limit if specified
    if args.limit:
        domains = domains[:args.limit]
        logger.info(f"Limited to first {args.limit} domains")
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    print("\\n" + "="*60)
    print("DOMAIN RELOAD CONFIGURATION")
    print("="*60)
    print(f"📁 Domains file: {args.domains_file}")
    print(f"🌐 API URL: {args.api_url}")
    print(f"📊 Analysis type: {args.analysis_type}")
    print(f"🏃 Max concurrent: {args.max_concurrent}")
    print(f"⏱️  Delay between requests: {args.delay}s")
    print(f"📄 Output directory: {args.output_dir}")
    print(f"📂 Cache directory: {args.cache_dir}")
    print(f"⏳ Cache duration: {args.cache_duration}h")
    print(f"🚫 No cache: {args.no_cache}")
    print(f"📂 Cache only: {args.cache_only}")
    print(f"⏱️  Amass timeout: {args.amass_timeout}s ({args.amass_timeout//60}m)")
    print(f"⏱️  Task timeout: {args.task_timeout}s ({args.task_timeout//60}m)")
    print(f"⏱️  Subdomain timeout: {args.subdomain_timeout}s")
    print(f"🎯 Domains to process: {len(domains)}")
    
    if args.dry_run:
        print("\\n🔍 DRY RUN - First 10 domains that would be processed:")
        for i, domain in enumerate(domains[:10]):
            print(f"   {i+1}. {domain}")
        if len(domains) > 10:
            print(f"   ... and {len(domains) - 10} more")
        print("\\n✅ Dry run completed")
        return
    
    # Estimate total time
    estimated_time_per_domain = 300  # 5 minutes average
    estimated_total_minutes = (len(domains) * estimated_time_per_domain) / args.max_concurrent / 60
    print(f"⏰ Estimated completion time: {estimated_total_minutes:.1f} minutes")
    
    print("\\n🚀 Starting domain reload...")
    
    # Process domains
    use_cache = not args.no_cache
    async with DomainReloader(args.api_url, args.max_concurrent, args.delay, 
                            args.cache_dir, args.cache_duration, args.cache_only,
                            args.amass_timeout, args.task_timeout, args.subdomain_timeout) as reloader:
        # Check API status
        if not await reloader.check_api_status():
            logger.error("API is not available. Please ensure domain-backend is running.")
            sys.exit(1)
        
        # Process domains
        results = await reloader.reload_domains_batch(domains, args.analysis_type, use_cache)
        
        # Save results
        results_file = reloader.save_results(args.output_dir)
        
        # Print final summary
        total_domains = len(results['success']) + len(results['failed'])
        success_rate = len(results['success']) / total_domains * 100 if total_domains > 0 else 0
        total_time = time.time() - reloader.start_time if reloader.start_time else 0
        
        print("\\n" + "="*60)
        print("DOMAIN RELOAD SUMMARY")
        print("="*60)
        print(f"📊 Total domains processed: {total_domains}")
        print(f"✅ Successful: {len(results['success'])}")
        print(f"❌ Failed: {len(results['failed'])}")
        print(f"📈 Success rate: {success_rate:.1f}%")
        print(f"⏱️  Total time: {total_time/60:.1f} minutes")
        print(f"🚀 Average rate: {total_domains/(total_time/60):.1f} domains/minute")
        print(f"📄 Results saved to: {results_file}")
        
        if results['failed']:
            print(f"\\n❌ Failed domains:")
            for result in results['failed'][:10]:  # Show first 10 failures
                print(f"   • {result['domain']}: {result.get('error', 'Unknown error')}")
            if len(results['failed']) > 10:
                print(f"   ... and {len(results['failed']) - 10} more failures")
        
        if results['success']:
            # Calculate averages for successful domains
            avg_subdomains = sum(r.get('subdomains_found', 0) for r in results['success']) / len(results['success'])
            avg_duration = sum(r.get('duration_seconds', 0) for r in results['success']) / len(results['success'])
            
            print(f"\\n📊 Success metrics:")
            print(f"   • Average subdomains found: {avg_subdomains:.1f}")
            print(f"   • Average processing time: {avg_duration:.1f}s")
        
        print("\\n✅ Domain reload completed!")

if __name__ == "__main__":
    asyncio.run(main())
