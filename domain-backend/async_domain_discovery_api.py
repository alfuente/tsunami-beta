#!/usr/bin/env python3
"""
async_domain_discovery_api.py - Asynchronous Domain Discovery Service API

This refactored service provides incremental graph building with async task management.
Based on requirements:
1. Amass subdomain and provider discovery with caching
2. Service discovery per domain/subdomain  
3. DNS analysis
4. MX record analysis with SPF, DMARC, DKIM
5. Website and TLS analysis
6. Web technology detection
7. Task progress tracking and status monitoring
8. Incremental graph updates

Each operation can be triggered independently and run asynchronously.
"""

from fastapi import FastAPI, HTTPException, Query, Path, BackgroundTasks, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Union
import asyncio
import uvicorn
import logging
import time
import json
import uuid
import redis
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import gzip
import hashlib
import os
import subprocess
import tempfile
import os
import threading
from concurrent.futures import ThreadPoolExecutor
import socket
import ssl
import dns.resolver
import dns.exception
import requests
import re

# Neo4j integration
try:
    from neo4j import GraphDatabase
    import neo4j
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False

# Import existing classes and utilities
try:
    from subdomain_relationship_discovery_v5 import (
        EnhancedProviderResolver, 
        ProviderInfo, 
        EnhancedDomainInfo,
        is_valid_domain_name
    )
    HAS_DISCOVERY_UTILS = True
except ImportError:
    HAS_DISCOVERY_UTILS = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Task status enumeration
class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"

class TaskType(str, Enum):
    AMASS_DISCOVERY = "amass_discovery"
    SERVICE_DISCOVERY = "service_discovery"
    DNS_ANALYSIS = "dns_analysis"
    MX_ANALYSIS = "mx_analysis"
    TLS_ANALYSIS = "tls_analysis"
    TECH_ANALYSIS = "tech_analysis"
    FULL_ANALYSIS = "full_analysis"
    BATCH_ANALYSIS = "batch_analysis"

# Pydantic models
class TaskInfo(BaseModel):
    task_id: str
    task_type: TaskType
    domain: str
    subdomain: Optional[str] = None
    status: TaskStatus
    progress: int = 0
    started_at: datetime
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = {}

class AmassResult(BaseModel):
    domain: str
    subdomains: List[str]
    providers: List[Dict[str, Any]]
    cached: bool = False
    discovered_at: datetime
    metadata: Dict[str, Any] = {}

class ServiceAnalysisResult(BaseModel):
    domain: str
    subdomain: Optional[str] = None
    services: List[Dict[str, Any]]
    ports_scanned: List[int] = []
    metadata: Dict[str, Any] = {}

class DNSAnalysisResult(BaseModel):
    domain: str
    subdomain: Optional[str] = None
    records: Dict[str, List[str]]
    nameservers: List[str] = []
    metadata: Dict[str, Any] = {}

class MXAnalysisResult(BaseModel):
    domain: str
    mx_records: List[Dict[str, Any]]
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    dkim_keys: List[Dict[str, Any]] = []
    metadata: Dict[str, Any] = {}

class TLSAnalysisResult(BaseModel):
    domain: str
    subdomain: Optional[str] = None
    certificate_info: Dict[str, Any]
    tls_version: Optional[str] = None
    cipher_suites: List[str] = []
    metadata: Dict[str, Any] = {}

class TechAnalysisResult(BaseModel):
    domain: str
    subdomain: Optional[str] = None
    technologies: List[Dict[str, Any]]
    web_server: Optional[str] = None
    cms: Optional[str] = None
    metadata: Dict[str, Any] = {}

@dataclass
class CachedAmassData:
    """Cached Amass results"""
    domain: str
    subdomains: List[str]
    providers: List[Dict[str, Any]]
    discovered_at: datetime
    raw_output: str
    metadata: Dict[str, Any]

class AsyncDomainDiscoveryService:
    """Main service class for async domain discovery"""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str, 
                 redis_host: str = "localhost", redis_port: int = 6379,
                 amass_cache_dir: str = "./amass_cache", cache_duration_hours: int = 168):
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_password = neo4j_password
        
        # Initialize local amass cache configuration
        self.amass_cache_dir = amass_cache_dir
        self.cache_duration_hours = cache_duration_hours
        self.metadata_dir = os.path.join(amass_cache_dir, "metadata")
        self.data_dir = os.path.join(amass_cache_dir, "data")
        
        # Initialize Redis for caching
        try:
            self.redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
            self.redis_client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.warning(f"Redis not available: {e}")
            self.redis_client = None
        
        # Initialize Neo4j
        if HAS_NEO4J:
            try:
                self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
                with self.driver.session() as session:
                    session.run("RETURN 1")
                logger.info("Neo4j connection established")
            except Exception as e:
                logger.error(f"Failed to connect to Neo4j: {e}")
                raise
        
        # Initialize provider resolver
        if HAS_DISCOVERY_UTILS:
            self.provider_resolver = EnhancedProviderResolver()
        
        # Task tracking
        self.active_tasks: Dict[str, TaskInfo] = {}
        self.executor = ThreadPoolExecutor(max_workers=10)
        
        # Amass cache TTL (1 week = 604800 seconds)
        self.amass_cache_ttl = 7 * 24 * 3600

    def close(self):
        """Clean up resources"""
        if hasattr(self, 'driver'):
            self.driver.close()
        if self.executor:
            self.executor.shutdown(wait=True)

    def _get_cache_key(self, prefix: str, domain: str, subdomain: str = None) -> str:
        """Generate cache key"""
        if subdomain:
            return f"{prefix}:{domain}:{subdomain}"
        return f"{prefix}:{domain}"

    def _cache_amass_results(self, domain: str, results: CachedAmassData) -> None:
        """Cache Amass results in Redis"""
        if not self.redis_client:
            return
        
        cache_key = self._get_cache_key("amass", domain)
        cache_data = {
            "domain": results.domain,
            "subdomains": json.dumps(results.subdomains),
            "providers": json.dumps(results.providers),
            "discovered_at": results.discovered_at.isoformat(),
            "raw_output": results.raw_output,
            "metadata": json.dumps(results.metadata)
        }
        
        try:
            self.redis_client.hmset(cache_key, cache_data)
            self.redis_client.expire(cache_key, self.amass_cache_ttl)
            logger.info(f"Cached Amass results for {domain}")
        except Exception as e:
            logger.warning(f"Failed to cache Amass results: {e}")

    def _generate_domain_hash(self, domain: str) -> str:
        """Generate hash for domain (same as standalone_amass_executor.sh)"""
        return hashlib.sha256(domain.encode()).hexdigest()[:16]

    def _is_local_cache_valid(self, domain: str) -> bool:
        """Check if local cache entry exists and is valid"""
        if not os.path.exists(self.metadata_dir):
            return False
        
        domain_hash = self._generate_domain_hash(domain)
        metadata_file = os.path.join(self.metadata_dir, f"{domain_hash}.json")
        
        if not os.path.exists(metadata_file):
            return False
        
        try:
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            # Check if metadata is complete
            if 'timestamp' not in metadata or 'subdomain_count' not in metadata:
                logger.debug(f"Invalid local cache metadata for {domain}")
                return False
            
            # Check if cache is expired
            timestamp_str = metadata['timestamp']
            cache_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            current_time = datetime.now()
            age_hours = (current_time - cache_time.replace(tzinfo=None)).total_seconds() / 3600
            
            if age_hours > self.cache_duration_hours:
                logger.debug(f"Local cache expired for {domain} (age: {age_hours:.1f}h)")
                return False
            
            logger.info(f"Valid local cache found for {domain} (age: {age_hours:.1f}h)")
            return True
            
        except Exception as e:
            logger.debug(f"Error checking local cache for {domain}: {e}")
            return False

    def _get_local_cache_results(self, domain: str) -> Optional[List[str]]:
        """Get cached subdomains from local cache"""
        if not self._is_local_cache_valid(domain):
            return None
            
        try:
            domain_hash = self._generate_domain_hash(domain)
            data_file = os.path.join(self.data_dir, f"{domain_hash}.json.gz")
            
            if not os.path.exists(data_file):
                return None
            
            with gzip.open(data_file, 'rt', encoding='utf-8') as f:
                subdomains = json.load(f)
            
            if isinstance(subdomains, list):
                logger.info(f"Retrieved {len(subdomains)} subdomains from local cache for {domain}")
                return subdomains
            else:
                logger.warning(f"Invalid local cache format for {domain}")
                return None
                
        except Exception as e:
            logger.error(f"Error reading local cache for {domain}: {e}")
            return None

    def _get_cached_amass_results(self, domain: str) -> Optional[CachedAmassData]:
        """Get cached Amass results from local cache first, then Redis"""
        
        # Try local cache first (from standalone_amass_executor.sh)
        local_cache = self._get_local_cache_results(domain)
        if local_cache:
            logger.info(f"Using local cache for {domain} ({len(local_cache)} subdomains)")
            return CachedAmassData(
                domain=domain,
                subdomains=local_cache,
                providers=[],  # Local cache doesn't have provider info
                discovered_at=datetime.now(),
                raw_output="",
                metadata={"source": "local_cache", "count": len(local_cache)}
            )
        
        # Fallback to Redis cache
        if not self.redis_client:
            return None
            
        cache_key = self._get_cache_key("amass", domain)
        
        try:
            cached_data = self.redis_client.hgetall(cache_key)
            if not cached_data:
                return None
            
            return CachedAmassData(
                domain=cached_data["domain"],
                subdomains=json.loads(cached_data["subdomains"]),
                providers=json.loads(cached_data["providers"]),
                discovered_at=datetime.fromisoformat(cached_data["discovered_at"]),
                raw_output=cached_data["raw_output"],
                metadata=json.loads(cached_data["metadata"])
            )
        except Exception as e:
            logger.warning(f"Failed to get cached Amass results: {e}")
            return None

    async def run_amass_discovery(self, domain: str, task_id: str, timeout: int = 900) -> AmassResult:
        """Run Amass discovery with caching"""
        logger.info(f"Starting Amass discovery for {domain} (task: {task_id})")
        
        # Update task status
        if task_id in self.active_tasks:
            self.active_tasks[task_id].status = TaskStatus.RUNNING
            self.active_tasks[task_id].progress = 10
        
        # Check cache first
        cached_results = self._get_cached_amass_results(domain)
        if cached_results:
            logger.info(f"Using cached Amass results for {domain}")
            result = AmassResult(
                domain=domain,
                subdomains=cached_results.subdomains,
                providers=cached_results.providers,
                cached=True,
                discovered_at=cached_results.discovered_at,
                metadata=cached_results.metadata
            )
            
            if task_id in self.active_tasks:
                self.active_tasks[task_id].status = TaskStatus.COMPLETED
                self.active_tasks[task_id].progress = 100
                self.active_tasks[task_id].result = result.dict()
                self.active_tasks[task_id].completed_at = datetime.now()
            
            return result
        
        # Run Amass in executor
        loop = asyncio.get_event_loop()
        
        def run_amass():
            return self._run_amass_sync(domain, task_id, timeout)
        
        try:
            result = await loop.run_in_executor(self.executor, run_amass)
            
            # Update task status
            if task_id in self.active_tasks:
                self.active_tasks[task_id].status = TaskStatus.COMPLETED
                self.active_tasks[task_id].progress = 100
                self.active_tasks[task_id].result = result.dict()
                self.active_tasks[task_id].completed_at = datetime.now()
            
            return result
            
        except Exception as e:
            logger.error(f"Amass discovery failed for {domain}: {e}")
            if task_id in self.active_tasks:
                self.active_tasks[task_id].status = TaskStatus.FAILED
                self.active_tasks[task_id].error = str(e)
                self.active_tasks[task_id].completed_at = datetime.now()
            raise

    def _extract_providers_from_amass_output(self, amass_output_file: str, domain: str) -> list:
        """Extract provider information from amass output using the same logic as add_providers_from_amass.py"""
        providers_found = []
        
        # Provider mappings from the standalone script
        ASN_PROVIDER_MAPPING = {
            'AS22047': {'name': 'telefonica_chile', 'confidence': 0.9},
            'AS27651': {'name': 'entel_chile', 'confidence': 0.9},
            'AS14259': {'name': 'gtd_chile', 'confidence': 0.9},
            'AS7418': {'name': 'telefonica_chile', 'confidence': 0.9},
            'AS19551': {'name': 'imperva', 'confidence': 0.9},
            'AS13335': {'name': 'cloudflare', 'confidence': 0.9},
        }
        
        ORG_PROVIDER_MAPPING = {
            'google': {'name': 'google', 'confidence': 0.8},
            'microsoft': {'name': 'microsoft', 'confidence': 0.8},
            'amazon': {'name': 'amazon', 'confidence': 0.8},
            'cloudflare': {'name': 'cloudflare', 'confidence': 0.8},
            'akamai': {'name': 'akamai', 'confidence': 0.8},
            'fastly': {'name': 'fastly', 'confidence': 0.8},
            'azure': {'name': 'microsoft', 'confidence': 0.7},
            'aws': {'name': 'amazon', 'confidence': 0.7},
            'outlook': {'name': 'microsoft', 'confidence': 0.7},
            'github': {'name': 'github', 'confidence': 0.8},
            'heroku': {'name': 'heroku', 'confidence': 0.8},
            'salesforce': {'name': 'salesforce', 'confidence': 0.8},
            'telefonica': {'name': 'telefonica_chile', 'confidence': 0.7},
            'entel': {'name': 'entel_chile', 'confidence': 0.7},
            'gtd': {'name': 'gtd_chile', 'confidence': 0.7},
        }
        
        try:
            # Look at stderr output which contains the structured data
            stderr_file = amass_output_file.replace('.txt', '_stderr.txt')
            if os.path.exists(stderr_file):
                amass_output_file = stderr_file
                
            with open(amass_output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Look for CNAME records that indicate providers
                    if 'cname_record' in line and '-->' in line:
                        self._process_cname_for_providers(line, domain, providers_found, ORG_PROVIDER_MAPPING)
                    
                    # Look for MX records
                    elif 'mx_record' in line and '-->' in line:
                        self._process_mx_for_providers(line, domain, providers_found, ORG_PROVIDER_MAPPING)
                    
                    # Look for NS records
                    elif 'ns_record' in line and '-->' in line:
                        self._process_ns_for_providers(line, domain, providers_found, ORG_PROVIDER_MAPPING)
                        
        except Exception as e:
            logger.debug(f"Error extracting providers from amass output: {e}")
        
        return providers_found
    
    def _process_cname_for_providers(self, line: str, domain: str, providers_found: list, mapping: dict):
        """Process CNAME records to find providers"""
        try:
            parts = line.split(' --> ')
            if len(parts) >= 3:
                source_fqdn = parts[0].split(' ')[0]
                target_fqdn = parts[2].split(' ')[0]
                
                # Check if target indicates a provider
                target_lower = target_fqdn.lower()
                for pattern, provider_info in mapping.items():
                    if pattern in target_lower:
                        providers_found.append({
                            'name': provider_info['name'],
                            'confidence': provider_info['confidence'],
                            'source': 'amass_cname',
                            'subdomain': source_fqdn,
                            'ip': '',
                            'evidence': f"cname_record -> {target_fqdn}"
                        })
                        break
        except Exception as e:
            logger.debug(f"Error processing CNAME: {e}")
    
    def _process_mx_for_providers(self, line: str, domain: str, providers_found: list, mapping: dict):
        """Process MX records to find providers"""
        try:
            parts = line.split(' --> ')
            if len(parts) >= 3:
                source_fqdn = parts[0].split(' ')[0]
                target_fqdn = parts[2].split(' ')[0]
                
                # Check if target indicates a provider
                target_lower = target_fqdn.lower()
                for pattern, provider_info in mapping.items():
                    if pattern in target_lower:
                        providers_found.append({
                            'name': provider_info['name'],
                            'confidence': provider_info['confidence'],
                            'source': 'amass_mx',
                            'subdomain': source_fqdn,
                            'ip': '',
                            'evidence': f"mx_record -> {target_fqdn}"
                        })
                        break
        except Exception as e:
            logger.debug(f"Error processing MX: {e}")
    
    def _process_ns_for_providers(self, line: str, domain: str, providers_found: list, mapping: dict):
        """Process NS records to find providers"""
        try:
            parts = line.split(' --> ')
            if len(parts) >= 3:
                source_fqdn = parts[0].split(' ')[0]
                target_fqdn = parts[2].split(' ')[0]
                
                # Check if target indicates a provider
                target_lower = target_fqdn.lower()
                for pattern, provider_info in mapping.items():
                    if pattern in target_lower:
                        providers_found.append({
                            'name': provider_info['name'],
                            'confidence': provider_info['confidence'],
                            'source': 'amass_ns',
                            'subdomain': source_fqdn,
                            'ip': '',
                            'evidence': f"ns_record -> {target_fqdn}"
                        })
                        break
        except Exception as e:
            logger.debug(f"Error processing NS: {e}")

    def _run_amass_sync(self, domain: str, task_id: str, timeout: int) -> AmassResult:
        """Synchronous Amass execution using direct binary"""
        # Create temp file for output
        temp_filename = f"/tmp/amass_output_{domain}_{int(time.time())}.txt"
        
        try:
            # Update progress
            if task_id in self.active_tasks:
                self.active_tasks[task_id].progress = 30
            
            # Run Amass command directly with active discovery and brute forcing
            cmd = [
                '/usr/local/bin/amass', 'enum',
                '-d', domain,
                '-active',
                '-brute',
                '-o', temp_filename,
                '-timeout', str(max(5, timeout // 60)),
                '-v'
            ]
            
            logger.info(f"Running Amass command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 60)
            
            if result.returncode != 0:
                raise Exception(f"Amass command failed: {result.stderr}")
            
            # Update progress
            if task_id in self.active_tasks:
                self.active_tasks[task_id].progress = 70
            
            # Parse results from Amass structured output
            subdomains = set()  # Use set to avoid duplicates
            providers = []
            
            import re
            subdomain_pattern = re.compile(r'([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')')
            
            with open(temp_filename, 'r') as f:
                content = f.read()
                # Extract all subdomains using regex
                matches = subdomain_pattern.findall(content)
                for match in matches:
                    if is_valid_domain_name(match):
                        subdomains.add(match)
                        
            # Extract provider information from amass output
            providers.extend(self._extract_providers_from_amass_output(temp_filename, domain))
            
            # Convert set back to list
            subdomains = list(subdomains)
            
            # Update progress
            if task_id in self.active_tasks:
                self.active_tasks[task_id].progress = 90
            
            # Resolve providers for discovered subdomains (sample for performance)
            sample_subdomains = subdomains[:10] if len(subdomains) > 10 else subdomains
            for subdomain in sample_subdomains:
                try:
                    ip_addresses = []
                    try:
                        answers = dns.resolver.resolve(subdomain, 'A')
                        ip_addresses = [str(answer) for answer in answers]
                    except dns.exception.DNSException:
                        continue
                    
                    for ip in ip_addresses:
                        if HAS_DISCOVERY_UTILS:
                            provider_info = self.provider_resolver.resolve_provider_comprehensive(ip, subdomain)
                            if provider_info.name != "unknown":
                                providers.append({
                                    "name": provider_info.name,
                                    "confidence": provider_info.confidence,
                                    "source": provider_info.source,
                                    "subdomain": subdomain,
                                    "ip": ip,
                                    "country": provider_info.country,
                                    "tld": provider_info.tld
                                })
                except Exception as e:
                    logger.debug(f"Provider resolution failed for {subdomain}: {e}")
            
            # Create result
            result_data = AmassResult(
                domain=domain,
                subdomains=subdomains,
                providers=providers,
                cached=False,
                discovered_at=datetime.now(),
                metadata={
                    "total_subdomains": len(subdomains),
                    "total_providers": len(providers),
                    "timeout_used": timeout,
                    "amass_output": result.stdout
                }
            )
            
            # Cache results
            cached_data = CachedAmassData(
                domain=domain,
                subdomains=subdomains,
                providers=providers,
                discovered_at=datetime.now(),
                raw_output=result.stdout,
                metadata=result_data.metadata
            )
            self._cache_amass_results(domain, cached_data)
            
            # Save to Neo4j
            self._save_amass_to_neo4j(result_data)
            
            return result_data
            
        finally:
            if os.path.exists(temp_filename):
                os.unlink(temp_filename)

    def _save_amass_to_neo4j(self, result: AmassResult):
        """Save Amass results to Neo4j graph"""
        if not HAS_NEO4J:
            return
        
        try:
            with self.driver.session() as session:
                session.write_transaction(self._create_amass_nodes, result)
            logger.info(f"Saved Amass results for {result.domain} to Neo4j")
        except Exception as e:
            logger.error(f"Failed to save Amass results to Neo4j: {e}")

    def _create_amass_nodes(self, tx, result: AmassResult):
        """Create Neo4j nodes for Amass results"""
        current_time = datetime.now().isoformat()
        
        # Create or update base domain
        tx.run("""
            MERGE (d:Domain {fqdn: $domain})
            SET d.last_amass_scan = $current_time,
                d.subdomain_count = $subdomain_count,
                d.provider_count = $provider_count,
                d.updated_at = $current_time
        """, domain=result.domain, current_time=current_time,
             subdomain_count=len(result.subdomains),
             provider_count=len(result.providers))
        
        # Create subdomain nodes
        for subdomain in result.subdomains:
            tx.run("""
                MERGE (s:Subdomain {fqdn: $subdomain})
                SET s.discovery_method = 'amass',
                    s.discovered_at = $current_time,
                    s.updated_at = $current_time
                WITH s
                MATCH (d:Domain {fqdn: $domain})
                MERGE (d)-[r:HAS_SUBDOMAIN]->(s)
                SET r.discovered_via = 'amass',
                    r.created_at = $current_time
            """, subdomain=subdomain, domain=result.domain, current_time=current_time)
        
        # Create provider nodes using real provider IDs
        for provider in result.providers:
            # Map provider name to real provider ID
            provider_name = provider['name'].lower()
            provider_id = provider_name  # Use the provider name as ID initially
            
            # Map old provider names to new provider IDs
            provider_mapping = {
                'google': 'google',
                'amazon': 'amazon', 
                'microsoft': 'microsoft',
                'cloudflare': 'cloudflare',
                'github': 'github',
                'heroku': 'heroku',
                'salesforce': 'salesforce',
                'fastly': 'fastly',
                'digitalocean': 'digitalocean',
                'akamai': 'akamai',
                'linode': 'linode',
                'vultr': 'vultr',
                'ovh': 'ovh',
                'hetzner': 'hetzner',
                'godaddy': 'godaddy',
                'namecheap': 'namecheap'
            }
            
            # Use real provider ID if available
            if provider_name in provider_mapping:
                provider_id = provider_mapping[provider_name]
            
            # Only connect to existing providers from our curated list
            result = tx.run("""
                MATCH (existing:Provider {id: $provider_id})
                WITH existing
                MATCH (s:Subdomain {fqdn: $subdomain})
                MERGE (s)-[r:USES_PROVIDER]->(existing)
                SET r.confidence = $confidence,
                    r.source = $source,
                    r.ip = $ip,
                    r.created_at = $current_time,
                    r.updated_at = $current_time
                RETURN existing.name as provider_name
            """, provider_id=provider_id, subdomain=provider['subdomain'],
                 confidence=provider['confidence'], source=provider['source'],
                 ip=provider['ip'], current_time=current_time)
            
            # Log if connection was made or if provider was ignored
            connection_result = result.single()
            if connection_result:
                logger.debug(f"Connected {provider['subdomain']} -> {connection_result['provider_name']}")
            else:
                logger.debug(f"Ignored provider '{provider['name']}' (not in curated list) for {provider['subdomain']}")

    async def run_service_discovery(self, domain: str, subdomain: Optional[str], task_id: str) -> ServiceAnalysisResult:
        """Run service discovery for domain or subdomain"""
        target = subdomain if subdomain else domain
        logger.info(f"Starting service discovery for {target} (task: {task_id})")
        
        # Update task status
        if task_id in self.active_tasks:
            self.active_tasks[task_id].status = TaskStatus.RUNNING
            self.active_tasks[task_id].progress = 20
        
        loop = asyncio.get_event_loop()
        
        def run_service_scan():
            return self._run_service_scan_sync(domain, subdomain, task_id)
        
        try:
            result = await loop.run_in_executor(self.executor, run_service_scan)
            
            # Update task status
            if task_id in self.active_tasks:
                self.active_tasks[task_id].status = TaskStatus.COMPLETED
                self.active_tasks[task_id].progress = 100
                self.active_tasks[task_id].result = result.dict()
                self.active_tasks[task_id].completed_at = datetime.now()
            
            return result
            
        except Exception as e:
            logger.error(f"Service discovery failed for {target}: {e}")
            if task_id in self.active_tasks:
                self.active_tasks[task_id].status = TaskStatus.FAILED
                self.active_tasks[task_id].error = str(e)
                self.active_tasks[task_id].completed_at = datetime.now()
            raise

    def _run_service_scan_sync(self, domain: str, subdomain: Optional[str], task_id: str) -> ServiceAnalysisResult:
        """Synchronous service scanning"""
        target = subdomain if subdomain else domain
        services = []
        ports_scanned = []
        
        # Common ports to check
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443]
        
        # Update progress
        if task_id in self.active_tasks:
            self.active_tasks[task_id].progress = 40
        
        for i, port in enumerate(common_ports):
            try:
                sock = socket.create_connection((target, port), timeout=2)
                sock.close()
                
                service_info = {
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": self._identify_service(port),
                    "detected_at": datetime.now().isoformat()
                }
                services.append(service_info)
                ports_scanned.append(port)
                
                logger.debug(f"Found open port {port} on {target}")
                
            except (socket.timeout, socket.error):
                pass
            
            # Update progress
            if task_id in self.active_tasks:
                progress = 40 + int((i + 1) / len(common_ports) * 50)
                self.active_tasks[task_id].progress = progress
        
        result = ServiceAnalysisResult(
            domain=domain,
            subdomain=subdomain,
            services=services,
            ports_scanned=common_ports,
            metadata={
                "total_services_found": len(services),
                "scan_method": "tcp_connect",
                "target": target
            }
        )
        
        # Save to Neo4j
        self._save_services_to_neo4j(result)
        
        return result

    def _identify_service(self, port: int) -> str:
        """Identify service based on port number"""
        service_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 135: "rpc", 139: "netbios", 143: "imap",
            443: "https", 993: "imaps", 995: "pop3s", 1723: "pptp", 
            3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
            8080: "http-alt", 8443: "https-alt"
        }
        return service_map.get(port, "unknown")

    def _save_services_to_neo4j(self, result: ServiceAnalysisResult):
        """Save service results to Neo4j"""
        if not HAS_NEO4J:
            return
        
        target = result.subdomain if result.subdomain else result.domain
        services_count = len(result.services)
        
        try:
            with self.driver.session() as session:
                session.write_transaction(self._create_service_nodes, result)
            
            # Detailed logging
            if services_count > 0:
                services_list = [f"{s['service']}:{s['port']}" for s in result.services]
                logger.info(f"Saved {services_count} services to Neo4j for {target}: {', '.join(services_list)}")
            else:
                logger.info(f"No services found for {target}, updated Neo4j with empty service list")
                
        except Exception as e:
            logger.error(f"Failed to save services to Neo4j for {target}: {e}")

    def _create_service_nodes(self, tx, result: ServiceAnalysisResult):
        """Create Neo4j nodes for services"""
        current_time = datetime.now().isoformat()
        target = result.subdomain if result.subdomain else result.domain
        
        for service in result.services:
            service_id = f"{target}_{service['port']}_{service['protocol']}"
            tx.run("""
                MERGE (srv:Service {id: $service_id})
                SET srv.port = $port,
                    srv.protocol = $protocol,
                    srv.service_name = $service_name,
                    srv.state = $state,
                    srv.detected_at = $detected_at,
                    srv.updated_at = $current_time
                WITH srv
                MATCH (n {fqdn: $target})
                MERGE (n)-[r:RUNS_SERVICE]->(srv)
                SET r.created_at = $current_time
            """, service_id=service_id, port=service['port'], 
                 protocol=service['protocol'], service_name=service['service'],
                 state=service['state'], detected_at=service['detected_at'],
                 target=target, current_time=current_time)

    async def run_dns_analysis(self, domain: str, subdomain: Optional[str], task_id: str) -> DNSAnalysisResult:
        """Run DNS analysis for domain or subdomain"""
        target = subdomain if subdomain else domain
        logger.info(f"Starting DNS analysis for {target} (task: {task_id})")
        
        # Update task status
        if task_id in self.active_tasks:
            self.active_tasks[task_id].status = TaskStatus.RUNNING
            self.active_tasks[task_id].progress = 20
        
        loop = asyncio.get_event_loop()
        
        def run_dns_scan():
            return self._run_dns_analysis_sync(domain, subdomain, task_id)
        
        try:
            result = await loop.run_in_executor(self.executor, run_dns_scan)
            
            # Update task status
            if task_id in self.active_tasks:
                self.active_tasks[task_id].status = TaskStatus.COMPLETED
                self.active_tasks[task_id].progress = 100
                self.active_tasks[task_id].result = result.dict()
                self.active_tasks[task_id].completed_at = datetime.now()
            
            return result
            
        except Exception as e:
            logger.error(f"DNS analysis failed for {target}: {e}")
            if task_id in self.active_tasks:
                self.active_tasks[task_id].status = TaskStatus.FAILED
                self.active_tasks[task_id].error = str(e)
                self.active_tasks[task_id].completed_at = datetime.now()
            raise

    def _run_dns_analysis_sync(self, domain: str, subdomain: Optional[str], task_id: str) -> DNSAnalysisResult:
        """Synchronous DNS analysis"""
        target = subdomain if subdomain else domain
        records = {}
        nameservers = []
        
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
        
        # Update progress
        if task_id in self.active_tasks:
            self.active_tasks[task_id].progress = 30
        
        for i, record_type in enumerate(record_types):
            try:
                answers = dns.resolver.resolve(target, record_type)
                records[record_type] = [str(answer) for answer in answers]
                
                if record_type == 'NS':
                    nameservers = records[record_type]
                
            except dns.exception.DNSException as e:
                records[record_type] = []
                logger.debug(f"No {record_type} records for {target}: {e}")
            
            # Update progress
            if task_id in self.active_tasks:
                progress = 30 + int((i + 1) / len(record_types) * 60)
                self.active_tasks[task_id].progress = progress
        
        result = DNSAnalysisResult(
            domain=domain,
            subdomain=subdomain,
            records=records,
            nameservers=nameservers,
            metadata={
                "target": target,
                "record_types_checked": record_types,
                "total_records": sum(len(records[rt]) for rt in records)
            }
        )
        
        # Save to Neo4j
        self._save_dns_to_neo4j(result)
        
        return result

    def _save_dns_to_neo4j(self, result: DNSAnalysisResult):
        """Save DNS results to Neo4j"""
        if not HAS_NEO4J:
            return
        
        try:
            with self.driver.session() as session:
                session.write_transaction(self._create_dns_nodes, result)
            logger.info(f"Saved DNS results to Neo4j")
        except Exception as e:
            logger.error(f"Failed to save DNS to Neo4j: {e}")

    def _create_dns_nodes(self, tx, result: DNSAnalysisResult):
        """Create Neo4j nodes for DNS records"""
        current_time = datetime.now().isoformat()
        target = result.subdomain if result.subdomain else result.domain
        
        # Update target node with DNS info
        tx.run("""
            MATCH (n {fqdn: $target})
            SET n.dns_records = $dns_records,
                n.nameservers = $nameservers,
                n.dns_analyzed_at = $current_time,
                n.updated_at = $current_time
        """, target=target, dns_records=json.dumps(result.records),
             nameservers=result.nameservers, current_time=current_time)

    async def run_mx_analysis(self, domain: str, task_id: str) -> MXAnalysisResult:
        """Run MX record analysis with SPF, DMARC, DKIM"""
        logger.info(f"Starting MX analysis for {domain} (task: {task_id})")
        
        # Update task status
        if task_id in self.active_tasks:
            self.active_tasks[task_id].status = TaskStatus.RUNNING
            self.active_tasks[task_id].progress = 20
        
        loop = asyncio.get_event_loop()
        
        def run_mx_scan():
            return self._run_mx_analysis_sync(domain, task_id)
        
        try:
            result = await loop.run_in_executor(self.executor, run_mx_scan)
            
            # Update task status
            if task_id in self.active_tasks:
                self.active_tasks[task_id].status = TaskStatus.COMPLETED
                self.active_tasks[task_id].progress = 100
                self.active_tasks[task_id].result = result.dict()
                self.active_tasks[task_id].completed_at = datetime.now()
            
            return result
            
        except Exception as e:
            logger.error(f"MX analysis failed for {domain}: {e}")
            if task_id in self.active_tasks:
                self.active_tasks[task_id].status = TaskStatus.FAILED
                self.active_tasks[task_id].error = str(e)
                self.active_tasks[task_id].completed_at = datetime.now()
            raise

    def _run_mx_analysis_sync(self, domain: str, task_id: str) -> MXAnalysisResult:
        """Synchronous MX analysis"""
        mx_records = []
        spf_record = None
        dmarc_record = None
        dkim_keys = []
        
        # Update progress
        if task_id in self.active_tasks:
            self.active_tasks[task_id].progress = 30
        
        # Get MX records
        try:
            mx_answers = dns.resolver.resolve(domain, 'MX')
            for mx in mx_answers:
                mx_records.append({
                    "priority": mx.preference,
                    "exchange": str(mx.exchange),
                    "mx_record": str(mx)
                })
        except dns.exception.DNSException:
            logger.debug(f"No MX records for {domain}")
        
        # Update progress
        if task_id in self.active_tasks:
            self.active_tasks[task_id].progress = 50
        
        # Get SPF record
        try:
            txt_answers = dns.resolver.resolve(domain, 'TXT')
            for txt in txt_answers:
                txt_str = str(txt).strip('"')
                if txt_str.startswith('v=spf1'):
                    spf_record = txt_str
                    break
        except dns.exception.DNSException:
            logger.debug(f"No SPF record for {domain}")
        
        # Update progress
        if task_id in self.active_tasks:
            self.active_tasks[task_id].progress = 70
        
        # Get DMARC record
        try:
            dmarc_domain = f"_dmarc.{domain}"
            dmarc_answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for txt in dmarc_answers:
                txt_str = str(txt).strip('"')
                if txt_str.startswith('v=DMARC1'):
                    dmarc_record = txt_str
                    break
        except dns.exception.DNSException:
            logger.debug(f"No DMARC record for {domain}")
        
        # Update progress
        if task_id in self.active_tasks:
            self.active_tasks[task_id].progress = 90
        
        # Check for common DKIM selectors
        common_selectors = ['default', 'selector1', 'selector2', 'google', 'mail', 'k1']
        for selector in common_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                dkim_answers = dns.resolver.resolve(dkim_domain, 'TXT')
                for txt in dkim_answers:
                    txt_str = str(txt).strip('"')
                    if 'k=' in txt_str or 'p=' in txt_str:
                        dkim_keys.append({
                            "selector": selector,
                            "record": txt_str,
                            "domain": dkim_domain
                        })
                        break
            except dns.exception.DNSException:
                continue
        
        result = MXAnalysisResult(
            domain=domain,
            mx_records=mx_records,
            spf_record=spf_record,
            dmarc_record=dmarc_record,
            dkim_keys=dkim_keys,
            metadata={
                "mx_count": len(mx_records),
                "has_spf": spf_record is not None,
                "has_dmarc": dmarc_record is not None,
                "dkim_selectors_found": len(dkim_keys)
            }
        )
        
        # Save to Neo4j
        self._save_mx_to_neo4j(result)
        
        return result

    def _save_mx_to_neo4j(self, result: MXAnalysisResult):
        """Save MX results to Neo4j"""
        if not HAS_NEO4J:
            return
        
        try:
            with self.driver.session() as session:
                session.write_transaction(self._create_mx_nodes, result)
            logger.info(f"Saved MX results to Neo4j")
        except Exception as e:
            logger.error(f"Failed to save MX to Neo4j: {e}")

    def _create_mx_nodes(self, tx, result: MXAnalysisResult):
        """Create Neo4j nodes for MX records"""
        current_time = datetime.now().isoformat()
        
        # Update domain with email security info
        tx.run("""
            MATCH (d:Domain {fqdn: $domain})
            SET d.mx_records = $mx_records,
                d.spf_record = $spf_record,
                d.dmarc_record = $dmarc_record,
                d.dkim_keys = $dkim_keys,
                d.mx_analyzed_at = $current_time,
                d.updated_at = $current_time
        """, domain=result.domain,
             mx_records=json.dumps(result.mx_records),
             spf_record=result.spf_record,
             dmarc_record=result.dmarc_record,
             dkim_keys=json.dumps(result.dkim_keys),
             current_time=current_time)

    async def run_tls_analysis(self, domain: str, subdomain: Optional[str], task_id: str) -> TLSAnalysisResult:
        """Run TLS analysis for domain or subdomain"""
        target = subdomain if subdomain else domain
        logger.info(f"Starting TLS analysis for {target} (task: {task_id})")
        
        # Update task status
        if task_id in self.active_tasks:
            self.active_tasks[task_id].status = TaskStatus.RUNNING
            self.active_tasks[task_id].progress = 20
        
        loop = asyncio.get_event_loop()
        
        def run_tls_scan():
            return self._run_tls_analysis_sync(domain, subdomain, task_id)
        
        try:
            result = await loop.run_in_executor(self.executor, run_tls_scan)
            
            # Update task status
            if task_id in self.active_tasks:
                self.active_tasks[task_id].status = TaskStatus.COMPLETED
                self.active_tasks[task_id].progress = 100
                self.active_tasks[task_id].result = result.dict()
                self.active_tasks[task_id].completed_at = datetime.now()
            
            return result
            
        except Exception as e:
            logger.error(f"TLS analysis failed for {target}: {e}")
            if task_id in self.active_tasks:
                self.active_tasks[task_id].status = TaskStatus.FAILED
                self.active_tasks[task_id].error = str(e)
                self.active_tasks[task_id].completed_at = datetime.now()
            raise

    def _run_tls_analysis_sync(self, domain: str, subdomain: Optional[str], task_id: str) -> TLSAnalysisResult:
        """Synchronous TLS analysis"""
        target = subdomain if subdomain else domain
        certificate_info = {}
        tls_version = None
        cipher_suites = []
        
        # Update progress
        if task_id in self.active_tasks:
            self.active_tasks[task_id].progress = 40
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    tls_version = ssock.version()
                    # Fix cipher suite formatting - convert tuple to string
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        cipher_suites = [str(cipher_info[0]) if isinstance(cipher_info, tuple) else str(cipher_info)]
                    else:
                        cipher_suites = []
                    
                    cert = ssock.getpeercert()
                    certificate_info = {
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "version": cert.get('version'),
                        "serial_number": str(cert.get('serialNumber')),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter'),
                        "subject_alt_name": [x[1] for x in cert.get('subjectAltName', [])],
                        "signature_algorithm": cert.get('signatureAlgorithm')
                    }
        
        except Exception as e:
            logger.debug(f"TLS analysis failed for {target}: {e}")
            certificate_info = {"error": str(e)}
        
        # Update progress
        if task_id in self.active_tasks:
            self.active_tasks[task_id].progress = 80
        
        result = TLSAnalysisResult(
            domain=domain,
            subdomain=subdomain,
            certificate_info=certificate_info,
            tls_version=tls_version,
            cipher_suites=cipher_suites,
            metadata={
                "target": target,
                "has_valid_cert": "error" not in certificate_info,
                "tls_version": tls_version
            }
        )
        
        # Save to Neo4j
        self._save_tls_to_neo4j(result)
        
        return result

    def _save_tls_to_neo4j(self, result: TLSAnalysisResult):
        """Save TLS results to Neo4j"""
        if not HAS_NEO4J:
            return
        
        try:
            with self.driver.session() as session:
                session.write_transaction(self._create_tls_nodes, result)
            logger.info(f"Saved TLS results to Neo4j")
        except Exception as e:
            logger.error(f"Failed to save TLS to Neo4j: {e}")

    def _create_tls_nodes(self, tx, result: TLSAnalysisResult):
        """Create Neo4j nodes for TLS info"""
        current_time = datetime.now().isoformat()
        target = result.subdomain if result.subdomain else result.domain
        
        # Update target node with TLS info
        tx.run("""
            MATCH (n {fqdn: $target})
            SET n.certificate_info = $cert_info,
                n.tls_version = $tls_version,
                n.cipher_suites = $cipher_suites,
                n.tls_analyzed_at = $current_time,
                n.updated_at = $current_time
        """, target=target,
             cert_info=json.dumps(result.certificate_info),
             tls_version=result.tls_version,
             cipher_suites=result.cipher_suites,
             current_time=current_time)

    async def run_tech_analysis(self, domain: str, subdomain: Optional[str], task_id: str) -> TechAnalysisResult:
        """Run web technology analysis"""
        target = subdomain if subdomain else domain
        logger.info(f"Starting tech analysis for {target} (task: {task_id})")
        
        # Update task status
        if task_id in self.active_tasks:
            self.active_tasks[task_id].status = TaskStatus.RUNNING
            self.active_tasks[task_id].progress = 20
        
        loop = asyncio.get_event_loop()
        
        def run_tech_scan():
            return self._run_tech_analysis_sync(domain, subdomain, task_id)
        
        try:
            result = await loop.run_in_executor(self.executor, run_tech_scan)
            
            # Update task status
            if task_id in self.active_tasks:
                self.active_tasks[task_id].status = TaskStatus.COMPLETED
                self.active_tasks[task_id].progress = 100
                self.active_tasks[task_id].result = result.dict()
                self.active_tasks[task_id].completed_at = datetime.now()
            
            return result
            
        except Exception as e:
            logger.error(f"Tech analysis failed for {target}: {e}")
            if task_id in self.active_tasks:
                self.active_tasks[task_id].status = TaskStatus.FAILED
                self.active_tasks[task_id].error = str(e)
                self.active_tasks[task_id].completed_at = datetime.now()
            raise

    def _run_tech_analysis_sync(self, domain: str, subdomain: Optional[str], task_id: str) -> TechAnalysisResult:
        """Synchronous technology analysis"""
        target = subdomain if subdomain else domain
        technologies = []
        web_server = None
        cms = None
        
        # Update progress
        if task_id in self.active_tasks:
            self.active_tasks[task_id].progress = 40
        
        try:
            # Make HTTP request to analyze headers and content
            url = f"https://{target}"
            response = requests.get(url, timeout=10, verify=False)
            
            # Analyze headers
            headers = response.headers
            
            # Identify web server
            if 'Server' in headers:
                web_server = headers['Server']
                technologies.append({
                    "name": headers['Server'],
                    "category": "web_server",
                    "confidence": 0.9,
                    "source": "http_header"
                })
            
            # Update progress
            if task_id in self.active_tasks:
                self.active_tasks[task_id].progress = 60
            
            # Identify technologies from headers
            tech_headers = {
                'X-Powered-By': 'framework',
                'X-Generator': 'cms',
                'X-Drupal-Cache': 'cms',
                'X-WordPress': 'cms'
            }
            
            for header, category in tech_headers.items():
                if header in headers:
                    tech_name = headers[header]
                    technologies.append({
                        "name": tech_name,
                        "category": category,
                        "confidence": 0.8,
                        "source": "http_header"
                    })
                    
                    if category == 'cms':
                        cms = tech_name
            
            # Enhanced banner detection for vulnerabilities
            self._analyze_banners_for_vulnerabilities(headers, response, technologies)
            
            # TLS/SSL analysis
            self._analyze_tls_configuration(domain, subdomain, technologies)
            
            # Enhanced threat intelligence analysis
            self._analyze_with_threat_intelligence(target, technologies)
            
            # Professional SSL analysis with SSL Labs
            self._analyze_ssl_labs(target, technologies)
            
            # Update progress
            if task_id in self.active_tasks:
                self.active_tasks[task_id].progress = 80
            
            # Analyze content for technology indicators and third-party providers
            content = response.text[:50000]  # First 50KB for better analysis
            content_lower = content.lower()
            
            # Enhanced technology detection
            content_indicators = {
                'WordPress': ['wp-content', 'wp-includes', '/wp-admin/', 'wordpress'],
                'Drupal': ['sites/default', 'drupal', 'misc/drupal.js'],
                'Joomla': ['components/com_', 'joomla', '/media/jui/'],
                'jQuery': ['jquery', '//code.jquery.com'],
                'React': ['react', 'reactjs', '_reactInternalInstance'],
                'Vue': ['vue', 'vuejs', '__vue__'],
                'Angular': ['ng-', 'angular', 'angularjs'],
                'Bootstrap': ['bootstrap', 'getbootstrap'],
                'D3.js': ['d3.js', 'd3.min.js'],
                'Lodash': ['lodash', 'underscore'],
                'Moment.js': ['moment.js', 'momentjs']
            }
            
            # Third-party providers and analytics detection
            provider_indicators = {
                'Google Analytics': ['google-analytics', 'gtag', 'ga.js', 'analytics.google.com'],
                'Google Tag Manager': ['googletagmanager', 'gtm.js'],
                'Google Fonts': ['fonts.googleapis.com', 'fonts.gstatic.com'],
                'Google Maps': ['maps.googleapis.com', 'maps.google.com'],
                'Facebook Pixel': ['facebook.net/tr', 'fbevents.js', 'connect.facebook.net'],
                'Cloudflare': ['cloudflare', 'cdnjs.cloudflare.com'],
                'Amazon S3': ['amazonaws.com', 's3.amazonaws.com'],
                'AWS CloudFront': ['cloudfront.net'],
                'Microsoft': ['microsoft.com', 'office.com', 'outlook.com'],
                'Adobe': ['adobe.com', 'typekit.net'],
                'Twitter': ['twitter.com', 'twimg.com'],
                'LinkedIn': ['linkedin.com', 'licdn.com'],
                'YouTube': ['youtube.com', 'ytimg.com'],
                'Vimeo': ['vimeo.com', 'vimeocdn.com'],
                'Stripe': ['stripe.com', 'js.stripe.com'],
                'PayPal': ['paypal.com', 'paypalobjects.com'],
                'Hotjar': ['hotjar.com', 'static.hotjar.com'],
                'Intercom': ['intercom.io', 'widget.intercom.io'],
                'Zendesk': ['zendesk.com', 'zdassets.com'],
                'HubSpot': ['hubspot.com', 'hsforms.net'],
                'Salesforce': ['salesforce.com', 'force.com'],
                'Mailchimp': ['mailchimp.com', 'list-manage.com'],
                'Akamai': ['akamai.net', 'akamaihd.net'],
                'Fastly': ['fastly.com', 'fastlylb.net'],
                'MaxCDN': ['maxcdn.com', 'bootstrapcdn.com'],
                'jsDelivr': ['jsdelivr.net'],
                'unpkg': ['unpkg.com'],
                'cdnjs': ['cdnjs.cloudflare.com']
            }
            
            # Check for technologies
            for tech, indicators in content_indicators.items():
                found = False
                for indicator in indicators:
                    if indicator in content_lower:
                        found = True
                        break
                
                if found:
                    technologies.append({
                        "name": tech,
                        "category": "javascript" if tech in ['jQuery', 'React', 'Vue', 'Angular', 'Bootstrap', 'D3.js', 'Lodash', 'Moment.js'] else "cms",
                        "confidence": 0.7,
                        "source": "content_analysis"
                    })
                    
                    if tech in ['WordPress', 'Drupal', 'Joomla'] and not cms:
                        cms = tech
            
            # Check for third-party providers (these become additional providers)
            for provider_name, indicators in provider_indicators.items():
                found = False
                for indicator in indicators:
                    if indicator in content_lower:
                        found = True
                        break
                
                if found:
                    technologies.append({
                        "name": provider_name,
                        "category": "third_party_provider",
                        "confidence": 0.8,
                        "source": "content_analysis",
                        "provider_type": self._classify_provider_type(provider_name)
                    })
        
        except Exception as e:
            logger.debug(f"Tech analysis failed for {target}: {e}")
            technologies.append({
                "name": "analysis_failed",
                "category": "error",
                "confidence": 1.0,
                "source": "error",
                "error": str(e)
            })
        
        # Calculate comprehensive risk profile
        risk_profile = self._calculate_domain_risk_profile(technologies, domain, subdomain)
        
        result = TechAnalysisResult(
            domain=domain,
            subdomain=subdomain,
            technologies=technologies,
            web_server=web_server,
            cms=cms,
            metadata={
                "target": target,
                "total_technologies": len(technologies),
                "analysis_successful": not any(t.get("category") == "error" for t in technologies),
                "risk_profile": risk_profile
            }
        )
        
        # Save to Neo4j
        self._save_tech_to_neo4j(result)
        
        return result

    def _calculate_domain_risk_profile(self, technologies, domain, subdomain):
        """Calculate comprehensive risk profile based on all detected technologies and vulnerabilities"""
        
        risk_profile = {
            "overall_risk_score": 0.0,
            "risk_level": "low",
            "risk_factors": [],
            "vulnerability_count": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "security_strengths": [],
            "recommendations": [],
            "third_party_exposure": 0,
            "tls_security_grade": "Unknown"
        }
        
        # Analyze each technology for risk factors
        for tech in technologies:
            category = tech.get("category", "")
            risk_level = tech.get("risk_level", "")
            name = tech.get("name", "")
            
            # Count vulnerabilities by severity
            if risk_level == "critical":
                risk_profile["vulnerability_count"]["critical"] += 1
                risk_profile["risk_factors"].append(f"Critical: {name}")
                risk_profile["overall_risk_score"] += 40.0
            elif risk_level == "high":
                risk_profile["vulnerability_count"]["high"] += 1
                risk_profile["risk_factors"].append(f"High: {name}")
                risk_profile["overall_risk_score"] += 25.0
            elif risk_level == "medium":
                risk_profile["vulnerability_count"]["medium"] += 1
                risk_profile["risk_factors"].append(f"Medium: {name}")
                risk_profile["overall_risk_score"] += 10.0
            elif risk_level == "low":
                risk_profile["vulnerability_count"]["low"] += 1
                risk_profile["risk_factors"].append(f"Low: {name}")
                risk_profile["overall_risk_score"] += 3.0
            
            # Check for specific security issues
            if category == "admin_exposure":
                risk_profile["overall_risk_score"] += 15.0
                risk_profile["recommendations"].append("Secure or remove exposed administrative interfaces")
            
            elif category == "debug_exposure":
                risk_profile["overall_risk_score"] += 8.0
                risk_profile["recommendations"].append("Disable debug information exposure in production")
            
            elif category == "web_server_version":
                if "version" in tech:
                    risk_profile["recommendations"].append(f"Update {name} to latest version")
            
            elif category == "third_party_provider":
                risk_profile["third_party_exposure"] += 1
                # Third-party providers increase attack surface
                risk_profile["overall_risk_score"] += 2.0
            
            elif category in ["threat_intelligence_risk", "ssl_risk", "geopolitical_risk", "domain_risk"]:
                # Enhanced risk categories from threat intelligence
                if risk_level == "critical":
                    risk_profile["overall_risk_score"] += 50.0
                elif risk_level == "high": 
                    risk_profile["overall_risk_score"] += 30.0
                elif risk_level == "medium":
                    risk_profile["overall_risk_score"] += 15.0
            
            elif category == "tls_configuration":
                grade = tech.get("tls_grade", "Unknown")
                risk_profile["tls_security_grade"] = grade
                
                if grade == "A+":
                    risk_profile["security_strengths"].append("Excellent TLS configuration")
                elif grade == "A":
                    risk_profile["security_strengths"].append("Good TLS configuration")
                elif grade == "B":
                    risk_profile["overall_risk_score"] += 5.0
                    risk_profile["recommendations"].append("Improve TLS configuration")
                elif grade in ["C", "D", "F"]:
                    risk_profile["overall_risk_score"] += 15.0
                    risk_profile["recommendations"].append("Critical TLS configuration issues need immediate attention")
            
            elif category == "tls_certificate":
                days_until_expiry = tech.get("days_until_expiry", 365)
                if days_until_expiry < 30:
                    risk_profile["overall_risk_score"] += 10.0
                    risk_profile["recommendations"].append("Certificate expires soon - plan renewal")
                elif days_until_expiry < 90:
                    risk_profile["overall_risk_score"] += 3.0
                    risk_profile["recommendations"].append("Certificate expires in less than 90 days")
        
        # Calculate final risk level and grade (both numeric and A-E scale)
        score = risk_profile["overall_risk_score"]
        
        if score >= 80:
            risk_profile["risk_level"] = "critical"
            risk_profile["risk_grade"] = "E"
        elif score >= 60:
            risk_profile["risk_level"] = "high"
            risk_profile["risk_grade"] = "D"
        elif score >= 40:
            risk_profile["risk_level"] = "medium-high"
            risk_profile["risk_grade"] = "C"
        elif score >= 20:
            risk_profile["risk_level"] = "medium"
            risk_profile["risk_grade"] = "B"
        elif score >= 10:
            risk_profile["risk_level"] = "low-medium"
            risk_profile["risk_grade"] = "B-"
        else:
            risk_profile["risk_level"] = "low"
            risk_profile["risk_grade"] = "A"
        
        # Add general recommendations based on findings
        if risk_profile["third_party_exposure"] > 5:
            risk_profile["recommendations"].append("High third-party exposure - review data sharing agreements")
        
        if not any(t.get("category") == "tls_certificate" for t in technologies):
            risk_profile["recommendations"].append("No TLS certificate information available - verify HTTPS configuration")
        
        # Add security strengths
        if risk_profile["vulnerability_count"]["critical"] == 0:
            risk_profile["security_strengths"].append("No critical vulnerabilities detected")
        
        if risk_profile["third_party_exposure"] < 3:
            risk_profile["security_strengths"].append("Limited third-party exposure")
        
        # Cap the overall risk score at 100
        risk_profile["overall_risk_score"] = min(risk_profile["overall_risk_score"], 100.0)
        
        return risk_profile

    def _analyze_tls_configuration(self, domain, subdomain, technologies):
        """Analyze TLS/SSL configuration"""
        target = subdomain if subdomain else domain
        
        # Always start with basic SSL check which is more reliable
        self._basic_ssl_check(target, technologies)
        
        # Try advanced SSLyze analysis if available
        try:
            from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation
            from sslyze.plugins.scan_commands import ScanCommand
            
            # Create server location
            try:
                server_location = ServerNetworkLocation(target, 443)
                scan_request = ServerScanRequest(
                    server_location=server_location,
                    scan_commands={
                        ScanCommand.TLS_1_3_SCAN,
                        ScanCommand.TLS_1_2_SCAN,
                        ScanCommand.TLS_1_1_SCAN,
                        ScanCommand.TLS_1_0_SCAN,
                        ScanCommand.CERTIFICATE_INFO,
                        ScanCommand.HEARTBLEED,
                    }
                )
                
                # Run TLS scan with timeout
                scanner = Scanner()
                scanner.queue_scans([scan_request])
                
                # Get results (limited scan for reliability)
                for scan_result in scanner.get_results():
                    if scan_result.server_location.hostname == target:
                        self._process_tls_scan_results_limited(scan_result, technologies)
                        break
                
            except Exception as scan_error:
                logger.debug(f"Advanced TLS scan failed for {target}: {scan_error}")
                
        except ImportError:
            logger.debug("SSLyze not available, using basic TLS analysis only")
        except Exception as e:
            logger.debug(f"TLS analysis error for {target}: {e}")

    def _process_tls_scan_results_limited(self, scan_result, technologies):
        """Process limited TLS scan results for reliability"""
        try:
            # Check for Heartbleed specifically
            if hasattr(scan_result, 'heartbleed_scan_result') and scan_result.heartbleed_scan_result:
                if hasattr(scan_result.heartbleed_scan_result, 'is_vulnerable_to_heartbleed'):
                    if scan_result.heartbleed_scan_result.is_vulnerable_to_heartbleed:
                        technologies.append({
                            "name": "Heartbleed Vulnerability",
                            "category": "tls_vulnerability",
                            "confidence": 1.0,
                            "source": "tls_analysis",
                            "risk_level": "critical",
                            "vulnerability_notes": "Server is vulnerable to Heartbleed attack (CVE-2014-0160)"
                        })
            
            # Basic protocol version check
            supported_versions = []
            if hasattr(scan_result, 'tls_1_3_scan_result') and scan_result.tls_1_3_scan_result:
                if hasattr(scan_result.tls_1_3_scan_result, 'is_tls_version_supported'):
                    if scan_result.tls_1_3_scan_result.is_tls_version_supported:
                        supported_versions.append("TLS 1.3")
            
            if hasattr(scan_result, 'tls_1_2_scan_result') and scan_result.tls_1_2_scan_result:
                if hasattr(scan_result.tls_1_2_scan_result, 'is_tls_version_supported'):
                    if scan_result.tls_1_2_scan_result.is_tls_version_supported:
                        supported_versions.append("TLS 1.2")
            
            if supported_versions:
                technologies.append({
                    "name": "Advanced TLS Support",
                    "category": "tls_configuration",
                    "confidence": 1.0,
                    "source": "advanced_tls_scan",
                    "supported_versions": supported_versions,
                    "tls_grade": self._calculate_tls_grade(supported_versions)
                })
        
        except Exception as e:
            logger.debug(f"Limited TLS processing error: {e}")

    def _process_tls_scan_results(self, scan_result, technologies):
        """Process comprehensive TLS scan results"""
        
        # Certificate analysis
        if hasattr(scan_result, 'certificate_info'):
            cert_result = scan_result.certificate_info
            if cert_result and hasattr(cert_result, 'certificate_deployments'):
                for cert_deployment in cert_result.certificate_deployments:
                    cert = cert_deployment.received_certificate_chain[0]
                    
                    # Certificate validity
                    import datetime
                    now = datetime.datetime.now()
                    
                    technologies.append({
                        "name": "TLS Certificate",
                        "category": "tls_certificate",
                        "confidence": 1.0,
                        "source": "tls_analysis",
                        "issuer": cert.issuer.rfc4514_string(),
                        "subject": cert.subject.rfc4514_string(),
                        "valid_from": cert.not_valid_before.isoformat(),
                        "valid_until": cert.not_valid_after.isoformat(),
                        "days_until_expiry": (cert.not_valid_after - now).days,
                        "signature_algorithm": cert.signature_algorithm_oid._name,
                        "key_size": cert.public_key().key_size if hasattr(cert.public_key(), 'key_size') else 'unknown'
                    })
                    
                    # Check for weak certificates
                    if hasattr(cert.public_key(), 'key_size') and cert.public_key().key_size < 2048:
                        technologies.append({
                            "name": "Weak Certificate Key",
                            "category": "tls_vulnerability",
                            "confidence": 1.0,
                            "source": "tls_analysis",
                            "risk_level": "high",
                            "vulnerability_notes": f"Certificate key size {cert.public_key().key_size} bits is below recommended 2048 bits"
                        })
        
        # Protocol support analysis
        tls_versions = []
        if hasattr(scan_result, 'tls_1_3_scan_result') and scan_result.tls_1_3_scan_result:
            if scan_result.tls_1_3_scan_result.is_tls_version_supported:
                tls_versions.append("TLS 1.3")
        
        if hasattr(scan_result, 'tls_1_2_scan_result') and scan_result.tls_1_2_scan_result:
            if scan_result.tls_1_2_scan_result.is_tls_version_supported:
                tls_versions.append("TLS 1.2")
        
        if hasattr(scan_result, 'tls_1_1_scan_result') and scan_result.tls_1_1_scan_result:
            if scan_result.tls_1_1_scan_result.is_tls_version_supported:
                tls_versions.append("TLS 1.1")
                technologies.append({
                    "name": "TLS 1.1 Support",
                    "category": "tls_vulnerability",
                    "confidence": 1.0,
                    "source": "tls_analysis",
                    "risk_level": "medium",
                    "vulnerability_notes": "TLS 1.1 is deprecated and should be disabled"
                })
        
        if hasattr(scan_result, 'tls_1_0_scan_result') and scan_result.tls_1_0_scan_result:
            if scan_result.tls_1_0_scan_result.is_tls_version_supported:
                tls_versions.append("TLS 1.0")
                technologies.append({
                    "name": "TLS 1.0 Support",
                    "category": "tls_vulnerability",
                    "confidence": 1.0,
                    "source": "tls_analysis",
                    "risk_level": "high",
                    "vulnerability_notes": "TLS 1.0 is deprecated and vulnerable to attacks"
                })
        
        if hasattr(scan_result, 'ssl_3_0_scan_result') and scan_result.ssl_3_0_scan_result:
            if scan_result.ssl_3_0_scan_result.is_tls_version_supported:
                tls_versions.append("SSL 3.0")
                technologies.append({
                    "name": "SSL 3.0 Support",
                    "category": "tls_vulnerability",
                    "confidence": 1.0,
                    "source": "tls_analysis",
                    "risk_level": "critical",
                    "vulnerability_notes": "SSL 3.0 is critically vulnerable (POODLE attack)"
                })
        
        technologies.append({
            "name": "TLS Protocol Support",
            "category": "tls_configuration",
            "confidence": 1.0,
            "source": "tls_analysis",
            "supported_versions": tls_versions,
            "tls_grade": self._calculate_tls_grade(tls_versions)
        })
        
        # Check for specific vulnerabilities
        if hasattr(scan_result, 'heartbleed_scan_result') and scan_result.heartbleed_scan_result:
            if scan_result.heartbleed_scan_result.is_vulnerable_to_heartbleed:
                technologies.append({
                    "name": "Heartbleed Vulnerability",
                    "category": "tls_vulnerability",
                    "confidence": 1.0,
                    "source": "tls_analysis",
                    "risk_level": "critical",
                    "vulnerability_notes": "Server is vulnerable to Heartbleed attack (CVE-2014-0160)"
                })
        
        if hasattr(scan_result, 'openssl_ccs_injection_scan_result') and scan_result.openssl_ccs_injection_scan_result:
            if scan_result.openssl_ccs_injection_scan_result.is_vulnerable_to_ccs_injection:
                technologies.append({
                    "name": "OpenSSL CCS Injection",
                    "category": "tls_vulnerability",
                    "confidence": 1.0,
                    "source": "tls_analysis",
                    "risk_level": "high",
                    "vulnerability_notes": "Server is vulnerable to OpenSSL CCS injection attack"
                })

    def _basic_ssl_check(self, target, technologies):
        """Basic SSL/TLS check as fallback"""
        import ssl
        import socket
        
        try:
            # Test TLS connection
            context = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    technologies.append({
                        "name": f"TLS {version}",
                        "category": "tls_configuration",
                        "confidence": 0.9,
                        "source": "basic_tls_check",
                        "cipher_suite": cipher[0] if cipher else "unknown",
                        "tls_version": version
                    })
                    
                    if cert:
                        import datetime
                        not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (not_after - datetime.datetime.now()).days
                        
                        technologies.append({
                            "name": "TLS Certificate (Basic)",
                            "category": "tls_certificate",
                            "confidence": 0.8,
                            "source": "basic_tls_check",
                            "subject": cert.get('subject', 'unknown'),
                            "issuer": cert.get('issuer', 'unknown'),
                            "days_until_expiry": days_until_expiry
                        })
                        
                        if days_until_expiry < 30:
                            technologies.append({
                                "name": "Certificate Expiring Soon",
                                "category": "tls_vulnerability",
                                "confidence": 1.0,
                                "source": "basic_tls_check",
                                "risk_level": "medium",
                                "vulnerability_notes": f"Certificate expires in {days_until_expiry} days"
                            })
        
        except Exception as e:
            logger.debug(f"Basic SSL check failed for {target}: {e}")

    def _calculate_tls_grade(self, tls_versions):
        """Calculate TLS security grade based on supported versions"""
        if "SSL 3.0" in tls_versions or "SSL 2.0" in tls_versions:
            return "F"
        elif "TLS 1.0" in tls_versions:
            return "C"
        elif "TLS 1.1" in tls_versions and "TLS 1.3" not in tls_versions:
            return "B"
        elif "TLS 1.2" in tls_versions and "TLS 1.3" in tls_versions:
            return "A"
        elif "TLS 1.3" in tls_versions:
            return "A+"
        else:
            return "Unknown"

    def _analyze_with_threat_intelligence(self, target, technologies):
        """Comprehensive threat intelligence analysis using multiple APIs"""
        
        # Get IP address for target
        import socket
        try:
            ip_address = socket.gethostbyname(target)
        except:
            ip_address = None
        
        # Shodan analysis
        self._analyze_with_shodan(target, ip_address, technologies)
        
        # VirusTotal analysis  
        self._analyze_with_virustotal(target, technologies)
        
        # AlienVault OTX analysis
        self._analyze_with_alienvault(target, technologies)
        
        # IPinfo analysis
        if ip_address:
            self._analyze_with_ipinfo(ip_address, technologies)
        
        # Enhanced WHOIS analysis
        self._analyze_whois_detailed(target, technologies)

    def _analyze_with_shodan(self, target, ip_address, technologies):
        """Analyze with Shodan API for port scanning and vulnerability data"""
        try:
            import shodan
            
            api = shodan.Shodan("xwGnANztoOVfECntTZxyL2CemzbHWIjg")
            
            if ip_address:
                try:
                    # Get host information
                    host_info = api.host(ip_address)
                    
                    # Extract vulnerability data
                    vulns = host_info.get('vulns', [])
                    open_ports = [str(service['port']) for service in host_info.get('data', [])]
                    
                    technologies.append({
                        "name": "Shodan Intelligence",
                        "category": "threat_intelligence",
                        "confidence": 0.95,
                        "source": "shodan_api",
                        "open_ports": open_ports,
                        "vulnerability_count": len(vulns),
                        "vulns": vulns[:5],  # Top 5 vulnerabilities
                        "last_updated": host_info.get('last_update', 'unknown')
                    })
                    
                    # Add risk based on vulnerabilities
                    if len(vulns) > 0:
                        risk_level = "critical" if len(vulns) > 10 else "high" if len(vulns) > 5 else "medium"
                        technologies.append({
                            "name": f"Shodan Vulnerabilities ({len(vulns)} found)",
                            "category": "threat_intelligence_risk",
                            "confidence": 0.95,
                            "source": "shodan_api",
                            "risk_level": risk_level,
                            "vulnerability_notes": f"{len(vulns)} known vulnerabilities detected by Shodan"
                        })
                    
                    # Check for dangerous open ports
                    dangerous_ports = ['22', '23', '25', '53', '80', '110', '143', '993', '995', '3389']
                    exposed_dangerous = [p for p in open_ports if p in dangerous_ports]
                    if exposed_dangerous:
                        technologies.append({
                            "name": "Exposed Dangerous Ports",
                            "category": "threat_intelligence_risk", 
                            "confidence": 0.9,
                            "source": "shodan_api",
                            "risk_level": "medium",
                            "vulnerability_notes": f"Exposed ports: {', '.join(exposed_dangerous)}"
                        })
                
                except shodan.APIError as e:
                    logger.debug(f"Shodan API error for {ip_address}: {e}")
                    
        except ImportError:
            logger.debug("Shodan library not available")
        except Exception as e:
            logger.debug(f"Shodan analysis error: {e}")

    def _analyze_with_virustotal(self, target, technologies):
        """Analyze with VirusTotal API for malware and reputation data"""
        try:
            import requests
            import base64
            
            # VirusTotal API v3
            api_key = "34226ba9cbb815c341102bbefebadc60536a2bec726819c85a466903fa0d50ac"
            headers = {"x-apikey": api_key}
            
            # Domain analysis
            url = f"https://www.virustotal.com/api/v3/domains/{target}"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                # Reputation data
                reputation = attributes.get('reputation', 0)
                malicious_votes = attributes.get('last_analysis_stats', {}).get('malicious', 0)
                suspicious_votes = attributes.get('last_analysis_stats', {}).get('suspicious', 0)
                
                technologies.append({
                    "name": "VirusTotal Reputation",
                    "category": "threat_intelligence",
                    "confidence": 0.95,
                    "source": "virustotal_api",
                    "reputation_score": reputation,
                    "malicious_votes": malicious_votes,
                    "suspicious_votes": suspicious_votes
                })
                
                # Add risk based on reputation
                if malicious_votes > 0:
                    technologies.append({
                        "name": "Malicious Domain Reputation",
                        "category": "threat_intelligence_risk",
                        "confidence": 0.95,
                        "source": "virustotal_api",
                        "risk_level": "critical",
                        "vulnerability_notes": f"{malicious_votes} security vendors flagged this domain as malicious"
                    })
                elif suspicious_votes > 2:
                    technologies.append({
                        "name": "Suspicious Domain Reputation", 
                        "category": "threat_intelligence_risk",
                        "confidence": 0.9,
                        "source": "virustotal_api",
                        "risk_level": "high",
                        "vulnerability_notes": f"{suspicious_votes} security vendors flagged this domain as suspicious"
                    })
                    
        except Exception as e:
            logger.debug(f"VirusTotal analysis error: {e}")

    def _analyze_with_alienvault(self, target, technologies):
        """Analyze with AlienVault OTX API for threat intelligence"""
        try:
            import requests
            
            api_key = "b3e1749b53bc4916f36247c6963f1588c34801f08a342fea815f3589d18c4a99"
            headers = {"X-OTX-API-KEY": api_key}
            
            # OTX domain lookup
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/general"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                pulse_count = data.get('pulse_info', {}).get('count', 0)
                pulses = data.get('pulse_info', {}).get('pulses', [])
                
                technologies.append({
                    "name": "AlienVault OTX Intelligence",
                    "category": "threat_intelligence",
                    "confidence": 0.9,
                    "source": "alienvault_otx",
                    "pulse_count": pulse_count,
                    "threat_pulses": [p.get('name', 'Unknown') for p in pulses[:3]]
                })
                
                if pulse_count > 0:
                    risk_level = "critical" if pulse_count > 10 else "high" if pulse_count > 3 else "medium"
                    technologies.append({
                        "name": f"Threat Intelligence Alerts ({pulse_count} pulses)",
                        "category": "threat_intelligence_risk",
                        "confidence": 0.9,
                        "source": "alienvault_otx",
                        "risk_level": risk_level,
                        "vulnerability_notes": f"Domain appears in {pulse_count} threat intelligence pulses"
                    })
                    
        except Exception as e:
            logger.debug(f"AlienVault OTX analysis error: {e}")

    def _analyze_with_ipinfo(self, ip_address, technologies):
        """Analyze with IPinfo API for geolocation and ISP data"""
        try:
            import requests
            
            api_key = "0bf607ce2c13ac"
            url = f"https://ipinfo.io/{ip_address}?token={api_key}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                country = data.get('country', 'Unknown')
                org = data.get('org', 'Unknown')
                city = data.get('city', 'Unknown')
                
                technologies.append({
                    "name": "IP Geolocation & ISP",
                    "category": "infrastructure_intelligence",
                    "confidence": 0.95,
                    "source": "ipinfo_api",
                    "country": country,
                    "city": city,
                    "organization": org,
                    "ip_address": ip_address
                })
                
                # Flag high-risk countries (basic example)
                high_risk_countries = ['CN', 'RU', 'KP', 'IR']
                if country in high_risk_countries:
                    technologies.append({
                        "name": "High-Risk Geolocation",
                        "category": "geopolitical_risk",
                        "confidence": 0.8,
                        "source": "ipinfo_api",
                        "risk_level": "medium",
                        "vulnerability_notes": f"Server located in high-risk country: {country}"
                    })
                    
        except Exception as e:
            logger.debug(f"IPinfo analysis error: {e}")

    def _analyze_whois_detailed(self, target, technologies):
        """Enhanced WHOIS analysis using WhoisXMLAPI"""
        try:
            import requests
            
            api_key = "at_axSdVa1qdNAkgi7kyP1fYt76cnK84"
            url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
            
            params = {
                'apiKey': api_key,
                'domainName': target,
                'outputFormat': 'JSON'
            }
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                whois_record = data.get('WhoisRecord', {})
                
                creation_date = whois_record.get('createdDate', 'Unknown')
                expiry_date = whois_record.get('expiresDate', 'Unknown')
                registrar = whois_record.get('registrarName', 'Unknown')
                
                technologies.append({
                    "name": "Enhanced WHOIS Data",
                    "category": "domain_intelligence",
                    "confidence": 0.95,
                    "source": "whoisxml_api",
                    "creation_date": creation_date,
                    "expiry_date": expiry_date,
                    "registrar": registrar
                })
                
                # Check for domain age (new domains can be risky)
                if creation_date != 'Unknown':
                    from datetime import datetime
                    try:
                        created = datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
                        age_days = (datetime.now() - created).days
                        
                        if age_days < 30:
                            technologies.append({
                                "name": "New Domain Registration",
                                "category": "domain_risk",
                                "confidence": 0.8,
                                "source": "whoisxml_api",
                                "risk_level": "medium",
                                "vulnerability_notes": f"Domain registered only {age_days} days ago"
                            })
                    except:
                        pass
                        
        except Exception as e:
            logger.debug(f"WHOIS analysis error: {e}")

    def _analyze_ssl_labs(self, target, technologies):
        """Professional SSL analysis using SSL Labs API"""
        try:
            import requests
            import time
            
            # SSL Labs API
            base_url = "https://api.ssllabs.com/api/v3/"
            
            # Start analysis
            analyze_url = f"{base_url}analyze"
            params = {
                'host': target,
                'startNew': 'on',
                'all': 'done'
            }
            
            response = requests.get(analyze_url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                # Wait for analysis to complete (simplified - in production would poll)
                if data.get('status') == 'READY':
                    endpoints = data.get('endpoints', [])
                    
                    for endpoint in endpoints:
                        grade = endpoint.get('grade', 'Unknown')
                        grade_trust_ignored = endpoint.get('gradeTrustIgnored', 'Unknown')
                        
                        technologies.append({
                            "name": "SSL Labs Analysis",
                            "category": "ssl_professional",
                            "confidence": 1.0,
                            "source": "ssl_labs_api",
                            "grade": grade,
                            "grade_trust_ignored": grade_trust_ignored,
                            "ip_address": endpoint.get('ipAddress', 'Unknown')
                        })
                        
                        # Add risk based on SSL grade
                        if grade in ['F', 'T']:
                            technologies.append({
                                "name": f"Poor SSL Configuration (Grade {grade})",
                                "category": "ssl_risk",
                                "confidence": 1.0,
                                "source": "ssl_labs_api",
                                "risk_level": "critical",
                                "vulnerability_notes": f"SSL Labs grade {grade} indicates serious security issues"
                            })
                        elif grade in ['C', 'D']:
                            technologies.append({
                                "name": f"Weak SSL Configuration (Grade {grade})",
                                "category": "ssl_risk",
                                "confidence": 1.0,
                                "source": "ssl_labs_api",
                                "risk_level": "high",
                                "vulnerability_notes": f"SSL Labs grade {grade} indicates security weaknesses"
                            })
                            
        except Exception as e:
            logger.debug(f"SSL Labs analysis error: {e}")

    def _analyze_banners_for_vulnerabilities(self, headers, response, technologies):
        """Analyze HTTP headers and response for vulnerable software versions"""
        
        # Web server version analysis
        server_header = headers.get('Server', '')
        if server_header:
            self._check_server_vulnerabilities(server_header, technologies)
        
        # Check other revealing headers
        vulnerable_headers = {
            'X-Powered-By': 'framework',
            'X-AspNet-Version': 'framework', 
            'X-Generator': 'cms',
            'X-Drupal-Cache': 'cms',
            'Server': 'web_server'
        }
        
        for header, category in vulnerable_headers.items():
            if header in headers:
                self._check_software_version(headers[header], category, technologies)
        
        # Check for exposed administrative interfaces
        self._check_admin_interfaces(response, technologies)
        
        # Check for debug information exposure
        self._check_debug_exposure(response, technologies)

    def _check_server_vulnerabilities(self, server_header, technologies):
        """Check web server versions for known vulnerabilities"""
        server_lower = server_header.lower()
        
        # Apache version detection
        if 'apache' in server_lower:
            import re
            apache_match = re.search(r'apache[\/\s]+(\d+\.\d+\.\d+)', server_lower)
            if apache_match:
                version = apache_match.group(1)
                risk_level = self._assess_apache_version_risk(version)
                technologies.append({
                    "name": f"Apache {version}",
                    "category": "web_server_version",
                    "confidence": 0.95,
                    "source": "banner_analysis",
                    "version": version,
                    "risk_level": risk_level,
                    "vulnerability_notes": f"Apache {version} - check CVE database"
                })
        
        # Nginx version detection  
        elif 'nginx' in server_lower:
            import re
            nginx_match = re.search(r'nginx[\/\s]+(\d+\.\d+\.\d+)', server_lower)
            if nginx_match:
                version = nginx_match.group(1)
                risk_level = self._assess_nginx_version_risk(version)
                technologies.append({
                    "name": f"Nginx {version}",
                    "category": "web_server_version", 
                    "confidence": 0.95,
                    "source": "banner_analysis",
                    "version": version,
                    "risk_level": risk_level,
                    "vulnerability_notes": f"Nginx {version} - check CVE database"
                })
        
        # IIS version detection
        elif 'microsoft-iis' in server_lower:
            import re
            iis_match = re.search(r'microsoft-iis[\/\s]+(\d+\.\d+)', server_lower)
            if iis_match:
                version = iis_match.group(1)
                risk_level = self._assess_iis_version_risk(version)
                technologies.append({
                    "name": f"IIS {version}",
                    "category": "web_server_version",
                    "confidence": 0.95,
                    "source": "banner_analysis",
                    "version": version,
                    "risk_level": risk_level,
                    "vulnerability_notes": f"IIS {version} - check for known vulnerabilities"
                })
        
        # Gunicorn version detection
        elif 'gunicorn' in server_lower:
            import re
            gunicorn_match = re.search(r'gunicorn[\/\s]+(\d+\.\d+\.\d+)', server_lower)
            if gunicorn_match:
                version = gunicorn_match.group(1)
                risk_level = self._assess_gunicorn_version_risk(version)
                technologies.append({
                    "name": f"Gunicorn {version}",
                    "category": "web_server_version",
                    "confidence": 0.95,
                    "source": "banner_analysis",
                    "version": version,
                    "risk_level": risk_level,
                    "vulnerability_notes": f"Gunicorn {version} - Python WSGI server version"
                })
        
        # Other web servers
        else:
            # Generic version detection for other servers
            import re
            version_match = re.search(r'(\w+)[\/\s]+(\d+\.\d+\.?\d*)', server_lower)
            if version_match:
                server_name = version_match.group(1)
                version = version_match.group(2)
                technologies.append({
                    "name": f"{server_name.title()} {version}",
                    "category": "web_server_version",
                    "confidence": 0.8,
                    "source": "banner_analysis",
                    "version": version,
                    "risk_level": "unknown",
                    "vulnerability_notes": f"{server_name.title()} {version} - check for known vulnerabilities"
                })

    def _check_software_version(self, header_value, category, technologies):
        """Check specific software versions for vulnerabilities"""
        import re
        
        # PHP version detection
        if 'php' in header_value.lower():
            php_match = re.search(r'php[\/\s]+(\d+\.\d+\.\d+)', header_value.lower())
            if php_match:
                version = php_match.group(1)
                risk_level = self._assess_php_version_risk(version)
                technologies.append({
                    "name": f"PHP {version}",
                    "category": "language_version",
                    "confidence": 0.9,
                    "source": "header_analysis",
                    "version": version,
                    "risk_level": risk_level,
                    "vulnerability_notes": f"PHP {version} - check for security updates"
                })
        
        # ASP.NET version detection
        elif 'asp.net' in header_value.lower():
            aspnet_match = re.search(r'(\d+\.\d+\.\d+)', header_value)
            if aspnet_match:
                version = aspnet_match.group(1)
                technologies.append({
                    "name": f"ASP.NET {version}",
                    "category": "framework_version",
                    "confidence": 0.9,
                    "source": "header_analysis",
                    "version": version,
                    "risk_level": "medium",
                    "vulnerability_notes": f"ASP.NET {version} - verify security updates"
                })

    def _check_admin_interfaces(self, response, technologies):
        """Check for exposed administrative interfaces"""
        content = response.text[:10000].lower()  # First 10KB
        
        admin_indicators = {
            'wp-admin': 'WordPress Admin',
            'phpmyadmin': 'phpMyAdmin',
            'adminer': 'Adminer Database Tool',
            '/admin': 'Generic Admin Interface',
            'cpanel': 'cPanel',
            'plesk': 'Plesk Panel'
        }
        
        for indicator, name in admin_indicators.items():
            if indicator in content:
                technologies.append({
                    "name": name,
                    "category": "admin_exposure",
                    "confidence": 0.7,
                    "source": "content_analysis",
                    "risk_level": "high",
                    "vulnerability_notes": f"Exposed {name} interface - potential security risk"
                })

    def _check_debug_exposure(self, response, technologies):
        """Check for debug information exposure"""
        content = response.text[:20000].lower()  # First 20KB
        
        debug_indicators = {
            'stack trace': 'Stack Trace Exposure',
            'mysql error': 'MySQL Error Exposure', 
            'php warning': 'PHP Warning Exposure',
            'php error': 'PHP Error Exposure',
            'asp.net error': 'ASP.NET Error Exposure',
            'debug mode': 'Debug Mode Enabled'
        }
        
        for indicator, name in debug_indicators.items():
            if indicator in content:
                technologies.append({
                    "name": name,
                    "category": "debug_exposure",
                    "confidence": 0.8,
                    "source": "content_analysis", 
                    "risk_level": "medium",
                    "vulnerability_notes": f"{name} detected - information disclosure risk"
                })

    def _assess_apache_version_risk(self, version):
        """Assess Apache version risk level"""
        try:
            major, minor, patch = map(int, version.split('.'))
            
            # Very old versions (2.2.x and below) 
            if major < 2 or (major == 2 and minor < 4):
                return "critical"
            # Older 2.4.x versions with known issues
            elif major == 2 and minor == 4 and patch < 41:
                return "high"
            else:
                return "low"
        except:
            return "unknown"

    def _assess_nginx_version_risk(self, version):
        """Assess Nginx version risk level"""
        try:
            major, minor, patch = map(int, version.split('.'))
            
            # Very old versions
            if major < 1 or (major == 1 and minor < 18):
                return "high"
            # Moderately old versions
            elif major == 1 and minor < 20:
                return "medium"
            else:
                return "low"
        except:
            return "unknown"

    def _assess_iis_version_risk(self, version):
        """Assess IIS version risk level"""
        try:
            major, minor = map(int, version.split('.'))
            
            # Very old IIS versions
            if major < 8:
                return "critical"
            elif major < 10:
                return "high" 
            else:
                return "medium"
        except:
            return "unknown"

    def _assess_php_version_risk(self, version):
        """Assess PHP version risk level"""
        try:
            major, minor, patch = map(int, version.split('.'))
            
            # PHP 5.x and below (end of life)
            if major < 7:
                return "critical"
            # PHP 7.x versions (most end of life)
            elif major == 7:
                return "high"
            # PHP 8.0 (end of life)
            elif major == 8 and minor == 0:
                return "medium"
            else:
                return "low"
        except:
            return "unknown"

    def _assess_gunicorn_version_risk(self, version):
        """Assess Gunicorn version risk level"""
        try:
            major, minor, patch = map(int, version.split('.'))
            
            # Very old versions (pre-20.x)
            if major < 20:
                return "high"
            # Older 20.x versions
            elif major == 20 and minor < 1:
                return "medium"
            else:
                return "low"
        except:
            return "unknown"

    def _classify_provider_type(self, provider_name: str) -> str:
        """Classify provider type for risk assessment"""
        provider_lower = provider_name.lower()
        
        # Analytics and tracking
        if any(keyword in provider_lower for keyword in ['analytics', 'tracking', 'pixel', 'tag']):
            return 'analytics'
        
        # CDN and hosting
        elif any(keyword in provider_lower for keyword in ['cdn', 'cloudflare', 'fastly', 'azure', 'aws', 'amazon']):
            return 'infrastructure'
        
        # Social media
        elif any(keyword in provider_lower for keyword in ['facebook', 'twitter', 'linkedin', 'instagram', 'youtube']):
            return 'social_media'
        
        # Advertising
        elif any(keyword in provider_lower for keyword in ['ads', 'adnxs', 'doubleclick', 'adsystem']):
            return 'advertising'
        
        # Security
        elif any(keyword in provider_lower for keyword in ['recaptcha', 'hcaptcha', 'security']):
            return 'security'
        
        # Payment processing
        elif any(keyword in provider_lower for keyword in ['stripe', 'paypal', 'payment']):
            return 'payment'
        
        # Chat and support
        elif any(keyword in provider_lower for keyword in ['zendesk', 'intercom', 'chat']):
            return 'support'
        
        # Default
        else:
            return 'other'

    def _save_tech_to_neo4j(self, result: TechAnalysisResult):
        """Save technology results to Neo4j"""
        if not HAS_NEO4J:
            return
        
        try:
            with self.driver.session() as session:
                session.write_transaction(self._create_tech_nodes, result)
            logger.info(f"Saved tech results to Neo4j")
        except Exception as e:
            logger.error(f"Failed to save tech to Neo4j: {e}")

    def _create_tech_nodes(self, tx, result: TechAnalysisResult):
        """Create Neo4j nodes for technology info with detailed technology tracking"""
        current_time = datetime.now().isoformat()
        target = result.subdomain if result.subdomain else result.domain
        
        # Update target node with tech info
        tx.run("""
            MATCH (n {fqdn: $target})
            SET n.technologies = $technologies,
                n.web_server = $web_server,
                n.cms = $cms,
                n.tech_analyzed_at = $current_time,
                n.updated_at = $current_time
        """, target=target,
             technologies=json.dumps(result.technologies),
             web_server=result.web_server,
             cms=result.cms,
             current_time=current_time)
        
        # Process all technologies to create detailed nodes
        for tech in result.technologies:
            self._create_technology_nodes(tx, tech, target, current_time)
        
        # Create Provider nodes for third-party providers
        third_party_providers = [
            tech for tech in result.technologies 
            if tech.get("category") == "third_party_provider"
        ]
        
        for provider in third_party_providers:
            provider_name = provider["name"]
            provider_type = provider.get("provider_type", "other")
            confidence = provider.get("confidence", 0.8)
            
            # Create or update Provider node
            tx.run("""
                MERGE (p:Provider {name: $name})
                ON CREATE SET p.type = $type,
                             p.created_at = $current_time,
                             p.confidence = $confidence,
                             p.detection_source = $source
                ON MATCH SET p.updated_at = $current_time,
                            p.confidence = CASE 
                                WHEN $confidence > p.confidence THEN $confidence 
                                ELSE p.confidence 
                            END
            """, name=provider_name, type=provider_type, 
                 current_time=current_time, confidence=confidence,
                 source=provider.get("source", "web_analysis"))
            
            # Create relationship between domain and provider
            tx.run("""
                MATCH (d {fqdn: $target})
                MATCH (p:Provider {name: $provider_name})
                MERGE (d)-[r:USES_PROVIDER]->(p)
                ON CREATE SET r.detected_at = $current_time,
                             r.confidence = $confidence,
                             r.source = $source
                ON MATCH SET r.last_seen = $current_time,
                            r.confidence = CASE 
                                WHEN $confidence > r.confidence THEN $confidence 
                                ELSE r.confidence 
                            END
            """, target=target, provider_name=provider_name,
                 current_time=current_time, confidence=confidence,
                 source=provider.get("source", "web_analysis"))

    def _create_technology_nodes(self, tx, tech, target, current_time):
        """Create specific and generic technology nodes with proper relationships"""
        
        tech_name = tech.get("name", "Unknown")
        category = tech.get("category", "unknown")
        confidence = tech.get("confidence", 0.5)
        source = tech.get("source", "unknown")
        version = tech.get("version", None)
        risk_level = tech.get("risk_level", None)
        
        # Parse technology name and version for web servers, frameworks, etc.
        generic_name, specific_version = self._parse_technology_name(tech_name, category)
        
        if generic_name:
            # Create generic technology node
            tx.run("""
                MERGE (t:Technology {name: $generic_name, category: $category})
                ON CREATE SET t.created_at = $current_time,
                             t.type = $category,
                             t.detection_count = 1
                ON MATCH SET t.updated_at = $current_time,
                            t.detection_count = t.detection_count + 1
            """, generic_name=generic_name, category=category, current_time=current_time)
            
            # Create specific version node if version is available
            if specific_version:
                specific_tech_id = f"{generic_name}_{specific_version}"
                
                tx.run("""
                    MERGE (tv:TechnologyVersion {
                        id: $tech_id,
                        name: $generic_name,
                        version: $version,
                        category: $category
                    })
                    ON CREATE SET tv.created_at = $current_time,
                                 tv.risk_level = $risk_level,
                                 tv.detection_count = 1,
                                 tv.vulnerability_notes = $vuln_notes
                    ON MATCH SET tv.updated_at = $current_time,
                                tv.detection_count = tv.detection_count + 1,
                                tv.risk_level = CASE 
                                    WHEN $risk_level IS NOT NULL THEN $risk_level 
                                    ELSE tv.risk_level 
                                END
                """, tech_id=specific_tech_id, generic_name=generic_name, 
                     version=specific_version, category=category,
                     current_time=current_time, risk_level=risk_level,
                     vuln_notes=tech.get("vulnerability_notes", ""))
                
                # Link specific version to generic technology
                tx.run("""
                    MATCH (t:Technology {name: $generic_name, category: $category})
                    MATCH (tv:TechnologyVersion {id: $tech_id})
                    MERGE (tv)-[r:IS_VERSION_OF]->(t)
                    ON CREATE SET r.created_at = $current_time
                """, generic_name=generic_name, category=category, 
                     tech_id=specific_tech_id, current_time=current_time)
                
                # Link domain to specific version
                tx.run("""
                    MATCH (d {fqdn: $target})
                    MATCH (tv:TechnologyVersion {id: $tech_id})
                    MERGE (d)-[r:USES_TECHNOLOGY_VERSION]->(tv)
                    ON CREATE SET r.detected_at = $current_time,
                                 r.confidence = $confidence,
                                 r.source = $source
                    ON MATCH SET r.last_seen = $current_time,
                                r.confidence = CASE 
                                    WHEN $confidence > r.confidence THEN $confidence 
                                    ELSE r.confidence 
                                END
                """, target=target, tech_id=specific_tech_id, 
                     current_time=current_time, confidence=confidence, source=source)
            
            # Always link domain to generic technology
            tx.run("""
                MATCH (d {fqdn: $target})
                MATCH (t:Technology {name: $generic_name, category: $category})
                MERGE (d)-[r:USES_TECHNOLOGY]->(t)
                ON CREATE SET r.detected_at = $current_time,
                             r.confidence = $confidence,
                             r.source = $source
                ON MATCH SET r.last_seen = $current_time,
                            r.confidence = CASE 
                                WHEN $confidence > r.confidence THEN $confidence 
                                ELSE r.confidence 
                            END
            """, target=target, generic_name=generic_name, category=category,
                 current_time=current_time, confidence=confidence, source=source)

    def _parse_technology_name(self, tech_name, category):
        """Parse technology name to extract generic name and specific version"""
        import re
        
        # Web server patterns
        if category == "web_server" or category == "web_server_version":
            # Apache/2.4.41, nginx/1.18.0, IIS/10.0, Gunicorn/19.9.0
            patterns = [
                r'(Apache)\s*/?\s*(\d+\.\d+\.?\d*)',
                r'(nginx)\s*/?\s*(\d+\.\d+\.?\d*)',
                r'(Microsoft-)?IIS\s*/?\s*(\d+\.\d+)',
                r'(Gunicorn)\s*/?\s*(\d+\.\d+\.?\d*)',
                r'(cloudflare)',  # Generic cloudflare
                r'(\w+)\s*/?\s*(\d+\.\d+\.?\d*)'  # Generic pattern
            ]
            
            for pattern in patterns:
                match = re.search(pattern, tech_name, re.IGNORECASE)
                if match:
                    if pattern == r'(cloudflare)':
                        return "Cloudflare", None
                    elif len(match.groups()) >= 2:
                        generic = match.group(1) if match.group(1) != "Microsoft-" else "IIS"
                        version = match.group(2) if len(match.groups()) > 1 else None
                        return generic.title(), version
                    else:
                        return match.group(1).title(), None
        
        # Language/Framework patterns
        elif category in ["language_version", "framework_version", "framework"]:
            patterns = [
                r'(PHP)\s*/?\s*(\d+\.\d+\.?\d*)',
                r'(ASP\.NET)\s*/?\s*(\d+\.\d+\.?\d*)',
                r'(Python)\s*/?\s*(\d+\.\d+\.?\d*)',
                r'(Node\.js)\s*/?\s*(\d+\.\d+\.?\d*)',
                r'(React)',
                r'(Angular)', 
                r'(Vue\.js)',
                r'(Next\.js)'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, tech_name, re.IGNORECASE)
                if match:
                    generic = match.group(1)
                    version = match.group(2) if len(match.groups()) > 1 else None
                    return generic, version
        
        # CMS patterns
        elif category == "cms":
            cms_patterns = [
                r'(WordPress)\s*/?\s*(\d+\.\d+\.?\d*)',
                r'(Drupal)\s*/?\s*(\d+\.\d+\.?\d*)',
                r'(Joomla)\s*/?\s*(\d+\.\d+\.?\d*)'
            ]
            
            for pattern in cms_patterns:
                match = re.search(pattern, tech_name, re.IGNORECASE)
                if match:
                    generic = match.group(1)
                    version = match.group(2) if len(match.groups()) > 1 else None
                    return generic, version
        
        # JavaScript libraries
        elif category == "javascript":
            js_patterns = [
                r'(jQuery)\s*/?\s*(\d+\.\d+\.?\d*)',
                r'(React)',
                r'(Angular)',
                r'(Vue)'
            ]
            
            for pattern in js_patterns:
                match = re.search(pattern, tech_name, re.IGNORECASE)
                if match:
                    generic = match.group(1)
                    version = match.group(2) if len(match.groups()) > 1 else None
                    return generic, version
        
        # Default: use the technology name as-is
        return tech_name, None

# Global service instance
discovery_service = None

# FastAPI app
app = FastAPI(
    title="Async Domain Discovery API",
    description="Asynchronous domain analysis with incremental graph building",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize service on startup
@app.on_event("startup")
async def startup_event():
    global discovery_service
    try:
        discovery_service = AsyncDomainDiscoveryService(
            neo4j_uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            neo4j_user=os.getenv("NEO4J_USER", "neo4j"),
            neo4j_password=os.getenv("NEO4J_PASS", "test.password"),
            redis_host=os.getenv("REDIS_HOST", "localhost"),
            redis_port=int(os.getenv("REDIS_PORT", "6379")),
            amass_cache_dir=os.getenv("AMASS_CACHE_DIR", "./amass_cache"),
            cache_duration_hours=int(os.getenv("CACHE_DURATION_HOURS", "168"))
        )
        logger.info("Discovery service initialized")
    except Exception as e:
        logger.error(f"Failed to initialize discovery service: {e}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    global discovery_service
    if discovery_service:
        discovery_service.close()

# Health endpoint
@app.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "active_tasks": len(discovery_service.active_tasks) if discovery_service else 0
    }

# Task management endpoints
@app.get("/api/v1/tasks", tags=["Tasks"])
async def list_tasks():
    """List all active tasks"""
    if not discovery_service:
        raise HTTPException(status_code=503, detail="Service not available")
    
    tasks = list(discovery_service.active_tasks.values())
    tasks.sort(key=lambda t: t.started_at, reverse=True)
    return {"tasks": [task.dict() for task in tasks]}

@app.get("/api/v1/tasks/{task_id}", tags=["Tasks"])
async def get_task_status(task_id: str):
    """Get task status and results"""
    if not discovery_service:
        raise HTTPException(status_code=503, detail="Service not available")
    
    if task_id not in discovery_service.active_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return discovery_service.active_tasks[task_id].dict()

@app.delete("/api/v1/tasks/{task_id}", tags=["Tasks"])
async def delete_task(task_id: str):
    """Delete a completed task"""
    if not discovery_service:
        raise HTTPException(status_code=503, detail="Service not available")
    
    if task_id not in discovery_service.active_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = discovery_service.active_tasks[task_id]
    if task.status == TaskStatus.RUNNING:
        raise HTTPException(status_code=400, detail="Cannot delete running task")
    
    del discovery_service.active_tasks[task_id]
    return {"message": "Task deleted successfully"}

# Discovery endpoints
@app.post("/api/v1/discover/amass/{domain}", tags=["Discovery"])
async def start_amass_discovery(
    domain: str = Path(..., description="Domain to analyze"),
    timeout: int = Query(300, description="Amass timeout in seconds", ge=60, le=1800)
):
    """Start Amass subdomain and provider discovery"""
    if not discovery_service:
        raise HTTPException(status_code=503, detail="Service not available")
    
    task_id = str(uuid.uuid4())
    task = TaskInfo(
        task_id=task_id,
        task_type=TaskType.AMASS_DISCOVERY,
        domain=domain,
        status=TaskStatus.PENDING,
        started_at=datetime.now()
    )
    discovery_service.active_tasks[task_id] = task
    
    # Start async discovery
    asyncio.create_task(discovery_service.run_amass_discovery(domain, task_id, timeout))
    
    return {"task_id": task_id, "domain": domain, "status": "started"}

@app.post("/api/v1/discover/services/{domain}", tags=["Discovery"])
async def start_service_discovery(
    domain: str = Path(..., description="Domain to analyze"),
    subdomain: Optional[str] = Query(None, description="Specific subdomain to analyze")
):
    """Start service discovery for domain or subdomain"""
    if not discovery_service:
        raise HTTPException(status_code=503, detail="Service not available")
    
    task_id = str(uuid.uuid4())
    task = TaskInfo(
        task_id=task_id,
        task_type=TaskType.SERVICE_DISCOVERY,
        domain=domain,
        subdomain=subdomain,
        status=TaskStatus.PENDING,
        started_at=datetime.now()
    )
    discovery_service.active_tasks[task_id] = task
    
    # Start async discovery
    asyncio.create_task(discovery_service.run_service_discovery(domain, subdomain, task_id))
    
    return {"task_id": task_id, "domain": domain, "subdomain": subdomain, "status": "started"}

@app.post("/api/v1/discover/dns/{domain}", tags=["Discovery"])
async def start_dns_analysis(
    domain: str = Path(..., description="Domain to analyze"),
    subdomain: Optional[str] = Query(None, description="Specific subdomain to analyze")
):
    """Start DNS analysis for domain or subdomain"""
    if not discovery_service:
        raise HTTPException(status_code=503, detail="Service not available")
    
    task_id = str(uuid.uuid4())
    task = TaskInfo(
        task_id=task_id,
        task_type=TaskType.DNS_ANALYSIS,
        domain=domain,
        subdomain=subdomain,
        status=TaskStatus.PENDING,
        started_at=datetime.now()
    )
    discovery_service.active_tasks[task_id] = task
    
    # Start async analysis
    asyncio.create_task(discovery_service.run_dns_analysis(domain, subdomain, task_id))
    
    return {"task_id": task_id, "domain": domain, "subdomain": subdomain, "status": "started"}

@app.post("/api/v1/discover/mx/{domain}", tags=["Discovery"])
async def start_mx_analysis(domain: str = Path(..., description="Domain to analyze")):
    """Start MX analysis with SPF, DMARC, DKIM for domain"""
    if not discovery_service:
        raise HTTPException(status_code=503, detail="Service not available")
    
    task_id = str(uuid.uuid4())
    task = TaskInfo(
        task_id=task_id,
        task_type=TaskType.MX_ANALYSIS,
        domain=domain,
        status=TaskStatus.PENDING,
        started_at=datetime.now()
    )
    discovery_service.active_tasks[task_id] = task
    
    # Start async analysis
    asyncio.create_task(discovery_service.run_mx_analysis(domain, task_id))
    
    return {"task_id": task_id, "domain": domain, "status": "started"}

@app.post("/api/v1/discover/tls/{domain}", tags=["Discovery"])
async def start_tls_analysis(
    domain: str = Path(..., description="Domain to analyze"),
    subdomain: Optional[str] = Query(None, description="Specific subdomain to analyze")
):
    """Start TLS analysis for domain or subdomain"""
    if not discovery_service:
        raise HTTPException(status_code=503, detail="Service not available")
    
    task_id = str(uuid.uuid4())
    task = TaskInfo(
        task_id=task_id,
        task_type=TaskType.TLS_ANALYSIS,
        domain=domain,
        subdomain=subdomain,
        status=TaskStatus.PENDING,
        started_at=datetime.now()
    )
    discovery_service.active_tasks[task_id] = task
    
    # Start async analysis
    asyncio.create_task(discovery_service.run_tls_analysis(domain, subdomain, task_id))
    
    return {"task_id": task_id, "domain": domain, "subdomain": subdomain, "status": "started"}

@app.post("/api/v1/discover/tech/{domain}", tags=["Discovery"])
async def start_tech_analysis(
    domain: str = Path(..., description="Domain to analyze"),
    subdomain: Optional[str] = Query(None, description="Specific subdomain to analyze")
):
    """Start web technology analysis for domain or subdomain"""
    if not discovery_service:
        raise HTTPException(status_code=503, detail="Service not available")
    
    task_id = str(uuid.uuid4())
    task = TaskInfo(
        task_id=task_id,
        task_type=TaskType.TECH_ANALYSIS,
        domain=domain,
        subdomain=subdomain,
        status=TaskStatus.PENDING,
        started_at=datetime.now()
    )
    discovery_service.active_tasks[task_id] = task
    
    # Start async analysis
    asyncio.create_task(discovery_service.run_tech_analysis(domain, subdomain, task_id))
    
    return {"task_id": task_id, "domain": domain, "subdomain": subdomain, "status": "started"}

# Batch operations
async def _run_complete_subdomain_analysis(domain: str, task_id: str, analysis_type: str, amass_timeout: int):
    """Background task for complete subdomain discovery and analysis"""
    try:
        logger.info(f"Starting complete subdomain discovery and analysis for {domain} (task: {task_id})")
        
        # Step 1: Run Amass to discover subdomains
        logger.info(f"Step 1: Running Amass discovery for {domain}")
        amass_task_id = f"{task_id}_amass"
        amass_result = await discovery_service.run_amass_discovery(domain, amass_task_id)
        
        if not amass_result or not hasattr(amass_result, 'subdomains') or not amass_result.subdomains:
            logger.warning(f"No subdomains found for {domain} during Amass discovery")
            # Update main task as completed with no subdomains
            if task_id in discovery_service.active_tasks:
                task = discovery_service.active_tasks[task_id]
                task.status = TaskStatus.COMPLETED
                task.completed_at = datetime.now()
                task.result = {
                    "message": f"No subdomains discovered for {domain}",
                    "subdomains_found": 0,
                    "analysis_completed": 0
                }
            return
        
        subdomains = amass_result.subdomains
        logger.info(f"Step 2: Found {len(subdomains)} subdomains, starting {analysis_type} analysis")
        
        # Step 2: Analyze all discovered subdomains
        analysis_task_ids = []
        
        for subdomain in subdomains:
            analysis_task_id = f"{task_id}_analysis_{len(analysis_task_ids)}"
            
            if analysis_type == "services":
                task_type = TaskType.SERVICE_DISCOVERY
                coro = discovery_service.run_service_discovery(domain, subdomain, analysis_task_id)
            elif analysis_type == "dns":
                task_type = TaskType.DNS_ANALYSIS
                coro = discovery_service.run_dns_analysis(domain, subdomain, analysis_task_id)
            elif analysis_type == "tls":
                task_type = TaskType.TLS_ANALYSIS
                coro = discovery_service.run_tls_analysis(domain, subdomain, analysis_task_id)
            elif analysis_type == "tech":
                task_type = TaskType.TECH_ANALYSIS
                coro = discovery_service.run_tech_analysis(domain, subdomain, analysis_task_id)
            elif analysis_type == "all":
                # Run all types of analysis
                for analysis in ["services", "dns", "tls", "tech"]:
                    specific_task_id = f"{analysis_task_id}_{analysis}"
                    if analysis == "services":
                        task_type = TaskType.SERVICE_DISCOVERY
                        coro = discovery_service.run_service_discovery(domain, subdomain, specific_task_id)
                    elif analysis == "dns":
                        task_type = TaskType.DNS_ANALYSIS
                        coro = discovery_service.run_dns_analysis(domain, subdomain, specific_task_id)
                    elif analysis == "tls":
                        task_type = TaskType.TLS_ANALYSIS
                        coro = discovery_service.run_tls_analysis(domain, subdomain, specific_task_id)
                    elif analysis == "tech":
                        task_type = TaskType.TECH_ANALYSIS
                        coro = discovery_service.run_tech_analysis(domain, subdomain, specific_task_id)
                    
                    task = TaskInfo(
                        task_id=specific_task_id,
                        task_type=task_type,
                        domain=domain,
                        subdomain=subdomain,
                        status=TaskStatus.PENDING,
                        started_at=datetime.now()
                    )
                    discovery_service.active_tasks[specific_task_id] = task
                    asyncio.create_task(coro)
                    analysis_task_ids.append(specific_task_id)
                continue
            else:
                logger.error(f"Invalid analysis type: {analysis_type}")
                return
            
            task = TaskInfo(
                task_id=analysis_task_id,
                task_type=task_type,
                domain=domain,
                subdomain=subdomain,
                status=TaskStatus.PENDING,
                started_at=datetime.now()
            )
            discovery_service.active_tasks[analysis_task_id] = task
            asyncio.create_task(coro)
            analysis_task_ids.append(analysis_task_id)
        
        # Update main task as completed
        if task_id in discovery_service.active_tasks:
            task = discovery_service.active_tasks[task_id]
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now()
            task.result = {
                "message": f"Discovered {len(subdomains)} subdomains and started {analysis_type} analysis",
                "subdomains_found": len(subdomains),
                "analysis_task_ids": analysis_task_ids,
                "analysis_type": analysis_type
            }
        
        logger.info(f"Completed subdomain discovery and analysis setup for {domain} (task: {task_id})")
        
    except Exception as e:
        logger.error(f"Error in complete subdomain discovery and analysis for {domain}: {e}")
        # Update task as failed
        if task_id in discovery_service.active_tasks:
            task = discovery_service.active_tasks[task_id]
            task.status = TaskStatus.FAILED
            task.completed_at = datetime.now()
            task.error = str(e)

@app.post("/api/v1/discover/all-subdomains/{domain}", tags=["Batch Operations"])
async def discover_and_analyze_all_subdomains(
    domain: str = Path(..., description="Base domain to discover and analyze"),
    amass_timeout: int = Query(900, description="Timeout for Amass discovery in seconds"),
    max_subdomains: int = Query(1000, description="Maximum number of subdomains to discover"),
    max_workers: int = Query(10, description="Maximum number of worker threads"),
    timeout_per_subdomain: int = Query(30, description="Timeout per subdomain analysis"),
    save_to_neo4j: bool = Query(True, description="Save results to Neo4j database"),
    analysis_type: str = Query("services", description="Type of analysis: services, dns, tls, tech, all")
):
    """Discover all subdomains using Amass, then analyze them with specified analysis type"""
    if not discovery_service:
        raise HTTPException(status_code=503, detail="Service not available")
    
    if analysis_type not in ["services", "dns", "tls", "tech", "all"]:
        raise HTTPException(status_code=400, detail="Invalid analysis type. Use: services, dns, tls, tech, or all")
    
    task_id = str(uuid.uuid4())
    
    # Create main task
    main_task = TaskInfo(
        task_id=task_id,
        task_type=TaskType.BATCH_ANALYSIS,
        domain=domain,
        subdomain=None,
        status=TaskStatus.RUNNING,
        started_at=datetime.now()
    )
    discovery_service.active_tasks[task_id] = main_task
    
    # Start background task
    asyncio.create_task(_run_complete_subdomain_analysis(domain, task_id, analysis_type, amass_timeout))
    
    # Return immediately with task info
    return {
        "message": f"Started complete subdomain discovery and analysis for {domain}",
        "domain": domain,
        "task_id": task_id,
        "status": "started",
        "analysis_type": analysis_type,
        "amass_timeout": amass_timeout
    }

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "timestamp": datetime.now().isoformat(),
            "path": str(request.url)
        }
    )

if __name__ == "__main__":
    uvicorn.run(
        "async_domain_discovery_api:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    )