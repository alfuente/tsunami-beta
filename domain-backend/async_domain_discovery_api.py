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
                 redis_host: str = "localhost", redis_port: int = 6379):
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_password = neo4j_password
        
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
        
        # Amass cache TTL (24 hours)
        self.amass_cache_ttl = 24 * 3600

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

    def _get_cached_amass_results(self, domain: str) -> Optional[CachedAmassData]:
        """Get cached Amass results from Redis"""
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

    async def run_amass_discovery(self, domain: str, task_id: str, timeout: int = 300) -> AmassResult:
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

    def _run_amass_sync(self, domain: str, task_id: str, timeout: int) -> AmassResult:
        """Synchronous Amass execution using direct binary"""
        # Create temp file for output
        temp_filename = f"/tmp/amass_output_{domain}_{int(time.time())}.txt"
        
        try:
            # Update progress
            if task_id in self.active_tasks:
                self.active_tasks[task_id].progress = 30
            
            # Run Amass command directly
            cmd = [
                '/usr/local/bin/amass', 'enum',
                '-d', domain,
                '-passive',
                '-o', temp_filename,
                '-timeout', str(max(1, timeout // 60))
            ]
            
            logger.info(f"Running Amass command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 60)
            
            if result.returncode != 0:
                raise Exception(f"Amass command failed: {result.stderr}")
            
            # Update progress
            if task_id in self.active_tasks:
                self.active_tasks[task_id].progress = 70
            
            # Parse results
            subdomains = []
            providers = []
            
            with open(temp_filename, 'r') as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain and is_valid_domain_name(subdomain):
                        subdomains.append(subdomain)
            
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
        
        # Create provider nodes
        for provider in result.providers:
            provider_id = f"{provider['name']}_{provider['ip']}_{int(time.time()*1000000)}"
            tx.run("""
                MERGE (p:Provider {id: $provider_id})
                SET p.name = $name,
                    p.confidence = $confidence,
                    p.source = $source,
                    p.country = $country,
                    p.tld = $tld,
                    p.ip = $ip,
                    p.discovered_at = $current_time
                WITH p
                MATCH (s:Subdomain {fqdn: $subdomain})
                MERGE (s)-[r:USES_SERVICE]->(p)
                SET r.created_at = $current_time
            """, provider_id=provider_id, name=provider['name'],
                 confidence=provider['confidence'], source=provider['source'],
                 country=provider.get('country'), tld=provider.get('tld'),
                 ip=provider['ip'], subdomain=provider['subdomain'],
                 current_time=current_time)

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
        
        try:
            with self.driver.session() as session:
                session.write_transaction(self._create_service_nodes, result)
            logger.info(f"Saved service results to Neo4j")
        except Exception as e:
            logger.error(f"Failed to save services to Neo4j: {e}")

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
            
            # Update progress
            if task_id in self.active_tasks:
                self.active_tasks[task_id].progress = 80
            
            # Analyze content for technology indicators
            content = response.text[:10000]  # First 10KB
            
            content_indicators = {
                'WordPress': 'wp-content',
                'Drupal': 'sites/default',
                'Joomla': 'components/com_',
                'jQuery': 'jquery',
                'React': 'react',
                'Vue': 'vue',
                'Angular': 'ng-'
            }
            
            for tech, indicator in content_indicators.items():
                if indicator in content.lower():
                    technologies.append({
                        "name": tech,
                        "category": "javascript" if tech in ['jQuery', 'React', 'Vue', 'Angular'] else "cms",
                        "confidence": 0.7,
                        "source": "content_analysis"
                    })
                    
                    if tech in ['WordPress', 'Drupal', 'Joomla'] and not cms:
                        cms = tech
        
        except Exception as e:
            logger.debug(f"Tech analysis failed for {target}: {e}")
            technologies.append({
                "name": "analysis_failed",
                "category": "error",
                "confidence": 1.0,
                "source": "error",
                "error": str(e)
            })
        
        result = TechAnalysisResult(
            domain=domain,
            subdomain=subdomain,
            technologies=technologies,
            web_server=web_server,
            cms=cms,
            metadata={
                "target": target,
                "total_technologies": len(technologies),
                "analysis_successful": not any(t.get("category") == "error" for t in technologies)
            }
        )
        
        # Save to Neo4j
        self._save_tech_to_neo4j(result)
        
        return result

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
        """Create Neo4j nodes for technology info"""
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
            neo4j_password=os.getenv("NEO4J_PASS", "tsunami123"),
            redis_host=os.getenv("REDIS_HOST", "localhost"),
            redis_port=int(os.getenv("REDIS_PORT", "6379"))
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
@app.post("/api/v1/discover/all-subdomains/{domain}", tags=["Batch Operations"])
async def analyze_all_subdomains(
    domain: str = Path(..., description="Base domain to analyze"),
    analysis_type: str = Query("services", description="Type of analysis: services, dns, tls, tech")
):
    """Analyze all subdomains of a domain with specified analysis type"""
    if not discovery_service:
        raise HTTPException(status_code=503, detail="Service not available")
    
    # First get subdomains from Neo4j
    if not HAS_NEO4J:
        raise HTTPException(status_code=503, detail="Neo4j not available")
    
    subdomains = []
    try:
        with discovery_service.driver.session() as session:
            result = session.run("""
                MATCH (d:Domain {fqdn: $domain})-[:HAS_SUBDOMAIN]->(s:Subdomain)
                RETURN s.fqdn as subdomain
            """, domain=domain)
            subdomains = [record["subdomain"] for record in result]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get subdomains: {e}")
    
    if not subdomains:
        raise HTTPException(status_code=404, detail="No subdomains found for domain")
    
    # Start analysis tasks for all subdomains
    task_ids = []
    for subdomain in subdomains:
        task_id = str(uuid.uuid4())
        
        if analysis_type == "services":
            task_type = TaskType.SERVICE_DISCOVERY
            coro = discovery_service.run_service_discovery(domain, subdomain, task_id)
        elif analysis_type == "dns":
            task_type = TaskType.DNS_ANALYSIS
            coro = discovery_service.run_dns_analysis(domain, subdomain, task_id)
        elif analysis_type == "tls":
            task_type = TaskType.TLS_ANALYSIS
            coro = discovery_service.run_tls_analysis(domain, subdomain, task_id)
        elif analysis_type == "tech":
            task_type = TaskType.TECH_ANALYSIS
            coro = discovery_service.run_tech_analysis(domain, subdomain, task_id)
        else:
            raise HTTPException(status_code=400, detail="Invalid analysis type")
        
        task = TaskInfo(
            task_id=task_id,
            task_type=task_type,
            domain=domain,
            subdomain=subdomain,
            status=TaskStatus.PENDING,
            started_at=datetime.now()
        )
        discovery_service.active_tasks[task_id] = task
        asyncio.create_task(coro)
        task_ids.append(task_id)
    
    return {
        "message": f"Started {analysis_type} analysis for {len(subdomains)} subdomains",
        "domain": domain,
        "task_ids": task_ids,
        "analysis_type": analysis_type
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