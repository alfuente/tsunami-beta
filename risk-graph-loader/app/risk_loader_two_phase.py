#!/usr/bin/env python3
"""
risk_loader_two_phase.py - Two-phase subdomain discovery and processing

Phase 1: Discovery - Run Amass in parallel and write domains/subdomains to graph
Phase 2: Processing - Process all discovered subdomains in parallel using separate processes

Key features:
1. Fast subdomain discovery using parallel Amass execution
2. Immediate graph writing of discovered domains/subdomains
3. Separate process-based parallel processing of subdomains
4. Better resource utilization and fault tolerance
"""

from __future__ import annotations
import argparse, json, subprocess, tempfile, sys, socket, ssl, re
from collections import deque, defaultdict
from pathlib import Path
from datetime import datetime, timedelta
from typing import Iterable, Mapping, Any, List, Dict, Set, Tuple, Optional
import threading
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import multiprocessing as mp
from threading import Lock
import time
import queue
from dataclasses import dataclass
from enum import Enum
import random

import dns.resolver, dns.exception, requests, logging
import csv
import ipaddress

# Try to import optional modules
try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID, ExtensionOID
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    from neo4j import GraphDatabase, Driver
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False

try:
    import maxminddb
    HAS_MAXMINDDB = True
except ImportError:
    HAS_MAXMINDDB = False

# Global configurations
AMASS_IMAGE = "caffix/amass:latest"
RESOLVER = dns.resolver.Resolver(configure=True)
IPINFO_MMDB_PATH = "ipinfo_data/ipinfo.mmdb"
IPINFO_CSV_PATH = "ipinfo_data/ipinfo.csv"

# Suppress logging noise
logging.getLogger('whois.whois').setLevel(logging.CRITICAL)
RESOLVER.lifetime = RESOLVER.timeout = 5.0

# Common TLD list for fallback
COMMON_TLDS = {
    'cl', 'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'co.uk', 'co.jp', 'co.kr',
    'com.au', 'com.br', 'com.cn', 'com.mx', 'co.za', 'de', 'fr', 'it', 'es', 'ru',
    'jp', 'kr', 'au', 'br', 'cn', 'mx', 'za', 'uk', 'ca', 'us', 'ar', 'pe', 'co',
    'ec', 'bo', 'py', 'uy', 've', 'mx', 'gt', 'pa', 'cr', 'ni', 'hn', 'sv', 'do',
    'cu', 'jm', 'ht', 'tt', 'bb', 'gd', 'lc', 'vc', 'ag', 'dm', 'kn', 'ms', 'ai',
    'vg', 'vi', 'pr', 'ad', 'mc', 'sm', 'va', 'li', 'ch', 'at', 'be', 'nl', 'lu',
    'dk', 'se', 'no', 'fi', 'is', 'ie', 'pt', 'mt', 'cy', 'gr', 'bg', 'ro', 'hu',
    'sk', 'cz', 'pl', 'lt', 'lv', 'ee', 'si', 'hr', 'ba', 'rs', 'me', 'mk', 'al',
    'by', 'ua', 'md', 'ge', 'am', 'az', 'kz', 'kg', 'tj', 'tm', 'uz', 'mn', 'in',
    'pk', 'bd', 'lk', 'mv', 'bt', 'np', 'af', 'ir', 'iq', 'sy', 'lb', 'jo', 'ps',
    'il', 'tr', 'cy', 'eg', 'ly', 'tn', 'dz', 'ma', 'sd', 'so', 'dj', 'er', 'et',
    'ke', 'ug', 'tz', 'rw', 'bi', 'mw', 'zm', 'zw', 'bw', 'na', 'sz', 'ls', 'mg',
    'mu', 'sc', 'km', 'yt', 're', 'mz', 'ao', 'gh', 'tg', 'bj', 'bf', 'ne', 'ci',
    'lr', 'sl', 'gn', 'gw', 'cv', 'sn', 'gm', 'ml', 'mr', 'eh', 'st', 'gq', 'ga',
    'cg', 'cf', 'cd', 'cm', 'td', 'ng', 'bv', 'sj', 'gl', 'fo', 'ax', 'gf', 'sr',
    'gy', 'fk', 'gs', 'sh', 'ac', 'ta', 'io', 'tf', 'hm', 'aq', 'pn', 'ck', 'nu',
    'tk', 'to', 'ws', 'ki', 'tv', 'fj', 'vu', 'nc', 'pg', 'sb', 'nf', 'as', 'gu',
    'mp', 'pw', 'mh', 'fm', 'um', 'cc', 'cx', 'cw', 'sx', 'bq', 'gp', 'mq', 'bl',
    'mf', 'pm', 'wf', 'pf', 'tk', 'je', 'gg', 'im', 'za', 'info', 'name', 'travel',
    'museum', 'biz', 'pro', 'aero', 'coop', 'jobs', 'mobi', 'tel', 'asia', 'cat',
    'xxx', 'post', 'travel', 'arpa'
}

def extract_tld_fallback(fqdn: str):
    """Fallback TLD extraction when tldextract is not available."""
    parts = fqdn.split('.')
    if len(parts) < 2:
        return None, fqdn, ''
    
    # Try to match known TLDs (including multi-part ones like co.uk)
    for i in range(len(parts) - 1):
        potential_tld = '.'.join(parts[i:])
        if potential_tld in COMMON_TLDS:
            domain = parts[i-1] if i > 0 else parts[0]
            subdomain = '.'.join(parts[:i-1]) if i > 1 else ''
            return domain, potential_tld, subdomain
    
    # Fallback to simple parsing
    domain = parts[-2]
    tld = parts[-1]
    subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
    
    return domain, tld, subdomain

@dataclass
class DomainInfo:
    """Enhanced domain information with proper TLD/subdomain distinction."""
    fqdn: str
    domain: str  # The actual domain part (e.g., "bci" from "bci.cl")
    tld: str     # The TLD (e.g., "cl" from "bci.cl")
    subdomain: str  # The subdomain part (e.g., "www" from "www.bci.cl")
    is_tld_domain: bool  # True if this is a TLD domain (e.g., "bci.cl")
    parent_domain: Optional[str] = None  # For subdomains, points to parent
    
    @classmethod
    def from_fqdn(cls, fqdn: str) -> 'DomainInfo':
        """Create DomainInfo from FQDN using proper TLD extraction."""
        
        if HAS_TLDEXTRACT:
            try:
                extracted = tldextract.extract(fqdn)
                if extracted and extracted.domain and extracted.suffix:
                    domain = extracted.domain
                    tld = extracted.suffix
                    subdomain = extracted.subdomain
                else:
                    # Fallback to manual parsing
                    domain, tld, subdomain = extract_tld_fallback(fqdn)
            except:
                # Fallback if tldextract fails
                domain, tld, subdomain = extract_tld_fallback(fqdn)
        else:
            # Use fallback method when tldextract is not available
            domain, tld, subdomain = extract_tld_fallback(fqdn)
        
        # Determine if this is a TLD domain (no subdomain part)
        is_tld_domain = not subdomain
        
        # For subdomains, construct parent domain
        parent_domain = None
        if not is_tld_domain:
            parent_domain = f"{domain}.{tld}"
        
        return cls(
            fqdn=fqdn,
            domain=domain,
            tld=tld,
            subdomain=subdomain,
            is_tld_domain=is_tld_domain,
            parent_domain=parent_domain
        )

class TwoPhaseGraphIngester:
    """Two-phase graph ingester for discovery and processing."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str, ipinfo_token: str = None, 
                 mmdb_path: str = IPINFO_MMDB_PATH, csv_path: str = IPINFO_CSV_PATH):
        if not HAS_NEO4J:
            raise ImportError("Neo4j driver is required. Install with: pip install neo4j")
        
        self.drv = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
        self.ipinfo_token = ipinfo_token
        self.mmdb_path = mmdb_path
        self.csv_path = csv_path
        self.setup_constraints()
    
    def setup_constraints(self):
        """Setup Neo4j constraints for enhanced model."""
        with self.drv.session() as s:
            # TLD constraints
            s.run("CREATE CONSTRAINT tld_name IF NOT EXISTS FOR (t:TLD) REQUIRE t.name IS UNIQUE")
            
            # Domain constraints (for TLD domains like "bci.cl")
            s.run("CREATE CONSTRAINT domain_fqdn IF NOT EXISTS FOR (d:Domain) REQUIRE d.fqdn IS UNIQUE")
            
            # Subdomain constraints
            s.run("CREATE CONSTRAINT subdomain_fqdn IF NOT EXISTS FOR (s:Subdomain) REQUIRE s.fqdn IS UNIQUE")
            
            # Other existing constraints
            s.run("CREATE CONSTRAINT ip_addr IF NOT EXISTS FOR (ip:IPAddress) REQUIRE ip.address IS UNIQUE")
            s.run("CREATE CONSTRAINT service_name IF NOT EXISTS FOR (svc:Service) REQUIRE svc.name IS UNIQUE")
    
    def create_domain_hierarchy_batch(self, domains: List[str], batch_size: int = 100) -> Dict[str, Any]:
        """Create domain hierarchy for multiple domains in batches."""
        stats = {
            'domains_created': 0,
            'subdomains_created': 0,
            'tlds_created': 0,
            'errors': 0
        }
        
        # Process domains in batches
        for i in range(0, len(domains), batch_size):
            batch = domains[i:i+batch_size]
            
            with self.drv.session() as s:
                with s.begin_transaction() as tx:
                    for fqdn in batch:
                        try:
                            self._create_domain_hierarchy_single(fqdn, tx)
                            
                            domain_info = DomainInfo.from_fqdn(fqdn)
                            if domain_info.is_tld_domain:
                                stats['domains_created'] += 1
                            else:
                                stats['subdomains_created'] += 1
                                
                        except Exception as e:
                            print(f"Error creating hierarchy for {fqdn}: {e}")
                            stats['errors'] += 1
                    
                    tx.commit()
            
            print(f"✓ Processed batch {i//batch_size + 1}/{(len(domains)-1)//batch_size + 1}")
        
        return stats
    
    def _create_domain_hierarchy_single(self, fqdn: str, tx):
        """Create domain hierarchy for a single domain."""
        domain_info = DomainInfo.from_fqdn(fqdn)
        current_time = datetime.now().isoformat()
        
        # 1. Create/merge TLD node
        tx.run("""
            MERGE (tld:TLD {name: $tld})
            SET tld.last_updated = $current_time
            RETURN tld
        """, tld=domain_info.tld, current_time=current_time)
        
        # 2. Create/merge Domain node (TLD domain like "bci.cl")
        tld_domain_fqdn = f"{domain_info.domain}.{domain_info.tld}"
        tx.run("""
            MERGE (d:Domain {fqdn: $fqdn})
            SET d.domain_name = $domain_name,
                d.tld = $tld,
                d.last_analyzed = $current_time,
                d.discovery_phase = true
            RETURN d
        """, fqdn=tld_domain_fqdn, domain_name=domain_info.domain, tld=domain_info.tld,
             current_time=current_time)
        
        # 3. Create relationship: TLD -> Domain
        tx.run("""
            MATCH (tld:TLD {name: $tld})
            MATCH (d:Domain {fqdn: $domain_fqdn})
            MERGE (tld)-[:CONTAINS_DOMAIN]->(d)
        """, tld=domain_info.tld, domain_fqdn=tld_domain_fqdn)
        
        # 4. If this is a subdomain, create subdomain node and relationships
        if not domain_info.is_tld_domain:
            tx.run("""
                MERGE (s:Subdomain {fqdn: $fqdn})
                SET s.subdomain_name = $subdomain_name,
                    s.domain_name = $domain_name,
                    s.tld = $tld,
                    s.last_analyzed = $current_time,
                    s.discovery_phase = true,
                    s.processing_phase = false
                RETURN s
            """, fqdn=domain_info.fqdn, subdomain_name=domain_info.subdomain,
                 domain_name=domain_info.domain, tld=domain_info.tld,
                 current_time=current_time)
            
            # 5. Create relationship: Domain -> Subdomain
            tx.run("""
                MATCH (d:Domain {fqdn: $parent_fqdn})
                MATCH (s:Subdomain {fqdn: $subdomain_fqdn})
                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
            """, parent_fqdn=domain_info.parent_domain, subdomain_fqdn=domain_info.fqdn)
    
    def get_unprocessed_subdomains(self, batch_size: int = 100) -> List[str]:
        """Get subdomains that haven't been processed in phase 2."""
        with self.drv.session() as s:
            result = s.run("""
                MATCH (s:Subdomain)
                WHERE s.processing_phase IS NULL OR s.processing_phase = false
                RETURN s.fqdn as fqdn
                ORDER BY s.last_analyzed DESC
                LIMIT $batch_size
            """, batch_size=batch_size)
            
            return [record["fqdn"] for record in result]
    
    def mark_subdomain_as_processed(self, fqdn: str, tx=None):
        """Mark a subdomain as processed."""
        current_time = datetime.now().isoformat()
        
        if tx is None:
            with self.drv.session() as s:
                with s.begin_transaction() as tx:
                    self._mark_subdomain_processed_internal(fqdn, current_time, tx)
        else:
            self._mark_subdomain_processed_internal(fqdn, current_time, tx)
    
    def _mark_subdomain_processed_internal(self, fqdn: str, current_time: str, tx):
        """Internal method to mark subdomain as processed."""
        tx.run("""
            MATCH (s:Subdomain {fqdn: $fqdn})
            SET s.processing_phase = true,
                s.last_processed = $current_time
        """, fqdn=fqdn, current_time=current_time)
    
    def merge_ip_with_enhanced_tracking(self, fqdn: str, ip: str, tx=None):
        """Enhanced IP merge with proper domain/subdomain association."""
        domain_info = DomainInfo.from_fqdn(fqdn)
        current_time = datetime.now().isoformat()
        
        # Detect cloud provider
        prov = self.detect_cloud_provider_by_ip(ip)
        cloud_info = self.get_cloud_provider_info(ip)
        
        if tx is None:
            with self.drv.session() as s:
                with s.begin_transaction() as tx:
                    return self._merge_ip_internal(domain_info, ip, prov, cloud_info, current_time, tx)
        else:
            return self._merge_ip_internal(domain_info, ip, prov, cloud_info, current_time, tx)
    
    def _merge_ip_internal(self, domain_info: DomainInfo, ip: str, prov: str, cloud_info: dict, 
                          current_time: str, tx):
        """Internal IP merge logic."""
        
        # Create IP node with provider info
        tx.run("""
            MERGE (ip:IPAddress {address: $ip})
            SET ip.provider = $provider,
                ip.cloud_info = $cloud_info,
                ip.last_updated = $current_time
            RETURN ip
        """, ip=ip, provider=prov, cloud_info=json.dumps(cloud_info), current_time=current_time)
        
        # Create relationship based on node type
        if domain_info.is_tld_domain:
            # Domain -> IP relationship
            tx.run("""
                MATCH (d:Domain {fqdn: $fqdn})
                MATCH (ip:IPAddress {address: $ip})
                MERGE (d)-[:RESOLVES_TO]->(ip)
            """, fqdn=domain_info.fqdn, ip=ip)
        else:
            # Subdomain -> IP relationship
            tx.run("""
                MATCH (s:Subdomain {fqdn: $fqdn})
                MATCH (ip:IPAddress {address: $ip})
                MERGE (s)-[:RESOLVES_TO]->(ip)
            """, fqdn=domain_info.fqdn, ip=ip)
        
        # Create provider service if not exists
        if prov and prov != "unknown":
            tx.run("""
                MERGE (svc:Service {name: $provider, type: 'cloud_provider'})
                SET svc.last_updated = $current_time
                RETURN svc
            """, provider=prov, current_time=current_time)
            
            # Link IP to provider service
            tx.run("""
                MATCH (ip:IPAddress {address: $ip})
                MATCH (svc:Service {name: $provider, type: 'cloud_provider'})
                MERGE (ip)-[:HOSTED_BY]->(svc)
            """, ip=ip, provider=prov)
    
    def detect_cloud_provider_by_ip(self, ip: str) -> str:
        """Detect cloud provider for IP address using existing detection logic."""
        try:
            from risk_loader_advanced3 import detect_cloud_provider_by_ip
            return detect_cloud_provider_by_ip(ip, self.ipinfo_token, self.mmdb_path, self.csv_path)
        except ImportError:
            return "unknown"
    
    def get_cloud_provider_info(self, ip: str) -> dict:
        """Get detailed cloud provider info for IP."""
        try:
            from risk_loader_advanced3 import get_cloud_provider_info
            return get_cloud_provider_info(ip, self.ipinfo_token, self.mmdb_path, self.csv_path)
        except ImportError:
            return {}
    
    def get_discovery_statistics(self) -> Dict[str, Any]:
        """Get statistics about the discovery phase."""
        with self.drv.session() as s:
            result = s.run("""
                MATCH (d:Domain) 
                OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                RETURN 
                    count(DISTINCT d) as domain_count,
                    count(DISTINCT s) as subdomain_count,
                    count(DISTINCT CASE WHEN s.processing_phase = true THEN s END) as processed_subdomains,
                    count(DISTINCT CASE WHEN s.processing_phase IS NULL OR s.processing_phase = false THEN s END) as unprocessed_subdomains
            """)
            
            stats = dict(result.single())
            
            # Get TLD count
            tld_result = s.run("MATCH (t:TLD) RETURN count(t) as tld_count")
            stats['tld_count'] = tld_result.single()['tld_count']
            
            # Get IP count
            ip_result = s.run("MATCH (ip:IPAddress) RETURN count(ip) as ip_count")
            stats['ip_count'] = ip_result.single()['ip_count']
            
            return stats
    
    def close(self):
        """Close Neo4j connection."""
        self.drv.close()

def retry_on_deadlock(func, max_retries=3, initial_delay=0.1):
    """Decorator to retry operations on Neo4j deadlock detection."""
    def wrapper(*args, **kwargs):
        for attempt in range(max_retries):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_msg = str(e).lower()
                if "deadlock" in error_msg or "transient" in error_msg:
                    if attempt < max_retries - 1:
                        delay = initial_delay * (2 ** attempt) + random.uniform(0, 0.1)
                        print(f"Deadlock detected, retrying in {delay:.2f}s (attempt {attempt + 1}/{max_retries})")
                        time.sleep(delay)
                        continue
                    else:
                        print(f"Max retries reached for deadlock, giving up: {e}")
                        raise e
                else:
                    raise e
        return None
    return wrapper

def dns_query(domain: str, rdtype: str) -> List[str]:
    """DNS query with enhanced error handling."""
    try:
        result = RESOLVER.resolve(domain, rdtype)
        return [str(r) for r in result]
    except (dns.exception.DNSException, Exception):
        return []

def run_amass_discovery_only(domain: str, timeout: int = 60, mock_mode: bool = False, 
                             sample_mode: bool = False) -> List[str]:
    """Run Amass for subdomain discovery only (no processing)."""
    
    # Mock mode for testing
    if mock_mode:
        mock_subdomains = [
            f"www.{domain}",
            f"mail.{domain}",
            f"api.{domain}",
            f"admin.{domain}"
        ]
        print(f"[DISCOVERY] MOCK MODE: Found {len(mock_subdomains)} subdomains for {domain}")
        return mock_subdomains
    
    try:
        from risk_loader_advanced3 import run_amass_local
        
        # Get Amass results with configurable mode
        print(f"[DISCOVERY] Starting Amass for {domain} (sample_mode={sample_mode})")
        results = run_amass_local(domain, sample_mode=sample_mode)
        
        # Extract just the subdomain names
        subdomains = []
        for result in results:
            subdomain = result.get('name')
            if subdomain and subdomain != domain:
                subdomains.append(subdomain)
        
        print(f"[DISCOVERY] Found {len(subdomains)} subdomains for {domain}")
        if len(subdomains) == 0:
            print(f"[DISCOVERY] WARNING: No subdomains found for {domain} - this might indicate an issue")
        
        return subdomains
        
    except ImportError:
        print(f"[DISCOVERY] Cannot import Amass functions, skipping {domain}")
        return []
    except Exception as e:
        print(f"[DISCOVERY] Error discovering subdomains for {domain}: {e}")
        return []

def run_amass_discovery_parallel(domains: List[str], max_workers: int = 4, mock_mode: bool = False, 
                                  sample_mode: bool = False) -> Dict[str, List[str]]:
    """Run Amass discovery in parallel for multiple domains."""
    results = {}
    
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="AmassDiscovery") as executor:
        # Submit all discovery tasks
        future_to_domain = {
            executor.submit(run_amass_discovery_only, domain, 60, mock_mode, sample_mode): domain 
            for domain in domains
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                subdomains = future.result()
                results[domain] = subdomains
                print(f"✓ Discovery completed for {domain}: {len(subdomains)} subdomains")
            except Exception as e:
                print(f"✗ Discovery failed for {domain}: {e}")
                results[domain] = []
    
    return results

def process_subdomain_worker(args: Tuple[str, str, str, str, str]) -> Dict[str, Any]:
    """Worker function for processing a single subdomain in a separate process."""
    fqdn, neo4j_uri, neo4j_user, neo4j_pass, ipinfo_token = args
    
    @retry_on_deadlock
    def process_with_retry():
        # Create new ingester instance for this process
        ingester = TwoPhaseGraphIngester(neo4j_uri, neo4j_user, neo4j_pass, ipinfo_token)
        
        stats = {
            'fqdn': fqdn,
            'ip_count': 0,
            'provider_count': 0,
            'success': True,
            'error': None
        }
        
        # Process DNS records with smaller transactions to reduce deadlock probability
        try:
            # Process A and AAAA records
            for rdtype in ("A", "AAAA"):
                addrs = dns_query(fqdn, rdtype)
                for addr in addrs:
                    # Use separate transaction for each IP to minimize lock time
                    with ingester.drv.session() as s:
                        with s.begin_transaction() as tx:
                            ingester.merge_ip_with_enhanced_tracking(fqdn, addr, tx)
                            tx.commit()
                    stats['ip_count'] += 1
            
            # Mark as processed in separate transaction
            with ingester.drv.session() as s:
                with s.begin_transaction() as tx:
                    ingester.mark_subdomain_as_processed(fqdn, tx)
                    tx.commit()
        
        finally:
            ingester.close()
        
        return stats
    
    try:
        stats = process_with_retry()
        print(f"✓ Processed subdomain: {fqdn} ({stats['ip_count']} IPs)")
        return stats
        
    except Exception as e:
        print(f"✗ Error processing subdomain {fqdn}: {e}")
        return {
            'fqdn': fqdn,
            'ip_count': 0,
            'provider_count': 0,
            'success': False,
            'error': str(e)
        }

class TwoPhaseProcessor:
    """Two-phase processor for discovery and parallel processing."""
    
    def __init__(self, ingester: TwoPhaseGraphIngester, neo4j_uri: str, neo4j_user: str, 
                 neo4j_pass: str, max_discovery_workers: int = 4, max_processing_workers: int = 8, 
                 mock_mode: bool = False, sample_mode: bool = False):
        self.ingester = ingester
        self.max_discovery_workers = max_discovery_workers
        self.max_processing_workers = max_processing_workers
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_pass = neo4j_pass
        self.ipinfo_token = ingester.ipinfo_token
        self.mock_mode = mock_mode
        self.sample_mode = sample_mode
    
    def phase1_discovery(self, domains: List[str]) -> Dict[str, Any]:
        """Phase 1: Discover subdomains and write to graph."""
        print(f"\n🔍 PHASE 1: Subdomain Discovery")
        print(f"   Domains: {len(domains)}")
        print(f"   Discovery workers: {self.max_discovery_workers}")
        print("="*60)
        
        start_time = time.time()
        
        # Step 1: Create initial domain hierarchy
        print("Step 1: Creating domain hierarchy...")
        hierarchy_stats = self.ingester.create_domain_hierarchy_batch(domains)
        print(f"✓ Created {hierarchy_stats['domains_created']} domains")
        
        # Step 2: Run parallel Amass discovery
        print(f"Step 2: Running parallel subdomain discovery (sample_mode={self.sample_mode})...")
        discovery_results = run_amass_discovery_parallel(domains, self.max_discovery_workers, self.mock_mode, self.sample_mode)
        
        # Step 3: Collect all discovered subdomains
        all_subdomains = []
        for domain, subdomains in discovery_results.items():
            all_subdomains.extend(subdomains)
        
        print(f"✓ Discovered {len(all_subdomains)} total subdomains")
        
        # Step 4: Write discovered subdomains to graph
        if all_subdomains:
            print("Step 3: Writing discovered subdomains to graph...")
            subdomain_stats = self.ingester.create_domain_hierarchy_batch(all_subdomains)
            print(f"✓ Created {subdomain_stats['subdomains_created']} subdomain nodes")
        
        elapsed_time = time.time() - start_time
        
        stats = {
            'phase': 1,
            'domains_processed': len(domains),
            'subdomains_discovered': len(all_subdomains),
            'elapsed_time': elapsed_time,
            'discovery_results': discovery_results,
            'hierarchy_stats': hierarchy_stats,
            'subdomain_stats': subdomain_stats if all_subdomains else {}
        }
        
        print(f"\n✅ Phase 1 completed in {elapsed_time:.1f} seconds")
        print(f"   Domains processed: {stats['domains_processed']}")
        print(f"   Subdomains discovered: {stats['subdomains_discovered']}")
        print("="*60)
        
        return stats
    
    def phase2_processing(self, batch_size: int = 100) -> Dict[str, Any]:
        """Phase 2: Process discovered subdomains in parallel."""
        print(f"\n⚡ PHASE 2: Parallel Subdomain Processing")
        print(f"   Processing workers: {self.max_processing_workers}")
        print(f"   Batch size: {batch_size}")
        print("="*60)
        
        start_time = time.time()
        total_processed = 0
        total_successful = 0
        total_errors = 0
        
        while True:
            # Get batch of unprocessed subdomains
            subdomains = self.ingester.get_unprocessed_subdomains(batch_size)
            
            if not subdomains:
                print("No more subdomains to process")
                break
            
            print(f"Processing batch of {len(subdomains)} subdomains...")
            
            # Prepare arguments for worker processes
            worker_args = [
                (fqdn, self.neo4j_uri, self.neo4j_user, self.neo4j_pass, self.ipinfo_token)
                for fqdn in subdomains
            ]
            
            # Process subdomains in parallel using separate processes
            with ProcessPoolExecutor(max_workers=self.max_processing_workers) as executor:
                results = executor.map(process_subdomain_worker, worker_args)
                
                # Collect results
                for result in results:
                    total_processed += 1
                    if result['success']:
                        total_successful += 1
                    else:
                        total_errors += 1
                        print(f"Error processing {result['fqdn']}: {result['error']}")
            
            print(f"✓ Batch completed: {len(subdomains)} processed")
        
        elapsed_time = time.time() - start_time
        
        stats = {
            'phase': 2,
            'total_processed': total_processed,
            'successful': total_successful,
            'errors': total_errors,
            'elapsed_time': elapsed_time,
            'rate': total_processed / elapsed_time if elapsed_time > 0 else 0
        }
        
        print(f"\n✅ Phase 2 completed in {elapsed_time:.1f} seconds")
        print(f"   Subdomains processed: {stats['total_processed']}")
        print(f"   Successful: {stats['successful']}")
        print(f"   Errors: {stats['errors']}")
        print(f"   Rate: {stats['rate']:.1f} subdomains/second")
        print("="*60)
        
        return stats
    
    def run_two_phase_processing(self, domains: List[str], batch_size: int = 100) -> Dict[str, Any]:
        """Run complete two-phase processing."""
        print(f"\n🚀 Starting Two-Phase Subdomain Processing")
        print(f"   Input domains: {len(domains)}")
        print(f"   Discovery workers: {self.max_discovery_workers}")
        print(f"   Processing workers: {self.max_processing_workers}")
        print(f"   Processing batch size: {batch_size}")
        print("="*80)
        
        overall_start = time.time()
        
        # Phase 1: Discovery
        phase1_stats = self.phase1_discovery(domains)
        
        # Phase 2: Processing
        phase2_stats = self.phase2_processing(batch_size)
        
        # Final statistics
        overall_elapsed = time.time() - overall_start
        final_stats = self.ingester.get_discovery_statistics()
        
        combined_stats = {
            'overall_elapsed_time': overall_elapsed,
            'phase1_stats': phase1_stats,
            'phase2_stats': phase2_stats,
            'final_graph_stats': final_stats
        }
        
        print(f"\n🎉 Two-Phase Processing Completed!")
        print(f"   Total time: {overall_elapsed:.1f} seconds")
        print(f"   Final graph statistics:")
        print(f"     - Domains: {final_stats['domain_count']}")
        print(f"     - Subdomains: {final_stats['subdomain_count']}")
        print(f"     - Processed subdomains: {final_stats['processed_subdomains']}")
        print(f"     - IPs: {final_stats['ip_count']}")
        print(f"     - TLDs: {final_stats['tld_count']}")
        print("="*80)
        
        return combined_stats

def main():
    """Main function for two-phase processing."""
    parser = argparse.ArgumentParser(description="Two-phase subdomain discovery and processing")
    parser.add_argument("--domains", required=True, help="Input domains file")
    parser.add_argument("--bolt", default="bolt://localhost:7687", help="Neo4j bolt URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", required=True, help="Neo4j password")
    parser.add_argument("--ipinfo-token", help="IPInfo token")
    
    # Phase control
    parser.add_argument("--phase1-only", action="store_true", help="Run only discovery phase")
    parser.add_argument("--phase2-only", action="store_true", help="Run only processing phase")
    
    # Worker configuration
    parser.add_argument("--discovery-workers", type=int, default=4, help="Number of discovery workers")
    parser.add_argument("--processing-workers", type=int, default=4, help="Number of processing workers")
    parser.add_argument("--batch-size", type=int, default=50, help="Batch size for processing")
    parser.add_argument("--mock-mode", action="store_true", help="Use mock subdomain discovery for testing")
    parser.add_argument("--sample-mode", action="store_true", help="Use Amass sample mode (faster but less comprehensive)")
    
    args = parser.parse_args()
    
    # Initialize ingester
    ingester = TwoPhaseGraphIngester(args.bolt, args.user, args.password, args.ipinfo_token)
    
    try:
        # Read domains from file
        with open(args.domains, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        
        # Initialize processor
        processor = TwoPhaseProcessor(
            ingester, 
            args.bolt,
            args.user,
            args.password,
            args.discovery_workers, 
            args.processing_workers,
            args.mock_mode,
            args.sample_mode
        )
        
        # Run appropriate phase(s)
        if args.phase1_only:
            stats = processor.phase1_discovery(domains)
        elif args.phase2_only:
            stats = processor.phase2_processing(args.batch_size)
        else:
            stats = processor.run_two_phase_processing(domains, args.batch_size)
        
        print(f"\n📊 Final Statistics:")
        print(json.dumps(stats, indent=2, default=str))
        
    finally:
        ingester.close()

if __name__ == "__main__":
    main()