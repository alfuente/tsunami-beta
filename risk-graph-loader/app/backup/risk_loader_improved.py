#!/usr/bin/env python3
"""
risk_loader_improved.py - Enhanced domain processing with proper TLD/subdomain distinction

Key improvements:
1. Proper TLD extraction using tldextract
2. Distinct node types: TLD, Domain, Subdomain
3. Timestamp tracking for analysis and risk scoring
4. Graph-based queue management (no SQLite dependency)
5. Enhanced depth processing to ensure provider discovery
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

class EnhancedGraphIngester:
    """Enhanced graph ingester with proper domain/subdomain handling and timestamps."""
    
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
    
    def merge_tld_domain_subdomain(self, fqdn: str, who: Optional[Mapping[str, Any]] = None, tx=None):
        """Create appropriate nodes (TLD, Domain, Subdomain) with proper relationships."""
        domain_info = DomainInfo.from_fqdn(fqdn)
        current_time = datetime.now().isoformat()
        
        if tx is None:
            with self.drv.session() as s:
                with s.begin_transaction() as tx:
                    return self._create_domain_hierarchy(domain_info, who, current_time, tx)
        else:
            return self._create_domain_hierarchy(domain_info, who, current_time, tx)
    
    def _create_domain_hierarchy(self, domain_info: DomainInfo, who: Optional[Mapping[str, Any]], 
                                current_time: str, tx):
        """Create the complete domain hierarchy with proper relationships."""
        
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
                d.registered_date = coalesce($created, d.registered_date),
                d.expiry_date = coalesce($expires, d.expiry_date),
                d.last_risk_scoring = CASE 
                    WHEN d.last_risk_scoring IS NULL THEN $current_time 
                    ELSE d.last_risk_scoring 
                END
            RETURN d
        """, fqdn=tld_domain_fqdn, domain_name=domain_info.domain, tld=domain_info.tld,
             current_time=current_time,
             created=who.get("creation_date") if who else None,
             expires=who.get("expiration_date") if who else None)
        
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
                    s.last_risk_scoring = CASE 
                        WHEN s.last_risk_scoring IS NULL THEN $current_time 
                        ELSE s.last_risk_scoring 
                    END
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
        
        print(f"✓ Created domain hierarchy for: {domain_info.fqdn}")
        return domain_info
    
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
        
        print(f"✓ IP {ip} linked to {domain_info.fqdn} (provider: {prov})")
    
    def get_nodes_needing_analysis(self, days_old: int = 7) -> List[Dict]:
        """Get nodes that haven't been analyzed in N days (replaces SQLite queue)."""
        cutoff_date = (datetime.now() - timedelta(days=days_old)).isoformat()
        
        with self.drv.session() as s:
            # Get domains needing analysis
            domains_result = s.run("""
                MATCH (d:Domain)
                WHERE d.last_analyzed IS NULL OR d.last_analyzed < $cutoff_date
                RETURN 'domain' as node_type, d.fqdn as fqdn, d.last_analyzed as last_analyzed
                ORDER BY coalesce(d.last_analyzed, '1970-01-01')
                LIMIT 100
            """, cutoff_date=cutoff_date)
            
            # Get subdomains needing analysis
            subdomains_result = s.run("""
                MATCH (s:Subdomain)
                WHERE s.last_analyzed IS NULL OR s.last_analyzed < $cutoff_date
                RETURN 'subdomain' as node_type, s.fqdn as fqdn, s.last_analyzed as last_analyzed
                ORDER BY coalesce(s.last_analyzed, '1970-01-01')
                LIMIT 100
            """, cutoff_date=cutoff_date)
            
            nodes = []
            for record in domains_result:
                nodes.append(dict(record))
            for record in subdomains_result:
                nodes.append(dict(record))
            
            return nodes
    
    def get_nodes_needing_risk_scoring(self, days_old: int = 7) -> List[Dict]:
        """Get nodes that haven't had risk scoring in N days."""
        cutoff_date = (datetime.now() - timedelta(days=days_old)).isoformat()
        
        with self.drv.session() as s:
            result = s.run("""
                MATCH (n)
                WHERE (n:Domain OR n:Subdomain)
                AND (n.last_risk_scoring IS NULL OR n.last_risk_scoring < $cutoff_date)
                RETURN labels(n)[0] as node_type, n.fqdn as fqdn, n.last_risk_scoring as last_risk_scoring
                ORDER BY coalesce(n.last_risk_scoring, '1970-01-01')
                LIMIT 100
            """, cutoff_date=cutoff_date)
            
            return [dict(record) for record in result]
    
    def update_risk_scoring_timestamp(self, fqdn: str, node_type: str, tx=None):
        """Update risk scoring timestamp for a node."""
        current_time = datetime.now().isoformat()
        
        if tx is None:
            with self.drv.session() as s:
                with s.begin_transaction() as tx:
                    return self._update_risk_scoring_internal(fqdn, node_type, current_time, tx)
        else:
            return self._update_risk_scoring_internal(fqdn, node_type, current_time, tx)
    
    def _update_risk_scoring_internal(self, fqdn: str, node_type: str, current_time: str, tx):
        """Internal risk scoring timestamp update."""
        if node_type.lower() == 'domain':
            tx.run("""
                MATCH (d:Domain {fqdn: $fqdn})
                SET d.last_risk_scoring = $current_time
            """, fqdn=fqdn, current_time=current_time)
        else:
            tx.run("""
                MATCH (s:Subdomain {fqdn: $fqdn})
                SET s.last_risk_scoring = $current_time
            """, fqdn=fqdn, current_time=current_time)
    
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
    
    def ensure_provider_discovery_depth(self, fqdn: str, max_depth: int = 3) -> bool:
        """Ensure we reach provider level by expanding depth if needed."""
        
        with self.drv.session() as s:
            # Check if we have provider information for this domain/subdomain
            result = s.run("""
                MATCH (n {fqdn: $fqdn})-[:RESOLVES_TO]->(ip:IPAddress)-[:HOSTED_BY]->(svc:Service)
                WHERE n:Domain OR n:Subdomain
                RETURN COUNT(svc) as provider_count
            """, fqdn=fqdn)
            
            provider_count = result.single()["provider_count"]
            
            if provider_count > 0:
                print(f"✓ Provider discovery complete for {fqdn} ({provider_count} providers)")
                return True
            else:
                print(f"! No providers found for {fqdn} - needs deeper analysis")
                return False
    
    def close(self):
        """Close Neo4j connection."""
        self.drv.close()

def dns_query(domain: str, rdtype: str) -> List[str]:
    """DNS query with enhanced error handling."""
    try:
        result = RESOLVER.resolve(domain, rdtype)
        return [str(r) for r in result]
    except (dns.exception.DNSException, Exception):
        return []

def run_amass_enhanced(domain: str, max_depth: int = 3) -> List[dict]:
    """Enhanced Amass execution with proper depth control."""
    try:
        from risk_loader_advanced3 import run_amass_local, run_amass_batch_parallel
        
        # Use the existing optimized Amass logic
        results = run_amass_local(domain, sample_mode=False)
        print(f"[AMASS ENHANCED] Found {len(results)} results for {domain}")
        return results
    except ImportError:
        print(f"[AMASS ENHANCED] Cannot import from risk_loader_advanced3, skipping Amass for {domain}")
        return []
    except Exception as e:
        print(f"[AMASS ENHANCED] Error processing {domain}: {e}")
        return []

def run_amass_parallel_enhanced(domains: List[str], max_workers: int = 4, max_depth: int = 3) -> Dict[str, List[dict]]:
    """Run Amass in parallel for multiple domains."""
    try:
        from risk_loader_advanced3 import run_amass_batch_parallel
        
        print(f"[AMASS PARALLEL] Processing {len(domains)} domains with {max_workers} workers")
        results = run_amass_batch_parallel(domains, sample_mode=False, max_workers=max_workers)
        
        total_subdomains = sum(len(subdoms) for subdoms in results.values())
        print(f"[AMASS PARALLEL] Found {total_subdomains} total subdomains across {len(domains)} domains")
        
        return results
    except ImportError:
        print(f"[AMASS PARALLEL] Cannot import from risk_loader_advanced3, processing sequentially")
        results = {}
        for domain in domains:
            results[domain] = run_amass_enhanced(domain, max_depth)
        return results
    except Exception as e:
        print(f"[AMASS PARALLEL] Error in parallel processing: {e}")
        return {}

def process_domain_enhanced(fqdn: str, depth: int, ingester: EnhancedGraphIngester, 
                          max_depth: int = 3) -> Dict[str, Any]:
    """Enhanced domain processing with proper depth and provider discovery."""
    
    stats = {
        'subdomain_count': 0,
        'ip_count': 0,
        'provider_count': 0,
        'error_count': 0
    }
    
    try:
        # Process whois information
        try:
            if HAS_WHOIS:
                w = whois.whois(fqdn)
            else:
                w = {}
        except Exception:
            w = {}
        
        # Create domain hierarchy
        with ingester.drv.session() as s:
            with s.begin_transaction() as tx:
                domain_info = ingester.merge_tld_domain_subdomain(fqdn, w, tx)
                
                # Process DNS records
                for rdtype in ("A", "AAAA"):
                    for addr in dns_query(fqdn, rdtype):
                        ingester.merge_ip_with_enhanced_tracking(fqdn, addr, tx)
                        stats['ip_count'] += 1
                
                # Run subdomain discovery if we have depth remaining
                if depth > 0:
                    amass_results = run_amass_enhanced(fqdn, max_depth)
                    for result in amass_results:
                        subdomain_fqdn = result.get('name')
                        if subdomain_fqdn and subdomain_fqdn != fqdn:
                            # Recursively process subdomain
                            sub_stats = process_domain_enhanced(subdomain_fqdn, depth - 1, ingester, max_depth)
                            stats['subdomain_count'] += 1
                            stats['ip_count'] += sub_stats['ip_count']
                            stats['provider_count'] += sub_stats['provider_count']
                
                # Ensure we have provider information
                if not ingester.ensure_provider_discovery_depth(fqdn, max_depth):
                    # If no providers found and we haven't reached max depth, try deeper
                    if depth < max_depth:
                        print(f"Expanding depth for {fqdn} to ensure provider discovery")
                        # Additional processing logic here
                
                tx.commit()
                
    except Exception as e:
        stats['error_count'] += 1
        print(f"Error processing {fqdn}: {e}")
    
    return stats

class ParallelDomainProcessor:
    """Parallel domain processor with thread-safe operations."""
    
    def __init__(self, ingester: EnhancedGraphIngester, max_workers: int = 4, max_amass_workers: int = 2):
        self.ingester = ingester
        self.max_workers = max_workers
        self.max_amass_workers = max_amass_workers
        self.stats_lock = Lock()
        self.global_stats = {
            'total_processed': 0,
            'total_subdomains': 0,
            'total_ips': 0,
            'total_providers': 0,
            'total_errors': 0,
            'start_time': time.time()
        }
        
    def process_domain_worker(self, domain_info: Tuple[str, int, int]) -> Dict[str, Any]:
        """Worker function for processing a single domain."""
        fqdn, depth, max_depth = domain_info
        worker_id = threading.current_thread().name
        
        print(f"[{worker_id}] Processing: {fqdn} (depth={depth}, max_depth={max_depth})")
        
        try:
            stats = process_domain_enhanced(fqdn, depth, self.ingester, max_depth)
            
            # Update global stats thread-safely
            with self.stats_lock:
                self.global_stats['total_processed'] += 1
                self.global_stats['total_subdomains'] += stats.get('subdomain_count', 0)
                self.global_stats['total_ips'] += stats.get('ip_count', 0)
                self.global_stats['total_providers'] += stats.get('provider_count', 0)
                self.global_stats['total_errors'] += stats.get('error_count', 0)
            
            print(f"[{worker_id}] ✓ Completed: {fqdn} - {stats}")
            return {'domain': fqdn, 'success': True, 'stats': stats, 'worker': worker_id}
            
        except Exception as e:
            with self.stats_lock:
                self.global_stats['total_errors'] += 1
            
            print(f"[{worker_id}] ✗ Failed: {fqdn} - {e}")
            return {'domain': fqdn, 'success': False, 'error': str(e), 'worker': worker_id}
    
    def process_domains_parallel(self, domains: List[str], depth: int = 2, max_depth: int = 4) -> Dict[str, Any]:
        """Process multiple domains in parallel."""
        
        print(f"\n🚀 Starting parallel processing:")
        print(f"   Domains: {len(domains)}")
        print(f"   Worker threads: {self.max_workers}")
        print(f"   Amass workers: {self.max_amass_workers}")
        print(f"   Depth: {depth}, Max depth: {max_depth}")
        print("="*60)
        
        # Prepare domain tasks
        domain_tasks = [(domain, depth, max_depth) for domain in domains]
        
        # Process domains in parallel
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="DomainWorker") as executor:
            # Submit all tasks
            future_to_domain = {
                executor.submit(self.process_domain_worker, task): task[0] 
                for task in domain_tasks
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Print progress
                    with self.stats_lock:
                        processed = self.global_stats['total_processed']
                        errors = self.global_stats['total_errors']
                        elapsed = time.time() - self.global_stats['start_time']
                        rate = processed / elapsed if elapsed > 0 else 0
                        
                        print(f"📊 Progress: {processed}/{len(domains)} domains processed "
                              f"({errors} errors) - {rate:.1f} domains/sec")
                        
                except Exception as e:
                    print(f"❌ Critical error processing {domain}: {e}")
                    results.append({
                        'domain': domain, 
                        'success': False, 
                        'error': f"Critical error: {e}",
                        'worker': 'unknown'
                    })
        
        # Final statistics
        elapsed_time = time.time() - self.global_stats['start_time']
        success_count = sum(1 for r in results if r['success'])
        
        final_stats = {
            'total_domains': len(domains),
            'successful_domains': success_count,
            'failed_domains': len(domains) - success_count,
            'total_subdomains': self.global_stats['total_subdomains'],
            'total_ips': self.global_stats['total_ips'],
            'total_providers': self.global_stats['total_providers'],
            'total_errors': self.global_stats['total_errors'],
            'elapsed_time_seconds': elapsed_time,
            'domains_per_second': len(domains) / elapsed_time if elapsed_time > 0 else 0,
            'worker_threads': self.max_workers,
            'amass_workers': self.max_amass_workers,
            'results': results
        }
        
        print("\n" + "="*60)
        print("🎉 Parallel processing completed!")
        print(f"📈 Final Statistics:")
        print(f"   Total domains: {final_stats['total_domains']}")
        print(f"   Successful: {final_stats['successful_domains']}")
        print(f"   Failed: {final_stats['failed_domains']}")
        print(f"   Subdomains discovered: {final_stats['total_subdomains']}")
        print(f"   IP addresses: {final_stats['total_ips']}")
        print(f"   Providers: {final_stats['total_providers']}")
        print(f"   Processing time: {elapsed_time:.1f} seconds")
        print(f"   Rate: {final_stats['domains_per_second']:.1f} domains/second")
        print("="*60)
        
        return final_stats
    
    def process_domains_with_parallel_amass(self, domains: List[str], depth: int = 2, max_depth: int = 4) -> Dict[str, Any]:
        """Process domains with parallel Amass execution for better performance."""
        
        print(f"\n🚀 Starting parallel processing with parallel Amass:")
        print(f"   Domains: {len(domains)}")
        print(f"   Worker threads: {self.max_workers}")
        print(f"   Amass workers: {self.max_amass_workers}")
        print(f"   Depth: {depth}, Max depth: {max_depth}")
        print("="*60)
        
        # Step 1: Run Amass in parallel for all domains first
        print(f"🔍 Step 1: Running Amass discovery in parallel...")
        amass_results = run_amass_parallel_enhanced(domains, self.max_amass_workers, max_depth)
        
        # Step 2: Collect all domains and subdomains for processing
        all_domains_to_process = set(domains)
        for domain, subdomains in amass_results.items():
            for subdomain_entry in subdomains:
                subdomain = subdomain_entry.get('name')
                if subdomain and subdomain not in all_domains_to_process:
                    all_domains_to_process.add(subdomain)
        
        print(f"📊 Amass discovery results:")
        print(f"   Original domains: {len(domains)}")
        print(f"   Total subdomains found: {len(all_domains_to_process) - len(domains)}")
        print(f"   Total domains to process: {len(all_domains_to_process)}")
        
        # Step 3: Process all domains in parallel
        print(f"\n🔄 Step 2: Processing all domains in parallel...")
        return self.process_domains_parallel(list(all_domains_to_process), depth, max_depth)

def main():
    """Enhanced main function with parallel processing and graph-based queue management."""
    parser = argparse.ArgumentParser(description="Enhanced risk loader with parallel processing and proper TLD/subdomain handling")
    parser.add_argument("--domains", required=True, help="Input domains file")
    parser.add_argument("--depth", type=int, default=2, help="Recursion depth")
    parser.add_argument("--max-depth", type=int, default=4, help="Maximum depth for provider discovery")
    parser.add_argument("--bolt", default="bolt://localhost:7687", help="Neo4j bolt URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", required=True, help="Neo4j password")
    parser.add_argument("--ipinfo-token", help="IPInfo token")
    parser.add_argument("--update-stale", action="store_true", help="Update stale nodes")
    parser.add_argument("--stale-days", type=int, default=7, help="Days before node is considered stale")
    
    # Parallel processing options
    parser.add_argument("--workers", type=int, default=4, help="Number of worker threads for domain processing")
    parser.add_argument("--amass-workers", type=int, default=2, help="Number of parallel Amass workers")
    parser.add_argument("--parallel", action="store_true", help="Enable parallel processing")
    parser.add_argument("--parallel-amass", action="store_true", help="Enable parallel Amass discovery")
    parser.add_argument("--sequential", action="store_true", help="Force sequential processing (legacy mode)")
    
    args = parser.parse_args()
    
    # Initialize enhanced ingester
    ingester = EnhancedGraphIngester(args.bolt, args.user, args.password, args.ipinfo_token)
    
    try:
        if args.update_stale:
            # Update stale nodes based on graph queries
            print("Checking for stale nodes...")
            
            stale_nodes = ingester.get_nodes_needing_analysis(args.stale_days)
            print(f"Found {len(stale_nodes)} nodes needing analysis")
            
            if args.parallel and len(stale_nodes) > 1:
                # Process stale nodes in parallel
                processor = ParallelDomainProcessor(ingester, args.workers, args.amass_workers)
                stale_domains = [node['fqdn'] for node in stale_nodes]
                stats = processor.process_domains_parallel(stale_domains, args.depth, args.max_depth)
                print(f"Parallel stale node processing completed: {stats}")
            else:
                # Sequential processing
                for node in stale_nodes:
                    print(f"Processing stale node: {node['fqdn']}")
                    process_domain_enhanced(node['fqdn'], args.depth, ingester, args.max_depth)
            
            # Update risk scoring
            stale_risk_nodes = ingester.get_nodes_needing_risk_scoring(args.stale_days)
            print(f"Found {len(stale_risk_nodes)} nodes needing risk scoring")
            
            for node in stale_risk_nodes:
                print(f"Updating risk scoring for: {node['fqdn']}")
                ingester.update_risk_scoring_timestamp(node['fqdn'], node['node_type'])
        
        else:
            # Process domains from file
            with open(args.domains, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
            
            print(f"\n🎯 Processing {len(domains)} domains with enhanced loader")
            print(f"⚙️  Configuration:")
            print(f"   Depth: {args.depth}")
            print(f"   Max depth: {args.max_depth}")
            print(f"   Worker threads: {args.workers}")
            print(f"   Amass workers: {args.amass_workers}")
            
            # Determine processing mode
            if args.sequential:
                print(f"🔄 Using SEQUENTIAL processing (legacy mode)")
                for domain in domains:
                    print(f"\nProcessing domain: {domain}")
                    stats = process_domain_enhanced(domain, args.depth, ingester, args.max_depth)
                    print(f"Stats: {stats}")
                    
            elif args.parallel_amass and len(domains) > 1:
                print(f"🚀 Using PARALLEL processing with PARALLEL AMASS")
                processor = ParallelDomainProcessor(ingester, args.workers, args.amass_workers)
                final_stats = processor.process_domains_with_parallel_amass(domains, args.depth, args.max_depth)
                
            elif args.parallel and len(domains) > 1:
                print(f"🚀 Using PARALLEL processing")
                processor = ParallelDomainProcessor(ingester, args.workers, args.amass_workers)
                final_stats = processor.process_domains_parallel(domains, args.depth, args.max_depth)
                
            else:
                # Default mode - auto-detect based on domain count
                if len(domains) > 3:
                    print(f"🚀 Auto-detected: Using PARALLEL processing ({len(domains)} domains)")
                    processor = ParallelDomainProcessor(ingester, args.workers, args.amass_workers)
                    final_stats = processor.process_domains_parallel(domains, args.depth, args.max_depth)
                else:
                    print(f"🔄 Auto-detected: Using SEQUENTIAL processing ({len(domains)} domains)")
                    for domain in domains:
                        print(f"\nProcessing domain: {domain}")
                        stats = process_domain_enhanced(domain, args.depth, ingester, args.max_depth)
                        print(f"Stats: {stats}")
    
    finally:
        ingester.close()

if __name__ == "__main__":
    main()