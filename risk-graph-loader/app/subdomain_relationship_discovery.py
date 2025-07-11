#!/usr/bin/env python3
"""
subdomain_relationship_discovery.py - Enhanced subdomain relationship discovery

This module extends the two-phase subdomain discovery to include comprehensive relationship
mapping between subdomains, domains, services, and providers. It fixes the issue where
base domains appear as subdomains and adds advanced relationship discovery capabilities.

Key features:
1. Fixed domain hierarchy to prevent base domains appearing as subdomains
2. Cross-domain relationship discovery
3. Service provider relationship mapping
4. Enhanced subdomain relationship tracking
5. Provider service discovery and mapping
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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('subdomain_relationship_discovery.log')
    ]
)

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
class EnhancedDomainInfo:
    """Enhanced domain information with relationship tracking."""
    fqdn: str
    domain: str
    tld: str
    subdomain: str
    is_tld_domain: bool
    parent_domain: Optional[str] = None
    base_domain: str = None  # Always the base domain (e.g., "bice.cl")
    
    @classmethod
    def from_fqdn(cls, fqdn: str, input_domains: Set[str] = None) -> 'EnhancedDomainInfo':
        """Create EnhancedDomainInfo with proper base domain identification."""
        
        if HAS_TLDEXTRACT:
            try:
                extracted = tldextract.extract(fqdn)
                if extracted and extracted.domain and extracted.suffix:
                    domain = extracted.domain
                    tld = extracted.suffix
                    subdomain = extracted.subdomain
                else:
                    domain, tld, subdomain = extract_tld_fallback(fqdn)
            except:
                domain, tld, subdomain = extract_tld_fallback(fqdn)
        else:
            domain, tld, subdomain = extract_tld_fallback(fqdn)
        
        # Construct base domain
        base_domain = f"{domain}.{tld}"
        
        # FIXED: Check if this FQDN is actually one of the input base domains
        # If it is, treat it as a base domain, not a subdomain
        is_input_domain = input_domains and fqdn in input_domains
        
        # Determine if this is a TLD domain
        is_tld_domain = not subdomain or is_input_domain
        
        # For subdomains, parent domain points to base domain
        parent_domain = None
        if not is_tld_domain and not is_input_domain:
            parent_domain = base_domain
        
        return cls(
            fqdn=fqdn,
            domain=domain,
            tld=tld,
            subdomain=subdomain if not is_input_domain else '',
            is_tld_domain=is_tld_domain,
            parent_domain=parent_domain,
            base_domain=base_domain
        )

@dataclass
class RelationshipInfo:
    """Information about discovered relationships."""
    source_fqdn: str
    target_fqdn: str
    relationship_type: str
    confidence: float
    discovery_method: str
    metadata: Dict[str, Any] = None

class EnhancedSubdomainGraphIngester:
    """Enhanced graph ingester with relationship discovery capabilities."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str, ipinfo_token: str = None, 
                 mmdb_path: str = IPINFO_MMDB_PATH, csv_path: str = IPINFO_CSV_PATH):
        if not HAS_NEO4J:
            raise ImportError("Neo4j driver is required. Install with: pip install neo4j")
        
        self.drv = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
        self.ipinfo_token = ipinfo_token
        self.mmdb_path = mmdb_path
        self.csv_path = csv_path
        self.input_domains = set()  # Track input domains to prevent them appearing as subdomains
        
        # Check configuration and issue warnings
        self._check_configuration()
        
        self.setup_constraints()
    
    def _check_configuration(self):
        """Check configuration and issue warnings for missing components."""
        import os
        
        print("\n=== SUBDOMAIN RELATIONSHIP DISCOVERY CONFIGURATION CHECK ===")
        
        # Check API tokens
        if not self.ipinfo_token:
            print("⚠️  WARNING: No IPInfo token provided")
            print("   → Provider detection will use free tier with rate limits")
            print("   → Consider using --ipinfo-token for better results")
        else:
            print("✅ IPInfo token provided")
            
        # Check MMDB database
        if not os.path.exists(self.mmdb_path):
            print(f"⚠️  WARNING: MMDB database not found at {self.mmdb_path}")
            print("   → Local IP geolocation will be unavailable")
            print("   → Will rely on external APIs for provider detection")
        else:
            print(f"✅ MMDB database found at {self.mmdb_path}")
            
        # Check CSV database
        if not os.path.exists(self.csv_path):
            print(f"⚠️  WARNING: CSV database not found at {self.csv_path}")
            print("   → Local IP data will be unavailable")
        else:
            print(f"✅ CSV database found at {self.csv_path}")
            
        # Check optional dependencies
        missing_deps = []
        if not HAS_TLDEXTRACT:
            missing_deps.append('tldextract')
        if not HAS_WHOIS:
            missing_deps.append('whois')
        if not HAS_CRYPTOGRAPHY:
            missing_deps.append('cryptography')
        if not HAS_MAXMINDDB:
            missing_deps.append('maxminddb')
            
        if missing_deps:
            print(f"⚠️  WARNING: Missing optional dependencies: {', '.join(missing_deps)}")
            print("   → Some features may be limited")
        else:
            print("✅ All optional dependencies available")
            
        print("==========================================================\n")
    
    def set_input_domains(self, domains: List[str]):
        """Set the list of input domains to properly identify base domains."""
        self.input_domains = set(domains)
    
    def setup_constraints(self):
        """Setup Neo4j constraints for enhanced relationship model."""
        with self.drv.session() as s:
            # Core constraints
            s.run("CREATE CONSTRAINT tld_name IF NOT EXISTS FOR (t:TLD) REQUIRE t.name IS UNIQUE")
            s.run("CREATE CONSTRAINT domain_fqdn IF NOT EXISTS FOR (d:Domain) REQUIRE d.fqdn IS UNIQUE")
            s.run("CREATE CONSTRAINT subdomain_fqdn IF NOT EXISTS FOR (s:Subdomain) REQUIRE s.fqdn IS UNIQUE")
            s.run("CREATE CONSTRAINT ip_addr IF NOT EXISTS FOR (ip:IPAddress) REQUIRE ip.address IS UNIQUE")
            s.run("CREATE CONSTRAINT service_name IF NOT EXISTS FOR (svc:Service) REQUIRE svc.name IS UNIQUE")
            
            # New relationship constraints
            s.run("CREATE CONSTRAINT provider_name IF NOT EXISTS FOR (p:Provider) REQUIRE p.name IS UNIQUE")
            s.run("CREATE INDEX domain_base_domain IF NOT EXISTS FOR (d:Domain) ON (d.base_domain)")
            s.run("CREATE INDEX subdomain_base_domain IF NOT EXISTS FOR (s:Subdomain) ON (s.base_domain)")
    
    def create_enhanced_domain_hierarchy_batch(self, domains: List[str], batch_size: int = 100) -> Dict[str, Any]:
        """Create enhanced domain hierarchy with relationship tracking."""
        stats = {
            'domains_created': 0,
            'subdomains_created': 0,
            'tlds_created': 0,
            'relationships_created': 0,
            'errors': 0
        }
        
        for i in range(0, len(domains), batch_size):
            batch = domains[i:i+batch_size]
            
            with self.drv.session() as s:
                with s.begin_transaction() as tx:
                    for fqdn in batch:
                        try:
                            relationships = self._create_enhanced_domain_hierarchy_single(fqdn, tx)
                            
                            domain_info = EnhancedDomainInfo.from_fqdn(fqdn, self.input_domains)
                            if domain_info.is_tld_domain:
                                stats['domains_created'] += 1
                            else:
                                stats['subdomains_created'] += 1
                            
                            stats['relationships_created'] += relationships
                                
                        except Exception as e:
                            print(f"Error creating hierarchy for {fqdn}: {e}")
                            stats['errors'] += 1
                    
                    tx.commit()
            
            print(f"✓ Processed batch {i//batch_size + 1}/{(len(domains)-1)//batch_size + 1}")
        
        return stats
    
    def _create_enhanced_domain_hierarchy_single(self, fqdn: str, tx) -> int:
        """Create enhanced domain hierarchy for a single domain."""
        domain_info = EnhancedDomainInfo.from_fqdn(fqdn, self.input_domains)
        current_time = datetime.now().isoformat()
        relationships_created = 0
        
        # 1. Create/merge TLD node
        tx.run("""
            MERGE (tld:TLD {name: $tld})
            SET tld.last_updated = $current_time
            RETURN tld
        """, tld=domain_info.tld, current_time=current_time)
        
        # 2. Create/merge base Domain node
        tx.run("""
            MERGE (d:Domain {fqdn: $base_domain})
            SET d.domain_name = $domain_name,
                d.tld = $tld,
                d.base_domain = $base_domain,
                d.last_analyzed = $current_time,
                d.discovery_phase = true
            RETURN d
        """, base_domain=domain_info.base_domain, domain_name=domain_info.domain, 
             tld=domain_info.tld, current_time=current_time)
        
        # 3. Create TLD -> Domain relationship
        tx.run("""
            MATCH (tld:TLD {name: $tld})
            MATCH (d:Domain {fqdn: $domain_fqdn})
            MERGE (tld)-[:CONTAINS_DOMAIN]->(d)
        """, tld=domain_info.tld, domain_fqdn=domain_info.base_domain)
        relationships_created += 1
        
        # 4. If this is a subdomain (not the base domain), create subdomain node
        if not domain_info.is_tld_domain:
            tx.run("""
                MERGE (s:Subdomain {fqdn: $fqdn})
                SET s.subdomain_name = $subdomain_name,
                    s.domain_name = $domain_name,
                    s.tld = $tld,
                    s.base_domain = $base_domain,
                    s.last_analyzed = $current_time,
                    s.discovery_phase = true,
                    s.processing_phase = false
                RETURN s
            """, fqdn=domain_info.fqdn, subdomain_name=domain_info.subdomain,
                 domain_name=domain_info.domain, tld=domain_info.tld,
                 base_domain=domain_info.base_domain, current_time=current_time)
            
            # 5. Create Domain -> Subdomain relationship
            tx.run("""
                MATCH (d:Domain {fqdn: $parent_fqdn})
                MATCH (s:Subdomain {fqdn: $subdomain_fqdn})
                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
            """, parent_fqdn=domain_info.parent_domain, subdomain_fqdn=domain_info.fqdn)
            relationships_created += 1
        
        return relationships_created
    
    def discover_cross_domain_relationships(self, batch_size: int = 100) -> Dict[str, Any]:
        """Discover relationships between different domains and subdomains."""
        print("🔍 Discovering cross-domain relationships...")
        
        stats = {
            'ip_shared_relationships': 0,
            'provider_relationships': 0,
            'dns_relationships': 0,
            'certificate_relationships': 0
        }
        
        # Discover IP-based relationships
        ip_relationships = self._discover_ip_sharing_relationships()
        stats['ip_shared_relationships'] = len(ip_relationships)
        
        # Discover provider-based relationships
        provider_relationships = self._discover_provider_relationships()
        stats['provider_relationships'] = len(provider_relationships)
        
        # Discover DNS-based relationships
        dns_relationships = self._discover_dns_relationships()
        stats['dns_relationships'] = len(dns_relationships)
        
        # Discover certificate-based relationships (if available)
        if HAS_CRYPTOGRAPHY:
            cert_relationships = self._discover_certificate_relationships()
            stats['certificate_relationships'] = len(cert_relationships)
        
        return stats
    
    def _discover_ip_sharing_relationships(self) -> List[RelationshipInfo]:
        """Discover domains/subdomains that share IP addresses."""
        relationships = []
        
        with self.drv.session() as s:
            # Find domains/subdomains sharing IPs
            result = s.run("""
                MATCH (n1)-[:RESOLVES_TO]->(ip:IPAddress)<-[:RESOLVES_TO]-(n2)
                WHERE n1 <> n2 AND (n1:Domain OR n1:Subdomain) AND (n2:Domain OR n2:Subdomain)
                RETURN n1.fqdn as fqdn1, n2.fqdn as fqdn2, ip.address as shared_ip,
                       labels(n1) as labels1, labels(n2) as labels2
            """)
            
            for record in result:
                rel = RelationshipInfo(
                    source_fqdn=record["fqdn1"],
                    target_fqdn=record["fqdn2"],
                    relationship_type="SHARES_IP",
                    confidence=0.8,
                    discovery_method="ip_sharing",
                    metadata={"shared_ip": record["shared_ip"]}
                )
                relationships.append(rel)
        
        # Create relationships in graph
        self._create_relationships_batch(relationships)
        return relationships
    
    def _discover_provider_relationships(self) -> List[RelationshipInfo]:
        """Discover domains/subdomains using the same cloud provider."""
        relationships = []
        
        with self.drv.session() as s:
            # Find domains/subdomains sharing providers
            result = s.run("""
                MATCH (n1)-[:RESOLVES_TO]->(ip1:IPAddress)-[:HOSTED_BY]->(svc:Service)<-[:HOSTED_BY]-(ip2:IPAddress)<-[:RESOLVES_TO]-(n2)
                WHERE n1 <> n2 AND (n1:Domain OR n1:Subdomain) AND (n2:Domain OR n2:Subdomain)
                RETURN n1.fqdn as fqdn1, n2.fqdn as fqdn2, svc.name as provider
            """)
            
            for record in result:
                rel = RelationshipInfo(
                    source_fqdn=record["fqdn1"],
                    target_fqdn=record["fqdn2"],
                    relationship_type="SHARES_PROVIDER",
                    confidence=0.6,
                    discovery_method="provider_sharing",
                    metadata={"shared_provider": record["provider"]}
                )
                relationships.append(rel)
        
        self._create_relationships_batch(relationships)
        return relationships
    
    def _discover_dns_relationships(self) -> List[RelationshipInfo]:
        """Discover DNS-based relationships (CNAME, MX, etc.)."""
        relationships = []
        
        # Get all domains/subdomains for DNS analysis
        with self.drv.session() as s:
            result = s.run("""
                MATCH (n) WHERE n:Domain OR n:Subdomain
                RETURN n.fqdn as fqdn
            """)
            fqdns = [record["fqdn"] for record in result]
        
        # Analyze DNS records for relationships
        for fqdn in fqdns:
            try:
                # Check CNAME records
                cname_records = dns_query(fqdn, "CNAME")
                for cname in cname_records:
                    # Check if CNAME points to another tracked domain
                    if cname in fqdns:
                        rel = RelationshipInfo(
                            source_fqdn=fqdn,
                            target_fqdn=cname,
                            relationship_type="CNAME_POINTS_TO",
                            confidence=0.9,
                            discovery_method="dns_cname",
                            metadata={"record_type": "CNAME"}
                        )
                        relationships.append(rel)
                
                # Check MX records
                mx_records = dns_query(fqdn, "MX")
                for mx in mx_records:
                    mx_domain = mx.split()[-1].rstrip('.')  # Extract domain from MX record
                    if mx_domain in fqdns:
                        rel = RelationshipInfo(
                            source_fqdn=fqdn,
                            target_fqdn=mx_domain,
                            relationship_type="MX_POINTS_TO",
                            confidence=0.7,
                            discovery_method="dns_mx",
                            metadata={"record_type": "MX"}
                        )
                        relationships.append(rel)
                        
            except Exception as e:
                print(f"DNS analysis error for {fqdn}: {e}")
        
        self._create_relationships_batch(relationships)
        return relationships
    
    def _discover_certificate_relationships(self) -> List[RelationshipInfo]:
        """Discover relationships based on SSL certificate SANs."""
        relationships = []
        
        with self.drv.session() as s:
            result = s.run("""
                MATCH (n) WHERE n:Domain OR n:Subdomain
                RETURN n.fqdn as fqdn
            """)
            fqdns = [record["fqdn"] for record in result]
        
        # Analyze SSL certificates for SANs
        for fqdn in fqdns:
            try:
                san_domains = self._get_certificate_sans(fqdn)
                for san_domain in san_domains:
                    if san_domain in fqdns and san_domain != fqdn:
                        rel = RelationshipInfo(
                            source_fqdn=fqdn,
                            target_fqdn=san_domain,
                            relationship_type="SHARES_CERTIFICATE",
                            confidence=0.8,
                            discovery_method="ssl_certificate",
                            metadata={"cert_type": "SAN"}
                        )
                        relationships.append(rel)
                        
            except Exception as e:
                print(f"Certificate analysis error for {fqdn}: {e}")
        
        self._create_relationships_batch(relationships)
        return relationships
    
    def _get_certificate_sans(self, fqdn: str) -> List[str]:
        """Extract SAN domains from SSL certificate."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((fqdn, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=fqdn) as ssock:
                    cert_der = ssock.getpeercert_chain()[0].public_bytes(serialization.Encoding.DER)
                    cert = x509.load_der_x509_certificate(cert_der)
                    
                    try:
                        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        san_domains = [name.value for name in san_ext.value]
                        return san_domains
                    except x509.ExtensionNotFound:
                        return []
        except:
            return []
    
    def _create_relationships_batch(self, relationships: List[RelationshipInfo]):
        """Create relationship edges in the graph."""
        if not relationships:
            return
        
        with self.drv.session() as s:
            with s.begin_transaction() as tx:
                for rel in relationships:
                    try:
                        tx.run("""
                            MATCH (n1 {fqdn: $source_fqdn}), (n2 {fqdn: $target_fqdn})
                            WHERE (n1:Domain OR n1:Subdomain) AND (n2:Domain OR n2:Subdomain)
                            MERGE (n1)-[r:RELATED_TO]->(n2)
                            SET r.relationship_type = $rel_type,
                                r.confidence = $confidence,
                                r.discovery_method = $discovery_method,
                                r.metadata = $metadata,
                                r.created_at = $created_at
                        """, 
                        source_fqdn=rel.source_fqdn,
                        target_fqdn=rel.target_fqdn,
                        rel_type=rel.relationship_type,
                        confidence=rel.confidence,
                        discovery_method=rel.discovery_method,
                        metadata=json.dumps(rel.metadata) if rel.metadata else "{}",
                        created_at=datetime.now().isoformat())
                    except Exception as e:
                        print(f"Error creating relationship {rel.source_fqdn} -> {rel.target_fqdn}: {e}")
                
                tx.commit()
    
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
        domain_info = EnhancedDomainInfo.from_fqdn(fqdn, self.input_domains)
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
    
    def _merge_ip_internal(self, domain_info: EnhancedDomainInfo, ip: str, prov: str, cloud_info: dict, 
                          current_time: str, tx):
        """Internal IP merge logic with enhanced Service node creation."""
        
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
        
        # Enhanced Service node creation with fallback
        if prov and prov != "unknown":
            # Create provider service node
            tx.run("""
                MERGE (svc:Service {name: $provider, type: 'cloud_provider'})
                SET svc.last_updated = $current_time,
                    svc.detection_method = $detection_method,
                    svc.source_info = $source_info
                RETURN svc
            """, provider=prov, current_time=current_time, 
                 detection_method=cloud_info.get('detection_method', 'unknown'),
                 source_info=json.dumps(cloud_info))
            
            # Link IP to provider service
            tx.run("""
                MATCH (ip:IPAddress {address: $ip})
                MATCH (svc:Service {name: $provider, type: 'cloud_provider'})
                MERGE (ip)-[:HOSTED_BY]->(svc)
            """, ip=ip, provider=prov)
        else:
            # Create unknown provider service for tracking
            tx.run("""
                MERGE (svc:Service {name: 'unknown', type: 'cloud_provider'})
                SET svc.last_updated = $current_time,
                    svc.detection_method = 'failed',
                    svc.description = 'Provider detection failed or unknown'
                RETURN svc
            """)
            
            # Link IP to unknown provider service
            tx.run("""
                MATCH (ip:IPAddress {address: $ip})
                MATCH (svc:Service {name: 'unknown', type: 'cloud_provider'})
                MERGE (ip)-[:HOSTED_BY]->(svc)
            """, ip=ip)
    
    def detect_cloud_provider_by_ip(self, ip: str) -> str:
        """Detect cloud provider for IP address using enhanced detection logic."""
        try:
            from risk_loader_advanced3 import detect_cloud_provider_by_ip
            result = detect_cloud_provider_by_ip(ip, self.ipinfo_token, self.mmdb_path, self.csv_path)
            logging.info(f"[PROVIDER_DETECTION] Result for IP {ip}: {result}")
            return result
        except ImportError as e:
            logging.warning(f"[PROVIDER_DETECTION] Cannot import detection functions: {e}")
            return "unknown"
        except Exception as e:
            logging.error(f"[PROVIDER_DETECTION] Unexpected error detecting provider for IP {ip}: {e}")
            return "unknown"
    
    def get_cloud_provider_info(self, ip: str) -> dict:
        """Get detailed cloud provider info for IP."""
        try:
            from risk_loader_advanced3 import get_cloud_provider_info
            result = get_cloud_provider_info(ip, self.ipinfo_token, self.mmdb_path, self.csv_path)
            return result or {}
        except ImportError as e:
            logging.warning(f"[PROVIDER_DETECTION] Cannot import cloud provider info functions: {e}")
            return {}
        except Exception as e:
            logging.error(f"[PROVIDER_DETECTION] Unexpected error getting cloud info for IP {ip}: {e}")
            return {}
    
    def get_enhanced_statistics(self) -> Dict[str, Any]:
        """Get enhanced statistics including relationships."""
        with self.drv.session() as s:
            # Basic stats
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
            
            # Additional stats
            tld_result = s.run("MATCH (t:TLD) RETURN count(t) as tld_count")
            stats['tld_count'] = tld_result.single()['tld_count']
            
            ip_result = s.run("MATCH (ip:IPAddress) RETURN count(ip) as ip_count")
            stats['ip_count'] = ip_result.single()['ip_count']
            
            # Relationship stats
            rel_result = s.run("""
                MATCH ()-[r:RELATED_TO]->() 
                RETURN count(r) as total_relationships,
                       count(DISTINCT r.relationship_type) as relationship_types
            """)
            rel_stats = dict(rel_result.single())
            stats.update(rel_stats)
            
            # Provider stats
            provider_result = s.run("""
                MATCH (svc:Service {type: 'cloud_provider'})
                RETURN count(svc) as provider_count
            """)
            stats['provider_count'] = provider_result.single()['provider_count']
            
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

def run_amass_discovery_with_relationships(domain: str, timeout: int = 60, mock_mode: bool = False, 
                                         sample_mode: bool = False) -> List[str]:
    """Run Amass for subdomain discovery with enhanced relationship detection."""
    
    # Mock mode for testing
    if mock_mode:
        mock_subdomains = [
            f"www.{domain}",
            f"mail.{domain}",
            f"api.{domain}",
            f"admin.{domain}",
            f"cdn.{domain}",
            f"app.{domain}"
        ]
        print(f"[DISCOVERY] MOCK MODE: Found {len(mock_subdomains)} subdomains for {domain}")
        return mock_subdomains
    
    try:
        from risk_loader_advanced3 import run_amass_local
        
        print(f"[DISCOVERY] Starting enhanced Amass for {domain} (sample_mode={sample_mode})")
        results = run_amass_local(domain, sample_mode=sample_mode)
        
        # Extract subdomain names, excluding the base domain
        subdomains = []
        for result in results:
            subdomain = result.get('name')
            # FIXED: Don't add the base domain as a subdomain
            if subdomain and subdomain != domain:
                subdomains.append(subdomain)
        
        print(f"[DISCOVERY] Found {len(subdomains)} subdomains for {domain} (excluding base domain)")
        if len(subdomains) == 0:
            print(f"[DISCOVERY] WARNING: No subdomains found for {domain}")
        
        return subdomains
        
    except ImportError:
        print(f"[DISCOVERY] Cannot import Amass functions, skipping {domain}")
        return []
    except Exception as e:
        print(f"[DISCOVERY] Error discovering subdomains for {domain}: {e}")
        return []

def enhanced_process_subdomain_worker(args: Tuple[str, str, str, str, str, Set[str]]) -> Dict[str, Any]:
    """Enhanced worker function for processing subdomains with relationship discovery."""
    fqdn, neo4j_uri, neo4j_user, neo4j_pass, ipinfo_token, input_domains = args
    
    @retry_on_deadlock
    def process_with_retry():
        # Create new ingester instance for this process
        ingester = EnhancedSubdomainGraphIngester(neo4j_uri, neo4j_user, neo4j_pass, ipinfo_token)
        ingester.set_input_domains(list(input_domains))
        
        stats = {
            'fqdn': fqdn,
            'ip_count': 0,
            'provider_count': 0,
            'relationships_discovered': 0,
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
        print(f"✓ Enhanced processing completed: {fqdn} ({stats['ip_count']} IPs)")
        return stats
        
    except Exception as e:
        print(f"✗ Error in enhanced processing {fqdn}: {e}")
        return {
            'fqdn': fqdn,
            'ip_count': 0,
            'provider_count': 0,
            'relationships_discovered': 0,
            'success': False,
            'error': str(e)
        }

class EnhancedSubdomainProcessor:
    """Enhanced processor with relationship discovery capabilities."""
    
    def __init__(self, ingester: EnhancedSubdomainGraphIngester, neo4j_uri: str, neo4j_user: str, 
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
    
    def enhanced_phase1_discovery(self, domains: List[str]) -> Dict[str, Any]:
        """Enhanced Phase 1: Discovery with proper base domain handling."""
        print(f"\n🔍 ENHANCED PHASE 1: Subdomain Discovery")
        print(f"   Input domains: {len(domains)}")
        print(f"   Discovery workers: {self.max_discovery_workers}")
        print("="*60)
        
        # Set input domains in the ingester to prevent base domains appearing as subdomains
        self.ingester.set_input_domains(domains)
        
        start_time = time.time()
        
        # Step 1: Create initial domain hierarchy for base domains
        print("Step 1: Creating base domain hierarchy...")
        hierarchy_stats = self.ingester.create_enhanced_domain_hierarchy_batch(domains)
        print(f"✓ Created {hierarchy_stats['domains_created']} base domains")
        
        # Step 2: Run parallel Amass discovery
        print(f"Step 2: Running enhanced subdomain discovery (sample_mode={self.sample_mode})...")
        discovery_results = self._run_enhanced_discovery_parallel(domains)
        
        # Step 3: Collect all discovered subdomains (excluding base domains)
        all_subdomains = []
        for domain, subdomains in discovery_results.items():
            # Filter out any base domains that might have been included
            filtered_subdomains = [sub for sub in subdomains if sub not in domains]
            all_subdomains.extend(filtered_subdomains)
        
        print(f"✓ Discovered {len(all_subdomains)} unique subdomains (base domains excluded)")
        
        # Step 4: Write discovered subdomains to graph
        if all_subdomains:
            print("Step 3: Writing discovered subdomains to graph...")
            subdomain_stats = self.ingester.create_enhanced_domain_hierarchy_batch(all_subdomains)
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
        
        print(f"\n✅ Enhanced Phase 1 completed in {elapsed_time:.1f} seconds")
        print(f"   Base domains processed: {stats['domains_processed']}")
        print(f"   Subdomains discovered: {stats['subdomains_discovered']}")
        print("="*60)
        
        return stats
    
    def _run_enhanced_discovery_parallel(self, domains: List[str]) -> Dict[str, List[str]]:
        """Run enhanced discovery in parallel."""
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_discovery_workers, thread_name_prefix="EnhancedDiscovery") as executor:
            # Submit all discovery tasks
            future_to_domain = {
                executor.submit(run_amass_discovery_with_relationships, domain, 60, self.mock_mode, self.sample_mode): domain 
                for domain in domains
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    subdomains = future.result()
                    results[domain] = subdomains
                    print(f"✓ Enhanced discovery completed for {domain}: {len(subdomains)} subdomains")
                except Exception as e:
                    print(f"✗ Enhanced discovery failed for {domain}: {e}")
                    results[domain] = []
        
        return results
    
    def enhanced_phase2_processing(self, batch_size: int = 100) -> Dict[str, Any]:
        """Enhanced Phase 2: Process subdomains with relationship discovery."""
        print(f"\n⚡ ENHANCED PHASE 2: Subdomain Processing & Relationship Discovery")
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
                (fqdn, self.neo4j_uri, self.neo4j_user, self.neo4j_pass, self.ipinfo_token, self.ingester.input_domains)
                for fqdn in subdomains
            ]
            
            # Process subdomains in parallel using separate processes
            with ProcessPoolExecutor(max_workers=self.max_processing_workers) as executor:
                results = executor.map(enhanced_process_subdomain_worker, worker_args)
                
                # Collect results
                for result in results:
                    total_processed += 1
                    if result['success']:
                        total_successful += 1
                    else:
                        total_errors += 1
                        print(f"Error processing {result['fqdn']}: {result['error']}")
            
            print(f"✓ Batch completed: {len(subdomains)} processed")
        
        # Phase 2.5: Discover cross-domain relationships
        print("\n🔗 Phase 2.5: Discovering cross-domain relationships...")
        relationship_stats = self.ingester.discover_cross_domain_relationships()
        print(f"✓ Relationship discovery completed:")
        print(f"   - IP sharing relationships: {relationship_stats['ip_shared_relationships']}")
        print(f"   - Provider relationships: {relationship_stats['provider_relationships']}")
        print(f"   - DNS relationships: {relationship_stats['dns_relationships']}")
        print(f"   - Certificate relationships: {relationship_stats['certificate_relationships']}")
        
        elapsed_time = time.time() - start_time
        
        stats = {
            'phase': 2,
            'total_processed': total_processed,
            'successful': total_successful,
            'errors': total_errors,
            'elapsed_time': elapsed_time,
            'rate': total_processed / elapsed_time if elapsed_time > 0 else 0,
            'relationship_stats': relationship_stats
        }
        
        print(f"\n✅ Enhanced Phase 2 completed in {elapsed_time:.1f} seconds")
        print(f"   Subdomains processed: {stats['total_processed']}")
        print(f"   Successful: {stats['successful']}")
        print(f"   Errors: {stats['errors']}")
        print(f"   Rate: {stats['rate']:.1f} subdomains/second")
        print("="*60)
        
        return stats
    
    def run_enhanced_two_phase_processing(self, domains: List[str], batch_size: int = 100) -> Dict[str, Any]:
        """Run complete enhanced two-phase processing with relationship discovery."""
        print(f"\n🚀 Starting Enhanced Two-Phase Subdomain Processing")
        print(f"   Input domains: {len(domains)}")
        print(f"   Discovery workers: {self.max_discovery_workers}")
        print(f"   Processing workers: {self.max_processing_workers}")
        print(f"   Processing batch size: {batch_size}")
        print("="*80)
        
        overall_start = time.time()
        
        # Enhanced Phase 1: Discovery
        phase1_stats = self.enhanced_phase1_discovery(domains)
        
        # Enhanced Phase 2: Processing with relationships
        phase2_stats = self.enhanced_phase2_processing(batch_size)
        
        # Final statistics
        overall_elapsed = time.time() - overall_start
        final_stats = self.ingester.get_enhanced_statistics()
        
        combined_stats = {
            'overall_elapsed_time': overall_elapsed,
            'phase1_stats': phase1_stats,
            'phase2_stats': phase2_stats,
            'final_graph_stats': final_stats
        }
        
        print(f"\n🎉 Enhanced Two-Phase Processing Completed!")
        print(f"   Total time: {overall_elapsed:.1f} seconds")
        print(f"   Final enhanced graph statistics:")
        print(f"     - Base domains: {final_stats['domain_count']}")
        print(f"     - Subdomains: {final_stats['subdomain_count']}")
        print(f"     - Processed subdomains: {final_stats['processed_subdomains']}")
        print(f"     - IP addresses: {final_stats['ip_count']}")
        print(f"     - TLDs: {final_stats['tld_count']}")
        print(f"     - Providers: {final_stats['provider_count']}")
        print(f"     - Relationships: {final_stats['total_relationships']}")
        print(f"     - Relationship types: {final_stats['relationship_types']}")
        print("="*80)
        
        return combined_stats

def main():
    """Main function for enhanced subdomain relationship discovery."""
    parser = argparse.ArgumentParser(description="Enhanced subdomain discovery with relationship mapping")
    parser.add_argument("--domains", required=True, help="Input domains file")
    parser.add_argument("--bolt", default="bolt://localhost:7687", help="Neo4j bolt URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", required=True, help="Neo4j password", default="test.password")
    parser.add_argument("--ipinfo-token", help="IPInfo token", default="0bf607ce2c13ac")
    
    # Phase control
    parser.add_argument("--phase1-only", action="store_true", help="Run only discovery phase")
    parser.add_argument("--phase2-only", action="store_true", help="Run only processing phase")
    parser.add_argument("--relationships-only", action="store_true", help="Run only relationship discovery")
    
    # Worker configuration
    parser.add_argument("--discovery-workers", type=int, default=6, help="Number of discovery workers")
    parser.add_argument("--processing-workers", type=int, default=4, help="Number of processing workers")
    parser.add_argument("--batch-size", type=int, default=50, help="Batch size for processing")
    parser.add_argument("--mock-mode", action="store_true", help="Use mock subdomain discovery for testing")
    parser.add_argument("--sample-mode", action="store_true", help="Use Amass sample mode (faster but less comprehensive)")
    
    args = parser.parse_args()
    
    # Initialize enhanced ingester
    ingester = EnhancedSubdomainGraphIngester(args.bolt, args.user, args.password, args.ipinfo_token)
    
    try:
        # Read domains from file
        with open(args.domains, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        
        # Initialize enhanced processor
        processor = EnhancedSubdomainProcessor(
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
            stats = processor.enhanced_phase1_discovery(domains)
        elif args.phase2_only:
            stats = processor.enhanced_phase2_processing(args.batch_size)
        elif args.relationships_only:
            stats = ingester.discover_cross_domain_relationships()
        else:
            stats = processor.run_enhanced_two_phase_processing(domains, args.batch_size)
        
        print(f"\n📊 Final Enhanced Statistics:")
        print(json.dumps(stats, indent=2, default=str))
        
    finally:
        ingester.close()

if __name__ == "__main__":
    main()