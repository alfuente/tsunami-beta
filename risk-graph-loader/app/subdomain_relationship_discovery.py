#!/usr/bin/env python3
"""
subdomain_relationship_discovery.py - Enhanced subdomain relationship discovery v2.0

This module extends the two-phase subdomain discovery to include comprehensive relationship
mapping between subdomains, domains, services, providers, and risk analysis. It fixes the 
issues where Risk and Provider nodes were not being generated and adds multi-level 
subdomain discovery capabilities.

Key features:
1. Fixed domain hierarchy to prevent base domains appearing as subdomains
2. Cross-domain relationship discovery  
3. Provider node creation (not just Service nodes)
4. Risk node generation and analysis
5. Multi-level subdomain chain discovery (depth > 1)
6. Enhanced subdomain relationship tracking
7. Provider service discovery and mapping

Version history:
- v1.0: Initial implementation with Service nodes only
- v2.0: Added Provider nodes, Risk analysis, and multi-level subdomain discovery
"""

from __future__ import annotations
import argparse, json, subprocess, tempfile, sys, socket, ssl, re
from typing import Tuple
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
            
            # Risk analysis constraints (v2.0)
            s.run("CREATE CONSTRAINT risk_id IF NOT EXISTS FOR (r:Risk) REQUIRE r.risk_id IS UNIQUE")
            s.run("CREATE INDEX risk_domain IF NOT EXISTS FOR (r:Risk) ON (r.domain_fqdn)")
            s.run("CREATE INDEX risk_severity IF NOT EXISTS FOR (r:Risk) ON (r.severity)")
            s.run("CREATE INDEX risk_score IF NOT EXISTS FOR (r:Risk) ON (r.score)")
    
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
            
            # 5. Create Subdomain -> Domain relationship (SUBDOMAIN_OF for Java compatibility)
            tx.run("""
                MATCH (d:Domain {fqdn: $parent_fqdn})
                MATCH (s:Subdomain {fqdn: $subdomain_fqdn})
                MERGE (s)-[:SUBDOMAIN_OF]->(d)
                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
            """, parent_fqdn=domain_info.parent_domain, subdomain_fqdn=domain_info.fqdn)
            relationships_created += 1
        
        # 6. NEW: Detect and create service providers during hierarchy creation
        service_providers = self._detect_and_create_service_providers(domain_info.fqdn, current_time, tx)
        
        # 7. Link domain/subdomain to detected service providers (using DEPENDS_ON for Java compatibility)
        for service_provider in service_providers:
            if domain_info.is_tld_domain:
                tx.run("""
                    MATCH (d:Domain {fqdn: $fqdn})
                    MATCH (p:Provider {name: $service_provider, type: 'Service'})
                    MERGE (d)-[:DEPENDS_ON]->(p)
                """, fqdn=domain_info.fqdn, service_provider=service_provider)
            else:
                tx.run("""
                    MATCH (s:Subdomain {fqdn: $fqdn})
                    MATCH (p:Provider {name: $service_provider, type: 'Service'})
                    MERGE (s)-[:DEPENDS_ON]->(p)
                """, fqdn=domain_info.fqdn, service_provider=service_provider)
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
        
        # Enhanced Provider node creation (v2.0 - FIXED)
        provider_name = prov if prov and prov != "unknown" else "Unknown Provider"
        
        # Detect and create infrastructure provider
        infrastructure_provider = self._create_infrastructure_provider(provider_name, cloud_info, current_time, tx)
        
        # Detect and create service providers based on domain and subdomain patterns
        service_providers = self._detect_and_create_service_providers(domain_info.fqdn, current_time, tx)
        
        # Link IP to infrastructure provider
        tx.run("""
            MATCH (ip:IPAddress {address: $ip})
            MATCH (p:Provider {name: $provider_name, type: 'Infrastructure'})
            MERGE (ip)-[:HOSTED_BY]->(p)
        """, ip=ip, provider_name=provider_name)
        
        # Link domain/subdomain to service providers
        for service_provider in service_providers:
            if domain_info.is_tld_domain:
                tx.run("""
                    MATCH (d:Domain {fqdn: $fqdn})
                    MATCH (p:Provider {name: $service_provider, type: 'Service'})
                    MERGE (d)-[:USES_SERVICE]->(p)
                """, fqdn=domain_info.fqdn, service_provider=service_provider)
            else:
                tx.run("""
                    MATCH (s:Subdomain {fqdn: $fqdn})
                    MATCH (p:Provider {name: $service_provider, type: 'Service'})
                    MERGE (s)-[:USES_SERVICE]->(p)
                """, fqdn=domain_info.fqdn, service_provider=service_provider)
    
    def _create_infrastructure_provider(self, provider_name: str, cloud_info: dict, current_time: str, tx) -> str:
        """Create infrastructure provider node (AWS, Azure, GCP, etc.)."""
        # Create Provider node for infrastructure (with id field for Java compatibility)
        provider_id = f"provider_{provider_name.lower().replace(' ', '_')}"
        tx.run("""
            MERGE (p:Provider {name: $provider_name, type: 'Infrastructure'})
            SET p.id = $provider_id,
                p.last_updated = $current_time,
                p.detection_method = $detection_method,
                p.source_info = $source_info,
                p.status = $status,
                p.tier = 1,
                p.service_type = 'cloud',
                p.confidence = $confidence
            RETURN p
        """, provider_name=provider_name, provider_id=provider_id, current_time=current_time, 
             detection_method=cloud_info.get('detection_method', 'ip_analysis'),
             source_info=json.dumps(cloud_info),
             status='active' if provider_name and provider_name != "Unknown Provider" else 'unknown',
             confidence=0.8)
        
        # Create Service node for backwards compatibility (with id field for Java compatibility)
        service_id = f"service_{provider_name.lower().replace(' ', '_')}_cloud"
        tx.run("""
            MERGE (svc:Service {name: $provider_name, type: 'cloud_provider'})
            SET svc.id = $service_id,
                svc.last_updated = $current_time,
                svc.detection_method = $detection_method,
                svc.source_info = $source_info,
                svc.service_type = 'cloud',
                svc.confidence = $confidence
            RETURN svc
        """, provider_name=provider_name, service_id=service_id, current_time=current_time, 
             detection_method=cloud_info.get('detection_method', 'ip_analysis'),
             source_info=json.dumps(cloud_info),
             confidence=0.8)
        
        # Link Provider to Service (using PROVIDED_BY for Java compatibility)
        tx.run("""
            MATCH (p:Provider {name: $provider_name, type: 'Infrastructure'})
            MATCH (svc:Service {name: $provider_name, type: 'cloud_provider'})
            MERGE (svc)-[:PROVIDED_BY]->(p)
        """, provider_name=provider_name)
        
        return provider_name
    
    def analyze_subdomain_tls(self, fqdn: str) -> Optional[Dict[str, Any]]:
        """Analyze TLS certificate for a subdomain."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((fqdn, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=fqdn) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Parse certificate data
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    expires_in_days = (not_after - datetime.now()).days
                    
                    # Calculate TLS grade based on multiple factors
                    tls_grade = self._calculate_tls_grade(cert, cipher, expires_in_days)
                    
                    return {
                        'has_tls': True,
                        'tls_grade': tls_grade,
                        'expires_in_days': expires_in_days,
                        'not_after': cert['notAfter'],
                        'not_before': cert['notBefore'],
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'serial_number': cert.get('serialNumber', ''),
                        'version': cert.get('version', 0),
                        'is_self_signed': cert.get('issuer') == cert.get('subject'),
                        'cipher_suite': cipher[0] if cipher else None,
                        'tls_version': cipher[1] if cipher else None,
                        'key_exchange': cipher[2] if cipher else None
                    }
        except Exception as e:
            logging.warning(f"TLS analysis failed for {fqdn}: {e}")
            return {
                'has_tls': False,
                'tls_grade': 'F',
                'error': str(e)
            }
    
    def _calculate_tls_grade(self, cert: Dict, cipher: tuple, expires_in_days: int) -> str:
        """Calculate TLS grade based on certificate and connection info."""
        score = 100
        
        # Certificate expiration
        if expires_in_days < 0:
            return 'F'  # Expired certificate
        elif expires_in_days < 7:
            score -= 30
        elif expires_in_days < 30:
            score -= 20
        elif expires_in_days < 90:
            score -= 10
        
        # Self-signed certificate
        if cert.get('issuer') == cert.get('subject'):
            score -= 40
        
        # TLS version
        if cipher and len(cipher) > 1:
            tls_version = cipher[1]
            if 'TLSv1.3' in tls_version:
                score += 5
            elif 'TLSv1.2' in tls_version:
                pass  # No penalty or bonus
            elif 'TLSv1.1' in tls_version or 'TLSv1.0' in tls_version:
                score -= 20
            elif 'SSLv' in tls_version:
                score -= 40
        
        # Convert score to grade
        if score >= 95:
            return 'A+'
        elif score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
    
    def detect_services_and_providers(self, fqdn: str, ip_addresses: List[str]) -> tuple:
        """Detect services and providers for a subdomain."""
        services = []
        providers = []
        
        # Service detection based on subdomain name patterns
        service_patterns = {
            'mail': ['email', 'smtp', 'messaging'],
            'autodiscover': ['email', 'exchange', 'messaging'],
            'webmail': ['email', 'web', 'messaging'],
            'ftp': ['file_transfer', 'storage'],
            'api': ['api', 'integration', 'development'],
            'cdn': ['content_delivery', 'web', 'performance'],
            'www': ['web', 'http', 'frontend'],
            'blog': ['cms', 'web', 'content'],
            'shop': ['ecommerce', 'web', 'payment'],
            'admin': ['administration', 'management', 'web'],
            'test': ['testing', 'development', 'staging'],
            'staging': ['testing', 'development', 'staging'],
            'dev': ['development', 'testing'],
            'vpn': ['network', 'security', 'remote_access'],
            'proxy': ['network', 'security', 'proxy'],
            'monitor': ['monitoring', 'observability', 'management']
        }
        
        # Detect services based on subdomain prefix
        subdomain_prefix = fqdn.split('.')[0].lower()
        if subdomain_prefix in service_patterns:
            service_types = service_patterns[subdomain_prefix]
            for service_type in service_types:
                services.append({
                    'name': f"{service_type}_{subdomain_prefix}",
                    'type': service_type,
                    'source': 'subdomain_pattern',
                    'confidence': 0.8,
                    'subdomain': fqdn
                })
        
        # Port scanning for common services
        common_ports = {
            80: ('http', 'web'),
            443: ('https', 'web'),
            25: ('smtp', 'email'),
            587: ('smtp_submission', 'email'),
            993: ('imaps', 'email'),
            995: ('pop3s', 'email'),
            22: ('ssh', 'remote_access'),
            21: ('ftp', 'file_transfer'),
            3389: ('rdp', 'remote_access')
        }
        
        for ip in ip_addresses[:3]:  # Limit to first 3 IPs to avoid too many requests
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private:  # Only scan public IPs
                    for port, (service_name, service_type) in common_ports.items():
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(2)
                            result = sock.connect_ex((ip, port))
                            sock.close()
                            
                            if result == 0:  # Port is open
                                services.append({
                                    'name': f"{service_name}_{fqdn}",
                                    'type': service_type,
                                    'source': 'port_scan',
                                    'confidence': 0.9,
                                    'port': port,
                                    'ip': ip,
                                    'subdomain': fqdn
                                })
                        except Exception:
                            pass
            except Exception:
                continue
        
        # Provider detection based on IP geolocation and ASN
        for ip in ip_addresses:
            try:
                provider_info = self._detect_provider_from_ip(ip)
                if provider_info:
                    providers.append({
                        'name': provider_info['name'],
                        'type': provider_info['type'],
                        'source': 'ip_geolocation',
                        'confidence': provider_info['confidence'],
                        'ip': ip,
                        'asn': provider_info.get('asn'),
                        'country': provider_info.get('country'),
                        'subdomain': fqdn
                    })
            except Exception as e:
                logging.warning(f"Provider detection failed for IP {ip}: {e}")
        
        return services, providers
    
    def _detect_provider_from_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Detect provider/hosting service from IP address."""
        try:
            # Common cloud provider IP ranges (simplified detection)
            cloud_providers = {
                'amazonaws.com': {'name': 'Amazon Web Services', 'type': 'cloud', 'confidence': 0.95},
                'googleusercontent.com': {'name': 'Google Cloud Platform', 'type': 'cloud', 'confidence': 0.95},
                'azurewebsites.net': {'name': 'Microsoft Azure', 'type': 'cloud', 'confidence': 0.95},
                'cloudflare.com': {'name': 'Cloudflare', 'type': 'cdn', 'confidence': 0.9},
                'fastly.com': {'name': 'Fastly', 'type': 'cdn', 'confidence': 0.9}
            }
            
            # Try reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                for domain, provider_info in cloud_providers.items():
                    if domain in hostname.lower():
                        return {
                            'name': provider_info['name'],
                            'type': provider_info['type'],
                            'confidence': provider_info['confidence'],
                            'hostname': hostname
                        }
            except Exception:
                pass
            
            # Fallback: Basic provider detection
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return {
                    'name': 'Internal Network',
                    'type': 'internal',
                    'confidence': 0.8
                }
            else:
                return {
                    'name': 'External Provider',
                    'type': 'hosting',
                    'confidence': 0.5
                }
                
        except Exception:
            return None
    
    def _perform_subdomain_analysis(self, fqdn: str, tx):
        """Perform comprehensive subdomain analysis including TLS, services, and providers."""
        try:
            current_time = datetime.now().isoformat()
            
            # Get IP addresses from DNS
            dns_info = self.analyze_subdomain_dns(fqdn)
            ip_addresses = dns_info.get('a_records', [])
            
            # Analyze TLS
            tls_info = self.analyze_subdomain_tls(fqdn)
            
            # Detect services and providers
            services, providers = self.detect_services_and_providers(fqdn, ip_addresses)
            
            # Update subdomain node with TLS and DNS information
            tx.run("""
                MATCH (s:Subdomain {fqdn: $fqdn})
                SET s.has_tls = $has_tls,
                    s.tls_grade = $tls_grade,
                    s.tls_expires_in_days = $expires_in_days,
                    s.dns_a_records = $a_records,
                    s.dns_has_spf = $has_spf,
                    s.dns_has_dmarc = $has_dmarc,
                    s.last_analyzed = datetime(),
                    s.analysis_version = 'v2.1'
            """, 
            fqdn=fqdn,
            has_tls=tls_info.get('has_tls', False) if tls_info else False,
            tls_grade=tls_info.get('tls_grade', 'Unknown') if tls_info else 'Unknown',
            expires_in_days=tls_info.get('expires_in_days', 0) if tls_info else 0,
            a_records=dns_info.get('a_records', []),
            has_spf=dns_info.get('has_spf', False),
            has_dmarc=dns_info.get('has_dmarc', False)
            )
            
            # Create or update Certificate node if TLS info exists
            if tls_info and tls_info.get('has_tls'):
                cert_id = f"{fqdn}_{tls_info.get('serial_number', 'unknown')}"
                
                tx.run("""
                    MATCH (s:Subdomain {fqdn: $fqdn})
                    MERGE (c:Certificate {id: $cert_id})
                    SET c.tls_grade = $tls_grade,
                        c.expires_in_days = $expires_in_days,
                        c.not_after = $not_after,
                        c.not_before = $not_before,
                        c.issuer = $issuer,
                        c.subject = $subject,
                        c.serial_number = $serial_number,
                        c.is_self_signed = $is_self_signed,
                        c.cipher_suite = $cipher_suite,
                        c.tls_version = $tls_version,
                        c.domain = $fqdn,
                        c.created_at = datetime()
                    MERGE (s)-[:SECURED_BY]->(c)
                """,
                fqdn=fqdn,
                cert_id=cert_id,
                tls_grade=tls_info.get('tls_grade', 'Unknown'),
                expires_in_days=tls_info.get('expires_in_days', 0),
                not_after=tls_info.get('not_after', ''),
                not_before=tls_info.get('not_before', ''),
                issuer=json.dumps(tls_info.get('issuer', {})),
                subject=json.dumps(tls_info.get('subject', {})),
                serial_number=tls_info.get('serial_number', ''),
                is_self_signed=tls_info.get('is_self_signed', False),
                cipher_suite=tls_info.get('cipher_suite', ''),
                tls_version=tls_info.get('tls_version', '')
                )
            
            # Create Service nodes and relationships
            for service in services:
                service_id = f"{fqdn}_{service['name']}"
                tx.run("""
                    MATCH (s:Subdomain {fqdn: $fqdn})
                    MERGE (srv:Service {id: $service_id})
                    SET srv.name = $service_name,
                        srv.type = $service_type,
                        srv.source = $source,
                        srv.confidence = $confidence,
                        srv.subdomain = $subdomain,
                        srv.port = $port,
                        srv.created_at = datetime()
                    MERGE (s)-[:RUNS]->(srv)
                """,
                fqdn=fqdn,
                service_id=service_id,
                service_name=service['name'],
                service_type=service['type'],
                source=service['source'],
                confidence=service['confidence'],
                subdomain=service.get('subdomain', fqdn),
                port=service.get('port', 0)
                )
            
            # Create Provider nodes and relationships
            for i, provider in enumerate(providers):
                provider_id = f"{fqdn}_provider_{i}_{int(time.time())}"
                tx.run("""
                    MATCH (s:Subdomain {fqdn: $fqdn})
                    MERGE (p:Provider {id: $provider_id})
                    SET p.name = $provider_name,
                        p.type = $provider_type,
                        p.source = $source,
                        p.confidence = $confidence,
                        p.ip = $ip,
                        p.asn = $asn,
                        p.country = $country,
                        p.subdomain = $subdomain,
                        p.created_at = datetime()
                    MERGE (s)-[:USES_SERVICE]->(p)
                    MERGE (s)-[:RUNS]->(p)
                """,
                fqdn=fqdn,
                provider_id=provider_id,
                provider_name=provider['name'],
                provider_type=provider['type'],
                source=provider['source'],
                confidence=provider['confidence'],
                ip=provider.get('ip', ''),
                asn=provider.get('asn', ''),
                country=provider.get('country', ''),
                subdomain=provider.get('subdomain', fqdn)
                )
            
            logging.info(f"✓ Analyzed {fqdn}: {len(services)} services, {len(providers)} providers, TLS: {tls_info.get('tls_grade', 'N/A') if tls_info else 'N/A'}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to analyze {fqdn}: {e}")
            return False
    
    def analyze_subdomain_dns(self, fqdn: str) -> Dict[str, Any]:
        """Analyze DNS configuration for subdomain."""
        dns_info = {
            'a_records': [],
            'aaaa_records': [],
            'cname_records': [],
            'mx_records': [],
            'txt_records': [],
            'has_spf': False,
            'has_dmarc': False
        }
        
        try:
            # A records
            try:
                a_records = RESOLVER.resolve(fqdn, 'A')
                dns_info['a_records'] = [str(r) for r in a_records]
            except dns.resolver.NXDOMAIN:
                pass
            except Exception:
                pass
            
            # AAAA records
            try:
                aaaa_records = RESOLVER.resolve(fqdn, 'AAAA')
                dns_info['aaaa_records'] = [str(r) for r in aaaa_records]
            except Exception:
                pass
            
            # CNAME records
            try:
                cname_records = RESOLVER.resolve(fqdn, 'CNAME')
                dns_info['cname_records'] = [str(r) for r in cname_records]
            except Exception:
                pass
            
            # MX records
            try:
                mx_records = RESOLVER.resolve(fqdn, 'MX')
                dns_info['mx_records'] = [f"{r.preference} {r.exchange}" for r in mx_records]
            except Exception:
                pass
            
            # TXT records
            try:
                txt_records = RESOLVER.resolve(fqdn, 'TXT')
                txt_strings = [str(r) for r in txt_records]
                dns_info['txt_records'] = txt_strings
                
                # Check for SPF and DMARC
                for txt in txt_strings:
                    if txt.startswith('"v=spf1'):
                        dns_info['has_spf'] = True
                    if txt.startswith('"v=DMARC1'):
                        dns_info['has_dmarc'] = True
            except Exception:
                pass
            
        except Exception as e:
            logging.warning(f"DNS analysis failed for {fqdn}: {e}")
        
        return dns_info
    
    def _detect_and_create_service_providers(self, fqdn: str, current_time: str, tx) -> List[str]:
        """Detect and create service provider nodes based on domain patterns."""
        service_providers = []
        
        # Common service provider patterns in domain names
        service_patterns = {
            'salesforce': ['salesforce', 'force', 'lightning'],
            'microsoft': ['outlook', 'onedrive', 'sharepoint', 'office365', 'o365', 'microsoftonline'],
            'google': ['gmail', 'google', 'workspace', 'gsuite'],
            'adobe': ['adobe', 'creative', 'acrobat'],
            'zoom': ['zoom', 'zoomgov'],
            'slack': ['slack'],
            'dropbox': ['dropbox'],
            'atlassian': ['atlassian', 'jira', 'confluence'],
            'tableau': ['tableau'],
            'servicenow': ['servicenow', 'service-now'],
            'workday': ['workday'],
            'okta': ['okta'],
            'auth0': ['auth0'],
            'hubspot': ['hubspot'],
            'zendesk': ['zendesk'],
            'freshworks': ['freshworks', 'freshdesk'],
            'klaviyo': ['klaviyo'],
            'marketo': ['marketo'],
            'pardot': ['pardot'],
            'mailchimp': ['mailchimp'],
            'constant_contact': ['constantcontact'],
            'twilio': ['twilio'],
            'sendgrid': ['sendgrid'],
            'stripe': ['stripe'],
            'paypal': ['paypal'],
            'square': ['square', 'squareup'],
            'docusign': ['docusign'],
            'airtable': ['airtable'],
            'notion': ['notion'],
            'monday': ['monday'],
            'asana': ['asana'],
            'trello': ['trello'],
            'github': ['github'],
            'gitlab': ['gitlab'],
            'bitbucket': ['bitbucket'],
            'jenkins': ['jenkins'],
            'circleci': ['circleci'],
            'travis': ['travis-ci'],
            'newrelic': ['newrelic'],
            'datadog': ['datadog'],
            'splunk': ['splunk'],
            'elastic': ['elastic', 'elasticsearch'],
            'cloudflare': ['cloudflare'],
            'fastly': ['fastly'],
            'maxcdn': ['maxcdn'],
            'akamai': ['akamai'],
            'imperva': ['imperva'],
            'sucuri': ['sucuri']
        }
        
        fqdn_lower = fqdn.lower()
        
        # Check for service patterns in the domain
        for service_name, patterns in service_patterns.items():
            for pattern in patterns:
                if pattern in fqdn_lower:
                    service_providers.append(service_name.title())
                    break
        
        # Create service provider nodes (with id field for Java compatibility)
        created_providers = []
        for service_provider in set(service_providers):  # Remove duplicates
            # Create Provider node for service
            provider_id = f"provider_{service_provider.lower().replace(' ', '_')}"
            tx.run("""
                MERGE (p:Provider {name: $service_provider, type: 'Service'})
                SET p.id = $provider_id,
                    p.last_updated = $current_time,
                    p.detection_method = 'domain_pattern_analysis',
                    p.status = 'detected',
                    p.tier = 1,
                    p.service_type = 'saas',
                    p.confidence = $confidence,
                    p.source_info = $source_info
                RETURN p
            """, service_provider=service_provider, provider_id=provider_id, current_time=current_time,
                 confidence=0.7,
                 source_info=json.dumps({'detection_domain': fqdn, 'detection_method': 'pattern_matching'}))
            
            created_providers.append(service_provider)
        
        return created_providers
    
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
            
            # Provider stats (v2.0: Count actual Provider nodes)
            provider_result = s.run("""
                MATCH (p:Provider)
                RETURN count(p) as provider_count
            """)
            stats['provider_count'] = provider_result.single()['provider_count']
            
            # Risk stats (v2.0: Added risk node count)
            risk_result = s.run("""
                MATCH (r:Risk)
                RETURN count(r) as risk_count
            """)
            stats['risk_count'] = risk_result.single()['risk_count']
            
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
                                         sample_mode: bool = False, amass_timeout: int = None, 
                                         amass_passive: bool = None, cache_ttl_hours: int = 168) -> List[str]:
    """Run Amass for subdomain discovery with enhanced relationship detection."""
    
    # Mock mode for testing
    if mock_mode:
        mock_subdomains = [
            f"www.{domain}",
            f"mail.{domain}",
            f"api.{domain}",
            f"admin.{domain}",
            f"cdn.{domain}",
            f"app.{domain}",
            # v2.0: Added second-level mock subdomains
            f"secure.mail.{domain}",
            f"dev.api.{domain}",
            f"staging.app.{domain}"
        ]
        print(f"[DISCOVERY] MOCK MODE: Found {len(mock_subdomains)} subdomains for {domain}")
        return mock_subdomains
    
    try:
        # v2.0: Use enhanced multi-level discovery with configurable parameters
        results = run_enhanced_amass_multilevel(domain, sample_mode=sample_mode, 
                                               amass_timeout=amass_timeout, 
                                               amass_passive=amass_passive,
                                               cache_ttl_hours=cache_ttl_hours)
        
        # Extract subdomain names, excluding the base domain
        subdomains = []
        for result in results:
            subdomain = result.get('name') if isinstance(result, dict) else result
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

def run_enhanced_amass_multilevel(domain: str, sample_mode: bool = False, amass_timeout: int = None, 
                                  amass_passive: bool = None, cache_ttl_hours: int = 168) -> List[dict]:
    """v2.0: Enhanced Amass discovery with multi-level subdomain support."""
    try:
        from risk_loader_advanced3 import run_amass_with_fallback
        
        print(f"[DISCOVERY] Starting enhanced multi-level Amass for {domain} (sample_mode={sample_mode})")
        
        # First pass: Standard discovery with configurable parameters and fallbacks
        results = run_amass_with_fallback(domain, sample_mode=sample_mode, amass_timeout=amass_timeout, 
                                         amass_passive=amass_passive, cache_ttl_hours=cache_ttl_hours)
        all_subdomains = set()
        
        # Extract first-level subdomains
        for result in results:
            subdomain = result.get('name') if isinstance(result, dict) else result
            if subdomain and subdomain != domain:
                all_subdomains.add(subdomain)
        
        print(f"[DISCOVERY] First pass: Found {len(all_subdomains)} first-level subdomains")
        
        # Second pass: Discover subdomains of subdomains (if not in sample mode)
        if not sample_mode and all_subdomains:
            second_level_count = 0
            subdomain_list = list(all_subdomains)[:10]  # Limit to first 10 to avoid overwhelming
            
            print(f"[DISCOVERY] Second pass: Analyzing {len(subdomain_list)} subdomains for second-level discovery")
            
            for subdomain in subdomain_list:
                try:
                    # Quick discovery for each subdomain with configurable parameters and fallbacks
                    sub_results = run_amass_with_fallback(subdomain, sample_mode=True, amass_timeout=amass_timeout, 
                                                         amass_passive=amass_passive, cache_ttl_hours=cache_ttl_hours)  # Use sample mode for speed
                    
                    for sub_result in sub_results:
                        sub_subdomain = sub_result.get('name') if isinstance(sub_result, dict) else sub_result
                        if sub_subdomain and sub_subdomain not in all_subdomains and sub_subdomain != subdomain:
                            all_subdomains.add(sub_subdomain)
                            second_level_count += 1
                            
                except Exception as e:
                    print(f"[DISCOVERY] Error in second-level discovery for {subdomain}: {e}")
                    continue
            
            print(f"[DISCOVERY] Second pass: Found {second_level_count} additional second-level subdomains")
        
        # Convert back to dict format for compatibility
        final_results = [{'name': subdomain} for subdomain in all_subdomains]
        print(f"[DISCOVERY] Enhanced discovery completed: {len(final_results)} total subdomains")
        
        return final_results
        
    except ImportError:
        print(f"[DISCOVERY] Cannot import run_amass_local, falling back to basic discovery")
        return []
    except Exception as e:
        print(f"[DISCOVERY] Error in enhanced multi-level discovery: {e}")
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
                 mock_mode: bool = False, sample_mode: bool = False, amass_timeout: int = None, 
                 amass_passive: bool = None, cache_ttl_hours: int = 168, no_cache: bool = False):
        self.ingester = ingester
        self.max_discovery_workers = max_discovery_workers
        self.max_processing_workers = max_processing_workers
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_pass = neo4j_pass
        self.ipinfo_token = ingester.ipinfo_token
        self.mock_mode = mock_mode
        self.sample_mode = sample_mode
        self.amass_timeout = amass_timeout
        self.amass_passive = amass_passive
        self.cache_ttl_hours = cache_ttl_hours if not no_cache else 0  # 0 = disable cache
        self.no_cache = no_cache
    
    def enhanced_phase1_discovery(self, domains: List[str]) -> Dict[str, Any]:
        """Enhanced Phase 1: Discovery with proper base domain handling."""
        print(f"\n🔍 ENHANCED PHASE 1: Subdomain Discovery")
        print(f"   Input domains: {len(domains)}")
        print(f"   Discovery workers: {self.max_discovery_workers}")
        if self.no_cache:
            print(f"   Cache: DISABLED (fresh execution)")
        else:
            print(f"   Cache: ENABLED (TTL: {self.cache_ttl_hours}h)")
        print("="*60)
        
        # Set input domains in the ingester to prevent base domains appearing as subdomains
        self.ingester.set_input_domains(domains)
        
        start_time = time.time()
        
        # Step 1: Create initial domain hierarchy for base domains
        print("Step 1: Creating base domain hierarchy...")
        hierarchy_stats = self.ingester.create_enhanced_domain_hierarchy_batch(domains)
        print(f"✓ Created {hierarchy_stats['domains_created']} base domains")
        
        # Step 2: Enhanced progressive discovery with real-time graph writing
        print(f"Step 2: Running enhanced progressive discovery (sample_mode={self.sample_mode})...")
        print("📝 Writing to graph progressively as subdomains are discovered...")
        
        discovery_results, subdomain_stats = self._run_progressive_discovery_with_dependencies(domains)
        
        # Collect summary
        all_subdomains = []
        for domain, subdomains in discovery_results.items():
            filtered_subdomains = [sub for sub in subdomains if sub not in domains]
            all_subdomains.extend(filtered_subdomains)
        
        print(f"✓ Discovered and wrote {len(all_subdomains)} unique subdomains to graph")
        
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
            # Submit all discovery tasks with configurable parameters
            future_to_domain = {
                executor.submit(run_amass_discovery_with_relationships, domain, 60, self.mock_mode, 
                               self.sample_mode, self.amass_timeout, self.amass_passive, self.cache_ttl_hours): domain 
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
    
    def _run_progressive_discovery_with_dependencies(self, domains: List[str]) -> Tuple[Dict[str, List[str]], Dict[str, Any]]:
        """
        Ejecuta descubrimiento progresivo con escritura inmediata al grafo y análisis de dependencias.
        """
        from provider_detection import ProviderDetector
        
        results = {}
        total_subdomain_stats = {
            'subdomains_created': 0,
            'dependencies_detected': 0,
            'providers_created': 0,
            'relationships_created': 0
        }
        
        provider_detector = ProviderDetector()
        
        with ThreadPoolExecutor(max_workers=self.max_discovery_workers, thread_name_prefix="ProgressiveDiscovery") as executor:
            # Submit all discovery tasks
            future_to_domain = {
                executor.submit(self._progressive_discovery_worker, domain, provider_detector): domain 
                for domain in domains
            }
            
            # Process results as they complete
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    subdomains, stats = future.result()
                    results[domain] = subdomains
                    
                    # Aggregate stats
                    for key in total_subdomain_stats:
                        total_subdomain_stats[key] += stats.get(key, 0)
                    
                    print(f"✓ Progressive discovery completed for {domain}: {len(subdomains)} subdomains, {stats['dependencies_detected']} dependencies")
                    
                except Exception as e:
                    print(f"✗ Progressive discovery failed for {domain}: {e}")
                    results[domain] = []
        
        print(f"📊 Total Dependencies Analysis:")
        print(f"   - Subdomains created: {total_subdomain_stats['subdomains_created']}")
        print(f"   - Dependencies detected: {total_subdomain_stats['dependencies_detected']}")
        print(f"   - Providers identified: {total_subdomain_stats['providers_created']}")
        print(f"   - Relationships created: {total_subdomain_stats['relationships_created']}")
        
        return results, total_subdomain_stats
    
    def _progressive_discovery_worker(self, domain: str, provider_detector) -> Tuple[List[str], Dict[str, Any]]:
        """
        Worker que ejecuta descubrimiento progresivo para un dominio específico.
        """
        stats = {
            'subdomains_created': 0,
            'dependencies_detected': 0,
            'providers_created': 0,
            'relationships_created': 0
        }
        
        print(f"🔍 Starting progressive analysis for {domain}")
        
        # 1. Analizar dependencias del dominio base PRIMERO
        print(f"📋 Analyzing base domain dependencies: {domain}")
        base_dependencies = provider_detector.analyze_domain_dependencies(domain)
        
        if base_dependencies:
            # Escribir dependencias del dominio base al grafo inmediatamente
            deps_written = self._write_dependencies_to_graph(domain, base_dependencies, is_subdomain=False)
            stats['dependencies_detected'] += len(base_dependencies)
            stats['providers_created'] += deps_written['providers']
            stats['relationships_created'] += deps_written['relationships']
            print(f"   ✓ {domain}: {len(base_dependencies)} dependencies → {deps_written['providers']} providers")
        
        # 2. Ejecutar descubrimiento de subdominios
        subdomains = run_amass_discovery_with_relationships(
            domain, 60, self.mock_mode, self.sample_mode, 
            self.amass_timeout, self.amass_passive, self.cache_ttl_hours
        )
        
        # 3. Procesar cada subdominio progresivamente
        for subdomain in subdomains:
            try:
                # Escribir subdominio al grafo inmediatamente
                self._write_subdomain_to_graph_immediately(subdomain, domain)
                stats['subdomains_created'] += 1
                
                # Analizar dependencias del subdominio
                subdomain_dependencies = provider_detector.analyze_subdomain_dependencies(subdomain)
                
                if subdomain_dependencies:
                    # Escribir dependencias del subdominio al grafo
                    deps_written = self._write_dependencies_to_graph(subdomain, subdomain_dependencies, is_subdomain=True)
                    stats['dependencies_detected'] += len(subdomain_dependencies)
                    stats['providers_created'] += deps_written['providers']
                    stats['relationships_created'] += deps_written['relationships']
                    print(f"   ✓ {subdomain}: {len(subdomain_dependencies)} dependencies → {deps_written['providers']} providers")
                
            except Exception as e:
                print(f"   ✗ Error processing {subdomain}: {e}")
        
        return subdomains, stats
    
    def _write_subdomain_to_graph_immediately(self, subdomain: str, base_domain: str):
        """Escribe un subdominio al grafo inmediatamente."""
        try:
            # Usar el ingester existente para crear la jerarquía
            self.ingester.create_enhanced_domain_hierarchy_batch([subdomain])
        except Exception as e:
            print(f"Error writing subdomain {subdomain}: {e}")
    
    def _write_dependencies_to_graph(self, domain_or_subdomain: str, dependencies: List, is_subdomain: bool = False) -> Dict[str, int]:
        """
        Escribe dependencias al grafo y retorna estadísticas.
        """
        providers_created = 0
        relationships_created = 0
        
        try:
            with self.ingester.drv.session() as session:
                with session.begin_transaction() as tx:
                    current_time = datetime.now().isoformat()
                    
                    for dep in dependencies:
                        # 1. Crear nodo Provider
                        tx.run("""
                            MERGE (p:Provider {name: $provider_name, type: $service_type})
                            SET p.last_updated = $current_time,
                                p.detection_method = $detection_method,
                                p.risk_level = $risk_level,
                                p.confidence = $confidence,
                                p.service_category = $service_category,
                                p.metadata = $metadata
                            RETURN p
                        """, 
                        provider_name=dep.provider,
                        service_type=dep.service_type.value,
                        current_time=current_time,
                        detection_method=dep.detection_method,
                        risk_level=dep.risk_level.value,
                        confidence=dep.confidence,
                        service_category=dep.name,
                        metadata=json.dumps(dep.metadata))
                        providers_created += 1
                        
                        # 2. Crear nodo Service específico (with id field for Java compatibility)
                        service_id = f"service_{dep.name.lower().replace(' ', '_')}"
                        tx.run("""
                            MERGE (s:Service {name: $service_name, type: $service_type})
                            SET s.id = $service_id,
                                s.provider = $provider_name,
                                s.last_updated = $current_time,
                                s.detection_method = $detection_method,
                                s.risk_level = $risk_level,
                                s.service_type = $service_type,
                                s.confidence = $confidence,
                                s.metadata = $metadata
                            RETURN s
                        """,
                        service_name=dep.name,
                        service_id=service_id,
                        service_type=dep.service_type.value,
                        provider_name=dep.provider,
                        current_time=current_time,
                        detection_method=dep.detection_method,
                        risk_level=dep.risk_level.value,
                        confidence=dep.confidence,
                        metadata=json.dumps(dep.metadata))
                        
                        # 3. Crear relación Service -> Provider (using PROVIDED_BY for Java compatibility)
                        tx.run("""
                            MATCH (p:Provider {name: $provider_name})
                            MATCH (s:Service {name: $service_name})
                            MERGE (s)-[:PROVIDED_BY]->(p)
                        """, provider_name=dep.provider, service_name=dep.name)
                        relationships_created += 1
                        
                        # 4. Crear relación Domain/Subdomain -> Service
                        if is_subdomain:
                            tx.run("""
                                MATCH (sub:Subdomain {fqdn: $fqdn})
                                MATCH (s:Service {name: $service_name})
                                MERGE (sub)-[r:DEPENDS_ON]->(s)
                                SET r.detection_method = $detection_method,
                                    r.confidence = $confidence,
                                    r.created_at = $current_time
                            """, fqdn=domain_or_subdomain, service_name=dep.name, 
                                 detection_method=dep.detection_method, confidence=dep.confidence, 
                                 current_time=current_time)
                        else:
                            tx.run("""
                                MATCH (d:Domain {fqdn: $fqdn})
                                MATCH (s:Service {name: $service_name})
                                MERGE (d)-[r:DEPENDS_ON]->(s)
                                SET r.detection_method = $detection_method,
                                    r.confidence = $confidence,
                                    r.created_at = $current_time
                            """, fqdn=domain_or_subdomain, service_name=dep.name,
                                 detection_method=dep.detection_method, confidence=dep.confidence,
                                 current_time=current_time)
                        relationships_created += 1
                    
                    tx.commit()
        
        except Exception as e:
            print(f"Error writing dependencies for {domain_or_subdomain}: {e}")
        
        return {'providers': providers_created, 'relationships': relationships_created}
    
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
                        # Log comprehensive analysis results
                        if result.get('service_count', 0) > 0 or result.get('provider_count', 0) > 0:
                            print(f"  → {result['fqdn']}: {result['service_count']} services, {result['provider_count']} providers, TLS: {result['tls_grade']}")
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
        
        # Phase 2.6: Risk analysis (v2.0 - NEW)
        print("\n⚠️  Phase 2.6: Performing risk analysis...")
        risk_stats = self._perform_risk_analysis()
        print(f"✓ Risk analysis completed:")
        print(f"   - Risk nodes created: {risk_stats['risk_nodes_created']}")
        print(f"   - High risk domains: {risk_stats['high_risk_count']}")
        print(f"   - Medium risk domains: {risk_stats['medium_risk_count']}")
        print(f"   - Low risk domains: {risk_stats['low_risk_count']}")
        
        # Phase 2.7: Subdomain risk calculation (NEW)
        print("\n🎯 Phase 2.7: Calculating individual subdomain risks...")
        subdomain_risk_stats = self.calculate_subdomain_risks()
        print(f"✓ Subdomain risk calculation completed:")
        print(f"   - Subdomains processed: {subdomain_risk_stats['subdomains_processed']}")
        print(f"   - High risk subdomains: {subdomain_risk_stats['high_risk_subdomains']}")
        print(f"   - Medium risk subdomains: {subdomain_risk_stats['medium_risk_subdomains']}")
        print(f"   - Low risk subdomains: {subdomain_risk_stats['low_risk_subdomains']}")
        
        elapsed_time = time.time() - start_time
        
        stats = {
            'phase': 2,
            'total_processed': total_processed,
            'successful': total_successful,
            'errors': total_errors,
            'elapsed_time': elapsed_time,
            'rate': total_processed / elapsed_time if elapsed_time > 0 else 0,
            'relationship_stats': relationship_stats,
            'risk_stats': risk_stats,  # v2.0: Added risk statistics
            'subdomain_risk_stats': subdomain_risk_stats  # NEW: Subdomain risk statistics
        }
        
        print(f"\n✅ Enhanced Phase 2 completed in {elapsed_time:.1f} seconds")
        print(f"   Subdomains processed: {stats['total_processed']}")
        print(f"   Successful: {stats['successful']}")
        print(f"   Errors: {stats['errors']}")
        print(f"   Rate: {stats['rate']:.1f} subdomains/second")
        print("="*60)
        
        return stats
    
    def _perform_risk_analysis(self) -> Dict[str, Any]:
        """v2.0: Perform risk analysis and create Risk nodes."""
        try:
            # Import risk calculation functionality
            from domain_risk_calculator import DomainRiskCalculator
            
            risk_calculator = DomainRiskCalculator(
                self.neo4j_uri, self.neo4j_user, self.neo4j_pass
            )
            
            # Get all domains and subdomains for risk analysis
            with self.ingester.drv.session() as s:
                result = s.run("""
                    MATCH (n)
                    WHERE n:Domain OR n:Subdomain
                    RETURN n.fqdn as fqdn, labels(n)[0] as node_type
                """)
                nodes_to_analyze = [(record["fqdn"], record["node_type"]) for record in result]
            
            stats = {
                'risk_nodes_created': 0,
                'high_risk_count': 0,
                'medium_risk_count': 0,
                'low_risk_count': 0,
                'errors': 0
            }
            
            print(f"Analyzing risk for {len(nodes_to_analyze)} nodes...")
            
            for fqdn, node_type in nodes_to_analyze:
                try:
                    print(f"  Analyzing risks for {fqdn} ({node_type})")
                    
                    # Calculate domain risk 
                    risk_results = risk_calculator.calculate_domain_risks(fqdn)
                    
                    # Save risks to graph if any found
                    if risk_results and len(risk_results) > 0:
                        saved_count = risk_calculator.save_risks_to_graph(risk_results)
                        stats['risk_nodes_created'] += saved_count
                        
                        print(f"    Found {len(risk_results)} risks, saved {saved_count} to graph")
                        
                        # Count by severity from the actual risk objects
                        for risk in risk_results:
                            severity = risk.severity.value if hasattr(risk.severity, 'value') else str(risk.severity)
                            severity = severity.upper()  # Normalize to uppercase
                            if severity in ['CRITICAL', 'HIGH']:
                                stats['high_risk_count'] += 1
                            elif severity == 'MEDIUM':
                                stats['medium_risk_count'] += 1
                            else:
                                stats['low_risk_count'] += 1
                    else:
                        print(f"    No risks found for {fqdn}")
                            
                except Exception as e:
                    print(f"  Error analyzing risk for {fqdn}: {e}")
                    stats['errors'] += 1
            
            risk_calculator.close()
            return stats
            
        except ImportError:
            print("⚠️  Warning: domain_risk_calculator module not available. Skipping risk analysis.")
            return {
                'risk_nodes_created': 0,
                'high_risk_count': 0,
                'medium_risk_count': 0,
                'low_risk_count': 0,
                'errors': 0
            }
        except Exception as e:
            print(f"Error in risk analysis: {e}")
            return {
                'risk_nodes_created': 0,
                'high_risk_count': 0,
                'medium_risk_count': 0,
                'low_risk_count': 0,
                'errors': 1
            }
    
    def calculate_subdomain_risks(self) -> Dict[str, Any]:
        """Calculate individual risk scores for all subdomains based on their services, providers, and characteristics."""
        print("\n🎯 Calculating individual subdomain risk scores...")
        
        stats = {
            'subdomains_processed': 0,
            'subdomains_with_risks': 0,
            'average_risk_score': 0.0,
            'high_risk_subdomains': 0,
            'medium_risk_subdomains': 0,
            'low_risk_subdomains': 0,
            'errors': 0
        }
        
        try:
            with self.ingester.drv.session() as session:
                # Get all subdomains
                result = session.run("""
                    MATCH (s:Subdomain)
                    RETURN s.fqdn as fqdn, s.base_domain as base_domain
                    ORDER BY s.base_domain, s.fqdn
                """)
                
                subdomains = [(record["fqdn"], record["base_domain"]) for record in result]
                print(f"Found {len(subdomains)} subdomains to analyze")
                
                total_risk_score = 0.0
                
                for fqdn, base_domain in subdomains:
                    try:
                        # Calculate risk for individual subdomain
                        result = session.run("""
                            MATCH (s:Subdomain {fqdn: $fqdn})
                            OPTIONAL MATCH (s)-[:RUNS|DEPENDS_ON]->(svc:Service)
                            OPTIONAL MATCH (s)-[:DEPENDS_ON]->(p:Provider)
                            OPTIONAL MATCH (s)-[:RESOLVES_TO]->(ip:IPAddress)
                            OPTIONAL MATCH (s)<-[:AFFECTS]-(risk:Risk)
                            
                            WITH s, 
                                 count(DISTINCT svc) as service_count,
                                 count(DISTINCT p) as provider_count,
                                 count(DISTINCT ip) as ip_count,
                                 avg(CASE WHEN svc.risk_score IS NOT NULL THEN svc.risk_score ELSE 0 END) as avg_service_risk,
                                 avg(CASE WHEN p.risk_score IS NOT NULL THEN p.risk_score ELSE 0 END) as avg_provider_risk,
                                 avg(CASE WHEN risk.score IS NOT NULL THEN risk.score ELSE 0 END) as avg_risk_node_score
                            
                            // Calculate subdomain risk score
                            WITH s, service_count, provider_count, ip_count,
                                 (service_count * 0.4 + 
                                  provider_count * 0.3 + 
                                  ip_count * 0.1 + 
                                  avg_service_risk * 0.1 + 
                                  avg_provider_risk * 0.05 +
                                  avg_risk_node_score * 0.05) as calculated_risk
                            
                            SET s.risk_score = CASE 
                                WHEN calculated_risk > 10 THEN 10.0
                                WHEN calculated_risk < 0.5 THEN CASE 
                                    WHEN service_count > 0 OR provider_count > 0 OR ip_count > 0 THEN 1.0
                                    ELSE 0.5
                                END
                                ELSE calculated_risk
                            END,
                            s.risk_tier = CASE
                                WHEN s.risk_score >= 7 THEN 'high'
                                WHEN s.risk_score >= 4 THEN 'medium'
                                ELSE 'low'
                            END,
                            s.last_risk_calculated = datetime(),
                            s.service_count = service_count,
                            s.provider_count = provider_count,
                            s.ip_count = ip_count
                            
                            RETURN 
                                s.risk_score as risk_score, 
                                s.risk_tier as risk_tier,
                                service_count,
                                provider_count,
                                ip_count
                        """, fqdn=fqdn)
                        
                        if result.peek():
                            record = result.single()
                            risk_score = record['risk_score']
                            risk_tier = record['risk_tier']
                            
                            stats['subdomains_processed'] += 1
                            if risk_score > 0:
                                stats['subdomains_with_risks'] += 1
                                total_risk_score += risk_score
                            
                            # Count by risk tier
                            if risk_tier == 'high':
                                stats['high_risk_subdomains'] += 1
                            elif risk_tier == 'medium':
                                stats['medium_risk_subdomains'] += 1
                            else:
                                stats['low_risk_subdomains'] += 1
                            
                            if stats['subdomains_processed'] % 50 == 0:
                                print(f"  Processed {stats['subdomains_processed']} subdomains...")
                        
                    except Exception as e:
                        print(f"  Error calculating risk for {fqdn}: {e}")
                        stats['errors'] += 1
                
                # Calculate average risk score
                if stats['subdomains_with_risks'] > 0:
                    stats['average_risk_score'] = total_risk_score / stats['subdomains_with_risks']
                
                print(f"✅ Subdomain risk calculation completed:")
                print(f"   - Processed: {stats['subdomains_processed']}")
                print(f"   - With risks: {stats['subdomains_with_risks']}")
                print(f"   - Average risk: {stats['average_risk_score']:.2f}")
                print(f"   - High risk: {stats['high_risk_subdomains']}")
                print(f"   - Medium risk: {stats['medium_risk_subdomains']}")
                print(f"   - Low risk: {stats['low_risk_subdomains']}")
                print(f"   - Errors: {stats['errors']}")
        
        except Exception as e:
            print(f"❌ Error in subdomain risk calculation: {e}")
            stats['errors'] = 1
        
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
        print(f"     - Risk nodes: {final_stats.get('risk_count', 0)}")
        print("="*80)
        
        return combined_stats

def main():
    """Main function for enhanced subdomain relationship discovery."""
    parser = argparse.ArgumentParser(description="Enhanced subdomain discovery with relationship mapping")
    parser.add_argument("--domains", help="Input domains file")
    parser.add_argument("--bolt", default="bolt://localhost:7687", help="Neo4j bolt URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", help="Neo4j password", default="test.password")
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
    
    # Amass configuration
    parser.add_argument("--amass-timeout", type=int, help="Amass timeout in seconds (overrides default)")
    parser.add_argument("--amass-passive", action="store_const", const=True, default=None, help="Force Amass to use passive mode only")
    
    # Cache configuration
    parser.add_argument("--cache-ttl", type=int, default=168, help="Cache TTL in hours (default: 168 = 1 week)")
    parser.add_argument("--cache-dir", default="amass_cache", help="Cache directory (default: amass_cache)")
    parser.add_argument("--no-cache", action="store_true", help="Disable cache (force fresh Amass execution)")
    parser.add_argument("--cache-stats", action="store_true", help="Show cache statistics and exit")
    parser.add_argument("--cache-clear", action="store_true", help="Clear expired cache entries and exit")
    
    # v2.0: Version information
    parser.add_argument("-v", "--version", action="version", version="%(prog)s v2.0")
    
    args = parser.parse_args()
    
    # Handle cache-specific commands (before other validation)
    if args.cache_stats or args.cache_clear:
        from amass_cache import AmassCache
        cache = AmassCache(args.cache_dir, args.cache_ttl)
        
        if args.cache_stats:
            print("🗄️  AMASS CACHE STATISTICS")
            print("="*50)
            stats = cache.get_stats()
            for key, value in stats.items():
                print(f"{key:20}: {value}")
            
            print(f"\n📋 CACHED DOMAINS ({len(cache.list_cached_domains())} entries):")
            for entry in cache.list_cached_domains()[:10]:  # Show first 10
                expired = "⚠️ EXPIRED" if entry["expired"] else "✅"
                print(f"  {expired} {entry['domain']} ({entry['mode']}) - {entry['subdomain_count']} subdomains, {entry['age_hours']}h old")
            
            if len(cache.list_cached_domains()) > 10:
                print(f"  ... and {len(cache.list_cached_domains()) - 10} more")
            return
        
        if args.cache_clear:
            print("🧹 CLEARING EXPIRED CACHE ENTRIES")
            cleared = cache.clear_expired()
            print(f"✅ Cleared {cleared} expired entries")
            stats = cache.get_stats()
            print(f"📊 Cache now has {stats['current_entries']} active entries")
            return
    
    # Validate required arguments for normal operation
    if not args.domains:
        parser.error("--domains is required for normal operation")
    if not args.password:
        parser.error("--password is required for normal operation")
    
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
            args.sample_mode,
            args.amass_timeout,
            args.amass_passive,
            args.cache_ttl,
            args.no_cache
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