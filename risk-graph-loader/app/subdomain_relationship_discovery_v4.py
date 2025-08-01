#!/usr/bin/env python3
"""
subdomain_relationship_discovery_v4.py - Ultimate Subdomain Relationship Discovery v4.0

This module combines the best features from v2.0 and v3.0, plus enhanced provider resolution
to eliminate "unknown provider" issues through comprehensive data gathering and analysis.

Key features (NEW in v4.0):
1. Enhanced Provider Resolution System - Multiple fallback strategies for unknown providers
2. IPInfo.io deep integration - Comprehensive provider, ASN, and org data collection
3. WHOIS integration - Additional provider identification through domain registration data  
4. Geolocation-based provider hints - Regional cloud provider detection
5. DNS-based provider detection - PTR records and hostname analysis
6. Machine learning provider classification - Pattern-based provider identification
7. Provider confidence scoring - Weighted confidence based on multiple sources
8. Unknown provider tracking and analysis - Detailed metadata for resolution

Features from v3.0:
1. Comprehensive TLS certificate analysis with grade calculation
2. Intelligent service detection based on subdomain patterns and port scanning
3. Provider identification through reverse DNS and IP analysis
4. Real-time Certificate node creation with SECURED_BY relationships
5. Service node creation with RUNS relationships
6. Provider node creation with USES_SERVICE relationships
7. Enhanced risk scoring based on TLS configuration
8. Industry classification for domains

Features from v2.0:
1. Full subdomain discovery using Amass with fallbacks
2. Two-phase processing system (discovery + analysis)
3. Multi-level subdomain chain discovery (depth > 1)
4. Cross-domain relationship discovery
5. Caching system for Amass results
6. Worker-based parallel processing
7. Provider and Service node creation
8. Risk node generation and analysis

Version history:
- v1.0: Initial implementation with Service nodes only
- v2.0: Added Provider nodes, Risk analysis, and multi-level subdomain discovery
- v3.0: Added TLS analysis, service detection, and provider identification
- v4.0: Ultimate version with enhanced provider resolution and comprehensive analysis
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
import hashlib

import dns.resolver, dns.exception, requests, logging
import csv

# Import domain risk calculator
try:
    from domain_risk_calculator import DomainRiskCalculator
    HAS_RISK_CALCULATOR = True
except ImportError:
    HAS_RISK_CALCULATOR = False
import ipaddress

# Try to import optional modules
try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

try:
    from neo4j import GraphDatabase
    import neo4j
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False

try:
    from ipinfo import getHandler
    HAS_IPINFO = True
except ImportError:
    HAS_IPINFO = False

try:
    import maxminddb
    HAS_MAXMINDDB = True
except ImportError:
    HAS_MAXMINDDB = False

try:
    from industry_classifier import IndustryClassifier
    HAS_INDUSTRY_CLASSIFIER = True
except ImportError:
    HAS_INDUSTRY_CLASSIFIER = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

# Global configurations
AMASS_IMAGE = "caffix/amass:latest"
RESOLVER = dns.resolver.Resolver(configure=True)
IPINFO_MMDB_PATH = "ipinfo_data/ipinfo.mmdb"
IPINFO_CSV_PATH = "ipinfo_data/ipinfo.csv"

# Global logging configuration - will be reconfigured in setup_debug_logging if debug mode is enabled
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('subdomain_relationship_discovery_v4.log')
    ]
)

def setup_debug_logging(log_file, debug_mode=False):
    """Setup comprehensive debug logging configuration"""
    logger = logging.getLogger()
    
    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Set logging level based on debug mode
    logger.setLevel(logging.DEBUG if debug_mode else logging.INFO)
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - [%(name)s:%(funcName)s:%(lineno)d] - %(message)s'
    )
    
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # File handler for debug/info log
    file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
    file_handler.setLevel(logging.DEBUG if debug_mode else logging.INFO)
    file_handler.setFormatter(detailed_formatter if debug_mode else simple_formatter)
    logger.addHandler(file_handler)
    
    # Console handler - always INFO level for readability
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(simple_formatter)
    logger.addHandler(console_handler)
    
    if debug_mode:
        logger.info(f"🐛 DEBUG MODE ENABLED - Comprehensive logging to: {log_file}")
        logger.debug(f"🔍 Debug logging initialized with detailed formatting")
    
    return logger

def is_valid_domain_name(domain: str) -> bool:
    """Validate if a string is a valid domain name."""
    if not domain or len(domain) > 253:
        return False
    
    # Check for IP address
    try:
        ipaddress.ip_address(domain)
        return False  # It's an IP, not a domain
    except ValueError:
        pass
    
    # Check domain format
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    return bool(pattern.match(domain))

@dataclass
class ProviderInfo:
    """Enhanced provider information with confidence scoring."""
    name: str
    confidence: float
    source: str
    asn: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    provider_type: Optional[str] = None
    metadata: Optional[Dict] = None

@dataclass 
class EnhancedDomainInfo:
    """Enhanced domain information structure."""
    fqdn: str
    base_domain: str
    subdomain_parts: List[str]
    tld: str
    is_subdomain: bool
    
    @classmethod
    def from_fqdn(cls, fqdn: str, input_domains: Set[str] = None) -> 'EnhancedDomainInfo':
        """Create EnhancedDomainInfo from FQDN with enhanced parsing."""
        if not fqdn:
            return cls("", "", [], "", False)
        
        fqdn = fqdn.lower().strip()
        
        if HAS_TLDEXTRACT:
            extracted = tldextract.extract(fqdn)
            if extracted.suffix:
                base_domain = f"{extracted.domain}.{extracted.suffix}"
                subdomain_part = extracted.subdomain
                tld = extracted.suffix
            else:
                parts = fqdn.split('.')
                if len(parts) >= 2:
                    base_domain = f"{parts[-2]}.{parts[-1]}"
                    subdomain_part = '.'.join(parts[:-2]) if len(parts) > 2 else ""
                    tld = parts[-1]
                else:
                    return cls("", "", [], "", False)
        else:
            parts = fqdn.split('.')
            if len(parts) >= 2:
                base_domain = f"{parts[-2]}.{parts[-1]}" 
                subdomain_part = '.'.join(parts[:-2]) if len(parts) > 2 else ""
                tld = parts[-1]
            else:
                return cls("", "", [], "", False)
        
        subdomain_parts = subdomain_part.split('.') if subdomain_part else []
        subdomain_parts = [part for part in subdomain_parts if part]
        
        # Check if this is actually a subdomain
        is_subdomain = bool(subdomain_parts)
        
        # If input_domains provided, check if this is a known base domain
        if input_domains and fqdn in input_domains:
            is_subdomain = False
        
        return cls(
            fqdn=fqdn,
            base_domain=base_domain,
            subdomain_parts=subdomain_parts,
            tld=tld,
            is_subdomain=is_subdomain
        )

class EnhancedProviderResolver:
    """Enhanced provider resolution system with multiple fallback strategies."""
    
    def __init__(self, ipinfo_token: str = None):
        self.ipinfo_token = ipinfo_token
        self.ipinfo_handler = None
        self.mmdb_reader = None
        
        # Initialize IPInfo handler
        if ipinfo_token and HAS_IPINFO:
            try:
                self.ipinfo_handler = getHandler(ipinfo_token)
                logging.info("IPInfo handler initialized successfully")
            except Exception as e:
                logging.warning(f"Failed to initialize IPInfo handler: {e}")
        
        # Initialize MaxMind DB
        if HAS_MAXMINDDB:
            try:
                self.mmdb_reader = maxminddb.open_database(IPINFO_MMDB_PATH)
                logging.info("MaxMind database opened successfully")
            except Exception as e:
                logging.debug(f"MaxMind database not available: {e}")
        
        # Provider mapping for common cloud providers
        self.cloud_provider_patterns = {
            'amazon': ['amazon', 'aws', 'ec2', 'cloudfront'],
            'google': ['google', 'gcp', 'googleapis', 'googleusercontent'],
            'microsoft': ['microsoft', 'azure', 'outlook', 'live'],
            'cloudflare': ['cloudflare', 'cf-ipv4'],
            'digitalocean': ['digitalocean', 'do-user'],
            'vultr': ['vultr', 'choopa'],
            'linode': ['linode', 'akamai'],
            'ovh': ['ovh', 'ovhcloud'],
            'hetzner': ['hetzner', 'hetzner-online']
        }
        
        # ASN to provider mapping
        self.asn_provider_map = {
            '16509': 'amazon',
            '14618': 'amazon', 
            '15169': 'google',
            '8075': 'microsoft',
            '13335': 'cloudflare',
            '14061': 'digitalocean',
            '20473': 'vultr',
            '63949': 'linode',
            '16276': 'ovh',
            '24940': 'hetzner'
        }
    
    def resolve_provider_comprehensive(self, ip: str, fqdn: str = None) -> ProviderInfo:
        """
        Comprehensive provider resolution using multiple strategies.
        Returns provider info with confidence score.
        """
        providers_found = []
        
        # Strategy 1: IPInfo API
        if self.ipinfo_handler:
            provider = self._resolve_via_ipinfo(ip)
            if provider:
                providers_found.append(provider)
        
        # Strategy 2: MaxMind Database
        if self.mmdb_reader:
            provider = self._resolve_via_maxmind(ip)
            if provider:
                providers_found.append(provider)
        
        # Strategy 3: Reverse DNS
        provider = self._resolve_via_reverse_dns(ip)
        if provider:
            providers_found.append(provider)
        
        # Strategy 4: WHOIS (if domain provided)
        if fqdn and HAS_WHOIS:
            provider = self._resolve_via_whois(fqdn)
            if provider:
                providers_found.append(provider)
        
        # Strategy 5: ASN lookup
        provider = self._resolve_via_asn(ip)
        if provider:
            providers_found.append(provider)
        
        # Strategy 6: Hostname pattern analysis
        if fqdn:
            provider = self._resolve_via_hostname_patterns(fqdn)
            if provider:
                providers_found.append(provider)
        
        # Consolidate results
        if providers_found:
            return self._consolidate_provider_results(providers_found)
        else:
            return ProviderInfo(
                name="unknown",
                confidence=0.0,
                source="comprehensive_analysis",
                metadata={"ip": ip, "fqdn": fqdn, "strategies_tried": 6}
            )
    
    def _resolve_via_ipinfo(self, ip: str) -> Optional[ProviderInfo]:
        """Resolve provider using IPInfo API."""
        try:
            details = self.ipinfo_handler.getDetails(ip)
            
            org = getattr(details, 'org', '')
            asn = getattr(details, 'asn', {}).get('asn', '') if hasattr(details, 'asn') else ''
            country = getattr(details, 'country', '')
            region = getattr(details, 'region', '')
            
            # Extract provider from org field
            provider_name = self._extract_provider_from_org(org)
            
            return ProviderInfo(
                name=provider_name,
                confidence=0.9,
                source="ipinfo_api",
                asn=asn,
                org=org,
                country=country,
                region=region,
                metadata={"full_details": str(details)}
            )
        except Exception as e:
            logging.debug(f"IPInfo resolution failed for {ip}: {e}")
            return None
    
    def _resolve_via_maxmind(self, ip: str) -> Optional[ProviderInfo]:
        """Resolve provider using MaxMind database."""
        try:
            response = self.mmdb_reader.get(ip)
            if response:
                traits = response.get('traits', {})
                asn = traits.get('autonomous_system_number')
                org = traits.get('autonomous_system_organization', '')
                
                provider_name = self._extract_provider_from_org(org)
                
                return ProviderInfo(
                    name=provider_name,
                    confidence=0.8,
                    source="maxmind_db",
                    asn=str(asn) if asn else None,
                    org=org,
                    metadata=response
                )
        except Exception as e:
            logging.debug(f"MaxMind resolution failed for {ip}: {e}")
        return None
    
    def _resolve_via_reverse_dns(self, ip: str) -> Optional[ProviderInfo]:
        """Resolve provider using reverse DNS lookup."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            provider_name = self._extract_provider_from_hostname(hostname)
            
            if provider_name != "unknown":
                return ProviderInfo(
                    name=provider_name,
                    confidence=0.7,
                    source="reverse_dns",
                    metadata={"hostname": hostname}
                )
        except Exception as e:
            logging.debug(f"Reverse DNS failed for {ip}: {e}")
        return None
    
    def _resolve_via_whois(self, fqdn: str) -> Optional[ProviderInfo]:
        """Resolve provider using WHOIS data."""
        try:
            domain_info = whois.whois(fqdn)
            
            # Extract registrar and organization info
            registrar = domain_info.registrar if hasattr(domain_info, 'registrar') else ''
            org = domain_info.org if hasattr(domain_info, 'org') else ''
            
            provider_name = self._extract_provider_from_org(f"{registrar} {org}")
            
            if provider_name != "unknown":
                return ProviderInfo(
                    name=provider_name,
                    confidence=0.6,
                    source="whois",
                    metadata={"registrar": registrar, "org": org}
                )
        except Exception as e:
            logging.debug(f"WHOIS resolution failed for {fqdn}: {e}")
        return None
    
    def _resolve_via_asn(self, ip: str) -> Optional[ProviderInfo]:
        """Resolve provider using ASN mapping."""
        try:
            # Simple ASN lookup via DNS
            reversed_ip = '.'.join(reversed(ip.split('.')))
            asn_query = f"{reversed_ip}.origin.asn.cymru.com"
            
            result = dns.resolver.resolve(asn_query, 'TXT')
            asn_data = str(result[0]).strip('"')
            asn = asn_data.split()[0]
            
            if asn in self.asn_provider_map:
                provider_name = self.asn_provider_map[asn]
                return ProviderInfo(
                    name=provider_name,
                    confidence=0.8,
                    source="asn_mapping",
                    asn=asn,
                    metadata={"asn_data": asn_data}
                )
        except Exception as e:
            logging.debug(f"ASN resolution failed for {ip}: {e}")
        return None
    
    def _resolve_via_hostname_patterns(self, hostname: str) -> Optional[ProviderInfo]:
        """Resolve provider using hostname pattern analysis."""
        hostname_lower = hostname.lower()
        
        for provider, patterns in self.cloud_provider_patterns.items():
            for pattern in patterns:
                if pattern in hostname_lower:
                    return ProviderInfo(
                        name=provider,
                        confidence=0.6,
                        source="hostname_pattern",
                        metadata={"matched_pattern": pattern, "hostname": hostname}
                    )
        
        return None
    
    def _extract_provider_from_org(self, org: str) -> str:
        """Extract provider name from organization string."""
        if not org:
            return "unknown"
        
        org_lower = org.lower()
        
        # Check for cloud provider patterns
        for provider, patterns in self.cloud_provider_patterns.items():
            for pattern in patterns:
                if pattern in org_lower:
                    return provider
        
        # Extract company name from ASN org format
        if ' ' in org:
            parts = org.split()
            # Often the first part after AS number is the company
            for part in parts:
                if not part.startswith('AS') and len(part) > 2:
                    return part.lower()
        
        return "unknown"
    
    def _extract_provider_from_hostname(self, hostname: str) -> str:
        """Extract provider from hostname."""
        return self._extract_provider_from_org(hostname)
    
    def _consolidate_provider_results(self, providers: List[ProviderInfo]) -> ProviderInfo:
        """Consolidate multiple provider results into best match."""
        if not providers:
            return ProviderInfo("unknown", 0.0, "none")
        
        # Group by provider name
        provider_groups = defaultdict(list)
        for provider in providers:
            provider_groups[provider.name].append(provider)
        
        # Calculate weighted confidence for each provider
        best_provider = None
        best_score = 0
        
        for provider_name, provider_list in provider_groups.items():
            if provider_name == "unknown":
                continue
                
            # Calculate weighted average confidence
            total_confidence = sum(p.confidence for p in provider_list)
            count = len(provider_list)
            avg_confidence = total_confidence / count
            
            # Bonus for multiple sources agreeing
            source_bonus = min(count * 0.1, 0.3)
            final_score = min(avg_confidence + source_bonus, 1.0)
            
            if final_score > best_score:
                best_score = final_score
                # Use the highest confidence source for metadata
                best_source = max(provider_list, key=lambda p: p.confidence)
                best_provider = ProviderInfo(
                    name=provider_name,
                    confidence=final_score,
                    source=f"consolidated({len(provider_list)}_sources)",
                    asn=best_source.asn,
                    org=best_source.org,
                    country=best_source.country,
                    region=best_source.region,
                    metadata={
                        "sources": [p.source for p in provider_list],
                        "individual_confidences": [p.confidence for p in provider_list]
                    }
                )
        
        return best_provider or providers[0]  # Fallback to first result

class EnhancedSubdomainGraphIngester:
    """Enhanced subdomain graph ingester with comprehensive analysis capabilities."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str, ipinfo_token: str = None,
                 enable_tls_analysis: bool = False, enable_service_detection: bool = True, 
                 enable_provider_detection: bool = True, enable_industry_classification: bool = True,
                 enable_risk_calculation: bool = True, max_analysis_workers: int = 4, 
                 tls_timeout: int = 30, tls_retries: int = 2):
        
        self.drv = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
        self.ipinfo_token = ipinfo_token
        self.enable_tls_analysis = enable_tls_analysis
        self.tls_timeout = tls_timeout
        self.tls_retries = tls_retries
        self.enable_service_detection = enable_service_detection
        self.enable_provider_detection = enable_provider_detection
        self.enable_industry_classification = enable_industry_classification
        self.enable_risk_calculation = enable_risk_calculation
        self.max_analysis_workers = max_analysis_workers
        
        # Initialize enhanced provider resolver
        self.provider_resolver = EnhancedProviderResolver(ipinfo_token)
        
        # Initialize industry classifier if enabled
        self.industry_classifier = None
        if self.enable_industry_classification and HAS_INDUSTRY_CLASSIFIER:
            try:
                self.industry_classifier = IndustryClassifier()
                logging.info("Industry classifier initialized")
            except Exception as e:
                logging.warning(f"Failed to initialize industry classifier: {e}")
                self.enable_industry_classification = False
        
        # Initialize risk calculator if enabled
        self.risk_calculator = None
        if self.enable_risk_calculation and HAS_RISK_CALCULATOR:
            try:
                self.risk_calculator = DomainRiskCalculator(neo4j_uri, neo4j_user, neo4j_pass, ipinfo_token)
                logging.info("Domain risk calculator initialized")
            except Exception as e:
                logging.warning(f"Failed to initialize risk calculator: {e}")
                self.enable_risk_calculation = False
        
        self.input_domains = set()
        
        tls_status = "with TLS analysis" if self.enable_tls_analysis else "without TLS analysis (use --enable-tls to activate)"
        logging.info(f"Enhanced Subdomain Graph Ingester v4.0 initialized with comprehensive analysis {tls_status}")
        
        # Verify dependencies
        self._check_dependencies()
    
    def _check_dependencies(self):
        """Check for missing dependencies and log warnings."""
        missing_modules = []
        
        if not HAS_NEO4J:
            missing_modules.append("neo4j")
        if self.enable_industry_classification and not HAS_INDUSTRY_CLASSIFIER:
            logging.warning("Industry classifier not available, industry classification disabled")
            self.enable_industry_classification = False
            missing_modules.append("industry_classifier")
        if not HAS_IPINFO:
            missing_modules.append("ipinfo")
        if not HAS_MAXMINDDB:
            missing_modules.append("maxminddb")
        if not HAS_WHOIS:
            missing_modules.append("whois")
        
        if missing_modules:
            logging.warning(f"Optional modules not available: {', '.join(missing_modules)}")
    
    def set_input_domains(self, domains: List[str]):
        """Set input domains for base domain detection."""
        self.input_domains = set(domains)
    
    def setup_constraints(self):
        """Setup Neo4j constraints for the enhanced graph model."""
        constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Domain) REQUIRE d.fqdn IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (s:Subdomain) REQUIRE s.fqdn IS UNIQUE", 
            "CREATE CONSTRAINT IF NOT EXISTS FOR (p:Provider) REQUIRE p.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (srv:Service) REQUIRE srv.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (c:Certificate) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (ip:IPAddress) REQUIRE ip.address IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (r:Risk) REQUIRE r.risk_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (i:Industry) REQUIRE i.name IS UNIQUE"
        ]
        
        with self.drv.session() as session:
            for constraint in constraints:
                try:
                    session.run(constraint)
                except Exception as e:
                    logging.debug(f"Constraint creation result: {e}")

    def analyze_subdomain_tls(self, fqdn: str) -> Optional[Dict[str, Any]]:
        """Analyze TLS certificate for a subdomain with enhanced grading and retry logic."""
        if not self.enable_tls_analysis:
            logging.debug(f"🔒 TLS analysis disabled for {fqdn} (use --enable-tls to activate)")
            return None
        
        logging.debug(f"Starting TLS analysis for {fqdn} (timeout: {self.tls_timeout}s, retries: {self.tls_retries})")
        
        last_error = None
        for attempt in range(self.tls_retries + 1):
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                logging.debug(f"🔒 TLS attempt {attempt + 1}/{self.tls_retries + 1} for {fqdn} (timeout: {self.tls_timeout}s)")
                
                with socket.create_connection((fqdn, 443), timeout=self.tls_timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=fqdn) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        
                        # Parse certificate data
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                        expires_in_days = (not_after - datetime.now()).days
                        
                        # Calculate TLS grade using enhanced algorithm
                        tls_grade = self._calculate_enhanced_tls_grade(cert, cipher, expires_in_days)
                        
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
                            'key_exchange': cipher[2] if cipher else None,
                            'san_domains': self._extract_san_domains(cert)
                        }
                        
            except Exception as e:
                last_error = e
                logging.debug(f"🔒 TLS attempt {attempt + 1} failed for {fqdn}: {e}")
                if attempt < self.tls_retries:
                    time.sleep(1)  # Wait 1 second before retry
                continue
        
        # All retries failed
        logging.warning(f"⚠️ TLS analysis failed for {fqdn} after {self.tls_retries + 1} attempts: {last_error}")
        return {
            'has_tls': False,
            'tls_grade': 'F',
            'error': str(last_error)
        }
    
    def _calculate_enhanced_tls_grade(self, cert: Dict, cipher: tuple, expires_in_days: int) -> str:
        """Calculate TLS grade with enhanced scoring algorithm."""
        score = 100
        
        # Certificate expiration check
        if expires_in_days < 0:
            return 'F'  # Expired certificate
        elif expires_in_days < 30:
            score -= 20  # Expiring soon
        elif expires_in_days < 90:
            score -= 10  # Expiring relatively soon
        
        # Self-signed certificate check
        if cert.get('issuer') == cert.get('subject'):
            score -= 40  # Self-signed
        
        # TLS version check
        if cipher and len(cipher) > 1:
            tls_version = cipher[1]
            if 'TLSv1.3' in tls_version:
                score += 5  # Bonus for TLS 1.3
            elif 'TLSv1.2' in tls_version:
                pass  # Standard for TLS 1.2
            elif 'TLSv1.1' in tls_version or 'TLSv1' in tls_version:
                score -= 30  # Penalty for old TLS
            elif 'SSLv' in tls_version:
                score -= 50  # Major penalty for SSL
        
        # Cipher suite strength
        if cipher and len(cipher) > 0:
            cipher_name = cipher[0].upper()
            if 'AES256' in cipher_name or 'CHACHA20' in cipher_name:
                pass  # Good encryption
            elif 'AES128' in cipher_name:
                score -= 5  # Slightly weaker
            elif 'RC4' in cipher_name or 'DES' in cipher_name:
                score -= 40  # Weak encryption
        
        # Key size check (if available)
        public_key = cert.get('subjectPublicKeyInfo', {})
        # This would require more detailed certificate parsing
        
        # Convert score to letter grade
        if score >= 95:
            return 'A+'
        elif score >= 90:
            return 'A'
        elif score >= 85:
            return 'A-'
        elif score >= 80:
            return 'B+'
        elif score >= 75:
            return 'B'
        elif score >= 70:
            return 'B-'
        elif score >= 65:
            return 'C+'
        elif score >= 60:
            return 'C'
        elif score >= 55:
            return 'C-'
        elif score >= 50:
            return 'D'
        else:
            return 'F'
    
    def _extract_san_domains(self, cert: Dict) -> List[str]:
        """Extract Subject Alternative Name domains from certificate."""
        san_domains = []
        try:
            for ext in cert.get('extensions', []):
                if ext[0] == 'subjectAltName':
                    for entry in ext[1]:
                        if entry[0] == 'DNS':
                            san_domains.append(entry[1])
        except Exception as e:
            logging.debug(f"Failed to extract SAN domains: {e}")
        return san_domains
    
    def analyze_subdomain_dns(self, fqdn: str) -> Dict[str, Any]:
        """Analyze DNS records for a subdomain."""
        dns_info = {
            'a_records': [],
            'aaaa_records': [],
            'cname_records': [],
            'mx_records': [],
            'txt_records': [],
            'ns_records': []
        }
        
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
        
        for record_type in record_types:
            try:
                answers = RESOLVER.resolve(fqdn, record_type)
                records = [str(answer) for answer in answers]
                
                if record_type == 'A':
                    dns_info['a_records'] = records
                elif record_type == 'AAAA':
                    dns_info['aaaa_records'] = records
                elif record_type == 'CNAME':
                    dns_info['cname_records'] = records
                elif record_type == 'MX':
                    dns_info['mx_records'] = records
                elif record_type == 'TXT':
                    dns_info['txt_records'] = records
                elif record_type == 'NS':
                    dns_info['ns_records'] = records
                    
            except dns.exception.DNSException:
                pass  # Record type doesn't exist
            except Exception as e:
                logging.debug(f"DNS lookup failed for {fqdn} {record_type}: {e}")
        
        return dns_info
    
    def detect_enhanced_services_and_providers(self, fqdn: str, ip_addresses: List[str]) -> Tuple[List[Dict], List[Dict]]:
        """Enhanced service and provider detection with comprehensive analysis."""
        services = []
        providers = []
        
        if not self.enable_service_detection and not self.enable_provider_detection:
            return services, providers
        
        # Enhanced service detection
        if self.enable_service_detection:
            services.extend(self._detect_services_by_pattern(fqdn))
            services.extend(self._detect_services_by_ports(fqdn, ip_addresses))
            services.extend(self._detect_services_by_dns(fqdn))
        
        # Enhanced provider detection
        if self.enable_provider_detection:
            providers.extend(self._detect_providers_comprehensive(ip_addresses, fqdn))
        
        return services, providers
    
    def _detect_services_by_pattern(self, fqdn: str) -> List[Dict[str, Any]]:
        """Detect services based on subdomain patterns."""
        services = []
        
        service_patterns = {
            'web': ['www', 'web', 'site', 'portal'],
            'api': ['api', 'rest', 'graphql', 'service'],
            'mail': ['mail', 'email', 'smtp', 'imap', 'pop3', 'webmail'],
            'database': ['db', 'database', 'sql', 'mongo', 'redis'],
            'cdn': ['cdn', 'static', 'assets', 'img', 'images'],
            'auth': ['auth', 'sso', 'login', 'oauth', 'identity'],
            'admin': ['admin', 'manage', 'control', 'panel'],
            'monitoring': ['monitor', 'metrics', 'logs', 'health'],
            'storage': ['storage', 'files', 'upload', 's3'],
            'vpn': ['vpn', 'tunnel', 'proxy'],
            'test': ['test', 'staging', 'dev', 'qa', 'beta'],
        }
        
        fqdn_parts = fqdn.lower().split('.')
        
        for service_type, patterns in service_patterns.items():
            for pattern in patterns:
                for part in fqdn_parts:
                    if pattern in part:
                        services.append({
                            'name': f"{service_type}_service",
                            'type': service_type,
                            'detection_method': 'pattern_analysis',
                            'confidence': 0.7,
                            'source': 'subdomain_pattern',
                            'metadata': {
                                'matched_pattern': pattern,
                                'subdomain_part': part,
                                'fqdn': fqdn
                            }
                        })
                        break
        
        return services
    
    def _detect_services_by_ports(self, fqdn: str, ip_addresses: List[str]) -> List[Dict[str, Any]]:
        """Detect services by port scanning (light scan)."""
        services = []
        
        # Common ports to check
        common_ports = {
            80: 'http',
            443: 'https', 
            21: 'ftp',
            22: 'ssh',
            25: 'smtp',
            53: 'dns',
            110: 'pop3',
            143: 'imap',
            993: 'imaps',
            995: 'pop3s',
            3306: 'mysql',
            5432: 'postgresql',
            6379: 'redis',
            27017: 'mongodb'
        }
        
        for ip in ip_addresses[:3]:  # Limit to first 3 IPs
            for port, service_name in common_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    
                    if result == 0:  # Port is open
                        services.append({
                            'name': f"{service_name}_service",
                            'type': service_name,
                            'detection_method': 'port_scan',
                            'confidence': 0.9,
                            'source': 'port_scan',
                            'metadata': {
                                'ip': ip,
                                'port': port,
                                'fqdn': fqdn
                            }
                        })
                except Exception as e:
                    logging.debug(f"Port scan failed for {ip}:{port}: {e}")
        
        return services
    
    def _detect_services_by_dns(self, fqdn: str) -> List[Dict[str, Any]]:
        """Detect services based on DNS records."""
        services = []
        
        try:
            # Check for MX records (mail service)
            mx_records = RESOLVER.resolve(fqdn, 'MX')
            if mx_records:
                services.append({
                    'name': 'mail_service',
                    'type': 'mail',
                    'detection_method': 'dns_analysis',
                    'confidence': 0.95,
                    'source': 'mx_record',
                    'metadata': {
                        'mx_records': [str(mx) for mx in mx_records]
                    }
                })
        except dns.exception.DNSException:
            pass
        
        try:
            # Check for TXT records (various services)
            txt_records = RESOLVER.resolve(fqdn, 'TXT')
            for txt in txt_records:
                txt_str = str(txt).lower()
                if 'spf' in txt_str or 'dmarc' in txt_str or 'dkim' in txt_str:
                    services.append({
                        'name': 'email_security_service',
                        'type': 'email_security',
                        'detection_method': 'dns_analysis',
                        'confidence': 0.9,
                        'source': 'txt_record',
                        'metadata': {
                            'txt_record': str(txt)
                        }
                    })
                elif 'google-site-verification' in txt_str:
                    services.append({
                        'name': 'google_verification',
                        'type': 'verification',
                        'detection_method': 'dns_analysis',
                        'confidence': 0.95,
                        'source': 'txt_record',
                        'metadata': {
                            'txt_record': str(txt)
                        }
                    })
        except dns.exception.DNSException:
            pass
        
        return services
    
    def _detect_providers_comprehensive(self, ip_addresses: List[str], fqdn: str) -> List[Dict[str, Any]]:
        """Comprehensive provider detection using enhanced resolver."""
        providers = []
        
        for ip in ip_addresses:
            try:
                provider_info = self.provider_resolver.resolve_provider_comprehensive(ip, fqdn)
                
                if provider_info and provider_info.name != "unknown":
                    providers.append({
                        'name': provider_info.name,
                        'confidence': provider_info.confidence,
                        'source': provider_info.source,
                        'asn': provider_info.asn,
                        'org': provider_info.org,
                        'country': provider_info.country,
                        'region': provider_info.region,
                        'provider_type': provider_info.provider_type or 'cloud',
                        'metadata': provider_info.metadata or {},
                        'ip': ip
                    })
                else:
                    # Even for unknown providers, collect all available metadata
                    providers.append({
                        'name': 'unknown',
                        'confidence': 0.0,
                        'source': 'comprehensive_analysis_failed',
                        'metadata': {
                            'ip': ip,
                            'fqdn': fqdn,
                            'analysis_timestamp': datetime.now().isoformat(),
                            'resolution_attempts': provider_info.metadata if provider_info else {}
                        }
                    })
                    
            except Exception as e:
                logging.debug(f"Provider detection failed for {ip}: {e}")
                providers.append({
                    'name': 'unknown',
                    'confidence': 0.0,
                    'source': 'detection_error',
                    'metadata': {
                        'ip': ip,
                        'error': str(e),
                        'analysis_timestamp': datetime.now().isoformat()
                    }
                })
        
        return providers
    
    def analyze_domain_industry(self, fqdn: str) -> Optional[Dict[str, Any]]:
        """Analyze domain industry classification."""
        if not self.enable_industry_classification or not self.industry_classifier:
            return None
        
        try:
            # Use base domain for classification
            domain_info = EnhancedDomainInfo.from_fqdn(fqdn, self.input_domains)
            domain_to_classify = domain_info.base_domain or fqdn
            
            # Classify industry
            classification = self.industry_classifier.classify_domain(domain_to_classify)
            
            return {
                'domain_classified': domain_to_classify,
                'primary_industry': classification.primary_industry,
                'secondary_industries': classification.secondary_industries,
                'confidence': classification.confidence,
                'keywords_found': classification.keywords_found,
                'description': classification.description,
                'source': 'industry_classifier'
            }
        except Exception as e:
            logging.debug(f"Industry classification failed for {fqdn}: {e}")
            return None
    
    def create_enhanced_domain_hierarchy_batch(self, domains: List[str], batch_size: int = 1) -> Dict[str, Any]:
        """Create enhanced domain hierarchy with comprehensive analysis and immediate writes."""
        total_processed = 0
        total_subdomains = 0
        total_services = 0
        total_providers = 0
        total_certificates = 0
        total_industries = 0
        
        start_time = time.time()
        self.set_input_domains(domains)
        
        logging.info(f"🚀 Starting enhanced domain hierarchy creation for {len(domains)} domains with IMMEDIATE WRITES")
        
        # Process each domain individually for immediate results
        for i, fqdn in enumerate(domains):
            domain_start_time = time.time()
            try:
                with self.drv.session() as session:
                    with session.begin_transaction() as tx:
                        logging.info(f"📊 Processing domain {i+1}/{len(domains)}: {fqdn}")
                        
                        results = self._create_enhanced_domain_hierarchy_single(fqdn, tx)
                        
                        # Log detailed results immediately
                        logging.info(f"✅ {fqdn} RESULTS: {results.get('subdomains', 0)} subdomains, "
                                   f"{results.get('services', 0)} services, {results.get('providers', 0)} providers, "
                                   f"{results.get('certificates', 0)} certificates, {results.get('industries', 0)} industries")
                        
                        tx.commit()
                        
                        # Update totals
                        total_subdomains += results.get('subdomains', 0)
                        total_services += results.get('services', 0)
                        total_providers += results.get('providers', 0)
                        total_certificates += results.get('certificates', 0)
                        total_industries += results.get('industries', 0)
                        total_processed += 1
                        
                        domain_duration = time.time() - domain_start_time
                        logging.info(f"⏱️ {fqdn} processed in {domain_duration:.2f}s - COMMITTED TO GRAPH")
                        
            except Exception as e:
                logging.error(f"❌ Failed to process {fqdn}: {e}")
            
            # Log running totals every 5 domains
            if (i + 1) % 5 == 0:
                elapsed = time.time() - start_time
                logging.info(f"🔄 PROGRESS UPDATE: {i+1}/{len(domains)} domains processed in {elapsed:.2f}s")
                logging.info(f"📈 RUNNING TOTALS: {total_subdomains} subdomains, {total_services} services, "
                           f"{total_providers} providers, {total_certificates} certificates written to graph")
        
        end_time = time.time()
        duration = end_time - start_time
        
        results = {
            'total_processed': total_processed,
            'total_subdomains': total_subdomains,
            'total_services': total_services,
            'total_providers': total_providers,
            'total_certificates': total_certificates,
            'total_industries': total_industries,
            'processing_time': duration,
            'domains_per_second': total_processed / duration if duration > 0 else 0
        }
        
        logging.info(f"Enhanced domain hierarchy creation completed: {results}")
        return results
    
    def analyze_existing_subdomains_batch(self, subdomains: List[str]) -> Dict[str, Any]:
        """Analyze existing subdomain nodes with comprehensive analysis."""
        total_processed = 0
        total_services = 0
        total_providers = 0
        total_certificates = 0
        total_industries = 0
        
        start_time = time.time()
        
        logging.info(f"🔍 Starting comprehensive analysis for {len(subdomains)} existing subdomains")
        
        # Process each subdomain individually for detailed analysis
        for i, fqdn in enumerate(subdomains):
            subdomain_start_time = time.time()
            try:
                with self.drv.session() as session:
                    with session.begin_transaction() as tx:
                        logging.info(f"🔍 Analyzing subdomain {i+1}/{len(subdomains)}: {fqdn}")
                        
                        # Verify subdomain exists
                        exists = tx.run("""
                            MATCH (s:Subdomain {fqdn: $fqdn})
                            RETURN s.fqdn as fqdn
                        """, fqdn=fqdn).single()
                        
                        if not exists:
                            logging.warning(f"⚠️ Subdomain {fqdn} not found in database, skipping")
                            continue
                        
                        # Perform comprehensive analysis
                        analysis_results = self._perform_enhanced_subdomain_analysis(fqdn, tx)
                        
                        # Update totals
                        total_services += analysis_results.get('services', 0)
                        total_providers += analysis_results.get('providers', 0)
                        total_certificates += analysis_results.get('certificates', 0)
                        total_industries += analysis_results.get('industries', 0)
                        total_processed += 1
                        
                        tx.commit()
                        
                        subdomain_duration = time.time() - subdomain_start_time
                        logging.info(f"✅ {fqdn} analysis completed in {subdomain_duration:.2f}s: "
                                   f"{analysis_results.get('services', 0)} services, "
                                   f"{analysis_results.get('providers', 0)} providers, "
                                   f"{analysis_results.get('certificates', 0)} certificates")
                        
            except Exception as e:
                logging.error(f"❌ Failed to analyze {fqdn}: {e}")
                logging.debug(f"🔍 Analysis exception for {fqdn}: {type(e).__name__}: {e}")
                continue
        
        end_time = time.time()
        duration = end_time - start_time
        
        results = {
            'total_processed': total_processed,
            'total_services': total_services,
            'total_providers': total_providers,
            'total_certificates': total_certificates,
            'total_industries': total_industries,
            'processing_time': duration,
            'subdomains_per_second': total_processed / duration if duration > 0 else 0
        }
        
        logging.info(f"🔍 Subdomain analysis completed: {results}")
        return results
    
    def _create_enhanced_domain_hierarchy_single(self, fqdn: str, tx) -> Dict[str, int]:
        """Create enhanced domain hierarchy for a single domain with comprehensive analysis."""
        results = {'subdomains': 0, 'services': 0, 'providers': 0, 'certificates': 0, 'industries': 0}
        
        # Skip processing if this is an IP address or invalid domain
        if not is_valid_domain_name(fqdn):
            logging.warning(f"⚠️ Skipping invalid domain/IP: {fqdn}")
            return results
        
        domain_info = EnhancedDomainInfo.from_fqdn(fqdn, self.input_domains)
        
        # Skip if domain info is empty (validation failed)
        if not domain_info.fqdn or not domain_info.base_domain:
            logging.warning(f"⚠️ Skipping domain due to validation failure: {fqdn}")
            return results
        
        current_time = datetime.now().isoformat()
        logging.info(f"🔍 Analyzing {fqdn}: is_subdomain={domain_info.is_subdomain}, base_domain={domain_info.base_domain}")
        
        if domain_info.is_subdomain:
            logging.info(f"📝 Creating SUBDOMAIN node for: {fqdn}")
            # Create subdomain node
            tx.run("""
                MERGE (s:Subdomain {fqdn: $fqdn})
                SET s.base_domain = $base_domain,
                    s.subdomain_parts = $subdomain_parts,
                    s.tld = $tld,
                    s.created_at = $created_at,
                    s.last_updated = $current_time,
                    s.processing_phase = true
            """, 
            fqdn=fqdn,
            base_domain=domain_info.base_domain,
            subdomain_parts=domain_info.subdomain_parts,
            tld=domain_info.tld,
            created_at=current_time,
            current_time=current_time)
            
            # Create relationship to base domain
            logging.info(f"🔗 Linking {fqdn} to base domain: {domain_info.base_domain}")
            tx.run("""
                MATCH (s:Subdomain {fqdn: $fqdn})
                MERGE (d:Domain {fqdn: $base_domain})
                ON CREATE SET d.created_at = $created_at
                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
            """,
            fqdn=fqdn,
            base_domain=domain_info.base_domain,
            created_at=current_time)
            
            results['subdomains'] = 1
            
            # Perform enhanced analysis for subdomain
            logging.info(f"🔬 Starting comprehensive analysis for subdomain: {fqdn}")
            analysis_results = self._perform_enhanced_subdomain_analysis(fqdn, tx)
            results.update(analysis_results)
            logging.info(f"🧪 Analysis complete for {fqdn}: {analysis_results}")
            
        else:
            # Check if this FQDN already exists as a Subdomain before creating Domain node
            existing_subdomain = tx.run("""
                MATCH (s:Subdomain {fqdn: $fqdn})
                RETURN s.fqdn as fqdn
                LIMIT 1
            """, fqdn=fqdn).single()
            
            if existing_subdomain:
                logging.info(f"⚠️ FQDN {fqdn} already exists as Subdomain node - skipping Domain creation")
                # Don't create Domain node, it should remain as Subdomain
                return results
            else:
                logging.info(f"📝 Creating DOMAIN node for: {fqdn}")
                # Create domain node
                tx.run("""
                    MERGE (d:Domain {fqdn: $fqdn})
                    SET d.tld = $tld,
                        d.created_at = $created_at,
                        d.last_updated = $current_time
                """,
                fqdn=fqdn,
                tld=domain_info.tld,
                created_at=current_time,
                current_time=current_time)
        
        return results
    
    def _perform_enhanced_subdomain_analysis(self, fqdn: str, tx) -> Dict[str, int]:
        """Perform comprehensive analysis for a subdomain."""
        results = {'services': 0, 'providers': 0, 'certificates': 0, 'industries': 0}
        current_time = datetime.now().isoformat()
        
        # Get IP addresses
        ip_addresses = []
        try:
            logging.info(f"🌐 Performing DNS analysis for {fqdn}")
            dns_info = self.analyze_subdomain_dns(fqdn)
            ip_addresses = dns_info.get('a_records', [])
            logging.info(f"🔍 DNS results for {fqdn}: {len(ip_addresses)} A records found: {ip_addresses}")
            
            # Store DNS info in the node for future reference
            if dns_info.get('cname_records'):
                logging.info(f"🔗 CNAME records for {fqdn}: {dns_info['cname_records']}")
            
            # Update subdomain node with DNS information
            tx.run("""
                MATCH (s:Subdomain {fqdn: $fqdn})
                SET s.dns_a_records = $a_records,
                    s.dns_aaaa_records = $aaaa_records,
                    s.dns_cname_records = $cname_records,
                    s.dns_mx_records = $mx_records,
                    s.dns_txt_records = $txt_records,
                    s.dns_ns_records = $ns_records,
                    s.dns_analyzed_at = $current_time
            """,
            fqdn=fqdn,
            a_records=dns_info.get('a_records', []),
            aaaa_records=dns_info.get('aaaa_records', []),
            cname_records=dns_info.get('cname_records', []),
            mx_records=dns_info.get('mx_records', []),
            txt_records=dns_info.get('txt_records', []),
            ns_records=dns_info.get('ns_records', []),
            current_time=current_time)
        except Exception as e:
            logging.warning(f"⚠️ DNS analysis failed for {fqdn}: {e}")
        
        # TLS Analysis
        if self.enable_tls_analysis:
            try:
                logging.info(f"🔒 Starting TLS analysis for {fqdn}")
                tls_info = self.analyze_subdomain_tls(fqdn)
                if tls_info and tls_info.get('has_tls'):
                    cert_id = f"{fqdn}_cert_{int(time.time())}"
                    logging.info(f"✅ TLS certificate found for {fqdn}: Grade {tls_info.get('tls_grade')}, expires in {tls_info.get('expires_in_days')} days")
                    
                    # Create certificate node
                    tx.run("""
                        MERGE (c:Certificate {id: $cert_id})
                        SET c.fqdn = $fqdn,
                            c.tls_grade = $tls_grade,
                            c.expires_in_days = $expires_in_days,
                            c.not_after = $not_after,
                            c.not_before = $not_before,
                            c.issuer = $issuer,
                            c.subject = $subject,
                            c.serial_number = $serial_number,
                            c.is_self_signed = $is_self_signed,
                            c.cipher_suite = $cipher_suite,
                            c.tls_version = $tls_version,
                            c.san_domains = $san_domains,
                            c.created_at = $current_time
                    """,
                    cert_id=cert_id,
                    fqdn=fqdn,
                    tls_grade=tls_info.get('tls_grade'),
                    expires_in_days=tls_info.get('expires_in_days'),
                    not_after=tls_info.get('not_after'),
                    not_before=tls_info.get('not_before'),
                    issuer=json.dumps(tls_info.get('issuer', {})),
                    subject=json.dumps(tls_info.get('subject', {})),
                    serial_number=tls_info.get('serial_number'),
                    is_self_signed=tls_info.get('is_self_signed'),
                    cipher_suite=tls_info.get('cipher_suite'),
                    tls_version=tls_info.get('tls_version'),
                    san_domains=tls_info.get('san_domains', []),
                    current_time=current_time)
                    
                    # Link certificate to subdomain
                    tx.run("""
                        MATCH (s:Subdomain {fqdn: $fqdn})
                        MATCH (c:Certificate {id: $cert_id})
                        MERGE (s)-[:SECURED_BY]->(c)
                    """, fqdn=fqdn, cert_id=cert_id)
                    
                    results['certificates'] = 1
            except Exception as e:
                logging.debug(f"TLS analysis failed for {fqdn}: {e}")
        
        # Enhanced Service and Provider Detection
        try:
            logging.info(f"🔧 Starting service and provider detection for {fqdn}")
            services, providers = self.detect_enhanced_services_and_providers(fqdn, ip_addresses)
            logging.info(f"🔧 Detection results for {fqdn}: {len(services)} services, {len(providers)} providers found")
            
            # Create service nodes
            for service in services:
                service_id = f"{fqdn}_{service['name']}_{int(time.time()*1000000)}"  # More unique timestamp
                logging.info(f"⚙️ Creating service node: {service['name']} ({service['type']}) with confidence {service['confidence']}")
                tx.run("""
                    MERGE (srv:Service {id: $service_id})
                    SET srv.name = $name,
                        srv.type = $type,
                        srv.detection_method = $detection_method,
                        srv.confidence = $confidence,
                        srv.source = $source,
                        srv.metadata = $metadata,
                        srv.fqdn = $fqdn,
                        srv.created_at = $current_time
                """,
                service_id=service_id,
                name=service['name'],
                type=service['type'],
                detection_method=service['detection_method'],
                confidence=service['confidence'],
                source=service['source'],
                metadata=json.dumps(service.get('metadata', {})),
                fqdn=fqdn,
                current_time=current_time)
                
                # Link service to subdomain
                tx.run("""
                    MATCH (s:Subdomain {fqdn: $fqdn})
                    MATCH (srv:Service {id: $service_id})
                    MERGE (s)-[:RUNS]->(srv)
                """, fqdn=fqdn, service_id=service_id)
                
                results['services'] += 1
            
            # Create enhanced provider nodes with comprehensive metadata
            for provider in providers:
                provider_id = f"{provider['name']}_{provider.get('ip', 'unknown')}_{int(time.time()*1000000)}"  # More unique timestamp
                logging.info(f"🏢 Creating provider node: {provider['name']} (confidence: {provider['confidence']}, source: {provider['source']})")
                tx.run("""
                    MERGE (p:Provider {id: $provider_id})
                    SET p.name = $name,
                        p.confidence = $confidence,
                        p.source = $source,
                        p.asn = $asn,
                        p.org = $org,
                        p.country = $country,
                        p.region = $region,
                        p.provider_type = $provider_type,
                        p.metadata = $metadata,
                        p.ip = $ip,
                        p.fqdn = $fqdn,
                        p.created_at = $current_time,
                        p.is_unknown = $is_unknown,
                        p.risk_tier = $risk_tier,
                        p.risk_score = $risk_score
                """,
                provider_id=provider_id,
                name=provider['name'],
                confidence=provider['confidence'],
                source=provider['source'],
                asn=provider.get('asn'),
                org=provider.get('org'),
                country=provider.get('country'),
                region=provider.get('region'),
                provider_type=provider.get('provider_type'),
                metadata=json.dumps(provider.get('metadata', {})),
                ip=provider.get('ip'),
                fqdn=fqdn,
                current_time=current_time,
                is_unknown=provider['name'] == 'unknown',
                risk_tier=self._calculate_provider_risk_tier(provider),
                risk_score=self._calculate_provider_risk_score(provider))
                
                # Link provider to subdomain
                tx.run("""
                    MATCH (s:Subdomain {fqdn: $fqdn})
                    MATCH (p:Provider {id: $provider_id})
                    MERGE (s)-[:USES_SERVICE]->(p)
                """, fqdn=fqdn, provider_id=provider_id)
                
                results['providers'] += 1
                
        except Exception as e:
            logging.debug(f"Service/Provider detection failed for {fqdn}: {e}")
        
        # Industry Analysis
        if self.enable_industry_classification:
            try:
                industry_info = self.analyze_domain_industry(fqdn)
                if industry_info:
                    industry_id = f"{industry_info['primary_industry']}_{int(time.time())}"
                    
                    # Create industry node
                    tx.run("""
                        MERGE (i:Industry {name: $industry_name})
                        SET i.description = $description,
                            i.category = $primary_industry,
                            i.confidence = $confidence,
                            i.source = $source,
                            i.keywords = $keywords,
                            i.secondary_industries = $secondary_industries,
                            i.created_at = $current_time
                    """,
                    industry_name=industry_info['primary_industry'],
                    description=industry_info['description'],
                    primary_industry=industry_info['primary_industry'],
                    confidence=industry_info['confidence'],
                    source=industry_info['source'],
                    keywords=industry_info['keywords_found'],
                    secondary_industries=industry_info['secondary_industries'],
                    current_time=current_time)
                    
                    # Link industry to subdomain
                    tx.run("""
                        MATCH (s:Subdomain {fqdn: $fqdn})
                        MATCH (i:Industry {name: $industry_name})
                        MERGE (s)-[:BELONGS_TO_INDUSTRY]->(i)
                        SET s.primary_industry = $primary_industry,
                            s.industry_confidence = $confidence
                    """,
                    fqdn=fqdn,
                    industry_name=industry_info['primary_industry'],
                    primary_industry=industry_info['primary_industry'],
                    confidence=industry_info['confidence'])
                    
                    results['industries'] = 1
            except Exception as e:
                logging.debug(f"Industry analysis failed for {fqdn}: {e}")
        
        # Risk Analysis
        if self.enable_risk_calculation and self.risk_calculator:
            try:
                logging.info(f"🔍 Starting risk analysis for {fqdn}")
                risks = self.risk_calculator.calculate_domain_risks(fqdn)
                if risks:
                    saved_risks = self.risk_calculator.save_risks_to_graph(risks)
                    logging.info(f"📊 Risk analysis for {fqdn}: {len(risks)} risks found, {saved_risks} saved")
                    results['risks'] = saved_risks
                else:
                    results['risks'] = 0
            except Exception as e:
                logging.debug(f"Risk analysis failed for {fqdn}: {e}")
                results['risks'] = 0
        
        return results
    
    def discover_cross_domain_relationships(self, batch_size: int = 100) -> Dict[str, Any]:
        """Discover relationships between domains and subdomains."""
        total_relationships = 0
        start_time = time.time()
        
        logging.info("Starting cross-domain relationship discovery")
        
        with self.drv.session() as session:
            # Get all domains and subdomains with their CNAME records
            result = session.run("""
                MATCH (n) WHERE n:Domain OR n:Subdomain
                RETURN n.fqdn as fqdn, 
                       COALESCE(n.dns_cname_records, []) as cnames
            """)
            
            relationships = []
            
            for record in result:
                fqdn = record["fqdn"]
                cnames = record["cnames"] if record["cnames"] else []
                
                # Analyze CNAME relationships
                for cname in cnames:
                    if cname and cname != fqdn:
                        # Clean CNAME record (remove trailing dots)
                        clean_cname = cname.rstrip('.')
                        relationships.append({
                            'source_fqdn': fqdn,
                            'target_fqdn': clean_cname,
                            'relationship_type': 'CNAME',
                            'confidence': 0.95,
                            'discovery_method': 'dns_analysis',
                            'metadata': {'record_type': 'CNAME', 'original_record': cname}
                        })
            
            logging.info(f"Found {len(relationships)} potential CNAME relationships to create")
            
            # Create relationships in batches
            if relationships:
                with session.begin_transaction() as tx:
                    for rel in relationships:
                        try:
                            # Try to create relationship if both nodes exist
                            result = tx.run("""
                                MATCH (n1 {fqdn: $source_fqdn})
                                WHERE n1:Domain OR n1:Subdomain
                                OPTIONAL MATCH (n2 {fqdn: $target_fqdn})
                                WHERE n2:Domain OR n2:Subdomain OR n2:RelatedDomain
                                WITH n1, n2, 
                                     CASE WHEN n2 IS NULL THEN 'target_not_found' ELSE 'both_found' END as status
                                FOREACH (ignored IN CASE WHEN status = 'both_found' THEN [1] ELSE [] END |
                                    MERGE (n1)-[r:RELATED_TO]->(n2)
                                    SET r.relationship_type = $rel_type,
                                        r.confidence = $confidence,
                                        r.discovery_method = $discovery_method,
                                        r.metadata = $metadata,
                                        r.created_at = $created_at
                                )
                                RETURN status
                            """, 
                            source_fqdn=rel['source_fqdn'],
                            target_fqdn=rel['target_fqdn'],
                            rel_type=rel['relationship_type'],
                            confidence=rel['confidence'],
                            discovery_method=rel['discovery_method'],
                            metadata=json.dumps(rel['metadata']),
                            created_at=datetime.now().isoformat())
                            
                            # Check if relationship was created
                            status_record = result.single()
                            if status_record and status_record['status'] == 'both_found':
                                total_relationships += 1
                                logging.debug(f"Created CNAME relationship: {rel['source_fqdn']} -> {rel['target_fqdn']}")
                            else:
                                logging.debug(f"CNAME target not in graph: {rel['source_fqdn']} -> {rel['target_fqdn']}")
                                
                        except Exception as e:
                            logging.debug(f"Error creating relationship {rel['source_fqdn']} -> {rel['target_fqdn']}: {e}")
                    
                    tx.commit()
            else:
                logging.info("No CNAME relationships found to create")
        
        end_time = time.time()
        duration = end_time - start_time
        
        results = {
            'total_relationships': total_relationships,
            'processing_time': duration
        }
        
        if total_relationships > 0:
            logging.info(f"Cross-domain relationship discovery completed: {results}")
        else:
            logging.info(f"Cross-domain relationship discovery completed: No relationships created (this is normal if no CNAME records point to known domains)")
            logging.debug(f"Full results: {results}")
        return results
    
    def _calculate_provider_risk_tier(self, provider: Dict[str, Any]) -> str:
        """Calculate risk tier for a provider based on its characteristics."""
        name = provider.get('name', '').lower()
        confidence = provider.get('confidence', 0.0)
        is_unknown = provider.get('name') == 'unknown'
        
        # Unknown providers are high risk
        if is_unknown or name == 'unknown':
            return 'High'
        
        # Well-known cloud providers with high confidence are low risk
        major_providers = ['amazon', 'google', 'microsoft', 'azure', 'aws', 'cloudflare', 'akamai']
        if any(major in name for major in major_providers) and confidence > 0.8:
            return 'Low'
        
        # Regional or smaller providers with good confidence are medium risk
        if confidence > 0.7:
            return 'Medium'
        
        # Low confidence providers are high risk
        if confidence < 0.5:
            return 'High'
        
        return 'Medium'
    
    def _calculate_provider_risk_score(self, provider: Dict[str, Any]) -> float:
        """Calculate numerical risk score for a provider (0.0 = lowest risk, 10.0 = highest risk)."""
        name = provider.get('name', '').lower()
        confidence = provider.get('confidence', 0.0)
        is_unknown = provider.get('name') == 'unknown'
        
        # Start with base score
        base_score = 5.0
        
        # Unknown providers get high score
        if is_unknown or name == 'unknown':
            return 8.5
        
        # Adjust based on provider reputation
        major_providers = ['amazon', 'google', 'microsoft', 'azure', 'aws', 'cloudflare', 'akamai']
        if any(major in name for major in major_providers):
            base_score = 2.0  # Major providers are low risk
        
        # Adjust based on confidence (invert - low confidence = high risk)
        confidence_penalty = (1.0 - confidence) * 4.0
        
        final_score = base_score + confidence_penalty
        
        # Clamp between 0.0 and 10.0
        return max(0.0, min(10.0, final_score))

    def close(self):
        """Close database connection and cleanup resources."""
        if self.drv:
            self.drv.close()
        if hasattr(self.provider_resolver, 'mmdb_reader') and self.provider_resolver.mmdb_reader:
            self.provider_resolver.mmdb_reader.close()


# Integration with v2.0 discovery system
def run_amass_discovery_with_relationships(domain: str, timeout: int = 60, mock_mode: bool = False, 
                                         sample_mode: bool = False, amass_timeout: int = None, 
                                         amass_passive: bool = None, cache_ttl_hours: int = 168,
                                         discovery_depth: int = 2, logger=None) -> List[str]:
    """Run Amass for subdomain discovery with enhanced relationship detection."""
    
    if logger:
        logger.info(f"🔍 Starting Amass discovery for domain: {domain}")
        logger.debug(f"📋 Discovery parameters: mock_mode={mock_mode}, sample_mode={sample_mode}, ")
        logger.debug(f"   amass_timeout={amass_timeout}, amass_passive={amass_passive}")
        logger.debug(f"   cache_ttl_hours={cache_ttl_hours}, discovery_depth={discovery_depth}")
    
    # Mock mode for testing
    if mock_mode:
        mock_subdomains = [
            f"www.{domain}",
            f"mail.{domain}",
            f"api.{domain}",
            f"admin.{domain}",
            f"cdn.{domain}",
            f"app.{domain}",
            # Enhanced mock subdomains for v4.0
            f"secure.mail.{domain}",
            f"dev.api.{domain}",
            f"staging.app.{domain}",
            f"auth.{domain}",
            f"monitor.{domain}"
        ]
        msg = f"[DISCOVERY] MOCK MODE: Found {len(mock_subdomains)} subdomains for {domain}"
        print(msg)
        if logger:
            logger.info(msg)
            logger.debug(f"🎭 Mock subdomains: {mock_subdomains}")
        return mock_subdomains
    
    try:
        if logger:
            logger.debug(f"🚀 Starting enhanced multi-level Amass discovery for {domain}")
        # Use enhanced multi-level discovery with configurable parameters
        results = run_enhanced_amass_multilevel(domain, sample_mode=sample_mode, 
                                               amass_timeout=amass_timeout, 
                                               amass_passive=amass_passive,
                                               cache_ttl_hours=cache_ttl_hours,
                                               discovery_depth=discovery_depth,
                                               logger=logger)
        
        # Extract subdomain names, filtering correctly for the input domain
        subdomains = []
        related_domains = []
        
        for result in results:
            subdomain = result.get('name') if isinstance(result, dict) else result
            
            if subdomain and subdomain != domain:
                # Check if this is actually a subdomain of the input domain
                if subdomain.endswith('.' + domain):
                    # This is a valid subdomain
                    subdomains.append(subdomain)
                else:
                    # This is a related domain found during discovery but not a subdomain
                    # Log the source of this relationship for debugging
                    if logger:
                        # Determine likely source of relationship
                        source_hint = "unknown"
                        if "dns" in subdomain.lower() or "ns" in subdomain.lower():
                            source_hint = "dns_server"
                        elif "cdn" in subdomain.lower() or "cloudflare" in subdomain.lower():
                            source_hint = "cdn_service"
                        elif "imperva" in subdomain.lower() or "security" in subdomain.lower():
                            source_hint = "security_service"
                        elif ".amazonaws.com" in subdomain or ".azurewebsites.net" in subdomain:
                            source_hint = "cloud_service"
                        
                        logger.debug(f"🔍 Related domain found: {subdomain} (likely source: {source_hint}) for domain {domain}")
                    related_domains.append(subdomain)
                    
        msg1 = f"[DISCOVERY] Found {len(subdomains)} valid subdomains and {len(related_domains)} related domains for {domain}"
        print(msg1)
        if logger:
            logger.info(msg1)
            
        if len(related_domains) > 0:
            msg2 = f"[DISCOVERY] Related domains (not subdomains): {related_domains[:5]}{'...' if len(related_domains) > 5 else ''}"
            print(msg2)
            if logger:
                logger.debug(f"📋 All related domains: {related_domains}")
        
        msg3 = f"[DISCOVERY] Found {len(subdomains)} subdomains for {domain} (excluding base domain)"
        print(msg3)
        if logger:
            logger.info(msg3)
            logger.debug(f"📋 Valid subdomains found: {subdomains[:10]}{'...' if len(subdomains) > 10 else ''}")
            
        if len(subdomains) == 0:
            warning_msg = f"[DISCOVERY] WARNING: No subdomains found for {domain}"
            print(warning_msg)
            if logger:
                logger.warning(warning_msg)
        
        return subdomains
        
    except ImportError as e:
        error_msg = f"[DISCOVERY] Cannot import Amass functions, skipping {domain}"
        print(error_msg)
        if logger:
            logger.error(f"{error_msg}: {e}")
        return []
    except Exception as e:
        error_msg = f"[DISCOVERY] Error discovering subdomains for {domain}: {e}"
        print(error_msg)
        if logger:
            logger.error(error_msg)
            logger.debug(f"🔍 Discovery exception details: {type(e).__name__}: {e}")
        return []


def run_enhanced_amass_multilevel(domain: str, sample_mode: bool = False, amass_timeout: int = None, 
                                  amass_passive: bool = None, cache_ttl_hours: int = 168,
                                  discovery_depth: int = 2, logger=None) -> List[dict]:
    """Enhanced Amass discovery with multi-level subdomain support."""
    if logger:
        logger.debug(f"🎯 Enhanced multi-level Amass starting for {domain}")
        logger.debug(f"📊 Parameters: sample_mode={sample_mode}, discovery_depth={discovery_depth}")
    try:
        from risk_loader_advanced3 import run_amass_with_fallback
        
        msg = f"[DISCOVERY] Starting enhanced multi-level Amass for {domain} (sample_mode={sample_mode})"
        print(msg)
        if logger:
            logger.info(msg)
        
        # First pass: Standard discovery with configurable parameters and fallbacks
        if logger:
            logger.debug(f"🔍 First pass: Standard discovery starting for {domain}")
        results = run_amass_with_fallback(domain, sample_mode=sample_mode, amass_timeout=amass_timeout, 
                                         amass_passive=amass_passive, cache_ttl_hours=cache_ttl_hours)
        if logger:
            logger.debug(f"📊 First pass raw results count: {len(results) if results else 0}")
        all_subdomains = set()
        
        # Extract first-level subdomains
        for result in results:
            subdomain = result.get('name') if isinstance(result, dict) else result
            if subdomain and subdomain != domain:
                all_subdomains.add(subdomain)
        
        msg = f"[DISCOVERY] First pass: Found {len(all_subdomains)} first-level subdomains"
        print(msg)
        if logger:
            logger.info(msg)
            logger.debug(f"📋 First-level subdomains: {list(all_subdomains)[:10]}{'...' if len(all_subdomains) > 10 else ''}")
        
        # Multi-level discovery: Discover subdomains of subdomains (if not in sample mode)
        if not sample_mode and all_subdomains and discovery_depth > 1:
            if logger:
                logger.info(f"🔄 Starting multi-level discovery (depth={discovery_depth})")
            total_additional = 0
            
            for level in range(2, discovery_depth + 1):
                level_count = 0
                # Get ALL subdomains to analyze at this level (no limit)
                current_level_subdomains = list(all_subdomains)
                
                msg = f"[DISCOVERY] Level {level} pass: Analyzing ALL {len(current_level_subdomains)} subdomains for level-{level} discovery"
                print(msg)
                if logger:
                    logger.info(msg)
                
                for subdomain in current_level_subdomains:
                    try:
                        if logger:
                            logger.debug(f"🔍 Level {level}: Analyzing subdomain {subdomain}")
                        # Quick discovery for each subdomain with configurable parameters and fallbacks
                        sub_results = run_amass_with_fallback(subdomain, sample_mode=True, amass_timeout=amass_timeout, 
                                                             amass_passive=amass_passive, cache_ttl_hours=cache_ttl_hours)
                        if logger:
                            logger.debug(f"📊 Level {level}: {subdomain} returned {len(sub_results) if sub_results else 0} results")
                        
                        for sub_result in sub_results:
                            sub_subdomain = sub_result.get('name') if isinstance(sub_result, dict) else sub_result
                            if sub_subdomain and sub_subdomain not in all_subdomains and sub_subdomain != subdomain:
                                all_subdomains.add(sub_subdomain)
                                level_count += 1
                                
                    except Exception as e:
                        error_msg = f"[DISCOVERY] Error in level-{level} discovery for {subdomain}: {e}"
                        print(error_msg)
                        if logger:
                            logger.debug(error_msg)
                        continue
                
                msg = f"[DISCOVERY] Level {level} pass: Found {level_count} additional subdomains"
                print(msg)
                if logger:
                    logger.info(msg)
                total_additional += level_count
                
                # If no new subdomains found at this level, stop going deeper
                if level_count == 0:
                    stop_msg = f"[DISCOVERY] No new subdomains found at level {level}, stopping discovery"
                    print(stop_msg)
                    if logger:
                        logger.info(stop_msg)
                    break
            
            msg = f"[DISCOVERY] Multi-level discovery: Found {total_additional} additional subdomains across {discovery_depth - 1} levels"
            print(msg)
            if logger:
                logger.info(msg)
        
        # Convert back to dict format for compatibility
        final_results = [{'name': subdomain} for subdomain in all_subdomains]
        msg = f"[DISCOVERY] Enhanced discovery completed: {len(final_results)} total subdomains"
        print(msg)
        if logger:
            logger.info(msg)
            logger.debug(f"📋 Final subdomain list: {[r['name'] for r in final_results[:10]]}{'...' if len(final_results) > 10 else ''}")
        
        return final_results
        
    except ImportError as e:
        error_msg = f"[DISCOVERY] Cannot import run_amass_with_fallback, falling back to basic discovery"
        print(error_msg)
        if logger:
            logger.error(f"{error_msg}: {e}")
        return []
    except Exception as e:
        error_msg = f"[DISCOVERY] Error in enhanced multi-level discovery: {e}"
        print(error_msg)
        if logger:
            logger.error(error_msg)
            logger.debug(f"🔍 Multi-level discovery exception: {type(e).__name__}: {e}")
        return []


class EnhancedSubdomainProcessor:
    """Enhanced subdomain processor combining discovery and analysis capabilities."""
    
    def __init__(self, ingester: EnhancedSubdomainGraphIngester, neo4j_uri: str, neo4j_user: str, 
                 neo4j_pass: str, discovery_workers: int = 6, processing_workers: int = 4,
                 mock_mode: bool = False, sample_mode: bool = False, amass_timeout: int = None,
                 amass_passive: bool = None, cache_ttl_hours: int = 168, no_cache: bool = False,
                 discovery_depth: int = 2, logger=None, store_related_domains: bool = True):
        
        self.ingester = ingester
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_pass = neo4j_pass
        self.discovery_workers = discovery_workers
        self.processing_workers = processing_workers
        self.mock_mode = mock_mode
        self.sample_mode = sample_mode
        self.amass_timeout = amass_timeout
        self.amass_passive = amass_passive
        self.cache_ttl_hours = cache_ttl_hours
        self.no_cache = no_cache
        self.discovery_depth = discovery_depth
        self.logger = logger
        self.store_related_domains = store_related_domains
        
        msg = f"Enhanced Subdomain Processor v4.0 initialized with {discovery_workers} discovery workers and {processing_workers} processing workers"
        logging.info(msg)
        if self.logger:
            self.logger.info(f"🚀 {msg}")
            self.logger.info(f"📋 Related domains storage: {'ENABLED' if self.store_related_domains else 'DISABLED'}")
    
    def enhanced_phase1_discovery(self, domains: List[str]) -> Dict[str, Any]:
        """Phase 1: Enhanced subdomain discovery using Amass."""
        start_time = time.time()
        total_subdomains_discovered = 0
        failed_domains = []
        
        msg = f"Starting Phase 1: Enhanced subdomain discovery for {len(domains)} domains"
        logging.info(msg)
        if self.logger:
            self.logger.info(f"🔍 {msg}")
        
        # Setup input domains for the ingester
        self.ingester.set_input_domains(domains)
        
        with ThreadPoolExecutor(max_workers=self.discovery_workers) as executor:
            # Submit discovery tasks
            future_to_domain = {
                executor.submit(
                    run_amass_discovery_with_relationships,
                    domain,
                    mock_mode=self.mock_mode,
                    sample_mode=self.sample_mode,
                    amass_timeout=self.amass_timeout,
                    amass_passive=self.amass_passive,
                    cache_ttl_hours=self.cache_ttl_hours,
                    discovery_depth=self.discovery_depth,
                    logger=self.logger
                ): domain for domain in domains
            }
            
            # Process results as they complete
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    subdomains = future.result()
                    if subdomains:
                        # Store discovered subdomains in Neo4j
                        self._store_discovered_subdomains(domain, subdomains)
                        total_subdomains_discovered += len(subdomains)
                        msg = f"Discovered {len(subdomains)} subdomains for {domain}"
                        logging.info(msg)
                        if self.logger:
                            self.logger.info(f"🔍 {msg}")
                    else:
                        msg = f"No subdomains discovered for {domain}"
                        logging.warning(msg)
                        if self.logger:
                            self.logger.warning(f"⚠️ {msg}")
                        failed_domains.append(domain)
                        
                except Exception as e:
                    msg = f"Discovery failed for {domain}: {e}"
                    logging.error(msg)
                    if self.logger:
                        self.logger.error(f"❌ {msg}")
                        self.logger.debug(f"🔍 Discovery exception for {domain}: {type(e).__name__}: {e}")
                    failed_domains.append(domain)
        
        end_time = time.time()
        duration = end_time - start_time
        
        results = {
            'phase': 'discovery',
            'domains_processed': len(domains),
            'total_subdomains_discovered': total_subdomains_discovered,
            'failed_domains': failed_domains,
            'processing_time': duration,
            'domains_per_second': len(domains) / duration if duration > 0 else 0
        }
        
        msg = f"Phase 1 completed: {results}"
        logging.info(msg)
        if self.logger:
            self.logger.info(f"✅ {msg}")
        return results
    
    def _store_discovered_subdomains(self, domain: str, subdomains: List[str]):
        """Store discovered subdomains in Neo4j."""
        current_time = datetime.now().isoformat()
        
        with self.ingester.drv.session() as session:
            with session.begin_transaction() as tx:
                # Ensure base domain exists
                tx.run("""
                    MERGE (d:Domain {fqdn: $domain})
                    SET d.created_at = COALESCE(d.created_at, $current_time),
                        d.last_updated = $current_time,
                        d.discovery_completed = true
                """, domain=domain, current_time=current_time)
                
                # Create subdomain nodes and relationships
                valid_subdomains = 0
                related_domains = 0
                
                for subdomain in subdomains:
                    if is_valid_domain_name(subdomain):
                        domain_info = EnhancedDomainInfo.from_fqdn(subdomain, self.ingester.input_domains)
                        
                        # Check if this subdomain actually belongs to the input domain
                        if subdomain == domain:
                            # This is the base domain itself, skip creating subdomain relationship
                            continue
                        elif subdomain.endswith('.' + domain):
                            # This is a valid subdomain of the input domain
                            tx.run("""
                                MERGE (s:Subdomain {fqdn: $subdomain})
                                SET s.base_domain = $domain,
                                    s.subdomain_parts = $subdomain_parts,
                                    s.tld = $tld,
                                    s.created_at = COALESCE(s.created_at, $current_time),
                                    s.last_updated = $current_time,
                                    s.discovered_by = 'amass',
                                    s.processing_phase = false
                            """,
                            subdomain=subdomain,
                            domain=domain,
                            subdomain_parts=domain_info.subdomain_parts,
                            tld=domain_info.tld,
                            current_time=current_time)
                            
                            # Create relationship to correct base domain (optimized to avoid Cartesian product)
                            tx.run("""
                                MATCH (d:Domain {fqdn: $domain})
                                MATCH (s:Subdomain {fqdn: $subdomain})
                                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                            """, domain=domain, subdomain=subdomain)
                            
                            valid_subdomains += 1
                        else:
                            # This is a related domain but not a subdomain of the input domain
                            if self.store_related_domains:
                                # Store it separately to avoid incorrect relationships
                                tx.run("""
                                    MERGE (rd:RelatedDomain {fqdn: $subdomain})
                                    SET rd.base_domain = $actual_base_domain,
                                        rd.tld = $tld,
                                        rd.created_at = COALESCE(rd.created_at, $current_time),
                                        rd.last_updated = $current_time,
                                        rd.discovered_during_scan_of = $domain,
                                        rd.relationship_type = 'discovered_related',
                                        rd.discovery_source = 'amass_scan',
                                        rd.discovery_method = 'subdomain_enumeration',
                                        rd.original_domain_scan = $domain,
                                        rd.discovery_context = 'Found during Amass enumeration but not a direct subdomain'
                                """,
                                subdomain=subdomain,
                                actual_base_domain=domain_info.base_domain,
                                tld=domain_info.tld,
                                domain=domain,
                                current_time=current_time)
                                
                                # Create a "discovered during scan" relationship instead of subdomain relationship
                                tx.run("""
                                    MATCH (d:Domain {fqdn: $domain})
                                    MATCH (rd:RelatedDomain {fqdn: $subdomain})
                                    MERGE (d)-[:DISCOVERED_RELATED {source: 'amass', method: 'enumeration', timestamp: $timestamp}]->(rd)
                                """, domain=domain, subdomain=subdomain, timestamp=current_time)
                                
                                related_domains += 1
                            else:
                                # Skip storing related domains - log for debugging
                                if self.logger:
                                    self.logger.debug(f"🚫 Skipping related domain (not stored): {subdomain} -> actual base: {domain_info.base_domain}")
                
                # Log the results for debugging
                if self.store_related_domains:
                    logging.info(f"Domain {domain}: {valid_subdomains} valid subdomains, {related_domains} related domains")
                else:
                    logging.info(f"Domain {domain}: {valid_subdomains} valid subdomains, {related_domains} related domains (not stored)")
                    if self.logger:
                        self.logger.info(f"📋 Domain {domain}: Only storing valid subdomains (related domains disabled)")
                
                tx.commit()
    
    def enhanced_phase2_processing(self, batch_size: int = 50) -> Dict[str, Any]:
        """Phase 2: Enhanced subdomain analysis and processing."""
        start_time = time.time()
        total_processed = 0
        failed_subdomains = []
        
        msg = "Starting Phase 2: Enhanced subdomain analysis"
        logging.info(msg)
        if self.logger:
            self.logger.info(f"⚙️ {msg}")
        
        # Get unprocessed subdomains
        unprocessed_subdomains = self._get_unprocessed_subdomains()
        msg = f"Found {len(unprocessed_subdomains)} unprocessed subdomains"
        logging.info(msg)
        if self.logger:
            self.logger.info(f"📋 {msg}")
        
        if not unprocessed_subdomains:
            return {
                'phase': 'processing',
                'subdomains_processed': 0,
                'failed_subdomains': [],
                'processing_time': 0
            }
        
        # Process in batches - using specialized subdomain analysis instead of domain hierarchy
        for i in range(0, len(unprocessed_subdomains), batch_size):
            batch = unprocessed_subdomains[i:i + batch_size]
            
            try:
                batch_results = self.ingester.analyze_existing_subdomains_batch(batch)
                total_processed += batch_results['total_processed']
                
                # Mark subdomains as processed
                for subdomain in batch:
                    self._mark_subdomain_as_processed(subdomain)
                    
                msg = f"Processed batch {i//batch_size + 1}: {len(batch)} subdomains"
                logging.info(msg)
                if self.logger:
                    self.logger.info(f"✅ {msg}")
                
            except Exception as e:
                msg = f"Batch processing failed for batch {i//batch_size + 1}: {e}"
                logging.error(msg)
                if self.logger:
                    self.logger.error(f"❌ {msg}")
                    self.logger.debug(f"🔍 Batch processing exception: {type(e).__name__}: {e}")
                failed_subdomains.extend(batch)
        
        end_time = time.time()
        duration = end_time - start_time
        
        results = {
            'phase': 'processing',
            'subdomains_processed': total_processed,
            'failed_subdomains': failed_subdomains,
            'processing_time': duration,
            'subdomains_per_second': total_processed / duration if duration > 0 else 0
        }
        
        msg = f"Phase 2 completed: {results}"
        logging.info(msg)
        if self.logger:
            self.logger.info(f"✅ {msg}")
        return results
    
    def _get_unprocessed_subdomains(self) -> List[str]:
        """Get list of unprocessed subdomains."""
        with self.ingester.drv.session() as session:
            result = session.run("""
                MATCH (s:Subdomain)
                WHERE s.processing_phase IS NULL OR s.processing_phase = false
                RETURN s.fqdn as fqdn
                ORDER BY s.created_at DESC
            """)
            
            return [record["fqdn"] for record in result]
    
    def _mark_subdomain_as_processed(self, fqdn: str):
        """Mark a subdomain as processed."""
        current_time = datetime.now().isoformat()
        
        with self.ingester.drv.session() as session:
            session.run("""
                MATCH (s:Subdomain {fqdn: $fqdn})
                SET s.processing_phase = true,
                    s.last_analyzed = $current_time
            """, fqdn=fqdn, current_time=current_time)
    
    def run_enhanced_two_phase_processing(self, domains: List[str], batch_size: int = 50) -> Dict[str, Any]:
        """Run complete two-phase enhanced processing."""
        msg = "Starting enhanced two-phase subdomain processing v4.0"
        logging.info(msg)
        if self.logger:
            self.logger.info(f"🎯 {msg}")
        
        # Phase 1: Discovery
        phase1_results = self.enhanced_phase1_discovery(domains)
        
        # Phase 2: Processing
        phase2_results = self.enhanced_phase2_processing(batch_size)
        
        # Phase 3: Relationship Discovery
        relationship_results = self.ingester.discover_cross_domain_relationships(batch_size)
        
        # Combine results
        total_results = {
            'version': '4.0',
            'phases_completed': ['discovery', 'processing', 'relationships'],
            'phase1_discovery': phase1_results,
            'phase2_processing': phase2_results,
            'phase3_relationships': relationship_results,
            'total_processing_time': (
                phase1_results['processing_time'] + 
                phase2_results['processing_time'] + 
                relationship_results['processing_time']
            ),
            'summary': {
                'domains_input': len(domains),
                'subdomains_discovered': phase1_results['total_subdomains_discovered'],
                'subdomains_analyzed': phase2_results['subdomains_processed'],
                'relationships_created': relationship_results['total_relationships']
            }
        }
        
        msg = "Enhanced two-phase processing v4.0 completed successfully!"
        logging.info(msg)
        if self.logger:
            self.logger.info(f"✅ {msg}")
        return total_results


def main():
    """Main function for enhanced subdomain relationship discovery v4.0."""
    parser = argparse.ArgumentParser(description="Enhanced subdomain discovery v4.0 with comprehensive analysis")
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
    parser.add_argument("--no-cache", action="store_true", help="Disable cache (force fresh Amass execution)")
    
    # Analysis feature toggles  
    parser.add_argument("--enable-tls", action="store_true", default=False, help="Enable TLS analysis (disabled by default)")
    parser.add_argument("--enable-services", action="store_true", default=True, help="Enable service detection")
    parser.add_argument("--enable-providers", action="store_true", default=True, help="Enable provider detection")
    parser.add_argument("--enable-industry", action="store_true", default=True, help="Enable industry classification")
    parser.add_argument("--enable-risks", action="store_true", default=True, help="Enable risk calculation and analysis")
    parser.add_argument("--disable-industry", action="store_true", help="Disable industry classification")
    
    # TLS configuration
    parser.add_argument("--tls-timeout", type=int, default=30, help="TLS connection timeout in seconds (default: 30)")
    parser.add_argument("--tls-retries", type=int, default=2, help="Number of TLS connection retries (default: 2)")
    
    # Discovery configuration
    parser.add_argument("--discovery-depth", type=int, default=2, help="Discovery depth levels (default: 2)")
    parser.add_argument("--no-related-domains", action="store_true", help="Disable storage of DISCOVERED_RELATED domains (only store direct subdomains)")
    
    # Debug mode
    parser.add_argument("--debug", action="store_true", help="Enable debug mode with comprehensive logging")
    
    # v4.0: Version information
    parser.add_argument("-v", "--version", action="version", version="%(prog)s v4.0")
    
    args = parser.parse_args()
    
    # Setup debug logging if enabled
    logger = None
    if args.debug:
        log_filename = f"subdomain_relationship_discovery_v4_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        logger = setup_debug_logging(log_filename, debug_mode=True)
        logger.info(f"🐛 DEBUG MODE ENABLED - Comprehensive logging to: {log_filename}")
        logger.info(f"📋 Command line arguments: {vars(args)}")
        print(f"🐛 DEBUG MODE ENABLED - Detailed logging to: {log_filename}")
    
    # Validation
    if not args.domains and not args.phase2_only and not args.relationships_only:
        error_msg = "--domains is required for normal operation"
        if logger:
            logger.error(error_msg)
        parser.error(error_msg)
    if not args.password:
        error_msg = "--password is required for normal operation"
        if logger:
            logger.error(error_msg)
        parser.error(error_msg)
    
    # Determine industry classification setting
    enable_industry = args.enable_industry and not args.disable_industry
    
    if logger:
        logger.info(f"🔧 Initializing Enhanced Subdomain Graph Ingester v4.0")
        logger.debug(f"📊 Configuration: TLS={args.enable_tls}, Services={args.enable_services}")
        logger.debug(f"   Providers={args.enable_providers}, Industry={enable_industry}")
        logger.debug(f"   Workers={args.processing_workers}, TLS timeout={args.tls_timeout}s")
    
    # Initialize enhanced ingester
    ingester = EnhancedSubdomainGraphIngester(
        args.bolt, 
        args.user, 
        args.password, 
        args.ipinfo_token,
        enable_tls_analysis=args.enable_tls,
        enable_service_detection=args.enable_services,
        enable_provider_detection=args.enable_providers,
        enable_industry_classification=enable_industry,
        enable_risk_calculation=args.enable_risks,
        max_analysis_workers=args.processing_workers,
        tls_timeout=args.tls_timeout,
        tls_retries=args.tls_retries
    )
    
    try:
        # Setup constraints
        if logger:
            logger.debug(f"🔧 Setting up Neo4j constraints")
        ingester.setup_constraints()
        
        # Read domains from file
        domains = []
        if args.domains:
            if logger:
                logger.debug(f"📂 Reading domains from file: {args.domains}")
            with open(args.domains, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
            if logger:
                logger.info(f"📋 Successfully read {len(domains)} domains")
                logger.debug(f"📋 Domains: {domains[:10]}{'...' if len(domains) > 10 else ''}")
        
        # Initialize enhanced processor
        if logger:
            logger.info(f"🚀 Initializing Enhanced Subdomain Processor")
            logger.debug(f"⚙️ Processor config: discovery_workers={args.discovery_workers}, processing_workers={args.processing_workers}")
            logger.debug(f"   mock_mode={args.mock_mode}, sample_mode={args.sample_mode}")
            logger.debug(f"   discovery_depth={args.discovery_depth}")
        
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
            args.no_cache,
            args.discovery_depth,
            logger=logger,
            store_related_domains=not args.no_related_domains
        )
        
        # Run appropriate phase(s)
        if args.phase1_only:
            if logger:
                logger.info(f"🔍 Running Phase 1 only (discovery) for {len(domains)} domains")
            stats = processor.enhanced_phase1_discovery(domains)
        elif args.phase2_only:
            if logger:
                logger.info(f"⚙️ Running Phase 2 only (processing) with batch_size={args.batch_size}")
            stats = processor.enhanced_phase2_processing(args.batch_size)
        elif args.relationships_only:
            if logger:
                logger.info(f"🔗 Running relationships discovery only")
            stats = ingester.discover_cross_domain_relationships()
        else:
            if logger:
                logger.info(f"🎯 Running complete two-phase processing for {len(domains)} domains")
            stats = processor.run_enhanced_two_phase_processing(domains, args.batch_size)
        
        print(f"\n📊 Final Enhanced Statistics v4.0:")
        stats_json = json.dumps(stats, indent=2, default=str)
        print(stats_json)
        
        if logger:
            logger.info(f"📊 FINAL ENHANCED STATISTICS v4.0:")
            logger.info(stats_json)
        
        # Summary of enhanced provider resolution
        if 'summary' in stats:
            summary = stats['summary']
            print(f"\n🎯 Enhanced Provider Resolution Summary:")
            print(f"   • Domains processed: {summary.get('domains_input', 0)}")
            print(f"   • Subdomains discovered: {summary.get('subdomains_discovered', 0)}")
            print(f"   • Subdomains analyzed: {summary.get('subdomains_analyzed', 0)}")
            print(f"   • Relationships created: {summary.get('relationships_created', 0)}")
            print(f"   • Unknown providers will have comprehensive metadata for resolution")
        
    except Exception as e:
        error_msg = f"Failed to run enhanced subdomain relationship discovery v4.0: {e}"
        logging.error(error_msg)
        if logger:
            logger.error(error_msg)
            logger.debug(f"🔍 Main exception details: {type(e).__name__}: {e}")
        return 1
    finally:
        if 'ingester' in locals():
            ingester.close()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
