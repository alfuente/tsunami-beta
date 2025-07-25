#!/usr/bin/env python3
"""
subdomain_relationship_discovery_enhanced.py - Enhanced subdomain relationship discovery v3.0

This module extends the subdomain discovery to include comprehensive TLS analysis,
service detection, and provider identification for all subdomains during the data loading process.

Key features (NEW in v3.0):
1. Comprehensive TLS certificate analysis with grade calculation
2. Intelligent service detection based on subdomain patterns and port scanning
3. Provider identification through reverse DNS and IP analysis
4. Real-time Certificate node creation with SECURED_BY relationships
5. Service node creation with RUNS relationships
6. Provider node creation with USES_SERVICE relationships
7. Enhanced risk scoring based on TLS configuration

Previous features (v2.0):
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
- v3.0: Added TLS analysis, service detection, and provider identification
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
    from industry_classifier import IndustryClassifier
    HAS_INDUSTRY_CLASSIFIER = True
except ImportError:
    HAS_INDUSTRY_CLASSIFIER = False

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
        logging.FileHandler('subdomain_relationship_discovery_enhanced.log')
    ]
)

# Suppress logging noise
logging.getLogger('whois.whois').setLevel(logging.CRITICAL)
RESOLVER.lifetime = RESOLVER.timeout = 5.0

# Common TLD list for fallback
COMMON_TLDS = {
    'cl', 'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'co.uk', 'co.jp', 'co.kr',
    'com.au', 'com.br', 'com.mx', 'ca', 'de', 'fr', 'it', 'es', 'ru', 'cn', 'jp', 'kr'
}

def is_valid_domain_name(domain: str) -> bool:
    """Check if a string is a valid domain name (not an IP address)."""
    if not domain:
        return False
    
    # Check if it's an IP address
    try:
        ipaddress.ip_address(domain)
        return False  # It's an IP address, not a domain
    except (ValueError, ipaddress.AddressValueError):
        pass  # Not an IP address, continue validation
    
    # Basic domain name validation
    if len(domain) > 255:
        return False
    
    # Domain must contain at least one dot for TLD
    if '.' not in domain:
        return False
    
    # Check for valid characters
    import re
    if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
        return False
    
    # Each part must be valid
    parts = domain.split('.')
    for part in parts:
        if not part or len(part) > 63:
            return False
        if part.startswith('-') or part.endswith('-'):
            return False
    
    return True

def extract_tld_fallback(fqdn: str):
    """Fallback TLD extraction when tldextract is not available."""
    # First validate it's a domain, not an IP
    if not is_valid_domain_name(fqdn):
        return {'domain': '', 'suffix': '', 'subdomain': ''}
    
    parts = fqdn.lower().split('.')
    if len(parts) >= 2:
        # Check for common two-part TLDs first
        if len(parts) >= 3:
            two_part = f"{parts[-2]}.{parts[-1]}"
            if two_part in COMMON_TLDS:
                return {
                    'domain': parts[-3] if len(parts) >= 3 else '',
                    'suffix': two_part,
                    'subdomain': '.'.join(parts[:-3]) if len(parts) > 3 else ''
                }
        
        # Default to single-part TLD
        return {
            'domain': parts[-2],
            'suffix': parts[-1],
            'subdomain': '.'.join(parts[:-2]) if len(parts) > 2 else ''
        }
    return {'domain': fqdn, 'suffix': '', 'subdomain': ''}

@dataclass
class SubdomainAnalysisInfo:
    """Enhanced subdomain information including TLS, services, and providers."""
    fqdn: str
    ip_addresses: List[str]
    services: List[Dict[str, Any]]
    providers: List[Dict[str, Any]]
    tls_info: Optional[Dict[str, Any]]
    dns_info: Dict[str, Any]

@dataclass
class EnhancedDomainInfo:
    """Enhanced domain information structure."""
    fqdn: str
    base_domain: str
    subdomain_parts: str
    tld: str
    is_subdomain: bool
    
    @classmethod
    def from_fqdn(cls, fqdn: str, input_domains: Set[str] = None) -> 'EnhancedDomainInfo':
        """Create EnhancedDomainInfo from FQDN."""
        try:
            # Validate that this is a domain name, not an IP address
            if not is_valid_domain_name(fqdn):
                logging.warning(f"Invalid domain name or IP address detected: {fqdn}")
                return cls(fqdn="", base_domain="", subdomain_parts="", tld="", is_subdomain=False)
            
            if HAS_TLDEXTRACT:
                extracted = tldextract.extract(fqdn)
                base_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.domain and extracted.suffix else fqdn
                subdomain_parts = extracted.subdomain
                tld = extracted.suffix
            else:
                result = extract_tld_fallback(fqdn)
                base_domain = f"{result['domain']}.{result['suffix']}" if result['domain'] and result['suffix'] else fqdn
                subdomain_parts = result['subdomain']
                tld = result['suffix']
            
            # Additional validation for base_domain
            if not is_valid_domain_name(base_domain):
                logging.warning(f"Invalid base domain detected: {base_domain} from {fqdn}")
                return cls(fqdn="", base_domain="", subdomain_parts="", tld="", is_subdomain=False)
            
            # Determine if this is a subdomain
            is_subdomain = bool(subdomain_parts)
            
            # Additional check against input domains if provided
            if input_domains and base_domain in input_domains and subdomain_parts:
                is_subdomain = True
            elif input_domains and fqdn in input_domains:
                is_subdomain = False
                base_domain = fqdn
                subdomain_parts = ""
            
            return cls(
                fqdn=fqdn,
                base_domain=base_domain,
                subdomain_parts=subdomain_parts,
                tld=tld,
                is_subdomain=is_subdomain
            )
        except Exception as e:
            logging.warning(f"Failed to parse domain {fqdn}: {e}")
            return cls(fqdn="", base_domain="", subdomain_parts="", tld="", is_subdomain=False)

@dataclass
class RelationshipInfo:
    """Relationship information structure."""
    source_fqdn: str
    target_fqdn: str
    relationship_type: str
    confidence: float
    discovery_method: str
    metadata: Dict[str, Any] = None

class EnhancedSubdomainGraphIngester:
    """Enhanced subdomain graph ingester with TLS, service, and provider analysis."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str, ipinfo_token: str = None, 
                 enable_tls_analysis: bool = True, enable_service_detection: bool = True, 
                 enable_provider_detection: bool = True, enable_industry_classification: bool = True,
                 max_analysis_workers: int = 4):
        """Initialize the enhanced ingester."""
        if not HAS_NEO4J:
            raise ImportError("neo4j package required")
        
        self.drv = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
        self.ipinfo_token = ipinfo_token
        self.input_domains = set()
        self.enable_tls_analysis = enable_tls_analysis
        self.enable_service_detection = enable_service_detection
        self.enable_provider_detection = enable_provider_detection
        self.enable_industry_classification = enable_industry_classification
        self.max_analysis_workers = max_analysis_workers
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
        
        # Initialize industry classifier if enabled
        self.industry_classifier = None
        if self.enable_industry_classification and HAS_INDUSTRY_CLASSIFIER:
            try:
                self.industry_classifier = IndustryClassifier()
                logging.info("Industry classifier initialized")
            except Exception as e:
                logging.warning(f"Failed to initialize industry classifier: {e}")
                self.enable_industry_classification = False
        
        self._check_configuration()
        logging.info("Enhanced Subdomain Graph Ingester initialized with TLS, service, provider, and industry analysis")
    
    def _check_configuration(self):
        """Check configuration and available modules."""
        missing_modules = []
        
        if self.enable_tls_analysis and not HAS_CRYPTOGRAPHY:
            logging.warning("Cryptography module not available, TLS analysis disabled")
            self.enable_tls_analysis = False
            missing_modules.append("cryptography")
        
        if not HAS_TLDEXTRACT:
            logging.warning("tldextract not available, using fallback TLD extraction")
            missing_modules.append("tldextract")
        
        if self.enable_industry_classification and not HAS_INDUSTRY_CLASSIFIER:
            logging.warning("Industry classifier not available, industry classification disabled")
            self.enable_industry_classification = False
            missing_modules.append("industry_classifier")
        
        if missing_modules:
            logging.info(f"To enable all features, install: pip install {' '.join(missing_modules)}")
        
        # Test Neo4j connection
        try:
            with self.drv.session() as session:
                session.run("RETURN 1")
            logging.info("Neo4j connection successful")
        except Exception as e:
            logging.error(f"Neo4j connection failed: {e}")
            raise
    
    def set_input_domains(self, domains: List[str]):
        """Set the input domains for hierarchy determination."""
        self.input_domains = set(domains)
    
    def setup_constraints(self):
        """Setup Neo4j constraints for enhanced entities."""
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
                    logging.debug(f"Applied constraint: {constraint}")
                except Exception as e:
                    logging.warning(f"Constraint may already exist: {e}")
    
    def analyze_subdomain_tls(self, fqdn: str) -> Optional[Dict[str, Any]]:
        """Analyze TLS certificate for a subdomain."""
        if not self.enable_tls_analysis:
            return None
            
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
                    
                    # Calculate TLS grade
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
            logging.debug(f"TLS analysis failed for {fqdn}: {e}")
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
                a_records = self.resolver.resolve(fqdn, 'A')
                dns_info['a_records'] = [str(r) for r in a_records]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
                pass
            
            # AAAA records
            try:
                aaaa_records = self.resolver.resolve(fqdn, 'AAAA')
                dns_info['aaaa_records'] = [str(r) for r in aaaa_records]
            except Exception:
                pass
            
            # CNAME records
            try:
                cname_records = self.resolver.resolve(fqdn, 'CNAME')
                dns_info['cname_records'] = [str(r) for r in cname_records]
            except Exception:
                pass
            
            # MX records
            try:
                mx_records = self.resolver.resolve(fqdn, 'MX')
                dns_info['mx_records'] = [f"{r.preference} {r.exchange}" for r in mx_records]
            except Exception:
                pass
            
            # TXT records
            try:
                txt_records = self.resolver.resolve(fqdn, 'TXT')
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
            logging.debug(f"DNS analysis failed for {fqdn}: {e}")
        
        return dns_info
    
    def detect_services_and_providers(self, fqdn: str, ip_addresses: List[str]) -> Tuple[List[Dict], List[Dict]]:
        """Detect services and providers for a subdomain."""
        services = []
        providers = []
        
        if not self.enable_service_detection and not self.enable_provider_detection:
            return services, providers
        
        # Service detection based on subdomain name patterns
        if self.enable_service_detection:
            services.extend(self._detect_services_by_pattern(fqdn))
            services.extend(self._detect_services_by_ports(fqdn, ip_addresses))
        
        # Provider detection based on IP geolocation and ASN
        if self.enable_provider_detection:
            providers.extend(self._detect_providers_by_ip(fqdn, ip_addresses))
        
        return services, providers
    
    def _detect_services_by_pattern(self, fqdn: str) -> List[Dict[str, Any]]:
        """Detect services based on subdomain patterns."""
        services = []
        
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
            'monitor': ['monitoring', 'observability', 'management'],
            'backup': ['backup', 'storage', 'data'],
            'db': ['database', 'storage', 'data'],
            'mysql': ['database', 'storage', 'data'],
            'postgres': ['database', 'storage', 'data'],
            'redis': ['database', 'cache', 'data'],
            'elastic': ['search', 'database', 'data'],
            'kibana': ['visualization', 'analytics', 'monitoring'],
            'grafana': ['visualization', 'analytics', 'monitoring'],
            'jenkins': ['ci_cd', 'development', 'automation'],
            'gitlab': ['version_control', 'development', 'ci_cd'],
            'github': ['version_control', 'development'],
            'jira': ['project_management', 'development'],
            'confluence': ['documentation', 'collaboration'],
            'slack': ['communication', 'collaboration'],
            'teams': ['communication', 'collaboration'],
            'zoom': ['communication', 'video_conferencing'],
            'meet': ['communication', 'video_conferencing']
        }
        
        # Detect services based on subdomain prefix
        subdomain_prefix = fqdn.split('.')[0].lower()
        if subdomain_prefix in service_patterns:
            service_types = service_patterns[subdomain_prefix]
            for service_type in service_types:
                services.append({
                    'name': f"{service_type}_{subdomain_prefix}_{fqdn}",
                    'type': service_type,
                    'source': 'subdomain_pattern',
                    'confidence': 0.8,
                    'subdomain': fqdn,
                    'pattern_matched': subdomain_prefix
                })
        
        return services
    
    def _detect_services_by_ports(self, fqdn: str, ip_addresses: List[str]) -> List[Dict[str, Any]]:
        """Detect services by port scanning."""
        services = []
        
        common_ports = {
            80: ('http', 'web'),
            443: ('https', 'web'),
            25: ('smtp', 'email'),
            587: ('smtp_submission', 'email'),
            993: ('imaps', 'email'),
            995: ('pop3s', 'email'),
            22: ('ssh', 'remote_access'),
            21: ('ftp', 'file_transfer'),
            3389: ('rdp', 'remote_access'),
            3306: ('mysql', 'database'),
            5432: ('postgresql', 'database'),
            6379: ('redis', 'database'),
            9200: ('elasticsearch', 'search'),
            27017: ('mongodb', 'database')
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
                                    'name': f"{service_name}_{fqdn}_{port}",
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
        
        return services
    
    def _detect_providers_by_ip(self, fqdn: str, ip_addresses: List[str]) -> List[Dict[str, Any]]:
        """Detect providers based on IP addresses."""
        providers = []
        
        for ip in ip_addresses:
            try:
                provider_info = self._detect_provider_from_ip(ip, fqdn)
                if provider_info:
                    providers.append(provider_info)
            except Exception as e:
                logging.debug(f"Provider detection failed for IP {ip}: {e}")
        
        return providers
    
    def _detect_provider_from_ip(self, ip: str, fqdn: str) -> Optional[Dict[str, Any]]:
        """Detect provider/hosting service from IP address."""
        try:
            # Enhanced cloud provider IP ranges and patterns
            cloud_providers = {
                'amazonaws.com': {'name': 'aws', 'display_name': 'Amazon Web Services', 'type': 'cloud', 'confidence': 0.95},
                'amazon.com': {'name': 'aws', 'display_name': 'Amazon Web Services', 'type': 'cloud', 'confidence': 0.95},
                'ec2': {'name': 'aws', 'display_name': 'Amazon Web Services', 'type': 'cloud', 'confidence': 0.95},
                'aws': {'name': 'aws', 'display_name': 'Amazon Web Services', 'type': 'cloud', 'confidence': 0.95},
                'googleusercontent.com': {'name': 'google', 'display_name': 'Google Cloud Platform', 'type': 'cloud', 'confidence': 0.95},
                'google.com': {'name': 'google', 'display_name': 'Google Cloud Platform', 'type': 'cloud', 'confidence': 0.95},
                'gce': {'name': 'google', 'display_name': 'Google Cloud Platform', 'type': 'cloud', 'confidence': 0.95},
                'gcp': {'name': 'google', 'display_name': 'Google Cloud Platform', 'type': 'cloud', 'confidence': 0.95},
                'azurewebsites.net': {'name': 'azure', 'display_name': 'Microsoft Azure', 'type': 'cloud', 'confidence': 0.95},
                'azure.com': {'name': 'azure', 'display_name': 'Microsoft Azure', 'type': 'cloud', 'confidence': 0.95},
                'microsoft.com': {'name': 'azure', 'display_name': 'Microsoft Azure', 'type': 'cloud', 'confidence': 0.90},
                'cloudflare.com': {'name': 'cloudflare', 'display_name': 'Cloudflare', 'type': 'cdn', 'confidence': 0.9},
                'cloudflare': {'name': 'cloudflare', 'display_name': 'Cloudflare', 'type': 'cdn', 'confidence': 0.9},
                'fastly.com': {'name': 'fastly', 'display_name': 'Fastly', 'type': 'cdn', 'confidence': 0.9},
                'akamai.net': {'name': 'akamai', 'display_name': 'Akamai', 'type': 'cdn', 'confidence': 0.9},
                'akamai': {'name': 'akamai', 'display_name': 'Akamai', 'type': 'cdn', 'confidence': 0.9},
                'digitalocean.com': {'name': 'digitalocean', 'display_name': 'DigitalOcean', 'type': 'cloud', 'confidence': 0.9},
                'linode.com': {'name': 'linode', 'display_name': 'Linode', 'type': 'cloud', 'confidence': 0.9},
                'vultr.com': {'name': 'vultr', 'display_name': 'Vultr', 'type': 'cloud', 'confidence': 0.9},
                'ovh.com': {'name': 'ovh', 'display_name': 'OVH', 'type': 'hosting', 'confidence': 0.9},
                'ovh.net': {'name': 'ovh', 'display_name': 'OVH', 'type': 'hosting', 'confidence': 0.9},
                'hetzner.com': {'name': 'hetzner', 'display_name': 'Hetzner', 'type': 'hosting', 'confidence': 0.9},
                'contabo.com': {'name': 'contabo', 'display_name': 'Contabo', 'type': 'hosting', 'confidence': 0.9}
            }
            
            # Additional IP range detection for major providers
            ip_ranges = {
                # AWS IP ranges (sample - in real implementation would use AWS IP ranges JSON)
                '52.': 'aws',
                '54.': 'aws',
                '3.': 'aws',
                '18.': 'aws',
                # Google Cloud IP ranges  
                '35.': 'google',
                '34.': 'google',
                '104.': 'google',
                # Azure IP ranges
                '20.': 'azure',
                '40.': 'azure',
                '52.': 'azure',  # Overlaps with AWS, reverse DNS will resolve
                # Cloudflare
                '104.16.': 'cloudflare',
                '104.17.': 'cloudflare',
                '104.18.': 'cloudflare',
                '104.19.': 'cloudflare',
                '104.20.': 'cloudflare',
                '104.21.': 'cloudflare',
                '104.22.': 'cloudflare',
                '104.23.': 'cloudflare',
                '104.24.': 'cloudflare',
                '104.25.': 'cloudflare',
                '104.26.': 'cloudflare',
                '104.27.': 'cloudflare',
                '104.28.': 'cloudflare',
                '172.64.': 'cloudflare',
                '172.65.': 'cloudflare',
                '172.66.': 'cloudflare',
                '172.67.': 'cloudflare',
                '172.68.': 'cloudflare',
                '172.69.': 'cloudflare',
                '172.70.': 'cloudflare',
                '172.71.': 'cloudflare'
            }
            
            # Try reverse DNS lookup first
            hostname = None
            try:
                hostname = socket.gethostbyaddr(ip)[0].lower()
                logging.debug(f"Reverse DNS for {ip}: {hostname}")
                
                for domain, provider_info in cloud_providers.items():
                    if domain in hostname:
                        return {
                            'name': provider_info['name'],
                            'display_name': provider_info['display_name'],
                            'type': provider_info['type'],
                            'confidence': provider_info['confidence'],
                            'ip': ip,
                            'hostname': hostname,
                            'subdomain': fqdn,
                            'source': 'reverse_dns'
                        }
                
                # Extract provider name from hostname patterns
                if hostname:
                    # Pattern matching for common hosting providers
                    hostname_patterns = {
                        r'.*\.amazonaws\.com$': {'name': 'aws', 'display_name': 'Amazon Web Services', 'confidence': 0.95},
                        r'.*\.googleusercontent\.com$': {'name': 'google', 'display_name': 'Google Cloud Platform', 'confidence': 0.95},
                        r'.*\.cloudflare\.com$': {'name': 'cloudflare', 'display_name': 'Cloudflare', 'confidence': 0.95},
                        r'.*\.azurewebsites\.net$': {'name': 'azure', 'display_name': 'Microsoft Azure', 'confidence': 0.95},
                        r'.*\.digitalocean\.com$': {'name': 'digitalocean', 'display_name': 'DigitalOcean', 'confidence': 0.9},
                        r'.*\.ovh\..*$': {'name': 'ovh', 'display_name': 'OVH', 'confidence': 0.9},
                        r'.*\.hetzner\..*$': {'name': 'hetzner', 'display_name': 'Hetzner', 'confidence': 0.9}
                    }
                    
                    for pattern, info in hostname_patterns.items():
                        if re.match(pattern, hostname):
                            return {
                                'name': info['name'],
                                'display_name': info['display_name'],
                                'type': 'cloud',
                                'confidence': info['confidence'],
                                'ip': ip,
                                'hostname': hostname,
                                'subdomain': fqdn,
                                'source': 'hostname_pattern'
                            }
                    
                    # Generic hostname-based provider
                    parts = hostname.split('.')
                    if len(parts) >= 2:
                        domain_parts = '.'.join(parts[-2:])
                        provider_name = parts[-2] if parts[-2] not in ['com', 'net', 'org'] else parts[-3] if len(parts) >= 3 else 'unknown'
                        
                        return {
                            'name': provider_name.lower(),
                            'display_name': f'{provider_name.title()} Hosting',
                            'type': 'hosting',
                            'confidence': 0.7,
                            'ip': ip,
                            'hostname': hostname,
                            'subdomain': fqdn,
                            'source': 'hostname_analysis'
                        }
                        
            except Exception as e:
                logging.debug(f"Reverse DNS lookup failed for {ip}: {e}")
            
            # IP range-based detection
            for ip_prefix, provider_name in ip_ranges.items():
                if ip.startswith(ip_prefix):
                    if provider_name in ['aws', 'google', 'azure', 'cloudflare']:
                        provider_info = next((p for p in cloud_providers.values() if p['name'] == provider_name), None)
                        if provider_info:
                            return {
                                'name': provider_name,
                                'display_name': provider_info['display_name'],
                                'type': provider_info['type'],
                                'confidence': 0.8,
                                'ip': ip,
                                'hostname': hostname or '',
                                'subdomain': fqdn,
                                'source': 'ip_range'
                            }
            
            # Fallback: Basic provider detection
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return {
                    'name': 'internal',
                    'display_name': 'Internal Network',
                    'type': 'internal',
                    'confidence': 0.8,
                    'ip': ip,
                    'hostname': hostname or '',
                    'subdomain': fqdn,
                    'source': 'ip_analysis'
                }
            else:
                # Try to determine ISP/Provider from IP geolocation
                provider_name = self._get_isp_from_ip(ip)
                if provider_name and provider_name.lower() != 'unknown':
                    return {
                        'name': provider_name.lower().replace(' ', '_'),
                        'display_name': provider_name,
                        'type': 'isp',
                        'confidence': 0.6,
                        'ip': ip,
                        'hostname': hostname or '',
                        'subdomain': fqdn,
                        'source': 'geolocation'
                    }
                else:
                    # Last resort: use IP octets to create a meaningful identifier
                    ip_parts = ip.split('.')
                    network_id = f"{ip_parts[0]}.{ip_parts[1]}.x.x"
                    return {
                        'name': f'network_{ip_parts[0]}_{ip_parts[1]}',
                        'display_name': f'Network {network_id}',
                        'type': 'network',
                        'confidence': 0.3,
                        'ip': ip,
                        'hostname': hostname or '',
                        'subdomain': fqdn,
                        'source': 'ip_fallback'
                    }
                
        except Exception as e:
            logging.debug(f"Provider detection failed for IP {ip}: {e}")
            return {
                'name': 'unknown',
                'display_name': 'Unknown Provider',
                'type': 'unknown',
                'confidence': 0.1,
                'ip': ip,
                'hostname': '',
                'subdomain': fqdn,
                'source': 'error'
            }
    
    def _get_isp_from_ip(self, ip: str) -> str:
        """Get ISP information from IP address using various methods."""
        try:
            # Try whois lookup for ISP information
            if HAS_WHOIS:
                whois_data = whois.whois(ip)
                if hasattr(whois_data, 'org') and whois_data.org:
                    return whois_data.org
                elif hasattr(whois_data, 'orgname') and whois_data.orgname:
                    return whois_data.orgname
        except Exception:
            pass
        
        # Try basic HTTP request to ipinfo.io (free tier)
        try:
            response = requests.get(f'https://ipinfo.io/{ip}/json', timeout=5)
            if response.status_code == 200:
                data = response.json()
                if 'org' in data:
                    # Extract ISP name from org field (format usually "AS12345 ISP Name")
                    org = data['org']
                    if ' ' in org:
                        return org.split(' ', 1)[1]
                    return org
        except Exception:
            pass
        
        return 'Unknown'
    
    def analyze_domain_industry(self, fqdn: str) -> Optional[Dict[str, Any]]:
        """Analyze domain industry classification."""
        if not self.enable_industry_classification or not self.industry_classifier:
            return None
        
        try:
            # Extract base domain for classification
            domain_info = EnhancedDomainInfo.from_fqdn(fqdn, self.input_domains)
            domain_to_classify = domain_info.base_domain if domain_info.base_domain else fqdn
            
            # Classify industry
            classification = self.industry_classifier.classify_domain(domain_to_classify)
            
            if classification.confidence < 0.1:
                # Too low confidence, skip
                return None
            
            return {
                'primary_industry': classification.primary_industry,
                'confidence': classification.confidence,
                'secondary_industries': classification.secondary_industries,
                'source': classification.source,
                'keywords_found': classification.keywords_found[:10],  # Limit keywords
                'description': classification.description,
                'domain_classified': domain_to_classify
            }
            
        except Exception as e:
            logging.warning(f"Industry classification failed for {fqdn}: {e}")
            return None
    
    def create_enhanced_domain_hierarchy_batch(self, domains: List[str], batch_size: int = 50) -> Dict[str, Any]:
        """Create enhanced domain hierarchy with TLS, service, and provider analysis."""
        total_processed = 0
        total_subdomains = 0
        total_services = 0
        total_providers = 0
        total_certificates = 0
        total_industries = 0
        
        start_time = time.time()
        self.set_input_domains(domains)
        
        logging.info(f"Starting enhanced domain hierarchy creation for {len(domains)} domains")
        
        with self.drv.session() as session:
            for i in range(0, len(domains), batch_size):
                batch = domains[i:i + batch_size]
                
                with session.begin_transaction() as tx:
                    batch_subdomains = 0
                    batch_services = 0
                    batch_providers = 0
                    batch_certificates = 0
                    batch_industries = 0
                    
                    for fqdn in batch:
                        try:
                            results = self._create_enhanced_domain_hierarchy_single(fqdn, tx)
                            batch_subdomains += results.get('subdomains', 0)
                            batch_services += results.get('services', 0)
                            batch_providers += results.get('providers', 0)
                            batch_certificates += results.get('certificates', 0)
                            batch_industries += results.get('industries', 0)
                            total_processed += 1
                        except Exception as e:
                            logging.error(f"Failed to process {fqdn}: {e}")
                    
                    tx.commit()
                    
                    total_subdomains += batch_subdomains
                    total_services += batch_services
                    total_providers += batch_providers
                    total_certificates += batch_certificates
                    total_industries += batch_industries
                    
                    logging.info(f"Processed batch {i//batch_size + 1}: {len(batch)} domains, "
                               f"{batch_subdomains} subdomains, {batch_services} services, "
                               f"{batch_providers} providers, {batch_certificates} certificates, "
                               f"{batch_industries} industries")
        
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
    
    def _create_enhanced_domain_hierarchy_single(self, fqdn: str, tx) -> Dict[str, int]:
        """Create enhanced domain hierarchy for a single domain with analysis."""
        results = {'subdomains': 0, 'services': 0, 'providers': 0, 'certificates': 0, 'industries': 0}
        
        # Skip processing if this is an IP address or invalid domain
        if not is_valid_domain_name(fqdn):
            logging.warning(f"Skipping invalid domain/IP: {fqdn}")
            return results
        
        domain_info = EnhancedDomainInfo.from_fqdn(fqdn, self.input_domains)
        
        # Skip if domain info is empty (validation failed)
        if not domain_info.fqdn or not domain_info.base_domain:
            logging.warning(f"Skipping domain due to validation failure: {fqdn}")
            return results
        
        current_time = datetime.now().isoformat()
        
        if domain_info.is_subdomain:
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
            analysis_results = self._perform_subdomain_analysis(fqdn, tx)
            results.update(analysis_results)
            
        else:
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
    
    def _perform_subdomain_analysis(self, fqdn: str, tx) -> Dict[str, int]:
        """Perform comprehensive analysis of a subdomain."""
        results = {'services': 0, 'providers': 0, 'certificates': 0, 'industries': 0}
        
        try:
            # Get DNS information
            dns_info = self.analyze_subdomain_dns(fqdn)
            ip_addresses = dns_info.get('a_records', [])
            
            # Update subdomain with DNS info
            tx.run("""
                MATCH (s:Subdomain {fqdn: $fqdn})
                SET s.dns_a_records = $a_records,
                    s.dns_has_spf = $has_spf,
                    s.dns_has_dmarc = $has_dmarc,
                    s.dns_cname_records = $cname_records,
                    s.dns_mx_records = $mx_records
            """,
            fqdn=fqdn,
            a_records=dns_info.get('a_records', []),
            has_spf=dns_info.get('has_spf', False),
            has_dmarc=dns_info.get('has_dmarc', False),
            cname_records=dns_info.get('cname_records', []),
            mx_records=dns_info.get('mx_records', []))
            
            # Analyze TLS
            tls_info = self.analyze_subdomain_tls(fqdn)
            if tls_info:
                tx.run("""
                    MATCH (s:Subdomain {fqdn: $fqdn})
                    SET s.has_tls = $has_tls,
                        s.tls_grade = $tls_grade,
                        s.tls_expires_in_days = $expires_in_days
                """,
                fqdn=fqdn,
                has_tls=tls_info.get('has_tls', False),
                tls_grade=tls_info.get('tls_grade', 'Unknown'),
                expires_in_days=tls_info.get('expires_in_days', 0))
                
                # Create Certificate node if TLS exists
                if tls_info.get('has_tls'):
                    cert_id = f"{fqdn}_{tls_info.get('serial_number', 'unknown')}_{int(time.time())}"
                    
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
                    tls_version=tls_info.get('tls_version', ''))
                    
                    results['certificates'] = 1
            
            # Detect services and providers
            services, providers = self.detect_services_and_providers(fqdn, ip_addresses)
            
            # Create Service nodes
            for i, service in enumerate(services):
                service_id = f"{fqdn}_service_{i}_{int(time.time())}"
                tx.run("""
                    MATCH (s:Subdomain {fqdn: $fqdn})
                    MERGE (srv:Service {id: $service_id})
                    SET srv.name = $service_name,
                        srv.type = $service_type,
                        srv.source = $source,
                        srv.confidence = $confidence,
                        srv.subdomain = $subdomain,
                        srv.port = $port,
                        srv.pattern_matched = $pattern_matched,
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
                port=service.get('port', 0),
                pattern_matched=service.get('pattern_matched', ''))
            
            results['services'] = len(services)
            
            # Create Provider nodes
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
                        p.hostname = $hostname,
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
                hostname=provider.get('hostname', ''),
                subdomain=provider.get('subdomain', fqdn))
            
            results['providers'] = len(providers)
            
            # Analyze industry classification
            industry_info = self.analyze_domain_industry(fqdn)
            if industry_info:
                industry_id = f"{industry_info['primary_industry']}_{int(time.time())}"
                
                tx.run("""
                    MATCH (s:Subdomain {fqdn: $fqdn})
                    MERGE (i:Industry {name: $industry_name})
                    SET i.description = $description,
                        i.category = $primary_industry,
                        i.confidence = $confidence,
                        i.source = $source,
                        i.keywords = $keywords,
                        i.secondary_industries = $secondary_industries,
                        i.domain_classified = $domain_classified,
                        i.created_at = datetime()
                    MERGE (s)-[:BELONGS_TO_INDUSTRY]->(i)
                    SET s.primary_industry = $primary_industry,
                        s.industry_confidence = $confidence
                """,
                fqdn=fqdn,
                industry_name=industry_info['primary_industry'],
                description=industry_info['description'],
                primary_industry=industry_info['primary_industry'],
                confidence=industry_info['confidence'],
                source=industry_info['source'],
                keywords=industry_info['keywords_found'],
                secondary_industries=industry_info['secondary_industries'],
                domain_classified=industry_info['domain_classified'])
                
                results['industries'] = 1
            
        except Exception as e:
            logging.warning(f"Subdomain analysis failed for {fqdn}: {e}")
        
        return results
    
    # Include all original methods from subdomain_relationship_discovery.py
    def discover_cross_domain_relationships(self, batch_size: int = 100) -> Dict[str, Any]:
        """Discover relationships between domains and subdomains."""
        total_relationships = 0
        relationship_stats = {
            'ip_shared_relationships': 0,
            'provider_relationships': 0,
            'dns_relationships': 0,
            'certificate_relationships': 0
        }
        
        start_time = time.time()
        
        # Discover different types of relationships
        ip_relationships = self._discover_ip_sharing_relationships()
        provider_relationships = self._discover_provider_relationships()
        dns_relationships = self._discover_dns_relationships()
        certificate_relationships = self._discover_certificate_relationships()
        
        # Update statistics
        relationship_stats['ip_shared_relationships'] = len(ip_relationships)
        relationship_stats['provider_relationships'] = len(provider_relationships)
        relationship_stats['dns_relationships'] = len(dns_relationships)
        relationship_stats['certificate_relationships'] = len(certificate_relationships)
        
        total_relationships = sum(relationship_stats.values())
        
        end_time = time.time()
        duration = end_time - start_time
        
        results = {
            'total_relationships': total_relationships,
            'relationship_stats': relationship_stats,
            'processing_time': duration
        }
        
        logging.info(f"Cross-domain relationship discovery completed: {results}")
        return results
    
    def _discover_ip_sharing_relationships(self) -> List[RelationshipInfo]:
        """Discover relationships based on shared IP addresses."""
        relationships = []
        
        with self.drv.session() as s:
            result = s.run("""
                MATCH (d1)-[:RESOLVES_TO]->(ip:IPAddress)<-[:RESOLVES_TO]-(d2)
                WHERE (d1:Domain OR d1:Subdomain) AND (d2:Domain OR d2:Subdomain)
                AND d1.fqdn <> d2.fqdn
                RETURN d1.fqdn as source, d2.fqdn as target, ip.address as shared_ip
            """)
            
            for record in result:
                rel = RelationshipInfo(
                    source_fqdn=record["source"],
                    target_fqdn=record["target"],
                    relationship_type="SHARES_IP",
                    confidence=0.7,
                    discovery_method="ip_analysis",
                    metadata={"shared_ip": record["shared_ip"]}
                )
                relationships.append(rel)
        
        self._create_relationships_batch(relationships)
        return relationships
    
    def _discover_provider_relationships(self) -> List[RelationshipInfo]:
        """Discover relationships based on shared providers."""
        relationships = []
        
        with self.drv.session() as s:
            result = s.run("""
                MATCH (d1)-[:USES_SERVICE]->(p:Provider)<-[:USES_SERVICE]-(d2)
                WHERE (d1:Domain OR d1:Subdomain) AND (d2:Domain OR d2:Subdomain)
                AND d1.fqdn <> d2.fqdn
                RETURN d1.fqdn as source, d2.fqdn as target, p.name as provider_name
            """)
            
            for record in result:
                rel = RelationshipInfo(
                    source_fqdn=record["source"],
                    target_fqdn=record["target"],
                    relationship_type="SHARES_PROVIDER",
                    confidence=0.6,
                    discovery_method="provider_analysis",
                    metadata={"shared_provider": record["provider_name"]}
                )
                relationships.append(rel)
        
        self._create_relationships_batch(relationships)
        return relationships
    
    def _discover_dns_relationships(self) -> List[RelationshipInfo]:
        """Discover relationships based on DNS patterns."""
        relationships = []
        
        with self.drv.session() as s:
            result = s.run("""
                MATCH (n) WHERE n:Domain OR n:Subdomain
                RETURN n.fqdn as fqdn, n.dns_cname_records as cnames
            """)
            
            cname_map = {}
            for record in result:
                fqdn = record["fqdn"]
                cnames = record["cnames"] or []
                for cname in cnames:
                    if cname not in cname_map:
                        cname_map[cname] = []
                    cname_map[cname].append(fqdn)
            
            # Create relationships between domains with same CNAME
            for cname, domains in cname_map.items():
                if len(domains) > 1:
                    for i, source in enumerate(domains):
                        for target in domains[i+1:]:
                            rel = RelationshipInfo(
                                source_fqdn=source,
                                target_fqdn=target,
                                relationship_type="SHARES_CNAME",
                                confidence=0.8,
                                discovery_method="dns_analysis",
                                metadata={"shared_cname": cname}
                            )
                            relationships.append(rel)
        
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
                logging.debug(f"Certificate analysis error for {fqdn}: {e}")
        
        self._create_relationships_batch(relationships)
        return relationships
    
    def _get_certificate_sans(self, fqdn: str) -> List[str]:
        """Extract SAN domains from SSL certificate."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
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
                        logging.debug(f"Error creating relationship {rel.source_fqdn} -> {rel.target_fqdn}: {e}")
                
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
        
        if tx:
            tx.run("""
                MATCH (s:Subdomain {fqdn: $fqdn})
                SET s.processing_phase = true,
                    s.last_analyzed = $current_time
            """, fqdn=fqdn, current_time=current_time)
        else:
            with self.drv.session() as s:
                s.run("""
                    MATCH (s:Subdomain {fqdn: $fqdn})
                    SET s.processing_phase = true,
                        s.last_analyzed = $current_time
                """, fqdn=fqdn, current_time=current_time)
    
    def close(self):
        """Close the Neo4j driver."""
        if self.drv:
            self.drv.close()

def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description="Enhanced Subdomain Relationship Discovery with TLS, Services, and Providers")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--neo4j-user", default="neo4j", help="Neo4j username")
    parser.add_argument("--neo4j-pass", default="test.password", help="Neo4j password")
    parser.add_argument("--ipinfo-token", help="IPInfo.io API token")
    parser.add_argument("--domains-file", help="File containing domains to process")
    parser.add_argument("--domains", nargs="*", help="Domains to process")
    parser.add_argument("--batch-size", type=int, default=50, help="Batch size for processing")
    parser.add_argument("--max-workers", type=int, default=4, help="Maximum worker threads for analysis")
    parser.add_argument("--enable-tls", action="store_true", default=True, help="Enable TLS analysis")
    parser.add_argument("--enable-services", action="store_true", default=True, help="Enable service detection")
    parser.add_argument("--enable-providers", action="store_true", default=True, help="Enable provider detection")
    parser.add_argument("--enable-industry", action="store_true", default=True, help="Enable industry classification")
    parser.add_argument("--disable-industry", action="store_true", help="Disable industry classification")
    parser.add_argument("--relationships-only", action="store_true", help="Only discover relationships, skip domain creation")
    
    args = parser.parse_args()
    
    # Get domains to process
    domains = []
    if args.domains_file:
        with open(args.domains_file, 'r') as f:
            domains.extend([line.strip() for line in f if line.strip()])
    if args.domains:
        domains.extend(args.domains)
    
    if not domains and not args.relationships_only:
        logging.error("No domains provided. Use --domains-file or --domains")
        return 1
    
    # Determine industry classification setting
    enable_industry = args.enable_industry and not args.disable_industry
    
    # Initialize ingester
    try:
        ingester = EnhancedSubdomainGraphIngester(
            neo4j_uri=args.neo4j_uri,
            neo4j_user=args.neo4j_user,
            neo4j_pass=args.neo4j_pass,
            ipinfo_token=args.ipinfo_token,
            enable_tls_analysis=args.enable_tls,
            enable_service_detection=args.enable_services,
            enable_provider_detection=args.enable_providers,
            enable_industry_classification=enable_industry,
            max_analysis_workers=args.max_workers
        )
        
        # Setup constraints
        ingester.setup_constraints()
        
        if not args.relationships_only:
            # Create enhanced domain hierarchy
            results = ingester.create_enhanced_domain_hierarchy_batch(domains, args.batch_size)
            logging.info(f"Domain hierarchy creation results: {results}")
        
        # Discover relationships
        relationship_results = ingester.discover_cross_domain_relationships(args.batch_size)
        logging.info(f"Relationship discovery results: {relationship_results}")
        
        logging.info("Enhanced subdomain relationship discovery completed successfully!")
        
    except Exception as e:
        logging.error(f"Failed to run enhanced subdomain relationship discovery: {e}")
        return 1
    finally:
        if 'ingester' in locals():
            ingester.close()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())