#!/usr/bin/env python3
"""
Enhanced Subdomain Discovery and Risk Analysis
Fixes and improvements for subdomain relationship discovery v4.0

Main issues addressed:
1. Missing dependencies and import errors
2. IPInfo integration problems  
3. Missing risk calculation features
4. Timeouts and performance issues
5. Graph enrichment problems
6. Provider resolution failures
"""

import argparse
import json
import sys
import socket
import ssl
import re
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import threading
import hashlib
import ipaddress

# Required imports with fallbacks
try:
    from neo4j import GraphDatabase
    HAS_NEO4J = True
except ImportError:
    print("ERROR: neo4j module required. Install with: pip install neo4j")
    HAS_NEO4J = False

try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    print("ERROR: dnspython required. Install with: pip install dnspython")
    HAS_DNS = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    print("ERROR: requests required. Install with: pip install requests")
    HAS_REQUESTS = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('enhanced_subdomain_discovery.log')
    ]
)

class EnhancedIPInfoResolver:
    """Enhanced IP information resolver with fallbacks."""
    
    def __init__(self, token: str = None):
        self.token = token
        self.cache = {}
        self.resolver = dns.resolver.Resolver() if HAS_DNS else None
        
    def get_ip_info(self, ip: str) -> Dict[str, Any]:
        """Get comprehensive IP information."""
        if ip in self.cache:
            return self.cache[ip]
            
        info = {
            'ip': ip,
            'provider': 'unknown',
            'org': 'unknown',
            'asn': 'unknown',
            'country': 'unknown',
            'confidence': 0.0,
            'sources': []
        }
        
        # Try IPInfo API if token available
        if self.token and HAS_REQUESTS:
            try:
                api_info = self._query_ipinfo_api(ip)
                if api_info:
                    info.update(api_info)
                    info['sources'].append('ipinfo_api')
            except Exception as e:
                logging.debug(f"IPInfo API failed for {ip}: {e}")
        
        # Try reverse DNS
        try:
            reverse_info = self._get_reverse_dns(ip)
            if reverse_info:
                info.update(reverse_info)
                info['sources'].append('reverse_dns')
        except Exception as e:
            logging.debug(f"Reverse DNS failed for {ip}: {e}")
        
        # Try ASN lookup
        try:
            asn_info = self._get_asn_info(ip)
            if asn_info:
                info.update(asn_info)
                info['sources'].append('asn_lookup')
        except Exception as e:
            logging.debug(f"ASN lookup failed for {ip}: {e}")
        
        self.cache[ip] = info
        return info
    
    def _query_ipinfo_api(self, ip: str) -> Optional[Dict]:
        """Query IPInfo API."""
        try:
            url = f"https://ipinfo.io/{ip}/json"
            if self.token:
                url += f"?token={self.token}"
            
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                provider = self._extract_provider_from_org(data.get('org', ''))
                
                return {
                    'provider': provider,
                    'org': data.get('org', 'unknown'),
                    'asn': data.get('org', '').split(' ')[0] if data.get('org') else 'unknown',
                    'country': data.get('country', 'unknown'),
                    'region': data.get('region', 'unknown'),
                    'city': data.get('city', 'unknown'),
                    'confidence': 0.9
                }
        except Exception as e:
            logging.debug(f"IPInfo API error for {ip}: {e}")
        return None
    
    def _get_reverse_dns(self, ip: str) -> Optional[Dict]:
        """Get reverse DNS information."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            provider = self._extract_provider_from_hostname(hostname)
            
            if provider != 'unknown':
                return {
                    'provider': provider,
                    'hostname': hostname,
                    'confidence': 0.7
                }
        except Exception:
            pass
        return None
    
    def _get_asn_info(self, ip: str) -> Optional[Dict]:
        """Get ASN information."""
        if not self.resolver:
            return None
            
        try:
            # Reverse IP for ASN lookup
            reversed_ip = '.'.join(ip.split('.')[::-1])
            query = f"{reversed_ip}.origin.asn.cymru.com"
            
            result = self.resolver.resolve(query, 'TXT')
            if result:
                asn_data = str(result[0]).strip('"')
                parts = asn_data.split('|')
                if len(parts) >= 2:
                    asn = parts[0].strip()
                    org = parts[-1].strip() if len(parts) > 1 else ''
                    
                    provider = self._extract_provider_from_org(org)
                    
                    return {
                        'asn': asn,
                        'org': org,
                        'provider': provider,
                        'confidence': 0.8
                    }
        except Exception:
            pass
        return None
    
    def _extract_provider_from_org(self, org: str) -> str:
        """Extract provider from organization string."""
        if not org:
            return 'unknown'
        
        org_lower = org.lower()
        
        # Cloud provider patterns
        providers = {
            'amazon': ['amazon', 'aws', 'ec2', 'cloudfront'],
            'google': ['google', 'gcp', 'googleapis'],
            'microsoft': ['microsoft', 'azure', 'outlook'],
            'cloudflare': ['cloudflare', 'cf-ipv4'],
            'digitalocean': ['digitalocean', 'do-user'],
            'vultr': ['vultr', 'choopa'],
            'linode': ['linode', 'akamai'],
            'ovh': ['ovh', 'ovhcloud'],
            'hetzner': ['hetzner', 'hetzner-online']
        }
        
        for provider, patterns in providers.items():
            for pattern in patterns:
                if pattern in org_lower:
                    return provider
        
        # Extract first meaningful word
        words = org.split()
        for word in words:
            if not word.startswith('AS') and len(word) > 2:
                return word.lower()
        
        return 'unknown'
    
    def _extract_provider_from_hostname(self, hostname: str) -> str:
        """Extract provider from hostname."""
        return self._extract_provider_from_org(hostname)

class EnhancedTLSAnalyzer:
    """Enhanced TLS certificate analyzer."""
    
    def analyze_tls(self, fqdn: str) -> Dict[str, Any]:
        """Analyze TLS certificate for domain."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((fqdn, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=fqdn) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Parse certificate dates
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    expires_in_days = (not_after - datetime.now()).days
                    
                    # Calculate TLS grade
                    grade = self._calculate_tls_grade(cert, cipher, expires_in_days)
                    
                    return {
                        'has_tls': True,
                        'tls_grade': grade,
                        'expires_in_days': expires_in_days,
                        'not_after': cert['notAfter'],
                        'not_before': cert['notBefore'],
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'is_self_signed': cert.get('issuer') == cert.get('subject'),
                        'cipher_suite': cipher[0] if cipher else None,
                        'tls_version': cipher[1] if cipher else None,
                        'san_domains': self._extract_san_domains(cert)
                    }
        except Exception as e:
            logging.debug(f"TLS analysis failed for {fqdn}: {e}")
            return {
                'has_tls': False,
                'tls_grade': 'F',
                'error': str(e)
            }
    
    def _calculate_tls_grade(self, cert: Dict, cipher: tuple, expires_in_days: int) -> str:
        """Calculate TLS grade."""
        score = 100
        
        # Certificate expiration
        if expires_in_days < 0:
            return 'F'
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
                pass
            elif 'TLSv1.1' in tls_version or 'TLSv1' in tls_version:
                score -= 30
            elif 'SSLv' in tls_version:
                score -= 50
        
        # Convert to grade
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
        """Extract SAN domains."""
        san_domains = []
        try:
            for name, value in cert.get('subjectAltName', []):
                if name == 'DNS':
                    san_domains.append(value)
        except Exception:
            pass
        return san_domains

class EnhancedRiskCalculator:
    """Enhanced risk calculation engine."""
    
    def calculate_subdomain_risk(self, subdomain_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive risk score for subdomain."""
        risk_factors = []
        total_score = 0
        max_score = 0
        
        # TLS Risk Assessment
        tls_info = subdomain_data.get('tls', {})
        if tls_info.get('has_tls'):
            tls_grade = tls_info.get('tls_grade', 'F')
            expires_in_days = tls_info.get('expires_in_days', 0)
            
            if tls_grade in ['A+', 'A']:
                tls_score = 10
            elif tls_grade in ['A-', 'B+']:
                tls_score = 7
            elif tls_grade in ['B', 'B-']:
                tls_score = 5
            elif tls_grade in ['C+', 'C']:
                tls_score = 3
            else:
                tls_score = 0
            
            # Expiration penalty
            if expires_in_days < 30:
                tls_score = max(0, tls_score - 3)
            elif expires_in_days < 90:
                tls_score = max(0, tls_score - 1)
            
            total_score += tls_score
            max_score += 10
            risk_factors.append(f"TLS Grade: {tls_grade} (Score: {tls_score}/10)")
        else:
            risk_factors.append("No TLS - Critical Risk")
            max_score += 10
        
        # Provider Risk Assessment
        providers = subdomain_data.get('providers', [])
        if providers:
            known_providers = [p for p in providers if p.get('name') != 'unknown']
            if known_providers:
                provider_score = 8
                risk_factors.append(f"Known Provider: {known_providers[0].get('name')} (Score: 8/10)")
            else:
                provider_score = 2
                risk_factors.append("Unknown Provider - High Risk (Score: 2/10)")
            total_score += provider_score
        else:
            risk_factors.append("No Provider Info - Medium Risk (Score: 5/10)")
            total_score += 5
        max_score += 10
        
        # Service Risk Assessment
        services = subdomain_data.get('services', [])
        if services:
            high_risk_services = ['admin', 'test', 'dev', 'staging']
            service_names = [s.get('type', '') for s in services]
            
            if any(hrs in service_names for hrs in high_risk_services):
                service_score = 3
                risk_factors.append("High-Risk Service Detected (Score: 3/10)")
            else:
                service_score = 7
                risk_factors.append("Standard Services (Score: 7/10)")
            total_score += service_score
        else:
            service_score = 5
            risk_factors.append("No Service Detection (Score: 5/10)")
            total_score += service_score
        max_score += 10
        
        # DNS Risk Assessment
        dns_info = subdomain_data.get('dns', {})
        if dns_info:
            dns_score = 8
            risk_factors.append("DNS Records Available (Score: 8/10)")
        else:
            dns_score = 2
            risk_factors.append("No DNS Records - High Risk (Score: 2/10)")
        total_score += dns_score
        max_score += 10
        
        # Calculate final risk score
        risk_percentage = (total_score / max_score * 100) if max_score > 0 else 0
        
        # Risk level classification
        if risk_percentage >= 80:
            risk_level = 'LOW'
        elif risk_percentage >= 60:
            risk_level = 'MEDIUM'
        elif risk_percentage >= 40:
            risk_level = 'HIGH'
        else:
            risk_level = 'CRITICAL'
        
        return {
            'risk_score': risk_percentage,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'total_score': total_score,
            'max_possible_score': max_score,
            'assessment_timestamp': datetime.now().isoformat()
        }

class EnhancedSubdomainAnalyzer:
    """Main subdomain analysis engine with comprehensive features."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str, ipinfo_token: str = None):
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_pass = neo4j_pass
        
        # Initialize components
        self.ip_resolver = EnhancedIPInfoResolver(ipinfo_token)
        self.tls_analyzer = EnhancedTLSAnalyzer()
        self.risk_calculator = EnhancedRiskCalculator()
        
        # Initialize Neo4j driver
        if HAS_NEO4J:
            self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
        else:
            self.driver = None
            
        logging.info("Enhanced Subdomain Analyzer initialized")
    
    def setup_database_constraints(self):
        """Setup Neo4j constraints."""
        if not self.driver:
            return
            
        constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Domain) REQUIRE d.fqdn IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (s:Subdomain) REQUIRE s.fqdn IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (r:Risk) REQUIRE r.risk_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (p:Provider) REQUIRE p.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (srv:Service) REQUIRE srv.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (c:Certificate) REQUIRE c.id IS UNIQUE"
        ]
        
        with self.driver.session() as session:
            for constraint in constraints:
                try:
                    session.run(constraint)
                except Exception as e:
                    logging.debug(f"Constraint creation: {e}")
    
    def discover_subdomains(self, domain: str, use_mock: bool = False) -> List[str]:
        """Discover subdomains for a domain."""
        if use_mock:
            # Mock subdomains for testing
            mock_subdomains = [
                f"www.{domain}",
                f"mail.{domain}",
                f"api.{domain}",
                f"admin.{domain}",
                f"cdn.{domain}",
                f"ftp.{domain}",
                f"dev.{domain}",
                f"test.{domain}",
                f"auth.{domain}",
                f"app.{domain}"
            ]
            logging.info(f"Mock discovery: Found {len(mock_subdomains)} subdomains for {domain}")
            return mock_subdomains
        
        # Try to use existing Amass integration
        try:
            from risk_loader_advanced3 import run_amass_with_fallback
            results = run_amass_with_fallback(domain, sample_mode=True)
            subdomains = []
            for result in results:
                subdomain = result.get('name') if isinstance(result, dict) else result
                if subdomain and subdomain != domain:
                    subdomains.append(subdomain)
            logging.info(f"Amass discovery: Found {len(subdomains)} subdomains for {domain}")
            return subdomains
        except ImportError:
            logging.warning("Amass integration not available, using mock data")
            return self.discover_subdomains(domain, use_mock=True)
    
    def analyze_subdomain(self, fqdn: str) -> Dict[str, Any]:
        """Perform comprehensive analysis of a subdomain."""
        logging.info(f"Analyzing subdomain: {fqdn}")
        
        analysis = {
            'fqdn': fqdn,
            'timestamp': datetime.now().isoformat(),
            'dns': {},
            'tls': {},
            'providers': [],
            'services': [],
            'risks': {}
        }
        
        # DNS Analysis
        try:
            analysis['dns'] = self._analyze_dns(fqdn)
        except Exception as e:
            logging.debug(f"DNS analysis failed for {fqdn}: {e}")
        
        # TLS Analysis
        try:
            analysis['tls'] = self.tls_analyzer.analyze_tls(fqdn)
        except Exception as e:
            logging.debug(f"TLS analysis failed for {fqdn}: {e}")
        
        # IP and Provider Analysis
        try:
            ip_addresses = analysis['dns'].get('a_records', [])
            for ip in ip_addresses:
                provider_info = self.ip_resolver.get_ip_info(ip)
                analysis['providers'].append(provider_info)
        except Exception as e:
            logging.debug(f"Provider analysis failed for {fqdn}: {e}")
        
        # Service Detection
        try:
            analysis['services'] = self._detect_services(fqdn)
        except Exception as e:
            logging.debug(f"Service detection failed for {fqdn}: {e}")
        
        # Risk Assessment
        try:
            analysis['risks'] = self.risk_calculator.calculate_subdomain_risk(analysis)
        except Exception as e:
            logging.debug(f"Risk calculation failed for {fqdn}: {e}")
        
        return analysis
    
    def _analyze_dns(self, fqdn: str) -> Dict[str, Any]:
        """Analyze DNS records."""
        if not HAS_DNS:
            return {}
            
        dns_info = {
            'a_records': [],
            'aaaa_records': [],
            'cname_records': [],
            'mx_records': [],
            'txt_records': []
        }
        
        resolver = dns.resolver.Resolver()
        
        for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'TXT']:
            try:
                answers = resolver.resolve(fqdn, record_type)
                records = [str(answer) for answer in answers]
                dns_info[f"{record_type.lower()}_records"] = records
            except dns.exception.DNSException:
                pass
            except Exception as e:
                logging.debug(f"DNS {record_type} lookup failed for {fqdn}: {e}")
        
        return dns_info
    
    def _detect_services(self, fqdn: str) -> List[Dict[str, Any]]:
        """Detect services based on subdomain patterns."""
        services = []
        
        service_patterns = {
            'web': ['www', 'web', 'site'],
            'api': ['api', 'rest', 'service'],
            'mail': ['mail', 'email', 'smtp', 'webmail'],
            'database': ['db', 'database', 'sql'],
            'cdn': ['cdn', 'static', 'assets'],
            'auth': ['auth', 'sso', 'login'],
            'admin': ['admin', 'manage', 'panel'],
            'test': ['test', 'staging', 'dev', 'qa'],
            'ftp': ['ftp', 'files', 'upload'],
            'monitoring': ['monitor', 'metrics', 'logs']
        }
        
        fqdn_parts = fqdn.lower().split('.')
        
        for service_type, patterns in service_patterns.items():
            for pattern in patterns:
                for part in fqdn_parts:
                    if pattern in part:
                        services.append({
                            'name': f"{service_type}_service",
                            'type': service_type,
                            'confidence': 0.8,
                            'detection_method': 'pattern_match',
                            'matched_pattern': pattern
                        })
                        break
        
        return services
    
    def store_analysis_results(self, analysis: Dict[str, Any]):
        """Store analysis results in Neo4j."""
        if not self.driver:
            logging.warning("Neo4j not available, skipping storage")
            return
        
        with self.driver.session() as session:
            with session.begin_transaction() as tx:
                fqdn = analysis['fqdn']
                current_time = datetime.now().isoformat()
                
                # Create subdomain node
                tx.run("""
                    MERGE (s:Subdomain {fqdn: $fqdn})
                    SET s.analyzed_at = $timestamp,
                        s.has_dns = $has_dns,
                        s.has_tls = $has_tls,
                        s.tls_grade = $tls_grade,
                        s.risk_level = $risk_level,
                        s.risk_score = $risk_score
                """, 
                fqdn=fqdn,
                timestamp=current_time,
                has_dns=bool(analysis.get('dns', {}).get('a_records')),
                has_tls=analysis.get('tls', {}).get('has_tls', False),
                tls_grade=analysis.get('tls', {}).get('tls_grade', 'F'),
                risk_level=analysis.get('risks', {}).get('risk_level', 'UNKNOWN'),
                risk_score=analysis.get('risks', {}).get('risk_score', 0))
                
                # Store providers
                for i, provider in enumerate(analysis.get('providers', [])):
                    provider_id = f"{fqdn}_provider_{i}"
                    tx.run("""
                        MERGE (p:Provider {id: $provider_id})
                        SET p.name = $name,
                            p.org = $org,
                            p.asn = $asn,
                            p.country = $country,
                            p.confidence = $confidence,
                            p.ip = $ip
                        WITH p
                        MATCH (s:Subdomain {fqdn: $fqdn})
                        MERGE (s)-[:USES_PROVIDER]->(p)
                    """, 
                    provider_id=provider_id,
                    name=provider.get('provider', 'unknown'),
                    org=provider.get('org', 'unknown'),
                    asn=provider.get('asn', 'unknown'),
                    country=provider.get('country', 'unknown'),
                    confidence=provider.get('confidence', 0.0),
                    ip=provider.get('ip', ''),
                    fqdn=fqdn)
                
                # Store services
                for i, service in enumerate(analysis.get('services', [])):
                    service_id = f"{fqdn}_service_{i}"
                    tx.run("""
                        MERGE (srv:Service {id: $service_id})
                        SET srv.name = $name,
                            srv.type = $type,
                            srv.confidence = $confidence,
                            srv.detection_method = $detection_method
                        WITH srv
                        MATCH (s:Subdomain {fqdn: $fqdn})
                        MERGE (s)-[:RUNS_SERVICE]->(srv)
                    """,
                    service_id=service_id,
                    name=service.get('name', 'unknown'),
                    type=service.get('type', 'unknown'),
                    confidence=service.get('confidence', 0.0),
                    detection_method=service.get('detection_method', 'unknown'),
                    fqdn=fqdn)
                
                # Store risk assessment
                risks = analysis.get('risks', {})
                if risks:
                    risk_id = f"{fqdn}_risk_{int(time.time())}"
                    tx.run("""
                        MERGE (r:Risk {risk_id: $risk_id})
                        SET r.fqdn = $fqdn,
                            r.risk_level = $risk_level,
                            r.risk_score = $risk_score,
                            r.risk_factors = $risk_factors,
                            r.assessment_date = $assessment_date
                        WITH r
                        MATCH (s:Subdomain {fqdn: $fqdn})
                        MERGE (s)-[:HAS_RISK]->(r)
                    """,
                    risk_id=risk_id,
                    fqdn=fqdn,
                    risk_level=risks.get('risk_level', 'UNKNOWN'),
                    risk_score=risks.get('risk_score', 0),
                    risk_factors=json.dumps(risks.get('risk_factors', [])),
                    assessment_date=current_time)
                
                tx.commit()
    
    def process_domains(self, domains: List[str], use_mock: bool = False, max_workers: int = 4) -> Dict[str, Any]:
        """Process multiple domains with comprehensive analysis."""
        start_time = time.time()
        total_domains = len(domains)
        total_subdomains = 0
        processed_subdomains = 0
        failed_subdomains = []
        
        logging.info(f"Starting enhanced analysis for {total_domains} domains")
        
        # Setup database
        self.setup_database_constraints()
        
        # Process each domain
        for domain in domains:
            try:
                # Discover subdomains
                subdomains = self.discover_subdomains(domain, use_mock)
                total_subdomains += len(subdomains)
                
                # Store base domain
                if self.driver:
                    with self.driver.session() as session:
                        session.run("""
                            MERGE (d:Domain {fqdn: $domain})
                            SET d.subdomain_count = $count,
                                d.last_analyzed = $timestamp
                        """, domain=domain, count=len(subdomains), timestamp=datetime.now().isoformat())
                
                # Analyze subdomains with threading
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    future_to_subdomain = {
                        executor.submit(self.analyze_subdomain, subdomain): subdomain 
                        for subdomain in subdomains
                    }
                    
                    for future in as_completed(future_to_subdomain):
                        subdomain = future_to_subdomain[future]
                        try:
                            analysis = future.result()
                            self.store_analysis_results(analysis)
                            processed_subdomains += 1
                            
                            # Log progress
                            if processed_subdomains % 10 == 0:
                                logging.info(f"Processed {processed_subdomains}/{total_subdomains} subdomains")
                                
                        except Exception as e:
                            logging.error(f"Failed to analyze {subdomain}: {e}")
                            failed_subdomains.append(subdomain)
                
                logging.info(f"Completed analysis for {domain}: {len(subdomains)} subdomains")
                
            except Exception as e:
                logging.error(f"Failed to process domain {domain}: {e}")
        
        end_time = time.time()
        duration = end_time - start_time
        
        results = {
            'total_domains': total_domains,
            'total_subdomains_discovered': total_subdomains,
            'subdomains_analyzed': processed_subdomains,
            'failed_subdomains': len(failed_subdomains),
            'processing_time': duration,
            'subdomains_per_second': processed_subdomains / duration if duration > 0 else 0
        }
        
        logging.info(f"Enhanced analysis completed: {results}")
        return results
    
    def generate_risk_report(self) -> Dict[str, Any]:
        """Generate comprehensive risk report."""
        if not self.driver:
            return {'error': 'Neo4j not available'}
        
        with self.driver.session() as session:
            # Get risk statistics
            risk_stats = session.run("""
                MATCH (r:Risk)
                RETURN r.risk_level as level, count(*) as count
                ORDER BY count DESC
            """).data()
            
            # Get high-risk subdomains
            high_risk = session.run("""
                MATCH (s:Subdomain)-[:HAS_RISK]->(r:Risk)
                WHERE r.risk_level IN ['HIGH', 'CRITICAL']
                RETURN s.fqdn as subdomain, r.risk_level as level, r.risk_score as score
                ORDER BY r.risk_score ASC
                LIMIT 20
            """).data()
            
            # Get TLS statistics
            tls_stats = session.run("""
                MATCH (s:Subdomain)
                RETURN s.tls_grade as grade, count(*) as count
                ORDER BY count DESC
            """).data()
            
            # Get provider statistics
            provider_stats = session.run("""
                MATCH (p:Provider)
                RETURN p.name as provider, count(*) as count
                ORDER BY count DESC
                LIMIT 10
            """).data()
            
            return {
                'risk_distribution': risk_stats,
                'high_risk_subdomains': high_risk,
                'tls_grade_distribution': tls_stats,
                'top_providers': provider_stats,
                'report_timestamp': datetime.now().isoformat()
            }
    
    def close(self):
        """Close database connection."""
        if self.driver:
            self.driver.close()

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Enhanced Subdomain Discovery and Risk Analysis")
    parser.add_argument("--domains", required=True, help="Domain list file")
    parser.add_argument("--bolt", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", required=True, help="Neo4j password")
    parser.add_argument("--ipinfo-token", help="IPInfo API token")
    parser.add_argument("--mock", action="store_true", help="Use mock data for testing")
    parser.add_argument("--workers", type=int, default=4, help="Number of worker threads")
    parser.add_argument("--report", action="store_true", help="Generate risk report")
    
    args = parser.parse_args()
    
    # Check dependencies
    if not HAS_NEO4J or not HAS_DNS or not HAS_REQUESTS:
        print("ERROR: Missing required dependencies")
        return 1
    
    # Read domains
    try:
        with open(args.domains, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        print(f"Loaded {len(domains)} domains from {args.domains}")
    except Exception as e:
        print(f"ERROR: Cannot read domains file: {e}")
        return 1
    
    # Initialize analyzer
    analyzer = EnhancedSubdomainAnalyzer(
        args.bolt,
        args.user, 
        args.password,
        args.ipinfo_token
    )
    
    try:
        # Process domains
        results = analyzer.process_domains(domains, args.mock, args.workers)
        print(f"\n🎯 Processing Results:")
        print(json.dumps(results, indent=2))
        
        # Generate report if requested
        if args.report:
            report = analyzer.generate_risk_report()
            print(f"\n📊 Risk Report:")
            print(json.dumps(report, indent=2))
        
        return 0
        
    except Exception as e:
        logging.error(f"Analysis failed: {e}")
        return 1
    finally:
        analyzer.close()

if __name__ == "__main__":
    sys.exit(main())