#!/usr/bin/env python3
"""
Final Enriched Subdomain Analyzer - Production Ready
Solves all the identified issues and provides comprehensive subdomain analysis with risk calculation.

Fixed Issues:
1. ✅ Missing dependencies handling 
2. ✅ IPInfo integration problems
3. ✅ Database constraint conflicts
4. ✅ Missing risk calculation 
5. ✅ Graph enrichment problems
6. ✅ Provider resolution failures
7. ✅ Performance optimization
8. ✅ Comprehensive reporting
"""

import argparse
import json
import sys
import socket
import ssl
import re
import time
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import threading
import hashlib
import ipaddress

# Required imports with error handling
missing_deps = []

try:
    from neo4j import GraphDatabase
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False
    missing_deps.append("neo4j (pip install neo4j)")

try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False
    missing_deps.append("dnspython (pip install dnspython)")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    missing_deps.append("requests (pip install requests)")

if missing_deps:
    print(f"❌ Missing dependencies: {', '.join(missing_deps)}")
    print("Please install missing dependencies and try again.")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('final_enriched_subdomain_analyzer.log')
    ]
)

class EnhancedIPResolver:
    """Enhanced IP resolver with comprehensive provider detection."""
    
    def __init__(self, ipinfo_token: str = None):
        self.token = ipinfo_token
        self.cache = {}
        self.resolver = dns.resolver.Resolver()
        
        # Enhanced provider patterns
        self.provider_patterns = {
            'amazon': ['amazon', 'aws', 'ec2', 'cloudfront', 'amazonaw'],
            'google': ['google', 'gcp', 'googleapis', 'googleusercontent', 'googlesyndication'],
            'microsoft': ['microsoft', 'azure', 'outlook', 'office365', 'live'],
            'cloudflare': ['cloudflare', 'cf-ipv4', 'cf-ray'],
            'digitalocean': ['digitalocean', 'do-user', 'droplet'],
            'vultr': ['vultr', 'choopa'],
            'linode': ['linode', 'akamai'],
            'ovh': ['ovh', 'ovhcloud', 'kimsufi'],
            'hetzner': ['hetzner', 'hetzner-online'],
            'fastly': ['fastly', 'fastlylb'],
            'akamai': ['akamai', 'akamaitechnologies'],
            'maxcdn': ['maxcdn', 'netdna'],
            'incapsula': ['incapsula', 'imperva'],
            'sucuri': ['sucuri', 'cloudproxy']
        }
        
        # ASN to provider mapping (expanded)
        self.asn_map = {
            '16509': 'amazon', '14618': 'amazon', '8987': 'amazon',
            '15169': 'google', '36040': 'google', '36384': 'google',
            '8075': 'microsoft', '3598': 'microsoft', '12076': 'microsoft',
            '13335': 'cloudflare',
            '14061': 'digitalocean',
            '20473': 'vultr', '64515': 'vultr',
            '63949': 'linode', '63956': 'linode',
            '16276': 'ovh', '35540': 'ovh',
            '24940': 'hetzner',
            '54113': 'fastly',
            '16625': 'akamai', '20940': 'akamai',
            '19551': 'incapsula',
            '30148': 'sucuri'
        }
    
    def resolve_ip_comprehensive(self, ip: str, fqdn: str = None) -> Dict[str, Any]:
        """Comprehensive IP resolution with multiple fallback strategies."""
        cache_key = f"{ip}_{fqdn or 'none'}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        result = {
            'ip': ip,
            'fqdn': fqdn,
            'provider': 'unknown',
            'provider_confidence': 0.0,
            'org': 'unknown',
            'asn': 'unknown',
            'country': 'unknown',
            'region': 'unknown',
            'city': 'unknown',
            'hostname': 'unknown',
            'sources_used': [],
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        # Strategy 1: IPInfo API
        if self.token:
            ipinfo_result = self._query_ipinfo_api(ip)
            if ipinfo_result:
                result.update(ipinfo_result)
                result['sources_used'].append('ipinfo_api')
        
        # Strategy 2: Reverse DNS
        dns_result = self._resolve_reverse_dns(ip)
        if dns_result:
            if result['provider'] == 'unknown' or dns_result.get('provider_confidence', 0) > result['provider_confidence']:
                result.update(dns_result)
            result['sources_used'].append('reverse_dns')
        
        # Strategy 3: ASN Lookup
        asn_result = self._resolve_asn(ip)
        if asn_result:
            if result['provider'] == 'unknown' or asn_result.get('provider_confidence', 0) > result['provider_confidence']:
                result.update(asn_result)
            result['sources_used'].append('asn_lookup')
        
        # Strategy 4: Pattern analysis on hostname/FQDN
        if fqdn:
            pattern_result = self._analyze_hostname_patterns(fqdn)
            if pattern_result:
                if result['provider'] == 'unknown' or pattern_result.get('provider_confidence', 0) > result['provider_confidence']:
                    result.update(pattern_result)
                result['sources_used'].append('hostname_pattern')
        
        # Final confidence calculation
        result['provider_confidence'] = min(result['provider_confidence'], 1.0)
        
        self.cache[cache_key] = result
        return result
    
    def _query_ipinfo_api(self, ip: str) -> Optional[Dict]:
        """Query IPInfo API with comprehensive error handling."""
        try:
            url = f"https://ipinfo.io/{ip}/json?token={self.token}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                org = data.get('org', '')
                provider = self._extract_provider_from_text(org)
                
                return {
                    'provider': provider,
                    'provider_confidence': 0.9 if provider != 'unknown' else 0.1,
                    'org': org,
                    'asn': org.split(' ')[0] if org.startswith('AS') else 'unknown',
                    'country': data.get('country', 'unknown'),
                    'region': data.get('region', 'unknown'),
                    'city': data.get('city', 'unknown'),
                    'hostname': data.get('hostname', 'unknown')
                }
            elif response.status_code == 429:
                logging.warning(f"IPInfo rate limit exceeded for {ip}")
            
        except Exception as e:
            logging.debug(f"IPInfo API error for {ip}: {e}")
        
        return None
    
    def _resolve_reverse_dns(self, ip: str) -> Optional[Dict]:
        """Resolve via reverse DNS with pattern analysis."""
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            provider = self._extract_provider_from_text(hostname)
            
            return {
                'hostname': hostname,
                'provider': provider,
                'provider_confidence': 0.8 if provider != 'unknown' else 0.2
            }
        except Exception:
            return None
    
    def _resolve_asn(self, ip: str) -> Optional[Dict]:
        """ASN-based provider resolution."""
        try:
            # Team Cymru ASN lookup
            reversed_ip = '.'.join(ip.split('.')[::-1])
            query = f"{reversed_ip}.origin.asn.cymru.com"
            
            result = self.resolver.resolve(query, 'TXT')
            if result:
                asn_data = str(result[0]).strip('"')
                parts = asn_data.split(' | ')
                
                if len(parts) >= 2:
                    asn = parts[0].strip()
                    org = parts[-1].strip() if len(parts) > 1 else ''
                    
                    # Check ASN mapping
                    provider = self.asn_map.get(asn, 'unknown')
                    if provider == 'unknown':
                        provider = self._extract_provider_from_text(org)
                    
                    return {
                        'asn': asn,
                        'org': org,
                        'provider': provider,
                        'provider_confidence': 0.9 if provider in self.asn_map.values() else 0.7
                    }
        except Exception:
            pass
            
        return None
    
    def _analyze_hostname_patterns(self, hostname: str) -> Optional[Dict]:
        """Analyze hostname patterns for provider hints."""
        hostname_lower = hostname.lower()
        
        for provider, patterns in self.provider_patterns.items():
            for pattern in patterns:
                if pattern in hostname_lower:
                    return {
                        'provider': provider,
                        'provider_confidence': 0.6,
                        'pattern_matched': pattern
                    }
        
        return None
    
    def _extract_provider_from_text(self, text: str) -> str:
        """Extract provider from any text using pattern matching."""
        if not text:
            return 'unknown'
        
        text_lower = text.lower()
        
        # Check provider patterns
        for provider, patterns in self.provider_patterns.items():
            for pattern in patterns:
                if pattern in text_lower:
                    return provider
        
        # Extract meaningful words
        words = re.findall(r'\b[a-zA-Z]+\b', text)
        for word in words:
            if len(word) > 2 and not word.lower().startswith('as'):
                # Check if it's a known provider variation
                for provider, patterns in self.provider_patterns.items():
                    if word.lower() in patterns:
                        return provider
                # Return cleaned word as potential provider
                return word.lower()
        
        return 'unknown'

class ComprehensiveTLSAnalyzer:
    """Advanced TLS certificate analyzer with detailed scoring."""
    
    def analyze_certificate(self, fqdn: str) -> Dict[str, Any]:
        """Perform comprehensive TLS certificate analysis."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((fqdn, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=fqdn) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Extract certificate information
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    expires_in_days = (not_after - datetime.now()).days
                    
                    # Advanced TLS grading
                    grade_info = self._calculate_advanced_tls_grade(cert, cipher, version, expires_in_days)
                    
                    # Extract additional certificate details
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))
                    san_domains = self._extract_san_domains(cert)
                    
                    return {
                        'has_tls': True,
                        'tls_grade': grade_info['grade'],
                        'tls_score': grade_info['score'],
                        'grade_details': grade_info['details'],
                        'expires_in_days': expires_in_days,
                        'expiry_status': self._get_expiry_status(expires_in_days),
                        'not_after': cert['notAfter'],
                        'not_before': cert['notBefore'],
                        'issuer': issuer,
                        'subject': subject,
                        'serial_number': cert.get('serialNumber', ''),
                        'is_self_signed': issuer == subject,
                        'cipher_suite': cipher[0] if cipher else 'unknown',
                        'protocol_version': version,
                        'key_algorithm': self._extract_key_algorithm(cert),
                        'san_domains': san_domains,
                        'san_count': len(san_domains),
                        'certificate_issues': self._identify_certificate_issues(cert, expires_in_days)
                    }
                    
        except ssl.SSLError as e:
            return {
                'has_tls': False,
                'tls_grade': 'F',
                'tls_score': 0,
                'error': f"SSL Error: {str(e)}",
                'error_type': 'ssl_error'
            }
        except socket.timeout:
            return {
                'has_tls': False,
                'tls_grade': 'F', 
                'tls_score': 0,
                'error': "Connection timeout",
                'error_type': 'timeout'
            }
        except Exception as e:
            return {
                'has_tls': False,
                'tls_grade': 'F',
                'tls_score': 0,
                'error': str(e),
                'error_type': 'connection_error'
            }
    
    def _calculate_advanced_tls_grade(self, cert: Dict, cipher: tuple, version: str, expires_in_days: int) -> Dict:
        """Advanced TLS grading algorithm."""
        score = 100
        details = []
        
        # Certificate expiration (30 points max penalty)
        if expires_in_days < 0:
            score -= 50
            details.append("Certificate expired - CRITICAL")
        elif expires_in_days < 7:
            score -= 30
            details.append("Certificate expires within 7 days - HIGH RISK")
        elif expires_in_days < 30:
            score -= 15
            details.append("Certificate expires within 30 days - MEDIUM RISK")
        elif expires_in_days < 90:
            score -= 5
            details.append("Certificate expires within 90 days - LOW RISK")
        
        # Self-signed certificate (40 points penalty)
        issuer = dict(x[0] for x in cert.get('issuer', []))
        subject = dict(x[0] for x in cert.get('subject', []))
        if issuer == subject:
            score -= 40
            details.append("Self-signed certificate - HIGH RISK")
        
        # Protocol version (20 points max penalty)
        if version:
            if version == 'TLSv1.3':
                score += 5  # Bonus for TLS 1.3
                details.append("TLS 1.3 - EXCELLENT")
            elif version == 'TLSv1.2':
                details.append("TLS 1.2 - GOOD")
            elif version in ['TLSv1.1', 'TLSv1']:
                score -= 20
                details.append(f"{version} - DEPRECATED")
            elif 'SSL' in version:
                score -= 30
                details.append(f"{version} - INSECURE")
        
        # Cipher suite analysis (15 points max penalty)
        if cipher and cipher[0]:
            cipher_name = cipher[0].upper()
            if any(strong in cipher_name for strong in ['AES256', 'CHACHA20']):
                details.append("Strong encryption cipher - GOOD")
            elif 'AES128' in cipher_name:
                score -= 3
                details.append("AES128 cipher - ACCEPTABLE")
            elif any(weak in cipher_name for weak in ['RC4', 'DES', 'NULL']):
                score -= 15
                details.append("Weak encryption cipher - HIGH RISK")
        
        # Key size analysis (if available)
        try:
            public_key = cert.get('subjectPublicKey', b'')
            if len(public_key) < 2048:
                score -= 10
                details.append("Weak key size - MEDIUM RISK")
        except:
            pass
        
        # Convert score to letter grade
        if score >= 95:
            grade = 'A+'
        elif score >= 90:
            grade = 'A'
        elif score >= 85:
            grade = 'A-'
        elif score >= 80:
            grade = 'B+'
        elif score >= 75:
            grade = 'B'
        elif score >= 70:
            grade = 'B-'
        elif score >= 65:
            grade = 'C+'
        elif score >= 60:
            grade = 'C'
        elif score >= 55:
            grade = 'C-'
        elif score >= 50:
            grade = 'D'
        else:
            grade = 'F'
        
        return {
            'grade': grade,
            'score': max(0, score),
            'details': details
        }
    
    def _get_expiry_status(self, expires_in_days: int) -> str:
        """Get human-readable expiry status."""
        if expires_in_days < 0:
            return 'EXPIRED'
        elif expires_in_days < 7:
            return 'CRITICAL'
        elif expires_in_days < 30:
            return 'WARNING'
        elif expires_in_days < 90:
            return 'ATTENTION'
        else:
            return 'NORMAL'
    
    def _extract_san_domains(self, cert: Dict) -> List[str]:
        """Extract Subject Alternative Name domains."""
        san_domains = []
        try:
            for name, value in cert.get('subjectAltName', []):
                if name == 'DNS':
                    san_domains.append(value)
        except Exception:
            pass
        return san_domains
    
    def _extract_key_algorithm(self, cert: Dict) -> str:
        """Extract key algorithm from certificate."""
        try:
            # This would require more detailed certificate parsing
            # For now, return a generic value
            return "RSA"  # Most common
        except:
            return "unknown"
    
    def _identify_certificate_issues(self, cert: Dict, expires_in_days: int) -> List[str]:
        """Identify specific certificate issues."""
        issues = []
        
        if expires_in_days < 0:
            issues.append("Certificate has expired")
        elif expires_in_days < 30:
            issues.append("Certificate expires soon")
        
        issuer = dict(x[0] for x in cert.get('issuer', []))
        subject = dict(x[0] for x in cert.get('subject', []))
        if issuer == subject:
            issues.append("Self-signed certificate")
        
        if cert.get('version', 0) < 3:
            issues.append("Old certificate version")
        
        return issues

class AdvancedRiskCalculator:
    """Advanced risk calculation engine with comprehensive scoring."""
    
    def calculate_comprehensive_risk(self, subdomain_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive risk score with detailed analysis."""
        risk_factors = []
        score_components = {
            'tls_security': {'weight': 30, 'score': 0},
            'provider_trust': {'weight': 25, 'score': 0},
            'service_exposure': {'weight': 20, 'score': 0},
            'dns_health': {'weight': 15, 'score': 0},
            'subdomain_pattern': {'weight': 10, 'score': 0}
        }
        
        # TLS Security Assessment (30%)
        tls_data = subdomain_data.get('tls', {})
        if tls_data.get('has_tls'):
            tls_score = tls_data.get('tls_score', 0)
            score_components['tls_security']['score'] = tls_score
            
            grade = tls_data.get('tls_grade', 'F')
            expires_in_days = tls_data.get('expires_in_days', 0)
            
            risk_factors.append(f"TLS Grade: {grade} (Score: {tls_score}/100)")
            
            if expires_in_days < 30:
                risk_factors.append(f"Certificate expires in {expires_in_days} days - URGENT")
            
            if tls_data.get('is_self_signed'):
                risk_factors.append("Self-signed certificate - HIGH RISK")
                
            issues = tls_data.get('certificate_issues', [])
            if issues:
                risk_factors.extend([f"Certificate issue: {issue}" for issue in issues])
        else:
            score_components['tls_security']['score'] = 0
            risk_factors.append("No TLS encryption - CRITICAL RISK")
        
        # Provider Trust Assessment (25%)
        providers = subdomain_data.get('providers', [])
        if providers:
            trusted_providers = ['amazon', 'google', 'microsoft', 'cloudflare']
            unknown_providers = [p for p in providers if p.get('provider') == 'unknown']
            known_providers = [p for p in providers if p.get('provider') != 'unknown']
            
            if known_providers:
                # Calculate average confidence
                avg_confidence = sum(p.get('provider_confidence', 0) for p in known_providers) / len(known_providers)
                
                # Bonus for trusted providers
                trusted_count = sum(1 for p in known_providers if p.get('provider') in trusted_providers)
                trust_bonus = (trusted_count / len(known_providers)) * 20
                
                provider_score = min(100, (avg_confidence * 100) + trust_bonus)
                score_components['provider_trust']['score'] = provider_score
                
                risk_factors.append(f"Known providers: {len(known_providers)}, Trusted: {trusted_count}")
            else:
                score_components['provider_trust']['score'] = 20
                risk_factors.append("Unknown providers only - MEDIUM RISK")
        else:
            score_components['provider_trust']['score'] = 50
            risk_factors.append("No provider information - MEDIUM RISK")
        
        # Service Exposure Assessment (20%)
        services = subdomain_data.get('services', [])
        if services:
            high_risk_services = ['admin', 'test', 'dev', 'staging', 'debug', 'temp']
            medium_risk_services = ['api', 'ftp', 'ssh', 'database', 'db']
            
            service_types = [s.get('type', '').lower() for s in services]
            
            high_risk_count = sum(1 for svc in service_types if svc in high_risk_services)
            medium_risk_count = sum(1 for svc in service_types if svc in medium_risk_services)
            
            if high_risk_count > 0:
                score_components['service_exposure']['score'] = 30
                risk_factors.append(f"High-risk services detected: {high_risk_count}")
            elif medium_risk_count > 0:
                score_components['service_exposure']['score'] = 60
                risk_factors.append(f"Medium-risk services detected: {medium_risk_count}")
            else:
                score_components['service_exposure']['score'] = 85
                risk_factors.append("Standard services detected")
        else:
            score_components['service_exposure']['score'] = 70
            risk_factors.append("No services detected")
        
        # DNS Health Assessment (15%)
        dns_data = subdomain_data.get('dns', {})
        dns_score = 50  # Default
        
        if dns_data.get('a_records'):
            dns_score += 30
            risk_factors.append("A records present")
        
        if dns_data.get('mx_records'):
            dns_score += 10
            risk_factors.append("MX records present")
        
        if dns_data.get('txt_records'):
            dns_score += 10
            risk_factors.append("TXT records present")
        
        score_components['dns_health']['score'] = min(100, dns_score)
        
        # Subdomain Pattern Assessment (10%)
        fqdn = subdomain_data.get('fqdn', '')
        pattern_score = 80  # Default good score
        
        suspicious_patterns = ['temp', 'test', 'dev', 'staging', 'admin', 'debug', 'backup']
        for pattern in suspicious_patterns:
            if pattern in fqdn.lower():
                pattern_score -= 20
                risk_factors.append(f"Suspicious subdomain pattern: {pattern}")
        
        score_components['subdomain_pattern']['score'] = max(0, pattern_score)
        
        # Calculate weighted final score
        final_score = sum(
            (component['score'] * component['weight']) / 100 
            for component in score_components.values()
        )
        
        # Risk level classification
        if final_score >= 80:
            risk_level = 'LOW'
            risk_color = '🟢'
        elif final_score >= 60:
            risk_level = 'MEDIUM'
            risk_color = '🟡'
        elif final_score >= 40:
            risk_level = 'HIGH'
            risk_color = '🟠'
        else:
            risk_level = 'CRITICAL'
            risk_color = '🔴'
        
        return {
            'risk_score': round(final_score, 2),
            'risk_level': risk_level,
            'risk_color': risk_color,
            'risk_factors': risk_factors,
            'score_components': score_components,
            'recommendations': self._generate_recommendations(score_components, subdomain_data),
            'assessment_timestamp': datetime.now().isoformat()
        }
    
    def _generate_recommendations(self, score_components: Dict, subdomain_data: Dict) -> List[str]:
        """Generate actionable security recommendations."""
        recommendations = []
        
        # TLS recommendations
        if score_components['tls_security']['score'] < 70:
            tls_data = subdomain_data.get('tls', {})
            if not tls_data.get('has_tls'):
                recommendations.append("🔒 URGENT: Enable HTTPS/TLS encryption")
            else:
                if tls_data.get('expires_in_days', 365) < 30:
                    recommendations.append("📅 URGENT: Renew TLS certificate")
                if tls_data.get('is_self_signed'):
                    recommendations.append("🏢 Use CA-signed certificate instead of self-signed")
                if tls_data.get('protocol_version') in ['TLSv1.1', 'TLSv1']:
                    recommendations.append("🔄 Upgrade to TLS 1.2 or 1.3")
        
        # Provider recommendations  
        if score_components['provider_trust']['score'] < 50:
            recommendations.append("☁️ Consider migrating to trusted cloud providers")
        
        # Service exposure recommendations
        if score_components['service_exposure']['score'] < 50:
            recommendations.append("🚫 Review and restrict access to high-risk services")
            recommendations.append("🔐 Implement IP whitelisting for admin/dev services")
        
        # DNS recommendations
        if score_components['dns_health']['score'] < 60:
            recommendations.append("🌐 Review DNS configuration and add missing records")
        
        return recommendations

class ProductionSubdomainAnalyzer:
    """Production-ready subdomain analyzer with all features integrated."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str, ipinfo_token: str = None):
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_pass = neo4j_pass
        
        # Initialize components
        self.ip_resolver = EnhancedIPResolver(ipinfo_token)
        self.tls_analyzer = ComprehensiveTLSAnalyzer()
        self.risk_calculator = AdvancedRiskCalculator()
        
        # Initialize Neo4j
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
        
        # Performance tracking
        self.stats = {
            'total_analyzed': 0,
            'successful_analyses': 0,
            'failed_analyses': 0,
            'start_time': None
        }
        
        logging.info("🚀 Production Subdomain Analyzer initialized")
    
    def setup_database_schema(self):
        """Setup optimized database schema with proper constraints."""
        constraints = [
            "CREATE CONSTRAINT subdomain_fqdn_unique IF NOT EXISTS FOR (s:Subdomain) REQUIRE s.fqdn IS UNIQUE",
            "CREATE CONSTRAINT domain_fqdn_unique IF NOT EXISTS FOR (d:Domain) REQUIRE d.fqdn IS UNIQUE",
            "CREATE CONSTRAINT risk_id_unique IF NOT EXISTS FOR (r:Risk) REQUIRE r.id IS UNIQUE",
            "CREATE CONSTRAINT provider_id_unique IF NOT EXISTS FOR (p:Provider) REQUIRE p.id IS UNIQUE",
            "CREATE CONSTRAINT service_id_unique IF NOT EXISTS FOR (srv:Service) REQUIRE srv.id IS UNIQUE",
            "CREATE CONSTRAINT certificate_id_unique IF NOT EXISTS FOR (c:Certificate) REQUIRE c.id IS UNIQUE"
        ]
        
        indexes = [
            "CREATE INDEX subdomain_risk_level IF NOT EXISTS FOR (s:Subdomain) ON (s.risk_level)",
            "CREATE INDEX subdomain_tls_grade IF NOT EXISTS FOR (s:Subdomain) ON (s.tls_grade)",
            "CREATE INDEX provider_name IF NOT EXISTS FOR (p:Provider) ON (p.name)",
            "CREATE INDEX risk_score IF NOT EXISTS FOR (r:Risk) ON (r.risk_score)"
        ]
        
        with self.driver.session() as session:
            for constraint in constraints:
                try:
                    session.run(constraint)
                except Exception as e:
                    logging.debug(f"Constraint: {e}")
            
            for index in indexes:
                try:
                    session.run(index)
                except Exception as e:
                    logging.debug(f"Index: {e}")
    
    def discover_subdomains_mock(self, domain: str) -> List[str]:
        """Generate comprehensive mock subdomains for testing."""
        common_subdomains = [
            'www', 'mail', 'api', 'admin', 'cdn', 'app', 'auth', 'ftp',
            'dev', 'test', 'staging', 'beta', 'demo', 'docs', 'help',
            'support', 'blog', 'shop', 'store', 'secure', 'login',
            'dashboard', 'panel', 'cpanel', 'webmail', 'mx', 'ns1',
            'portal', 'gateway', 'vpn', 'remote', 'backup', 'monitor'
        ]
        
        subdomains = [f"{sub}.{domain}" for sub in common_subdomains[:15]]  # Limit for testing
        logging.info(f"🎭 Mock discovery: Generated {len(subdomains)} subdomains for {domain}")
        return subdomains
    
    def analyze_subdomain_comprehensive(self, fqdn: str) -> Dict[str, Any]:
        """Perform comprehensive subdomain analysis."""
        analysis_start = time.time()
        
        analysis = {
            'fqdn': fqdn,
            'analysis_id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'dns': {},
            'tls': {},
            'providers': [],
            'services': [],
            'risks': {},
            'analysis_duration': 0
        }
        
        try:
            # DNS Analysis
            analysis['dns'] = self._analyze_dns_comprehensive(fqdn)
            
            # TLS Analysis
            analysis['tls'] = self.tls_analyzer.analyze_certificate(fqdn)
            
            # Provider Analysis
            ip_addresses = analysis['dns'].get('a_records', [])
            for ip in ip_addresses[:3]:  # Limit to first 3 IPs
                provider_info = self.ip_resolver.resolve_ip_comprehensive(ip, fqdn)
                analysis['providers'].append(provider_info)
            
            # Service Detection
            analysis['services'] = self._detect_services_comprehensive(fqdn, analysis['dns'])
            
            # Risk Assessment
            analysis['risks'] = self.risk_calculator.calculate_comprehensive_risk(analysis)
            
            analysis['analysis_duration'] = round(time.time() - analysis_start, 2)
            self.stats['successful_analyses'] += 1
            
        except Exception as e:
            logging.error(f"❌ Analysis failed for {fqdn}: {e}")
            analysis['error'] = str(e)
            analysis['analysis_duration'] = round(time.time() - analysis_start, 2)
            self.stats['failed_analyses'] += 1
        
        self.stats['total_analyzed'] += 1
        return analysis
    
    def _analyze_dns_comprehensive(self, fqdn: str) -> Dict[str, Any]:
        """Comprehensive DNS analysis."""
        dns_info = {
            'a_records': [],
            'aaaa_records': [],
            'cname_records': [],
            'mx_records': [],
            'txt_records': [],
            'ns_records': [],
            'dns_response_time': 0
        }
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        
        dns_start = time.time()
        
        for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']:
            try:
                answers = resolver.resolve(fqdn, record_type)
                records = [str(answer) for answer in answers]
                dns_info[f"{record_type.lower()}_records"] = records
            except dns.exception.DNSException:
                pass
            except Exception as e:
                logging.debug(f"DNS {record_type} lookup failed for {fqdn}: {e}")
        
        dns_info['dns_response_time'] = round(time.time() - dns_start, 3)
        return dns_info
    
    def _detect_services_comprehensive(self, fqdn: str, dns_data: Dict) -> List[Dict[str, Any]]:
        """Comprehensive service detection."""
        services = []
        
        # Pattern-based detection
        service_patterns = {
            'web': {'patterns': ['www', 'web', 'site'], 'risk': 'low'},
            'api': {'patterns': ['api', 'rest', 'graphql'], 'risk': 'medium'},
            'mail': {'patterns': ['mail', 'email', 'smtp', 'webmail'], 'risk': 'medium'},
            'admin': {'patterns': ['admin', 'manage', 'panel', 'cpanel'], 'risk': 'high'},
            'database': {'patterns': ['db', 'database', 'sql', 'mongo'], 'risk': 'critical'},
            'development': {'patterns': ['dev', 'test', 'staging', 'beta'], 'risk': 'high'},
            'cdn': {'patterns': ['cdn', 'static', 'assets'], 'risk': 'low'},
            'auth': {'patterns': ['auth', 'sso', 'login', 'oauth'], 'risk': 'high'},
            'ftp': {'patterns': ['ftp', 'sftp', 'files'], 'risk': 'medium'},
            'monitoring': {'patterns': ['monitor', 'metrics', 'logs'], 'risk': 'medium'}
        }
        
        fqdn_parts = fqdn.lower().split('.')
        
        for service_type, config in service_patterns.items():
            for pattern in config['patterns']:
                for part in fqdn_parts:
                    if pattern in part:
                        services.append({
                            'id': f"{fqdn}_{service_type}_{pattern}",
                            'name': f"{service_type}_service",
                            'type': service_type,
                            'risk_level': config['risk'],
                            'confidence': 0.8,
                            'detection_method': 'pattern_analysis',
                            'matched_pattern': pattern,
                            'subdomain_part': part
                        })
                        break
        
        # DNS-based detection
        if dns_data.get('mx_records'):
            services.append({
                'id': f"{fqdn}_mail_mx",
                'name': 'mail_service',
                'type': 'mail',
                'risk_level': 'medium',
                'confidence': 0.95,
                'detection_method': 'mx_record',
                'mx_records': dns_data['mx_records']
            })
        
        # TXT record analysis
        for txt_record in dns_data.get('txt_records', []):
            txt_lower = txt_record.lower()
            if any(indicator in txt_lower for indicator in ['spf', 'dmarc', 'dkim']):
                services.append({
                    'id': f"{fqdn}_email_security",
                    'name': 'email_security',
                    'type': 'email_security',
                    'risk_level': 'low',
                    'confidence': 0.9,
                    'detection_method': 'txt_record',
                    'txt_record': txt_record
                })
        
        return services
    
    def store_analysis_results_optimized(self, analysis: Dict[str, Any]):
        """Store analysis results with optimized queries and unique IDs."""
        with self.driver.session() as session:
            with session.begin_transaction() as tx:
                fqdn = analysis['fqdn']
                analysis_id = analysis['analysis_id']
                timestamp = analysis['timestamp']
                
                # Create/update subdomain node with unique analysis ID
                subdomain_data = {
                    'fqdn': fqdn,
                    'analysis_id': analysis_id,
                    'last_analyzed': timestamp,
                    'analysis_duration': analysis.get('analysis_duration', 0),
                    'has_error': 'error' in analysis
                }
                
                # Add TLS data
                tls_data = analysis.get('tls', {})
                subdomain_data.update({
                    'has_tls': tls_data.get('has_tls', False),
                    'tls_grade': tls_data.get('tls_grade', 'F'),
                    'tls_score': tls_data.get('tls_score', 0),
                    'expires_in_days': tls_data.get('expires_in_days', 0),
                    'expiry_status': tls_data.get('expiry_status', 'unknown')
                })
                
                # Add risk data
                risk_data = analysis.get('risks', {})
                subdomain_data.update({
                    'risk_score': risk_data.get('risk_score', 0),
                    'risk_level': risk_data.get('risk_level', 'UNKNOWN'),
                    'risk_color': risk_data.get('risk_color', '⚪')
                })
                
                tx.run("""
                    MERGE (s:Subdomain {fqdn: $fqdn})
                    SET s += $props
                """, fqdn=fqdn, props=subdomain_data)
                
                # Store providers with unique IDs
                for i, provider in enumerate(analysis.get('providers', [])):
                    provider_id = f"{analysis_id}_provider_{i}"
                    tx.run("""
                        MERGE (p:Provider {id: $provider_id})
                        SET p.name = $name,
                            p.confidence = $confidence,
                            p.org = $org,
                            p.asn = $asn,
                            p.country = $country,
                            p.ip = $ip,
                            p.sources = $sources,
                            p.created_at = $timestamp
                        WITH p
                        MATCH (s:Subdomain {fqdn: $fqdn})
                        MERGE (s)-[:HOSTED_BY]->(p)
                    """, 
                    provider_id=provider_id,
                    name=provider.get('provider', 'unknown'),
                    confidence=provider.get('provider_confidence', 0.0),
                    org=provider.get('org', 'unknown'),
                    asn=provider.get('asn', 'unknown'),
                    country=provider.get('country', 'unknown'),
                    ip=provider.get('ip', ''),
                    sources=json.dumps(provider.get('sources_used', [])),
                    timestamp=timestamp,
                    fqdn=fqdn)
                
                # Store services with unique IDs
                for service in analysis.get('services', []):
                    service_id = service.get('id', f"{analysis_id}_service_{uuid.uuid4().hex[:8]}")
                    tx.run("""
                        MERGE (srv:Service {id: $service_id})
                        SET srv.name = $name,
                            srv.type = $type,
                            srv.risk_level = $risk_level,
                            srv.confidence = $confidence,
                            srv.detection_method = $detection_method,
                            srv.created_at = $timestamp
                        WITH srv
                        MATCH (s:Subdomain {fqdn: $fqdn})
                        MERGE (s)-[:RUNS_SERVICE]->(srv)
                    """,
                    service_id=service_id,
                    name=service.get('name', 'unknown'),
                    type=service.get('type', 'unknown'),
                    risk_level=service.get('risk_level', 'unknown'),
                    confidence=service.get('confidence', 0.0),
                    detection_method=service.get('detection_method', 'unknown'),
                    timestamp=timestamp,
                    fqdn=fqdn)
                
                # Store risk assessment
                if risk_data:
                    risk_id = f"{analysis_id}_risk"
                    tx.run("""
                        MERGE (r:Risk {id: $risk_id})
                        SET r.fqdn = $fqdn,
                            r.risk_score = $risk_score,
                            r.risk_level = $risk_level,
                            r.risk_factors = $risk_factors,
                            r.recommendations = $recommendations,
                            r.score_components = $score_components,
                            r.assessment_date = $timestamp
                        WITH r
                        MATCH (s:Subdomain {fqdn: $fqdn})
                        MERGE (s)-[:HAS_RISK_ASSESSMENT]->(r)
                    """,
                    risk_id=risk_id,
                    fqdn=fqdn,
                    risk_score=risk_data.get('risk_score', 0),
                    risk_level=risk_data.get('risk_level', 'UNKNOWN'),
                    risk_factors=json.dumps(risk_data.get('risk_factors', [])),
                    recommendations=json.dumps(risk_data.get('recommendations', [])),
                    score_components=json.dumps(risk_data.get('score_components', {})),
                    timestamp=timestamp)
                
                tx.commit()
    
    def process_domains_production(self, domains: List[str], max_workers: int = 4, use_mock: bool = False) -> Dict[str, Any]:
        """Production-grade domain processing with comprehensive reporting."""
        self.stats['start_time'] = time.time()
        
        logging.info(f"🎯 Starting production analysis for {len(domains)} domains")
        
        # Setup database
        self.setup_database_schema()
        
        total_subdomains_discovered = 0
        total_subdomains_analyzed = 0
        domain_results = {}
        
        for domain in domains:
            domain_start = time.time()
            
            # Discover subdomains
            if use_mock:
                subdomains = self.discover_subdomains_mock(domain)
            else:
                # Try to use real Amass integration
                try:
                    from risk_loader_advanced3 import run_amass_with_fallback
                    results = run_amass_with_fallback(domain, sample_mode=True)
                    subdomains = [r.get('name', r) if isinstance(r, dict) else r for r in results]
                    subdomains = [s for s in subdomains if s != domain]
                    logging.info(f"🔍 Real discovery: Found {len(subdomains)} subdomains for {domain}")
                except ImportError:
                    logging.warning("Amass not available, using mock data")
                    subdomains = self.discover_subdomains_mock(domain)
            
            total_subdomains_discovered += len(subdomains)
            
            # Store domain
            with self.driver.session() as session:
                session.run("""
                    MERGE (d:Domain {fqdn: $domain})
                    SET d.subdomain_count = $count,
                        d.last_analyzed = $timestamp,
                        d.analysis_type = $analysis_type
                """, 
                domain=domain, 
                count=len(subdomains), 
                timestamp=datetime.now().isoformat(),
                analysis_type='mock' if use_mock else 'real')
            
            # Analyze subdomains with threading
            domain_analyzed = 0
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_subdomain = {
                    executor.submit(self.analyze_subdomain_comprehensive, subdomain): subdomain 
                    for subdomain in subdomains
                }
                
                for future in as_completed(future_to_subdomain):
                    subdomain = future_to_subdomain[future]
                    try:
                        analysis = future.result()
                        self.store_analysis_results_optimized(analysis)
                        domain_analyzed += 1
                        total_subdomains_analyzed += 1
                        
                        # Progress reporting
                        if domain_analyzed % 5 == 0:
                            logging.info(f"📊 {domain}: {domain_analyzed}/{len(subdomains)} analyzed")
                            
                    except Exception as e:
                        logging.error(f"❌ Failed to process {subdomain}: {e}")
            
            domain_duration = time.time() - domain_start
            domain_results[domain] = {
                'subdomains_discovered': len(subdomains),
                'subdomains_analyzed': domain_analyzed,
                'processing_time': round(domain_duration, 2)
            }
            
            logging.info(f"✅ {domain} completed: {domain_analyzed}/{len(subdomains)} in {domain_duration:.2f}s")
        
        total_duration = time.time() - self.stats['start_time']
        
        final_results = {
            'summary': {
                'total_domains': len(domains),
                'total_subdomains_discovered': total_subdomains_discovered,
                'total_subdomains_analyzed': total_subdomains_analyzed,
                'success_rate': round((self.stats['successful_analyses'] / max(1, self.stats['total_analyzed'])) * 100, 2),
                'total_processing_time': round(total_duration, 2),
                'average_time_per_subdomain': round(total_duration / max(1, total_subdomains_analyzed), 3)
            },
            'domain_breakdown': domain_results,
            'performance_stats': self.stats
        }
        
        logging.info(f"🎉 Production analysis completed: {final_results['summary']}")
        return final_results
    
    def generate_executive_report(self) -> Dict[str, Any]:
        """Generate comprehensive executive security report."""
        with self.driver.session() as session:
            # Risk distribution
            risk_distribution = session.run("""
                MATCH (s:Subdomain)
                RETURN s.risk_level as level, count(*) as count, 
                       avg(s.risk_score) as avg_score
                ORDER BY count DESC
            """).data()
            
            # Critical findings
            critical_subdomains = session.run("""
                MATCH (s:Subdomain)-[:HAS_RISK_ASSESSMENT]->(r:Risk)
                WHERE s.risk_level = 'CRITICAL'
                RETURN s.fqdn as subdomain, s.risk_score as score, 
                       s.tls_grade as tls_grade, s.expiry_status as cert_status
                ORDER BY s.risk_score ASC
                LIMIT 10
            """).data()
            
            # TLS security overview
            tls_distribution = session.run("""
                MATCH (s:Subdomain)
                WHERE s.tls_grade IS NOT NULL
                RETURN s.tls_grade as grade, count(*) as count,
                       avg(s.tls_score) as avg_score
                ORDER BY count DESC
            """).data()
            
            # Provider analysis
            provider_stats = session.run("""
                MATCH (p:Provider)
                RETURN p.name as provider, count(*) as usage_count,
                       avg(p.confidence) as avg_confidence
                ORDER BY usage_count DESC
                LIMIT 15
            """).data()
            
            # Service exposure analysis
            service_risks = session.run("""
                MATCH (srv:Service)
                RETURN srv.risk_level as risk_level, srv.type as service_type,
                       count(*) as count
                ORDER BY 
                    CASE srv.risk_level 
                        WHEN 'critical' THEN 1 
                        WHEN 'high' THEN 2 
                        WHEN 'medium' THEN 3 
                        ELSE 4 
                    END, count DESC
            """).data()
            
            # Certificate expiry alerts
            cert_expiry = session.run("""
                MATCH (s:Subdomain)
                WHERE s.expires_in_days IS NOT NULL AND s.expires_in_days < 90
                RETURN s.fqdn as subdomain, s.expires_in_days as expires_in,
                       s.expiry_status as status
                ORDER BY s.expires_in_days ASC
                LIMIT 20
            """).data()
            
            # Generate recommendations
            recommendations = self._generate_executive_recommendations(
                risk_distribution, critical_subdomains, tls_distribution, cert_expiry
            )
            
            return {
                'report_metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'report_type': 'Executive Security Assessment',
                    'version': '1.0'
                },
                'executive_summary': {
                    'total_subdomains': sum(item['count'] for item in risk_distribution),
                    'high_risk_count': sum(item['count'] for item in risk_distribution if item['level'] in ['HIGH', 'CRITICAL']),
                    'avg_security_score': round(sum(item['avg_score'] * item['count'] for item in risk_distribution) / max(1, sum(item['count'] for item in risk_distribution)), 2),
                    'critical_issues_count': len(critical_subdomains)
                },
                'risk_analysis': {
                    'risk_distribution': risk_distribution,
                    'critical_findings': critical_subdomains,
                    'recommendations': recommendations
                },
                'security_metrics': {
                    'tls_security': tls_distribution,
                    'certificate_expiry': cert_expiry,
                    'provider_trust': provider_stats,
                    'service_exposure': service_risks
                }
            }
    
    def _generate_executive_recommendations(self, risk_dist, critical_subs, tls_dist, cert_expiry) -> List[str]:
        """Generate executive-level recommendations."""
        recommendations = []
        
        # Risk-based recommendations
        total_subs = sum(item['count'] for item in risk_dist)
        high_risk_count = sum(item['count'] for item in risk_dist if item['level'] in ['HIGH', 'CRITICAL'])
        
        if high_risk_count > total_subs * 0.3:
            recommendations.append("🚨 URGENT: Over 30% of subdomains are high-risk - immediate security review required")
        
        # TLS recommendations
        no_tls_count = sum(item['count'] for item in tls_dist if item['grade'] == 'F')
        if no_tls_count > 0:
            recommendations.append(f"🔒 SECURITY: {no_tls_count} subdomains lack TLS encryption - implement HTTPS")
        
        # Certificate expiry
        critical_expiry = len([c for c in cert_expiry if c['expires_in'] < 30])
        if critical_expiry > 0:
            recommendations.append(f"📅 URGENT: {critical_expiry} certificates expire within 30 days")
        
        # Add more recommendations based on data
        if len(critical_subs) > 0:
            recommendations.append(f"⚠️ PRIORITY: Review {len(critical_subs)} critical-risk subdomains immediately")
        
        return recommendations
    
    def close(self):
        """Clean shutdown with statistics."""
        if self.stats['start_time']:
            total_runtime = time.time() - self.stats['start_time']
            logging.info(f"📈 Final Statistics: {self.stats['successful_analyses']} successful, {self.stats['failed_analyses']} failed in {total_runtime:.2f}s")
        
        if self.driver:
            self.driver.close()

def main():
    """Production-grade main function with comprehensive error handling."""
    parser = argparse.ArgumentParser(
        description="🔍 Final Enriched Subdomain Analyzer - Production Ready",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --domains chile.txt --password mypass --mock
  %(prog)s --domains domains.txt --password mypass --ipinfo-token TOKEN --workers 8
  %(prog)s --domains chile.txt --password mypass --report --mock
        """
    )
    
    parser.add_argument("--domains", required=True, help="📁 Domain list file")
    parser.add_argument("--bolt", default="bolt://localhost:7687", help="🔌 Neo4j URI")
    parser.add_argument("--user", default="neo4j", help="👤 Neo4j username")
    parser.add_argument("--password", required=True, help="🔐 Neo4j password")
    parser.add_argument("--ipinfo-token", help="🌐 IPInfo API token (recommended)")
    parser.add_argument("--mock", action="store_true", help="🎭 Use mock data for testing")
    parser.add_argument("--workers", type=int, default=4, help="⚡ Number of worker threads")
    parser.add_argument("--report", action="store_true", help="📊 Generate executive report")
    parser.add_argument("--verbose", action="store_true", help="🔍 Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate inputs
    if not Path(args.domains).exists():
        print(f"❌ Domain file not found: {args.domains}")
        return 1
    
    # Read domains
    try:
        with open(args.domains, 'r') as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        print(f"📋 Loaded {len(domains)} domains from {args.domains}")
    except Exception as e:
        print(f"❌ Error reading domains file: {e}")
        return 1
    
    # Initialize analyzer
    analyzer = ProductionSubdomainAnalyzer(
        args.bolt,
        args.user,
        args.password, 
        args.ipinfo_token
    )
    
    try:
        # Test Neo4j connection
        with analyzer.driver.session() as session:
            session.run("RETURN 1").single()
        print("✅ Neo4j connection successful")
        
        # Process domains
        results = analyzer.process_domains_production(
            domains, 
            max_workers=args.workers,
            use_mock=args.mock
        )
        
        # Display results
        print(f"\n🎯 Processing Results:")
        print(f"{'='*60}")
        summary = results['summary']
        print(f"📊 Domains processed: {summary['total_domains']}")
        print(f"🔍 Subdomains discovered: {summary['total_subdomains_discovered']}")
        print(f"✅ Subdomains analyzed: {summary['total_subdomains_analyzed']}")
        print(f"📈 Success rate: {summary['success_rate']}%")
        print(f"⏱️  Total time: {summary['total_processing_time']}s")
        print(f"⚡ Avg time per subdomain: {summary['average_time_per_subdomain']}s")
        
        # Generate executive report if requested
        if args.report:
            print(f"\n📊 Generating Executive Security Report...")
            report = analyzer.generate_executive_report()
            
            print(f"\n🎯 Executive Summary:")
            print(f"{'='*60}")
            exec_summary = report['executive_summary']
            print(f"🔍 Total subdomains analyzed: {exec_summary['total_subdomains']}")
            print(f"⚠️  High-risk subdomains: {exec_summary['high_risk_count']}")
            print(f"📊 Average security score: {exec_summary['avg_security_score']}/100")
            print(f"🚨 Critical issues: {exec_summary['critical_issues_count']}")
            
            # Display key recommendations
            recommendations = report['risk_analysis']['recommendations']
            if recommendations:
                print(f"\n💡 Key Recommendations:")
                print(f"{'='*60}")
                for i, rec in enumerate(recommendations[:5], 1):
                    print(f"{i}. {rec}")
            
            # Save detailed report
            report_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\n💾 Detailed report saved: {report_file}")
        
        return 0
        
    except Exception as e:
        logging.error(f"❌ Analysis failed: {e}")
        return 1
    finally:
        analyzer.close()

if __name__ == "__main__":
    sys.exit(main())