#!/usr/bin/env python3
"""
Complete Subdomain Fix - Resolves issues with services, providers, and TLS for all subdomains

This script addresses the following issues:
1. Missing services and providers for subdomains
2. Missing TLS certificate analysis for subdomains
3. Incomplete risk calculation for subdomain nodes
4. Missing relationships between subdomains and their dependencies

The script performs:
- SSL/TLS certificate analysis for all subdomains
- Service and provider detection
- Proper relationship creation in Neo4j
- Risk score calculation updates
"""

import ssl
import socket
import dns.resolver
import requests
import json
import time
import random
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from neo4j import GraphDatabase
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from dataclasses import dataclass
import ipaddress

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('subdomain_fix.log')
    ]
)

logger = logging.getLogger(__name__)

@dataclass
class SubdomainInfo:
    fqdn: str
    ip_addresses: List[str]
    services: List[Dict[str, Any]]
    providers: List[Dict[str, Any]]
    tls_info: Optional[Dict[str, Any]]
    dns_info: Dict[str, Any]

class SubdomainAnalyzer:
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str):
        self.drv = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
        
    def get_all_subdomains(self) -> List[str]:
        """Get all subdomains from Neo4j."""
        with self.drv.session() as session:
            result = session.run("""
                MATCH (s:Subdomain)
                RETURN s.fqdn as fqdn
                ORDER BY s.fqdn
            """)
            return [record["fqdn"] for record in result]
    
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
            logger.warning(f"TLS analysis failed for {fqdn}: {e}")
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
            except dns.resolver.NXDOMAIN:
                pass
            except Exception:
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
            logger.warning(f"DNS analysis failed for {fqdn}: {e}")
        
        return dns_info
    
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
                logger.warning(f"Provider detection failed for IP {ip}: {e}")
        
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
    
    def update_subdomain_in_neo4j(self, subdomain_info: SubdomainInfo):
        """Update subdomain information in Neo4j."""
        with self.drv.session() as session:
            with session.begin_transaction() as tx:
                try:
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
                            s.analysis_version = 'v2.0'
                    """, 
                    fqdn=subdomain_info.fqdn,
                    has_tls=subdomain_info.tls_info.get('has_tls', False) if subdomain_info.tls_info else False,
                    tls_grade=subdomain_info.tls_info.get('tls_grade', 'Unknown') if subdomain_info.tls_info else 'Unknown',
                    expires_in_days=subdomain_info.tls_info.get('expires_in_days', 0) if subdomain_info.tls_info else 0,
                    a_records=subdomain_info.dns_info.get('a_records', []),
                    has_spf=subdomain_info.dns_info.get('has_spf', False),
                    has_dmarc=subdomain_info.dns_info.get('has_dmarc', False)
                    )
                    
                    # Create or update Certificate node if TLS info exists
                    if subdomain_info.tls_info and subdomain_info.tls_info.get('has_tls'):
                        tls = subdomain_info.tls_info
                        cert_id = f"{subdomain_info.fqdn}_{tls.get('serial_number', 'unknown')}"
                        
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
                        fqdn=subdomain_info.fqdn,
                        cert_id=cert_id,
                        tls_grade=tls.get('tls_grade', 'Unknown'),
                        expires_in_days=tls.get('expires_in_days', 0),
                        not_after=tls.get('not_after', ''),
                        not_before=tls.get('not_before', ''),
                        issuer=json.dumps(tls.get('issuer', {})),
                        subject=json.dumps(tls.get('subject', {})),
                        serial_number=tls.get('serial_number', ''),
                        is_self_signed=tls.get('is_self_signed', False),
                        cipher_suite=tls.get('cipher_suite', ''),
                        tls_version=tls.get('tls_version', '')
                        )
                    
                    # Create Service nodes and relationships
                    for service in subdomain_info.services:
                        service_id = f"{subdomain_info.fqdn}_{service['name']}"
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
                        fqdn=subdomain_info.fqdn,
                        service_id=service_id,
                        service_name=service['name'],
                        service_type=service['type'],
                        source=service['source'],
                        confidence=service['confidence'],
                        subdomain=service.get('subdomain', subdomain_info.fqdn),
                        port=service.get('port', 0)
                        )
                    
                    # Create Provider nodes and relationships
                    for i, provider in enumerate(subdomain_info.providers):
                        provider_id = f"{subdomain_info.fqdn}_provider_{i}_{int(time.time())}"
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
                        fqdn=subdomain_info.fqdn,
                        provider_id=provider_id,
                        provider_name=provider['name'],
                        provider_type=provider['type'],
                        source=provider['source'],
                        confidence=provider['confidence'],
                        ip=provider.get('ip', ''),
                        asn=provider.get('asn', ''),
                        country=provider.get('country', ''),
                        subdomain=provider.get('subdomain', subdomain_info.fqdn)
                        )
                    
                    tx.commit()
                    logger.info(f"✓ Updated {subdomain_info.fqdn}: {len(subdomain_info.services)} services, {len(subdomain_info.providers)} providers")
                    
                except Exception as e:
                    logger.error(f"Failed to update {subdomain_info.fqdn}: {e}")
                    tx.rollback()
    
    def analyze_single_subdomain(self, fqdn: str) -> SubdomainInfo:
        """Analyze a single subdomain comprehensively."""
        logger.info(f"Analyzing subdomain: {fqdn}")
        
        # Get IP addresses from DNS
        dns_info = self.analyze_subdomain_dns(fqdn)
        ip_addresses = dns_info.get('a_records', [])
        
        # Analyze TLS
        tls_info = self.analyze_subdomain_tls(fqdn)
        
        # Detect services and providers
        services, providers = self.detect_services_and_providers(fqdn, ip_addresses)
        
        return SubdomainInfo(
            fqdn=fqdn,
            ip_addresses=ip_addresses,
            services=services,
            providers=providers,
            tls_info=tls_info,
            dns_info=dns_info
        )
    
    def process_all_subdomains(self, max_workers: int = 10):
        """Process all subdomains with parallel execution."""
        subdomains = self.get_all_subdomains()
        logger.info(f"Found {len(subdomains)} subdomains to process")
        
        processed = 0
        failed = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all analysis tasks
            future_to_fqdn = {
                executor.submit(self.analyze_single_subdomain, fqdn): fqdn 
                for fqdn in subdomains
            }
            
            # Process completed analyses
            for future in as_completed(future_to_fqdn):
                fqdn = future_to_fqdn[future]
                try:
                    subdomain_info = future.result()
                    self.update_subdomain_in_neo4j(subdomain_info)
                    processed += 1
                    
                    if processed % 10 == 0:
                        logger.info(f"Progress: {processed}/{len(subdomains)} subdomains processed")
                        
                except Exception as e:
                    logger.error(f"Failed to process {fqdn}: {e}")
                    failed += 1
        
        logger.info(f"Processing complete. Processed: {processed}, Failed: {failed}")
        return processed, failed
    
    def update_subdomain_risk_scores(self):
        """Update risk scores for all subdomains based on new analysis."""
        with self.drv.session() as session:
            result = session.run("""
                MATCH (s:Subdomain)
                WHERE s.analysis_version = 'v2.0'
                WITH s, 
                     CASE WHEN s.tls_grade = 'F' THEN 20
                          WHEN s.tls_grade = 'D' THEN 15
                          WHEN s.tls_grade = 'C' THEN 10
                          WHEN s.tls_grade = 'B' THEN 5
                          WHEN s.tls_grade IN ['A', 'A+'] THEN 0
                          ELSE 10 END as tls_risk,
                     CASE WHEN s.has_tls = false THEN 25 ELSE 0 END as no_tls_risk,
                     CASE WHEN s.dns_has_spf = false THEN 5 ELSE 0 END as spf_risk,
                     CASE WHEN s.dns_has_dmarc = false THEN 5 ELSE 0 END as dmarc_risk,
                     CASE WHEN s.tls_expires_in_days < 30 THEN 15
                          WHEN s.tls_expires_in_days < 90 THEN 5
                          ELSE 0 END as expiry_risk
                
                WITH s, (tls_risk + no_tls_risk + spf_risk + dmarc_risk + expiry_risk) as base_risk_score
                
                SET s.risk_score = CASE 
                    WHEN base_risk_score >= 80 THEN 90 + (base_risk_score - 80) * 0.1
                    ELSE base_risk_score END,
                s.risk_tier = CASE 
                    WHEN base_risk_score >= 80 THEN 'Critical'
                    WHEN base_risk_score >= 60 THEN 'High'
                    WHEN base_risk_score >= 40 THEN 'Medium'
                    ELSE 'Low' END,
                s.last_calculated = datetime()
                
                RETURN count(s) as updated_count
            """)
            
            updated_count = result.single()["updated_count"]
            logger.info(f"Updated risk scores for {updated_count} subdomains")
            return updated_count
    
    def close(self):
        """Close Neo4j connection."""
        self.drv.close()

def main():
    # Configuration
    NEO4J_URI = "bolt://localhost:7687"
    NEO4J_USER = "neo4j"
    NEO4J_PASS = "test.password"
    
    analyzer = SubdomainAnalyzer(NEO4J_URI, NEO4J_USER, NEO4J_PASS)
    
    try:
        logger.info("Starting comprehensive subdomain analysis...")
        
        # Process all subdomains
        processed, failed = analyzer.process_all_subdomains(max_workers=4)
        
        # Update risk scores
        updated_risks = analyzer.update_subdomain_risk_scores()
        
        logger.info("=" * 60)
        logger.info("SUBDOMAIN ANALYSIS COMPLETE")
        logger.info(f"Processed: {processed} subdomains")
        logger.info(f"Failed: {failed} subdomains")
        logger.info(f"Risk scores updated: {updated_risks} subdomains")
        logger.info("=" * 60)
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
    finally:
        analyzer.close()

if __name__ == "__main__":
    main()