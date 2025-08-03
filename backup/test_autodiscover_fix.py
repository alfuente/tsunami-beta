#!/usr/bin/env python3
"""
Test Autodiscover Fix - Test specific subdomain fix for autodiscover.consorcio.cl
"""

import ssl
import socket
import dns.resolver
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from neo4j import GraphDatabase
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AutodiscoverTester:
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str):
        self.drv = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
        
    def check_current_state(self, fqdn: str):
        """Check current state of a subdomain in Neo4j."""
        with self.drv.session() as session:
            result = session.run("""
                MATCH (s:Subdomain {fqdn: $fqdn})
                OPTIONAL MATCH (s)-[:RUNS]->(svc:Service)
                OPTIONAL MATCH (s)-[:USES_SERVICE]->(p:Provider)
                OPTIONAL MATCH (s)-[:SECURED_BY]->(c:Certificate)
                RETURN 
                    s.fqdn as fqdn,
                    s.risk_score as risk_score,
                    s.risk_tier as risk_tier,
                    s.tls_grade as tls_grade,
                    s.has_tls as has_tls,
                    collect(DISTINCT svc.name) as services,
                    collect(DISTINCT p.name) as providers,
                    c.tls_grade as cert_tls_grade
            """, fqdn=fqdn)
            
            if result.peek():
                record = result.single()
                return {
                    'exists': True,
                    'fqdn': record['fqdn'],
                    'risk_score': record['risk_score'],
                    'risk_tier': record['risk_tier'],
                    'tls_grade': record['tls_grade'],
                    'has_tls': record['has_tls'],
                    'services': [s for s in record['services'] if s],
                    'providers': [p for p in record['providers'] if p],
                    'cert_tls_grade': record['cert_tls_grade']
                }
            else:
                return {'exists': False}
    
    def analyze_tls(self, fqdn: str) -> Optional[Dict[str, Any]]:
        """Analyze TLS certificate for subdomain."""
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
                    expires_in_days = (not_after - datetime.now()).days
                    
                    # Calculate TLS grade
                    tls_grade = self._calculate_tls_grade(cert, cipher, expires_in_days)
                    
                    return {
                        'has_tls': True,
                        'tls_grade': tls_grade,
                        'expires_in_days': expires_in_days,
                        'not_after': cert['notAfter'],
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'serial_number': cert.get('serialNumber', ''),
                        'is_self_signed': cert.get('issuer') == cert.get('subject'),
                        'cipher_suite': cipher[0] if cipher else None,
                        'tls_version': cipher[1] if cipher else None
                    }
        except Exception as e:
            logger.warning(f"TLS analysis failed for {fqdn}: {e}")
            return {
                'has_tls': False,
                'tls_grade': 'F',
                'error': str(e)
            }
    
    def _calculate_tls_grade(self, cert: Dict, cipher: tuple, expires_in_days: int) -> str:
        """Calculate TLS grade."""
        score = 100
        
        if expires_in_days < 0:
            return 'F'
        elif expires_in_days < 7:
            score -= 30
        elif expires_in_days < 30:
            score -= 20
        
        if cert.get('issuer') == cert.get('subject'):
            score -= 40
        
        if cipher and len(cipher) > 1:
            tls_version = cipher[1]
            if 'TLSv1.3' in tls_version:
                score += 5
            elif 'TLSv1.2' in tls_version:
                pass
            elif 'TLSv1.1' in tls_version or 'TLSv1.0' in tls_version:
                score -= 20
            elif 'SSLv' in tls_version:
                score -= 40
        
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
    
    def detect_services(self, fqdn: str) -> List[Dict[str, Any]]:
        """Detect services for autodiscover subdomain."""
        services = []
        
        # Autodiscover is specifically for Exchange/Outlook email discovery
        services.append({
            'name': f"exchange_autodiscover_{fqdn}",
            'type': 'email',
            'source': 'subdomain_pattern',
            'confidence': 0.95,
            'subdomain': fqdn,
            'description': 'Microsoft Exchange Autodiscover Service'
        })
        
        services.append({
            'name': f"outlook_autodiscover_{fqdn}",
            'type': 'email',
            'source': 'subdomain_pattern', 
            'confidence': 0.95,
            'subdomain': fqdn,
            'description': 'Microsoft Outlook Autodiscover Service'
        })
        
        # Check if HTTPS is available
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((fqdn, 443))
            sock.close()
            
            if result == 0:
                services.append({
                    'name': f"https_{fqdn}",
                    'type': 'web',
                    'source': 'port_scan',
                    'confidence': 0.9,
                    'port': 443,
                    'subdomain': fqdn
                })
        except Exception:
            pass
        
        return services
    
    def detect_providers(self, fqdn: str) -> List[Dict[str, Any]]:
        """Detect providers for subdomain."""
        providers = []
        
        try:
            # Get IP addresses
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            a_records = resolver.resolve(fqdn, 'A')
            
            for ip in a_records:
                ip_str = str(ip)
                
                # Try reverse DNS
                try:
                    hostname = socket.gethostbyaddr(ip_str)[0]
                    
                    # Check for known cloud providers
                    if 'amazonaws.com' in hostname.lower():
                        providers.append({
                            'name': 'Amazon Web Services',
                            'type': 'cloud',
                            'source': 'reverse_dns',
                            'confidence': 0.95,
                            'ip': ip_str,
                            'hostname': hostname,
                            'subdomain': fqdn
                        })
                    elif 'azure' in hostname.lower() or 'microsoft' in hostname.lower():
                        providers.append({
                            'name': 'Microsoft Azure',
                            'type': 'cloud',
                            'source': 'reverse_dns',
                            'confidence': 0.95,
                            'ip': ip_str,
                            'hostname': hostname,
                            'subdomain': fqdn
                        })
                    elif 'google' in hostname.lower():
                        providers.append({
                            'name': 'Google Cloud Platform',
                            'type': 'cloud',
                            'source': 'reverse_dns',
                            'confidence': 0.95,
                            'ip': ip_str,
                            'hostname': hostname,
                            'subdomain': fqdn
                        })
                    else:
                        providers.append({
                            'name': f'Hosting Provider ({hostname})',
                            'type': 'hosting',
                            'source': 'reverse_dns',
                            'confidence': 0.7,
                            'ip': ip_str,
                            'hostname': hostname,
                            'subdomain': fqdn
                        })
                        
                except Exception:
                    # Fallback to generic provider
                    providers.append({
                        'name': f'External Provider ({ip_str})',
                        'type': 'hosting',
                        'source': 'ip_address',
                        'confidence': 0.5,
                        'ip': ip_str,
                        'subdomain': fqdn
                    })
                    
        except Exception as e:
            logger.warning(f"Provider detection failed for {fqdn}: {e}")
        
        return providers
    
    def update_subdomain(self, fqdn: str, tls_info: Dict, services: List[Dict], providers: List[Dict]):
        """Update subdomain with new information."""
        with self.drv.session() as session:
            with session.begin_transaction() as tx:
                try:
                    # Update subdomain properties
                    tx.run("""
                        MATCH (s:Subdomain {fqdn: $fqdn})
                        SET s.has_tls = $has_tls,
                            s.tls_grade = $tls_grade,
                            s.tls_expires_in_days = $expires_in_days,
                            s.last_analyzed = datetime(),
                            s.analysis_version = 'v2.1_test'
                    """, 
                    fqdn=fqdn,
                    has_tls=tls_info.get('has_tls', False),
                    tls_grade=tls_info.get('tls_grade', 'Unknown'),
                    expires_in_days=tls_info.get('expires_in_days', 0)
                    )
                    
                    # Create Certificate node if TLS exists
                    if tls_info.get('has_tls'):
                        cert_id = f"{fqdn}_{tls_info.get('serial_number', 'test')}"
                        
                        tx.run("""
                            MATCH (s:Subdomain {fqdn: $fqdn})
                            MERGE (c:Certificate {id: $cert_id})
                            SET c.tls_grade = $tls_grade,
                                c.expires_in_days = $expires_in_days,
                                c.not_after = $not_after,
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
                        issuer=json.dumps(tls_info.get('issuer', {})),
                        subject=json.dumps(tls_info.get('subject', {})),
                        serial_number=tls_info.get('serial_number', ''),
                        is_self_signed=tls_info.get('is_self_signed', False),
                        cipher_suite=tls_info.get('cipher_suite', ''),
                        tls_version=tls_info.get('tls_version', '')
                        )
                    
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
                                srv.description = $description,
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
                        description=service.get('description', ''),
                        port=service.get('port', 0)
                        )
                    
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
                        subdomain=provider.get('subdomain', fqdn)
                        )
                    
                    tx.commit()
                    logger.info(f"✓ Updated {fqdn}: {len(services)} services, {len(providers)} providers")
                    return True
                    
                except Exception as e:
                    logger.error(f"Failed to update {fqdn}: {e}")
                    tx.rollback()
                    return False
    
    def test_subdomain(self, fqdn: str):
        """Test complete subdomain analysis."""
        logger.info(f"Testing subdomain: {fqdn}")
        
        # Check current state
        current_state = self.check_current_state(fqdn)
        logger.info(f"Current state: {current_state}")
        
        # Analyze TLS
        tls_info = self.analyze_tls(fqdn)
        logger.info(f"TLS info: {tls_info}")
        
        # Detect services
        services = self.detect_services(fqdn)
        logger.info(f"Detected services: {services}")
        
        # Detect providers  
        providers = self.detect_providers(fqdn)
        logger.info(f"Detected providers: {providers}")
        
        # Update subdomain
        success = self.update_subdomain(fqdn, tls_info, services, providers)
        
        if success:
            # Check new state
            new_state = self.check_current_state(fqdn)
            logger.info(f"New state: {new_state}")
            
            return {
                'success': True,
                'before': current_state,
                'after': new_state,
                'tls_info': tls_info,
                'services': services,
                'providers': providers
            }
        else:
            return {'success': False}
    
    def close(self):
        self.drv.close()

def main():
    # Configuration
    NEO4J_URI = "bolt://localhost:7687"
    NEO4J_USER = "neo4j"
    NEO4J_PASS = "test.password"
    
    tester = AutodiscoverTester(NEO4J_URI, NEO4J_USER, NEO4J_PASS)
    
    try:
        # Test specific subdomain
        test_domain = "autodiscover.consorcio.cl"
        result = tester.test_subdomain(test_domain)
        
        print("\n" + "="*60)
        print("AUTODISCOVER TEST RESULTS")
        print("="*60)
        
        if result['success']:
            print(f"✅ Successfully updated {test_domain}")
            print(f"\nBEFORE:")
            for key, value in result['before'].items():
                print(f"  {key}: {value}")
            
            print(f"\nAFTER:")
            for key, value in result['after'].items():
                print(f"  {key}: {value}")
                
            print(f"\nTLS Analysis:")
            for key, value in result['tls_info'].items():
                print(f"  {key}: {value}")
                
            print(f"\nServices Detected: {len(result['services'])}")
            for service in result['services']:
                print(f"  - {service['name']} ({service['type']})")
                
            print(f"\nProviders Detected: {len(result['providers'])}")
            for provider in result['providers']:
                print(f"  - {provider['name']} ({provider['type']})")
        else:
            print(f"❌ Failed to update {test_domain}")
        
        print("="*60)
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
    finally:
        tester.close()

if __name__ == "__main__":
    main()