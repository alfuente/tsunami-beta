#!/usr/bin/env python3
"""
domain_risk_calculator.py - Specialized risk calculation for base domains

This script calculates security risks specifically for base domains (like bice.cl, banco.cl)
without processing subdomains. It focuses on identifying and quantifying risks based on:

1. DNS configuration vulnerabilities
2. SSL/TLS certificate issues
3. IP address risks and geolocation
4. Cloud provider security posture
5. Subdomain exposure levels
6. Service misconfiguration risks

Key features:
- Base domain focused risk analysis
- Configurable risk scoring
- Direct Neo4j risk node creation
- Comprehensive security assessment
"""

from __future__ import annotations
import argparse, json, sys, socket, ssl, re
from datetime import datetime, timedelta
from typing import Iterable, Mapping, Any, List, Dict, Set, Tuple, Optional
import time
from dataclasses import dataclass
from enum import Enum
import random

import dns.resolver, dns.exception, requests, logging
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

# Global configurations
RESOLVER = dns.resolver.Resolver(configure=True)
RESOLVER.lifetime = RESOLVER.timeout = 5.0

# Risk severity levels
class RiskSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class DomainRisk:
    """Risk information for a domain."""
    domain_fqdn: str
    risk_type: str
    severity: RiskSeverity
    score: float  # 0.0 to 10.0
    description: str
    evidence: Dict[str, Any]
    remediation: str
    discovered_at: datetime

class DomainRiskCalculator:
    """Domain-focused risk calculator."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str, ipinfo_token: str = None):
        if not HAS_NEO4J:
            raise ImportError("Neo4j driver is required. Install with: pip install neo4j")
        
        self.drv = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
        self.ipinfo_token = ipinfo_token
        self.setup_constraints()
    
    def setup_constraints(self):
        """Setup Neo4j constraints for risk nodes."""
        with self.drv.session() as s:
            # Risk node constraints
            s.run("CREATE CONSTRAINT risk_id IF NOT EXISTS FOR (r:Risk) REQUIRE r.risk_id IS UNIQUE")
            s.run("CREATE INDEX risk_domain IF NOT EXISTS FOR (r:Risk) ON (r.domain_fqdn)")
            s.run("CREATE INDEX risk_severity IF NOT EXISTS FOR (r:Risk) ON (r.severity)")
            s.run("CREATE INDEX risk_score IF NOT EXISTS FOR (r:Risk) ON (r.score)")
    
    def get_base_domains(self) -> List[str]:
        """Get all base domains from the graph."""
        with self.drv.session() as s:
            result = s.run("""
                MATCH (d:Domain)
                WHERE d.fqdn IS NOT NULL
                RETURN DISTINCT d.fqdn as fqdn
                ORDER BY d.fqdn
            """)
            return [record["fqdn"] for record in result]
    
    def get_subdomains_for_base_domain(self, base_domain: str) -> List[str]:
        """Get all subdomains for a specific base domain."""
        with self.drv.session() as s:
            result = s.run("""
                MATCH (d:Domain {fqdn: $base_domain})-[:HAS_SUBDOMAIN]->(s:Subdomain)
                RETURN DISTINCT s.fqdn as fqdn
                ORDER BY s.fqdn
            """, base_domain=base_domain)
            return [record["fqdn"] for record in result]
    
    def get_domain_dependencies(self, base_domain: str) -> Dict[str, List[str]]:
        """Get all dependencies (services, providers, IPs) for a base domain."""
        with self.drv.session() as s:
            result = s.run("""
                MATCH (d:Domain {fqdn: $base_domain})
                OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                
                // Collect all domain and subdomain nodes
                WITH collect(d) + collect(s) as all_nodes
                UNWIND all_nodes as node
                WITH node WHERE node IS NOT NULL
                
                // Get services
                OPTIONAL MATCH (node)-[:RUNS]->(svc:Service)
                
                // Get providers via IP addresses
                OPTIONAL MATCH (node)-[:RESOLVES_TO]->(ip:IPAddress)-[:HOSTED_BY]->(prov:Service)
                WHERE prov.type = 'cloud_provider'
                
                // Get IP addresses
                OPTIONAL MATCH (node)-[:RESOLVES_TO]->(ip:IPAddress)
                
                // Get related domains via relationships
                OPTIONAL MATCH (node)-[:RELATED_TO]->(related)
                WHERE related:Domain OR related:Subdomain
                
                RETURN 
                    collect(DISTINCT svc.name) as services,
                    collect(DISTINCT prov.name) as providers,
                    collect(DISTINCT ip.address) as ip_addresses,
                    collect(DISTINCT related.fqdn) as related_domains
            """, base_domain=base_domain)
            
            record = result.single()
            return {
                'services': [s for s in record["services"] if s is not None],
                'providers': [p for p in record["providers"] if p is not None],
                'ip_addresses': [ip for ip in record["ip_addresses"] if ip is not None],
                'related_domains': [d for d in record["related_domains"] if d is not None]
            }
    
    def calculate_domain_risks(self, domain_fqdn: str) -> List[DomainRisk]:
        """Calculate all risks for a specific domain."""
        print(f"🔍 Analyzing risks for {domain_fqdn}")
        
        risks = []
        
        # 1. DNS Configuration Risks
        risks.extend(self._analyze_dns_risks(domain_fqdn))
        
        # 2. SSL/TLS Certificate Risks
        risks.extend(self._analyze_ssl_risks(domain_fqdn))
        
        # 3. IP Address and Geolocation Risks
        risks.extend(self._analyze_ip_risks(domain_fqdn))
        
        # 4. Subdomain Exposure Risks
        risks.extend(self._analyze_subdomain_exposure_risks(domain_fqdn))
        
        # 5. Cloud Provider Configuration Risks
        risks.extend(self._analyze_cloud_provider_risks(domain_fqdn))
        
        # 6. Domain Age and Reputation Risks
        risks.extend(self._analyze_domain_reputation_risks(domain_fqdn))
        
        print(f"✓ Found {len(risks)} risks for {domain_fqdn}")
        return risks
    
    def _analyze_dns_risks(self, domain_fqdn: str) -> List[DomainRisk]:
        """Analyze DNS configuration risks."""
        risks = []
        
        try:
            # Check for missing SPF record
            try:
                spf_records = self._dns_query(domain_fqdn, "TXT")
                has_spf = any("v=spf1" in record.lower() for record in spf_records)
                if not has_spf:
                    risks.append(DomainRisk(
                        domain_fqdn=domain_fqdn,
                        risk_type="dns_missing_spf",
                        severity=RiskSeverity.MEDIUM,
                        score=5.0,
                        description="Missing SPF record - domain vulnerable to email spoofing",
                        evidence={"spf_records": spf_records},
                        remediation="Add SPF record to DNS: 'v=spf1 -all' or configure properly",
                        discovered_at=datetime.now()
                    ))
            except:
                pass
            
            # Check for missing DMARC record
            try:
                dmarc_records = self._dns_query(f"_dmarc.{domain_fqdn}", "TXT")
                has_dmarc = any("v=DMARC1" in record for record in dmarc_records)
                if not has_dmarc:
                    risks.append(DomainRisk(
                        domain_fqdn=domain_fqdn,
                        risk_type="dns_missing_dmarc",
                        severity=RiskSeverity.MEDIUM,
                        score=5.5,
                        description="Missing DMARC record - no email authentication policy",
                        evidence={"dmarc_records": dmarc_records},
                        remediation="Add DMARC record: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@domain.com'",
                        discovered_at=datetime.now()
                    ))
            except:
                pass
            
            # Check for wildcard DNS
            try:
                wildcard_result = self._dns_query(f"nonexistent-random-{int(time.time())}.{domain_fqdn}", "A")
                if wildcard_result:
                    risks.append(DomainRisk(
                        domain_fqdn=domain_fqdn,
                        risk_type="dns_wildcard_configured",
                        severity=RiskSeverity.HIGH,
                        score=7.0,
                        description="Wildcard DNS configured - potential subdomain takeover risk",
                        evidence={"wildcard_response": wildcard_result},
                        remediation="Review wildcard DNS configuration and disable if not needed",
                        discovered_at=datetime.now()
                    ))
            except:
                pass
                
        except Exception as e:
            print(f"DNS analysis error for {domain_fqdn}: {e}")
        
        return risks
    
    def _analyze_ssl_risks(self, domain_fqdn: str) -> List[DomainRisk]:
        """Analyze SSL/TLS certificate risks."""
        risks = []
        
        try:
            cert_info = self._get_ssl_certificate_info(domain_fqdn)
            if not cert_info:
                risks.append(DomainRisk(
                    domain_fqdn=domain_fqdn,
                    risk_type="ssl_no_certificate",
                    severity=RiskSeverity.HIGH,
                    score=8.0,
                    description="No valid SSL certificate found",
                    evidence={"error": "Cannot retrieve certificate"},
                    remediation="Install valid SSL certificate",
                    discovered_at=datetime.now()
                ))
                return risks
            
            # Check certificate expiration
            if cert_info.get('expires_in_days', 0) < 30:
                severity = RiskSeverity.CRITICAL if cert_info.get('expires_in_days', 0) < 7 else RiskSeverity.HIGH
                score = 9.0 if cert_info.get('expires_in_days', 0) < 7 else 7.5
                risks.append(DomainRisk(
                    domain_fqdn=domain_fqdn,
                    risk_type="ssl_expiring_certificate",
                    severity=severity,
                    score=score,
                    description=f"SSL certificate expires in {cert_info.get('expires_in_days', 0)} days",
                    evidence=cert_info,
                    remediation="Renew SSL certificate before expiration",
                    discovered_at=datetime.now()
                ))
            
            # Check for weak signature algorithm
            if cert_info.get('signature_algorithm', '').lower() in ['sha1', 'md5']:
                risks.append(DomainRisk(
                    domain_fqdn=domain_fqdn,
                    risk_type="ssl_weak_signature",
                    severity=RiskSeverity.HIGH,
                    score=7.0,
                    description=f"Weak signature algorithm: {cert_info.get('signature_algorithm')}",
                    evidence=cert_info,
                    remediation="Replace certificate with SHA-256 or stronger signature",
                    discovered_at=datetime.now()
                ))
            
            # Check for self-signed certificate
            if cert_info.get('is_self_signed', False):
                risks.append(DomainRisk(
                    domain_fqdn=domain_fqdn,
                    risk_type="ssl_self_signed",
                    severity=RiskSeverity.HIGH,
                    score=8.0,
                    description="Self-signed SSL certificate detected",
                    evidence=cert_info,
                    remediation="Replace with certificate from trusted CA",
                    discovered_at=datetime.now()
                ))
                
        except Exception as e:
            print(f"SSL analysis error for {domain_fqdn}: {e}")
        
        return risks
    
    def _analyze_ip_risks(self, domain_fqdn: str) -> List[DomainRisk]:
        """Analyze IP address and geolocation risks."""
        risks = []
        
        try:
            # Get IPs for domain from graph
            with self.drv.session() as s:
                result = s.run("""
                    MATCH (d:Domain {fqdn: $fqdn})-[:RESOLVES_TO]->(ip:IPAddress)
                    RETURN ip.address as address, ip.provider as provider, ip.cloud_info as cloud_info
                """, fqdn=domain_fqdn)
                
                ips_data = [dict(record) for record in result]
            
            if not ips_data:
                risks.append(DomainRisk(
                    domain_fqdn=domain_fqdn,
                    risk_type="ip_no_resolution",
                    severity=RiskSeverity.HIGH,
                    score=8.0,
                    description="Domain does not resolve to any IP address",
                    evidence={"dns_resolution": "failed"},
                    remediation="Fix DNS configuration to point to valid IP",
                    discovered_at=datetime.now()
                ))
                return risks
            
            # Check for suspicious IP ranges
            for ip_data in ips_data:
                ip_addr = ip_data['address']
                try:
                    ip_obj = ipaddress.ip_address(ip_addr)
                    
                    # Check for private IP exposure
                    if ip_obj.is_private:
                        risks.append(DomainRisk(
                            domain_fqdn=domain_fqdn,
                            risk_type="ip_private_exposed",
                            severity=RiskSeverity.MEDIUM,
                            score=6.0,
                            description=f"Domain resolves to private IP: {ip_addr}",
                            evidence={"ip": ip_addr, "is_private": True},
                            remediation="Review DNS configuration - private IPs should not be publicly accessible",
                            discovered_at=datetime.now()
                        ))
                    
                    # Check for multiple providers (infrastructure diversity risk)
                    providers = set(ip['provider'] for ip in ips_data if ip.get('provider'))
                    if len(providers) > 2:
                        risks.append(DomainRisk(
                            domain_fqdn=domain_fqdn,
                            risk_type="ip_multiple_providers",
                            severity=RiskSeverity.LOW,
                            score=3.0,
                            description=f"Domain uses {len(providers)} different cloud providers",
                            evidence={"providers": list(providers), "ip_count": len(ips_data)},
                            remediation="Consider consolidating infrastructure for better security management",
                            discovered_at=datetime.now()
                        ))
                        break
                        
                except Exception as e:
                    print(f"IP analysis error for {ip_addr}: {e}")
                    
        except Exception as e:
            print(f"IP risk analysis error for {domain_fqdn}: {e}")
        
        return risks
    
    def _analyze_subdomain_exposure_risks(self, domain_fqdn: str) -> List[DomainRisk]:
        """Analyze subdomain exposure risks."""
        risks = []
        
        try:
            # Get subdomain count from graph
            with self.drv.session() as s:
                result = s.run("""
                    MATCH (d:Domain {fqdn: $fqdn})-[:HAS_SUBDOMAIN]->(s:Subdomain)
                    RETURN count(s) as subdomain_count,
                           collect(s.fqdn)[0..10] as sample_subdomains
                """, fqdn=domain_fqdn)
                
                record = result.single()
                if record:
                    subdomain_count = record["subdomain_count"]
                    sample_subdomains = record["sample_subdomains"]
                    
                    # High subdomain exposure risk
                    if subdomain_count > 100:
                        risks.append(DomainRisk(
                            domain_fqdn=domain_fqdn,
                            risk_type="subdomain_high_exposure",
                            severity=RiskSeverity.MEDIUM,
                            score=6.0,
                            description=f"High subdomain exposure: {subdomain_count} subdomains discovered",
                            evidence={"subdomain_count": subdomain_count, "samples": sample_subdomains},
                            remediation="Review subdomain necessity and remove unused subdomains",
                            discovered_at=datetime.now()
                        ))
                    
                    # Check for sensitive subdomain patterns
                    sensitive_patterns = ['admin', 'test', 'staging', 'dev', 'internal', 'api', 'ftp', 'ssh']
                    found_sensitive = []
                    for subdomain in sample_subdomains:
                        for pattern in sensitive_patterns:
                            if pattern in subdomain.lower():
                                found_sensitive.append(subdomain)
                                break
                    
                    if found_sensitive:
                        risks.append(DomainRisk(
                            domain_fqdn=domain_fqdn,
                            risk_type="subdomain_sensitive_exposed",
                            severity=RiskSeverity.HIGH,
                            score=7.5,
                            description=f"Sensitive subdomains exposed: {len(found_sensitive)} found",
                            evidence={"sensitive_subdomains": found_sensitive},
                            remediation="Secure or remove sensitive subdomains from public access",
                            discovered_at=datetime.now()
                        ))
                        
        except Exception as e:
            print(f"Subdomain exposure analysis error for {domain_fqdn}: {e}")
        
        return risks
    
    def _analyze_cloud_provider_risks(self, domain_fqdn: str) -> List[DomainRisk]:
        """Analyze cloud provider configuration risks."""
        risks = []
        
        try:
            # Get cloud provider info from graph
            with self.drv.session() as s:
                result = s.run("""
                    MATCH (d:Domain {fqdn: $fqdn})-[:RESOLVES_TO]->(ip:IPAddress)-[:HOSTED_BY]->(svc:Service)
                    WHERE svc.type = 'cloud_provider'
                    RETURN svc.name as provider, count(ip) as ip_count
                """, fqdn=domain_fqdn)
                
                providers = [dict(record) for record in result]
            
            # Check for single provider dependency
            if len(providers) == 1 and providers[0]['ip_count'] > 1:
                risks.append(DomainRisk(
                    domain_fqdn=domain_fqdn,
                    risk_type="cloud_single_provider_dependency",
                    severity=RiskSeverity.LOW,
                    score=4.0,
                    description=f"Single cloud provider dependency: {providers[0]['provider']}",
                    evidence={"provider": providers[0]['provider'], "ip_count": providers[0]['ip_count']},
                    remediation="Consider multi-cloud strategy for better resilience",
                    discovered_at=datetime.now()
                ))
            
            # Check for unknown/unmanaged providers
            for provider_data in providers:
                if provider_data['provider'] in ['unknown', 'unidentified']:
                    risks.append(DomainRisk(
                        domain_fqdn=domain_fqdn,
                        risk_type="cloud_unknown_provider",
                        severity=RiskSeverity.MEDIUM,
                        score=5.0,
                        description="Domain hosted on unknown/unidentified cloud provider",
                        evidence=provider_data,
                        remediation="Identify and verify hosting provider security posture",
                        discovered_at=datetime.now()
                    ))
                    
        except Exception as e:
            print(f"Cloud provider analysis error for {domain_fqdn}: {e}")
        
        return risks
    
    def _analyze_domain_reputation_risks(self, domain_fqdn: str) -> List[DomainRisk]:
        """Analyze domain age and reputation risks."""
        risks = []
        
        if HAS_WHOIS:
            try:
                domain_info = whois.whois(domain_fqdn)
                
                # Check domain age
                if domain_info.creation_date:
                    creation_date = domain_info.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    
                    # Handle both datetime objects and strings
                    if isinstance(creation_date, str):
                        try:
                            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                        except ValueError:
                            try:
                                creation_date = datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')
                            except ValueError:
                                print(f"Could not parse creation date: {creation_date}")
                                return risks  # Return early if we can't parse the date
                    
                    age_days = (datetime.now() - creation_date).days
                    
                    if age_days < 30:  # Very new domain
                        risks.append(DomainRisk(
                            domain_fqdn=domain_fqdn,
                            risk_type="domain_very_new",
                            severity=RiskSeverity.HIGH,
                            score=7.0,
                            description=f"Very new domain: {age_days} days old",
                            evidence={"creation_date": creation_date.isoformat(), "age_days": age_days},
                            remediation="Monitor new domain for suspicious activity",
                            discovered_at=datetime.now()
                        ))
                    elif age_days < 90:  # New domain
                        risks.append(DomainRisk(
                            domain_fqdn=domain_fqdn,
                            risk_type="domain_new",
                            severity=RiskSeverity.MEDIUM,
                            score=5.0,
                            description=f"New domain: {age_days} days old",
                            evidence={"creation_date": creation_date.isoformat(), "age_days": age_days},
                            remediation="Establish domain reputation monitoring",
                            discovered_at=datetime.now()
                        ))
                
                # Check expiration
                if domain_info.expiration_date:
                    expiration_date = domain_info.expiration_date
                    if isinstance(expiration_date, list):
                        expiration_date = expiration_date[0]
                    
                    # Handle both datetime objects and strings
                    if isinstance(expiration_date, str):
                        try:
                            expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
                        except ValueError:
                            try:
                                expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d %H:%M:%S')
                            except ValueError:
                                print(f"Could not parse expiration date: {expiration_date}")
                                return risks  # Return early if we can't parse the date
                    
                    days_to_expiry = (expiration_date - datetime.now()).days
                    
                    if days_to_expiry < 30:
                        severity = RiskSeverity.CRITICAL if days_to_expiry < 7 else RiskSeverity.HIGH
                        score = 9.5 if days_to_expiry < 7 else 8.0
                        risks.append(DomainRisk(
                            domain_fqdn=domain_fqdn,
                            risk_type="domain_expiring",
                            severity=severity,
                            score=score,
                            description=f"Domain expires in {days_to_expiry} days",
                            evidence={"expiration_date": expiration_date.isoformat(), "days_to_expiry": days_to_expiry},
                            remediation="Renew domain registration immediately",
                            discovered_at=datetime.now()
                        ))
                        
            except Exception as e:
                print(f"Domain reputation analysis error for {domain_fqdn}: {e}")
        
        return risks
    
    def _analyze_subdomain_specific_risks(self, subdomain_fqdn: str) -> List[DomainRisk]:
        """Analyze risks specific to subdomains."""
        risks = []
        
        try:
            # Check for exposed development/testing subdomains
            sensitive_keywords = ['dev', 'test', 'staging', 'admin', 'internal', 'api', 'ftp', 'ssh', 'vpn', 'backup']
            subdomain_parts = subdomain_fqdn.lower().split('.')
            
            for keyword in sensitive_keywords:
                if any(keyword in part for part in subdomain_parts):
                    # Check if subdomain is publicly accessible
                    if self._is_subdomain_publicly_accessible(subdomain_fqdn):
                        severity = RiskSeverity.HIGH if keyword in ['admin', 'internal', 'ssh', 'vpn'] else RiskSeverity.MEDIUM
                        score = 7.5 if keyword in ['admin', 'internal', 'ssh', 'vpn'] else 6.0
                        
                        risks.append(DomainRisk(
                            domain_fqdn=subdomain_fqdn,
                            risk_type=f"subdomain_sensitive_{keyword}_exposed",
                            severity=severity,
                            score=score,
                            description=f"Sensitive subdomain exposed: {keyword} subdomain is publicly accessible",
                            evidence={"subdomain": subdomain_fqdn, "sensitive_keyword": keyword},
                            remediation=f"Restrict access to {keyword} subdomain or move to internal network",
                            discovered_at=datetime.now()
                        ))
                    break  # Only flag once per subdomain
            
            # Check for subdomain takeover vulnerability
            takeover_risk = self._check_subdomain_takeover_risk(subdomain_fqdn)
            if takeover_risk:
                risks.append(takeover_risk)
                
            # Check for subdomain certificate issues
            cert_risks = self._analyze_subdomain_certificate_risks(subdomain_fqdn)
            risks.extend(cert_risks)
            
        except Exception as e:
            print(f"Subdomain-specific analysis error for {subdomain_fqdn}: {e}")
        
        return risks
    
    def _is_subdomain_publicly_accessible(self, subdomain_fqdn: str) -> bool:
        """Check if subdomain is publicly accessible."""
        try:
            # Try to resolve the subdomain
            ips = self._dns_query(subdomain_fqdn, "A")
            if not ips:
                ips = self._dns_query(subdomain_fqdn, "AAAA")
            
            return len(ips) > 0
        except:
            return False
    
    def _check_subdomain_takeover_risk(self, subdomain_fqdn: str) -> Optional[DomainRisk]:
        """Check for subdomain takeover vulnerability."""
        try:
            # Check CNAME records that might point to external services
            cname_records = self._dns_query(subdomain_fqdn, "CNAME")
            
            # Known vulnerable service patterns
            vulnerable_patterns = [
                'github.io', 'herokuapp.com', 'azurewebsites.net', 
                'cloudapp.net', 'amazonaws.com', 'elasticbeanstalk.com',
                'wordpress.com', 'tumblr.com', 'bitbucket.io'
            ]
            
            for cname in cname_records:
                for pattern in vulnerable_patterns:
                    if pattern in cname.lower():
                        return DomainRisk(
                            domain_fqdn=subdomain_fqdn,
                            risk_type="subdomain_takeover_vulnerable",
                            severity=RiskSeverity.HIGH,
                            score=8.5,
                            description=f"Potential subdomain takeover: CNAME points to {pattern}",
                            evidence={"cname_target": cname, "vulnerable_service": pattern},
                            remediation="Verify service ownership or remove CNAME record",
                            discovered_at=datetime.now()
                        )
            
            return None
            
        except Exception as e:
            print(f"Subdomain takeover check error for {subdomain_fqdn}: {e}")
            return None
    
    def _analyze_subdomain_certificate_risks(self, subdomain_fqdn: str) -> List[DomainRisk]:
        """Analyze certificate-specific risks for subdomains."""
        risks = []
        
        try:
            cert_info = self._get_ssl_certificate_info(subdomain_fqdn)
            if not cert_info:
                return risks
            
            # Check if subdomain uses wildcard certificate
            subject = cert_info.get('subject', {})
            if subject.get('commonName', '').startswith('*'):
                risks.append(DomainRisk(
                    domain_fqdn=subdomain_fqdn,
                    risk_type="subdomain_wildcard_certificate",
                    severity=RiskSeverity.MEDIUM,
                    score=5.5,
                    description="Subdomain uses wildcard certificate - potential security implications",
                    evidence={"common_name": subject.get('commonName'), "certificate_info": cert_info},
                    remediation="Consider using specific certificates for sensitive subdomains",
                    discovered_at=datetime.now()
                ))
            
        except Exception as e:
            print(f"Subdomain certificate analysis error for {subdomain_fqdn}: {e}")
        
        return risks
    
    def _analyze_dependency_risks(self, base_domain: str, dependencies: Dict[str, List[str]]) -> List[DomainRisk]:
        """Analyze risks related to domain dependencies."""
        risks = []
        
        try:
            # Check for too many external dependencies
            total_dependencies = (
                len(dependencies['services']) + 
                len(dependencies['providers']) + 
                len(dependencies['related_domains'])
            )
            
            if total_dependencies > 20:
                risks.append(DomainRisk(
                    domain_fqdn=base_domain,
                    risk_type="dependency_high_complexity",
                    severity=RiskSeverity.MEDIUM,
                    score=6.0,
                    description=f"High dependency complexity: {total_dependencies} external dependencies",
                    evidence=dependencies,
                    remediation="Review and reduce unnecessary dependencies",
                    discovered_at=datetime.now()
                ))
            
            # Check for unknown or risky providers
            risky_providers = ['unknown', 'unidentified', 'residential']
            for provider in dependencies['providers']:
                if any(risky in provider.lower() for risky in risky_providers):
                    risks.append(DomainRisk(
                        domain_fqdn=base_domain,
                        risk_type="dependency_risky_provider",
                        severity=RiskSeverity.HIGH,
                        score=7.0,
                        description=f"Domain uses risky provider: {provider}",
                        evidence={"risky_provider": provider, "all_providers": dependencies['providers']},
                        remediation=f"Migrate away from {provider} to trusted provider",
                        discovered_at=datetime.now()
                    ))
            
            # Check for IP address concentration risk
            ip_count = len(dependencies['ip_addresses'])
            if ip_count > 50:
                risks.append(DomainRisk(
                    domain_fqdn=base_domain,
                    risk_type="dependency_ip_concentration",
                    severity=RiskSeverity.LOW,
                    score=4.0,
                    description=f"High IP address concentration: {ip_count} IPs",
                    evidence={"ip_count": ip_count},
                    remediation="Review IP usage and consider load balancing improvements",
                    discovered_at=datetime.now()
                ))
            
        except Exception as e:
            print(f"Dependency analysis error for {base_domain}: {e}")
        
        return risks
    
    def _get_ssl_certificate_info(self, domain_fqdn: str) -> Dict[str, Any]:
        """Get SSL certificate information."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain_fqdn, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain_fqdn) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Parse expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    expires_in_days = (not_after - datetime.now()).days
                    
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'expires_in_days': expires_in_days,
                        'not_after': cert['notAfter'],
                        'serial_number': cert['serialNumber'],
                        'version': cert['version'],
                        'is_self_signed': cert['issuer'] == cert['subject']
                    }
        except Exception as e:
            print(f"SSL certificate error for {domain_fqdn}: {e}")
            return {}
    
    def _dns_query(self, domain: str, rdtype: str) -> List[str]:
        """DNS query with error handling."""
        try:
            result = RESOLVER.resolve(domain, rdtype)
            return [str(r) for r in result]
        except (dns.exception.DNSException, Exception):
            return []
    
    def save_risks_to_graph(self, risks: List[DomainRisk]) -> int:
        """Save calculated risks to Neo4j graph."""
        if not risks:
            return 0
        
        saved_count = 0
        current_time = datetime.now().isoformat()
        
        with self.drv.session() as s:
            with s.begin_transaction() as tx:
                for risk in risks:
                    try:
                        # Generate unique risk ID with random component to avoid collisions
                        risk_id = f"{risk.domain_fqdn}_{risk.risk_type}_{int(time.time())}_{random.randint(1000, 9999)}"
                        
                        # Create risk node
                        tx.run("""
                            MERGE (r:Risk {risk_id: $risk_id})
                            SET r.domain_fqdn = $domain_fqdn,
                                r.risk_type = $risk_type,
                                r.severity = $severity,
                                r.score = $score,
                                r.description = $description,
                                r.evidence = $evidence,
                                r.remediation = $remediation,
                                r.discovered_at = $discovered_at,
                                r.last_updated = $current_time
                            RETURN r
                        """, 
                        risk_id=risk_id,
                        domain_fqdn=risk.domain_fqdn,
                        risk_type=risk.risk_type,
                        severity=risk.severity.value,
                        score=risk.score,
                        description=risk.description,
                        evidence=json.dumps(risk.evidence) if risk.evidence else "{}",
                        remediation=risk.remediation,
                        discovered_at=risk.discovered_at.isoformat(),
                        current_time=current_time)
                        
                        # Link risk to domain - try both Domain and Subdomain
                        # First try Domain
                        result = tx.run("""
                            MATCH (d:Domain {fqdn: $domain_fqdn})
                            MATCH (r:Risk {risk_id: $risk_id})
                            MERGE (r)-[:AFFECTS]->(d)
                            RETURN COUNT(d) as domain_count
                        """, domain_fqdn=risk.domain_fqdn, risk_id=risk_id)
                        
                        domain_found = result.single()["domain_count"] > 0
                        
                        # If no Domain found, try Subdomain
                        if not domain_found:
                            tx.run("""
                                MATCH (s:Subdomain {fqdn: $domain_fqdn})
                                MATCH (r:Risk {risk_id: $risk_id})
                                MERGE (r)-[:AFFECTS]->(s)
                            """, domain_fqdn=risk.domain_fqdn, risk_id=risk_id)
                        
                        saved_count += 1
                        
                    except Exception as e:
                        print(f"Error saving risk {risk.risk_type} for {risk.domain_fqdn}: {e}")
                        continue
                
                tx.commit()
        
        return saved_count
    
    def calculate_all_domain_risks(self, domains: List[str] = None) -> Dict[str, Any]:
        """Calculate risks for all or specified domains."""
        if domains is None:
            domains = self.get_base_domains()
        
        print(f"\n🚀 Starting Domain Risk Analysis")
        print(f"   Domains to analyze: {len(domains)}")
        print("="*60)
        
        start_time = time.time()
        total_risks = 0
        total_saved = 0
        
        for i, domain in enumerate(domains, 1):
            print(f"\n[{i}/{len(domains)}] Analyzing {domain}")
            
            try:
                # Calculate risks for domain
                domain_risks = self.calculate_domain_risks(domain)
                
                # Save risks to graph
                saved_count = self.save_risks_to_graph(domain_risks)
                
                total_risks += len(domain_risks)
                total_saved += saved_count
                
                print(f"  ✓ Found {len(domain_risks)} risks, saved {saved_count} to graph")
                
            except Exception as e:
                print(f"  ✗ Error analyzing {domain}: {e}")
        
        elapsed_time = time.time() - start_time
        
        # Get final statistics
        stats = self.get_risk_statistics()
        
        result = {
            'analysis_summary': {
                'domains_analyzed': len(domains),
                'total_risks_found': total_risks,
                'total_risks_saved': total_saved,
                'elapsed_time': elapsed_time
            },
            'risk_statistics': stats
        }
        
        print(f"\n🎉 Domain Risk Analysis Completed!")
        print(f"   Domains analyzed: {len(domains)}")
        print(f"   Total risks found: {total_risks}")
        print(f"   Risks saved to graph: {total_saved}")
        print(f"   Analysis time: {elapsed_time:.1f} seconds")
        print("="*60)
        
        return result
    
    def calculate_domain_and_subdomain_risks(self, base_domain: str, include_dependencies: bool = True) -> Dict[str, Any]:
        """Calculate risks for a base domain including all its subdomains and dependencies."""
        print(f"\n🚀 Starting Comprehensive Risk Analysis for {base_domain}")
        print(f"   Include dependencies: {include_dependencies}")
        print("="*60)
        
        start_time = time.time()
        
        # Results containers
        all_risks = []
        analysis_results = {
            'base_domain': base_domain,
            'domain_risks': [],
            'subdomain_risks': [],
            'dependency_risks': [],
            'summary': {
                'total_risks': 0,
                'subdomains_analyzed': 0,
                'dependencies_found': {}
            }
        }
        
        try:
            # 1. Analyze the base domain
            print(f"\n[1/4] Analyzing base domain: {base_domain}")
            domain_risks = self.calculate_domain_risks(base_domain)
            analysis_results['domain_risks'] = [
                {
                    'fqdn': risk.domain_fqdn,
                    'risk_type': risk.risk_type,
                    'severity': risk.severity.value,
                    'score': risk.score,
                    'description': risk.description,
                    'remediation': risk.remediation
                }
                for risk in domain_risks
            ]
            all_risks.extend(domain_risks)
            print(f"  ✓ Found {len(domain_risks)} risks for base domain")
            
            # 2. Get and analyze subdomains
            print(f"\n[2/4] Discovering and analyzing subdomains...")
            subdomains = self.get_subdomains_for_base_domain(base_domain)
            analysis_results['summary']['subdomains_analyzed'] = len(subdomains)
            
            if subdomains:
                print(f"  Found {len(subdomains)} subdomains to analyze")
                subdomain_risks = []
                
                for i, subdomain in enumerate(subdomains, 1):
                    print(f"    [{i}/{len(subdomains)}] Analyzing {subdomain}")
                    
                    # Basic domain analysis for subdomain
                    basic_risks = self.calculate_domain_risks(subdomain)
                    
                    # Subdomain-specific analysis
                    specific_risks = self._analyze_subdomain_specific_risks(subdomain)
                    
                    subdomain_all_risks = basic_risks + specific_risks
                    all_risks.extend(subdomain_all_risks)
                    
                    subdomain_risks.append({
                        'fqdn': subdomain,
                        'risk_count': len(subdomain_all_risks),
                        'risks': [
                            {
                                'risk_type': risk.risk_type,
                                'severity': risk.severity.value,
                                'score': risk.score,
                                'description': risk.description,
                                'remediation': risk.remediation
                            }
                            for risk in subdomain_all_risks
                        ]
                    })
                    
                    print(f"      ✓ Found {len(subdomain_all_risks)} risks")
                
                analysis_results['subdomain_risks'] = subdomain_risks
            else:
                print("  No subdomains found")
            
            # 3. Analyze dependencies if requested
            if include_dependencies:
                print(f"\n[3/4] Analyzing domain dependencies...")
                dependencies = self.get_domain_dependencies(base_domain)
                analysis_results['summary']['dependencies_found'] = dependencies
                
                dependency_risks = self._analyze_dependency_risks(base_domain, dependencies)
                all_risks.extend(dependency_risks)
                
                analysis_results['dependency_risks'] = [
                    {
                        'risk_type': risk.risk_type,
                        'severity': risk.severity.value,
                        'score': risk.score,
                        'description': risk.description,
                        'remediation': risk.remediation
                    }
                    for risk in dependency_risks
                ]
                
                print(f"  ✓ Found {len(dependency_risks)} dependency-related risks")
                print(f"  Dependencies summary:")
                print(f"    - Services: {len(dependencies['services'])}")
                print(f"    - Providers: {len(dependencies['providers'])}")
                print(f"    - IP addresses: {len(dependencies['ip_addresses'])}")
                print(f"    - Related domains: {len(dependencies['related_domains'])}")
            
            # 4. Save all risks to graph
            print(f"\n[4/4] Saving risks to graph...")
            saved_count = self.save_risks_to_graph(all_risks)
            
            # Update summary
            analysis_results['summary']['total_risks'] = len(all_risks)
            analysis_results['summary']['risks_saved'] = saved_count
            analysis_results['summary']['elapsed_time'] = time.time() - start_time
            
            # Risk breakdown by severity
            severity_breakdown = {}
            for risk in all_risks:
                sev = risk.severity.value
                severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
            analysis_results['summary']['severity_breakdown'] = severity_breakdown
            
            # Risk breakdown by type
            type_breakdown = {}
            for risk in all_risks:
                risk_type = risk.risk_type
                type_breakdown[risk_type] = type_breakdown.get(risk_type, 0) + 1
            analysis_results['summary']['type_breakdown'] = type_breakdown
            
            elapsed_time = time.time() - start_time
            
            print(f"\n🎉 Comprehensive Analysis Completed!")
            print(f"   Base domain: {base_domain}")
            print(f"   Subdomains analyzed: {len(subdomains)}")
            print(f"   Total risks found: {len(all_risks)}")
            print(f"   Risks saved to graph: {saved_count}")
            print(f"   Analysis time: {elapsed_time:.1f} seconds")
            print(f"   Severity breakdown: {severity_breakdown}")
            print("="*60)
            
        except Exception as e:
            print(f"✗ Error during comprehensive analysis: {e}")
            analysis_results['error'] = str(e)
        
        return analysis_results
    
    def get_risk_statistics(self) -> Dict[str, Any]:
        """Get risk statistics from the graph."""
        with self.drv.session() as s:
            # Overall risk counts
            result = s.run("""
                MATCH (r:Risk)
                RETURN 
                    count(r) as total_risks,
                    count(DISTINCT r.domain_fqdn) as domains_with_risks,
                    avg(r.score) as average_risk_score,
                    max(r.score) as max_risk_score
            """)
            
            stats = dict(result.single()) if result.peek() else {}
            
            # Risk by severity
            severity_result = s.run("""
                MATCH (r:Risk)
                RETURN r.severity as severity, count(r) as count
                ORDER BY count DESC
            """)
            
            stats['by_severity'] = {record['severity']: record['count'] for record in severity_result}
            
            # Risk by type
            type_result = s.run("""
                MATCH (r:Risk)
                RETURN r.risk_type as risk_type, count(r) as count
                ORDER BY count DESC
                LIMIT 10
            """)
            
            stats['by_type'] = {record['risk_type']: record['count'] for record in type_result}
            
            # Top risky domains
            domain_result = s.run("""
                MATCH (r:Risk)
                RETURN r.domain_fqdn as domain, 
                       count(r) as risk_count,
                       avg(r.score) as avg_score,
                       max(r.score) as max_score
                ORDER BY avg_score DESC, risk_count DESC
                LIMIT 10
            """)
            
            stats['top_risky_domains'] = [dict(record) for record in domain_result]
            
            return stats
    
    def close(self):
        """Close Neo4j connection."""
        self.drv.close()

def main():
    """Main function for domain risk calculation."""
    parser = argparse.ArgumentParser(description="Calculate security risks for base domains")
    parser.add_argument("--domains", help="Input domains file (optional - will use all domains from graph if not specified)")
    parser.add_argument("--bolt", default="bolt://localhost:7687", help="Neo4j bolt URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", default="test.password", help="Neo4j password")
    parser.add_argument("--ipinfo-token", default="0bf607ce2c13ac", help="IPInfo token")
    parser.add_argument("--domain", help="Analyze single domain")
    parser.add_argument("--stats-only", action="store_true", help="Show only risk statistics")
    
    # New subdomain and dependency analysis options
    parser.add_argument("--include-subdomains", action="store_true", help="Include subdomains in analysis")
    parser.add_argument("--include-dependencies", action="store_true", help="Include dependency analysis")
    parser.add_argument("--comprehensive", action="store_true", help="Run comprehensive analysis (includes subdomains and dependencies)")
    parser.add_argument("--subdomains-only", action="store_true", help="Analyze only subdomains of the specified domain")
    
    args = parser.parse_args()
    
    # Initialize calculator
    calculator = DomainRiskCalculator(args.bolt, args.user, args.password, args.ipinfo_token)
    
    try:
        if args.stats_only:
            # Show only statistics
            stats = calculator.get_risk_statistics()
            print(f"\n📊 Domain Risk Statistics:")
            print(json.dumps(stats, indent=2, default=str))
        elif args.comprehensive or (args.include_subdomains and args.include_dependencies):
            # Run comprehensive analysis
            if not args.domain:
                print("❌ Error: --comprehensive analysis requires --domain to be specified")
                return
            
            results = calculator.calculate_domain_and_subdomain_risks(
                args.domain, 
                include_dependencies=True
            )
            
            print(f"\n📊 Comprehensive Risk Analysis Results:")
            print(json.dumps(results, indent=2, default=str))
            
        elif args.include_subdomains or args.subdomains_only:
            # Run subdomain-focused analysis
            if not args.domain:
                print("❌ Error: Subdomain analysis requires --domain to be specified")
                return
                
            if args.subdomains_only:
                # Analyze only subdomains, not the base domain
                print(f"\n🔍 Analyzing ONLY subdomains of {args.domain}")
                subdomains = calculator.get_subdomains_for_base_domain(args.domain)
                
                if not subdomains:
                    print(f"No subdomains found for {args.domain}")
                    return
                
                results = calculator.calculate_all_domain_risks(subdomains)
                
            else:
                # Include subdomains in analysis
                results = calculator.calculate_domain_and_subdomain_risks(
                    args.domain, 
                    include_dependencies=args.include_dependencies
                )
            
            print(f"\n📊 Subdomain Risk Analysis Results:")
            print(json.dumps(results, indent=2, default=str))
            
        else:
            # Standard domain analysis (base domains only)
            domains = None
            if args.domain:
                domains = [args.domain]
            elif args.domains:
                with open(args.domains, 'r') as f:
                    domains = [line.strip() for line in f if line.strip()]
            
            # Run standard risk analysis
            results = calculator.calculate_all_domain_risks(domains)
            
            print(f"\n📊 Standard Risk Analysis Results:")
            print(json.dumps(results, indent=2, default=str))
        
    finally:
        calculator.close()

if __name__ == "__main__":
    main()