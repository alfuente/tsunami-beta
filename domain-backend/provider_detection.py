#!/usr/bin/env python3
"""
provider_detection.py - Sistema avanzado de detección de proveedores y servicios

Este módulo identifica dependencias críticas analizando:
- Registros MX (servicios de email)
- Registros DNS (CDN, servicios de hosting)
- Patrones de subdominio (SaaS, terceros)
- Proveedores de infraestructura (cloud providers)
- Servicios de seguridad (WAF, DDoS protection)
"""

import dns.resolver
import dns.exception
import re
import logging
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum

class ServiceType(Enum):
    EMAIL = "email"
    CDN = "cdn"
    HOSTING = "hosting"
    SAAS = "saas"
    SECURITY = "security"
    CLOUD = "cloud"
    ANALYTICS = "analytics"
    MARKETING = "marketing"
    DEVELOPMENT = "development"

class ProviderRisk(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ProviderService:
    """Representa un servicio de proveedor detectado."""
    name: str
    provider: str
    service_type: ServiceType
    detection_method: str
    risk_level: ProviderRisk
    confidence: float
    metadata: Dict = field(default_factory=dict)

class ProviderDetector:
    """Detector avanzado de proveedores y servicios."""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5.0
        self.resolver.lifetime = 5.0
        
        # Patrones de detección de proveedores
        self._init_provider_patterns()
        
    def _init_provider_patterns(self):
        """Inicializa patrones de detección de proveedores."""
        
        # Servicios de Email (MX Records)
        self.mx_providers = {
            # Microsoft 365
            r'.*\.mail\.protection\.outlook\.com': ('Microsoft 365', ServiceType.EMAIL, ProviderRisk.MEDIUM),
            r'.*\.outlook\.com': ('Microsoft 365', ServiceType.EMAIL, ProviderRisk.MEDIUM),
            r'.*-mail\.protection\.outlook\.com': ('Microsoft 365', ServiceType.EMAIL, ProviderRisk.MEDIUM),
            
            # Google Workspace
            r'.*\.google\.com': ('Google Workspace', ServiceType.EMAIL, ProviderRisk.MEDIUM),
            r'.*\.googlemail\.com': ('Google Workspace', ServiceType.EMAIL, ProviderRisk.MEDIUM),
            r'aspmx.*\.googlemail\.com': ('Google Workspace', ServiceType.EMAIL, ProviderRisk.MEDIUM),
            
            # ProofPoint
            r'.*\.pphosted\.com': ('ProofPoint', ServiceType.SECURITY, ProviderRisk.HIGH),
            r'.*\.protection\.pphosted\.com': ('ProofPoint', ServiceType.SECURITY, ProviderRisk.HIGH),
            
            # Barracuda
            r'.*\.emailsrvr\.com': ('Barracuda', ServiceType.SECURITY, ProviderRisk.HIGH),
            r'.*\.barracudanetworks\.com': ('Barracuda', ServiceType.SECURITY, ProviderRisk.HIGH),
            
            # Mimecast
            r'.*\.mimecast\.com': ('Mimecast', ServiceType.SECURITY, ProviderRisk.HIGH),
            
            # SpamTitan
            r'.*\.spamtitan\.com': ('SpamTitan', ServiceType.SECURITY, ProviderRisk.HIGH),
            
            # Amazon SES
            r'.*\.amazonses\.com': ('Amazon SES', ServiceType.EMAIL, ProviderRisk.MEDIUM),
            
            # Mailgun
            r'.*\.mailgun\.org': ('Mailgun', ServiceType.EMAIL, ProviderRisk.MEDIUM),
            
            # SendGrid
            r'.*\.sendgrid\.net': ('SendGrid', ServiceType.EMAIL, ProviderRisk.MEDIUM),
        }
        
        # CDN y Servicios de Hosting (CNAME Records)
        self.cname_providers = {
            # Cloudflare
            r'.*\.cloudflare\.com': ('Cloudflare', ServiceType.CDN, ProviderRisk.MEDIUM),
            r'.*\.cloudflare\.net': ('Cloudflare', ServiceType.CDN, ProviderRisk.MEDIUM),
            
            # AWS CloudFront
            r'.*\.cloudfront\.net': ('AWS CloudFront', ServiceType.CDN, ProviderRisk.MEDIUM),
            r'.*\.amazonaws\.com': ('AWS', ServiceType.CLOUD, ProviderRisk.MEDIUM),
            
            # Fastly
            r'.*\.fastly\.com': ('Fastly', ServiceType.CDN, ProviderRisk.MEDIUM),
            r'.*\.fastlylb\.net': ('Fastly', ServiceType.CDN, ProviderRisk.MEDIUM),
            
            # Akamai
            r'.*\.akamai\.net': ('Akamai', ServiceType.CDN, ProviderRisk.MEDIUM),
            r'.*\.akamaiedge\.net': ('Akamai', ServiceType.CDN, ProviderRisk.MEDIUM),
            r'.*\.edgesuite\.net': ('Akamai', ServiceType.CDN, ProviderRisk.MEDIUM),
            
            # Azure CDN
            r'.*\.azureedge\.net': ('Microsoft Azure CDN', ServiceType.CDN, ProviderRisk.MEDIUM),
            r'.*\.trafficmanager\.net': ('Microsoft Azure', ServiceType.CLOUD, ProviderRisk.MEDIUM),
            
            # Incapsula/Imperva
            r'.*\.incapdns\.net': ('Imperva Incapsula', ServiceType.SECURITY, ProviderRisk.HIGH),
            r'.*\.impervadns\.net': ('Imperva', ServiceType.SECURITY, ProviderRisk.HIGH),
            
            # KeyCDN
            r'.*\.kxcdn\.com': ('KeyCDN', ServiceType.CDN, ProviderRisk.LOW),
            
            # MaxCDN/StackPath
            r'.*\.netdna-cdn\.com': ('StackPath MaxCDN', ServiceType.CDN, ProviderRisk.LOW),
        }
        
        # Patrones de subdominios SaaS
        self.subdomain_patterns = {
            # CRM y Sales
            'salesforce': ('Salesforce', ServiceType.SAAS, ProviderRisk.HIGH),
            'force': ('Salesforce', ServiceType.SAAS, ProviderRisk.HIGH),
            'lightning': ('Salesforce Lightning', ServiceType.SAAS, ProviderRisk.HIGH),
            'hubspot': ('HubSpot', ServiceType.MARKETING, ProviderRisk.MEDIUM),
            
            # Communication
            'slack': ('Slack', ServiceType.SAAS, ProviderRisk.MEDIUM),
            'teams': ('Microsoft Teams', ServiceType.SAAS, ProviderRisk.MEDIUM),
            'zoom': ('Zoom', ServiceType.SAAS, ProviderRisk.MEDIUM),
            
            # Development
            'github': ('GitHub', ServiceType.DEVELOPMENT, ProviderRisk.HIGH),
            'gitlab': ('GitLab', ServiceType.DEVELOPMENT, ProviderRisk.HIGH),
            'bitbucket': ('Bitbucket', ServiceType.DEVELOPMENT, ProviderRisk.HIGH),
            'jenkins': ('Jenkins', ServiceType.DEVELOPMENT, ProviderRisk.MEDIUM),
            'jira': ('Atlassian Jira', ServiceType.DEVELOPMENT, ProviderRisk.MEDIUM),
            'confluence': ('Atlassian Confluence', ServiceType.DEVELOPMENT, ProviderRisk.MEDIUM),
            
            # Analytics
            'analytics': ('Analytics Service', ServiceType.ANALYTICS, ProviderRisk.LOW),
            'gtm': ('Google Tag Manager', ServiceType.ANALYTICS, ProviderRisk.LOW),
            'ga': ('Google Analytics', ServiceType.ANALYTICS, ProviderRisk.LOW),
            
            # Storage
            'dropbox': ('Dropbox', ServiceType.SAAS, ProviderRisk.MEDIUM),
            'onedrive': ('Microsoft OneDrive', ServiceType.SAAS, ProviderRisk.MEDIUM),
            'sharepoint': ('Microsoft SharePoint', ServiceType.SAAS, ProviderRisk.MEDIUM),
            
            # Security
            'okta': ('Okta', ServiceType.SECURITY, ProviderRisk.HIGH),
            'auth0': ('Auth0', ServiceType.SECURITY, ProviderRisk.HIGH),
            'duo': ('Duo Security', ServiceType.SECURITY, ProviderRisk.HIGH),
            
            # Marketing
            'mailchimp': ('Mailchimp', ServiceType.MARKETING, ProviderRisk.MEDIUM),
            'sendgrid': ('SendGrid', ServiceType.EMAIL, ProviderRisk.MEDIUM),
            'marketo': ('Marketo', ServiceType.MARKETING, ProviderRisk.MEDIUM),
            
            # Payment
            'stripe': ('Stripe', ServiceType.SAAS, ProviderRisk.HIGH),
            'paypal': ('PayPal', ServiceType.SAAS, ProviderRisk.HIGH),
            'square': ('Square', ServiceType.SAAS, ProviderRisk.HIGH),
        }
    
    def analyze_domain_dependencies(self, domain: str) -> List[ProviderService]:
        """
        Analiza un dominio completo para identificar todas sus dependencias.
        
        Args:
            domain: Dominio a analizar
            
        Returns:
            Lista de servicios de proveedores detectados
        """
        detected_services = []
        
        try:
            # 1. Analizar registros MX (servicios de email)
            mx_services = self._analyze_mx_records(domain)
            detected_services.extend(mx_services)
            
            # 2. Analizar registros CNAME (CDN, hosting)
            cname_services = self._analyze_cname_records(domain)
            detected_services.extend(cname_services)
            
            # 3. Analizar patrones de subdominios (SaaS)
            subdomain_services = self._analyze_subdomain_patterns(domain)
            detected_services.extend(subdomain_services)
            
            # 4. Analizar registros TXT (verificaciones, SPF, DKIM)
            txt_services = self._analyze_txt_records(domain)
            detected_services.extend(txt_services)
            
            # 5. Analizar registros NS (servicios DNS)
            ns_services = self._analyze_ns_records(domain)
            detected_services.extend(ns_services)
            
            logging.info(f"[PROVIDER_DETECTION] Found {len(detected_services)} services for {domain}")
            
        except Exception as e:
            logging.error(f"[PROVIDER_DETECTION] Error analyzing {domain}: {e}")
        
        return detected_services
    
    def _analyze_mx_records(self, domain: str) -> List[ProviderService]:
        """Analiza registros MX para identificar proveedores de email."""
        services = []
        
        try:
            mx_records = self.resolver.resolve(domain, 'MX')
            
            for mx in mx_records:
                mx_host = str(mx.exchange).rstrip('.')
                
                for pattern, (provider, service_type, risk) in self.mx_providers.items():
                    if re.match(pattern, mx_host, re.IGNORECASE):
                        service = ProviderService(
                            name=f"{provider} Email",
                            provider=provider,
                            service_type=service_type,
                            detection_method="mx_record",
                            risk_level=risk,
                            confidence=0.9,
                            metadata={
                                "mx_host": mx_host,
                                "priority": mx.preference,
                                "record_type": "MX"
                            }
                        )
                        services.append(service)
                        logging.info(f"[MX] Detected {provider} for {domain} via {mx_host}")
                        break
                        
        except dns.exception.DNSException:
            pass  # No MX records found
        except Exception as e:
            logging.warning(f"[MX] Error analyzing MX for {domain}: {e}")
        
        return services
    
    def _analyze_cname_records(self, domain: str) -> List[ProviderService]:
        """Analiza registros CNAME para identificar CDN y servicios de hosting."""
        services = []
        
        # Subdominios comunes que suelen usar CNAME
        common_subdomains = ['www', 'cdn', 'static', 'assets', 'media', 'images', 'api']
        
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            
            try:
                cname_records = self.resolver.resolve(full_domain, 'CNAME')
                
                for cname in cname_records:
                    cname_target = str(cname.target).rstrip('.')
                    
                    for pattern, (provider, service_type, risk) in self.cname_providers.items():
                        if re.match(pattern, cname_target, re.IGNORECASE):
                            service = ProviderService(
                                name=f"{provider} {service_type.value.title()}",
                                provider=provider,
                                service_type=service_type,
                                detection_method="cname_record",
                                risk_level=risk,
                                confidence=0.8,
                                metadata={
                                    "cname_target": cname_target,
                                    "source_domain": full_domain,
                                    "record_type": "CNAME"
                                }
                            )
                            services.append(service)
                            logging.info(f"[CNAME] Detected {provider} for {full_domain} -> {cname_target}")
                            break
                            
            except dns.exception.DNSException:
                pass  # No CNAME record found
            except Exception as e:
                logging.warning(f"[CNAME] Error analyzing CNAME for {full_domain}: {e}")
        
        return services
    
    def _analyze_subdomain_patterns(self, domain: str) -> List[ProviderService]:
        """Analiza patrones de subdominios para identificar servicios SaaS."""
        services = []
        
        # Esta función se puede mejorar obteniendo subdominios reales del dominio
        # Por ahora, analiza patrones conocidos
        
        for pattern, (provider, service_type, risk) in self.subdomain_patterns.items():
            # Construir subdominios potenciales
            potential_subdomains = [
                f"{pattern}.{domain}",
                f"{pattern}-api.{domain}",
                f"{pattern}-app.{domain}",
                f"app-{pattern}.{domain}"
            ]
            
            for subdomain in potential_subdomains:
                try:
                    # Verificar si el subdominio existe
                    self.resolver.resolve(subdomain, 'A')
                    
                    service = ProviderService(
                        name=f"{provider} Service",
                        provider=provider,
                        service_type=service_type,
                        detection_method="subdomain_pattern",
                        risk_level=risk,
                        confidence=0.6,
                        metadata={
                            "subdomain": subdomain,
                            "pattern": pattern,
                            "record_type": "A"
                        }
                    )
                    services.append(service)
                    logging.info(f"[SUBDOMAIN] Detected {provider} via {subdomain}")
                    
                except dns.exception.DNSException:
                    pass  # Subdomain doesn't exist
                except Exception as e:
                    logging.warning(f"[SUBDOMAIN] Error checking {subdomain}: {e}")
        
        return services
    
    def _analyze_txt_records(self, domain: str) -> List[ProviderService]:
        """Analiza registros TXT para identificar servicios y verificaciones."""
        services = []
        
        try:
            txt_records = self.resolver.resolve(domain, 'TXT')
            
            for txt in txt_records:
                txt_value = str(txt).strip('"')
                
                # Detectar servicios por patrones en TXT
                if 'google-site-verification' in txt_value:
                    service = ProviderService(
                        name="Google Site Verification",
                        provider="Google",
                        service_type=ServiceType.ANALYTICS,
                        detection_method="txt_record",
                        risk_level=ProviderRisk.LOW,
                        confidence=0.9,
                        metadata={"txt_content": txt_value[:100], "record_type": "TXT"}
                    )
                    services.append(service)
                
                elif 'v=spf1' in txt_value:
                    # Analizar SPF para identificar proveedores de email
                    spf_providers = self._parse_spf_record(txt_value)
                    services.extend(spf_providers)
                
                elif 'v=DMARC1' in txt_value:
                    service = ProviderService(
                        name="DMARC Policy",
                        provider="Email Security",
                        service_type=ServiceType.SECURITY,
                        detection_method="txt_record",
                        risk_level=ProviderRisk.LOW,
                        confidence=0.8,
                        metadata={"dmarc_policy": txt_value, "record_type": "TXT"}
                    )
                    services.append(service)
                    
        except dns.exception.DNSException:
            pass  # No TXT records found
        except Exception as e:
            logging.warning(f"[TXT] Error analyzing TXT for {domain}: {e}")
        
        return services
    
    def _parse_spf_record(self, spf_value: str) -> List[ProviderService]:
        """Parsea registro SPF para identificar proveedores de email."""
        services = []
        
        # Patrones SPF conocidos
        spf_patterns = {
            'include:_spf.google.com': ('Google Workspace', ServiceType.EMAIL, ProviderRisk.MEDIUM),
            'include:spf.protection.outlook.com': ('Microsoft 365', ServiceType.EMAIL, ProviderRisk.MEDIUM),
            'include:amazonses.com': ('Amazon SES', ServiceType.EMAIL, ProviderRisk.MEDIUM),
            'include:_spf.salesforce.com': ('Salesforce', ServiceType.EMAIL, ProviderRisk.HIGH),
            'include:servers.mcsv.net': ('Mailchimp', ServiceType.MARKETING, ProviderRisk.MEDIUM),
            'include:sendgrid.net': ('SendGrid', ServiceType.EMAIL, ProviderRisk.MEDIUM),
        }
        
        for pattern, (provider, service_type, risk) in spf_patterns.items():
            if pattern in spf_value:
                service = ProviderService(
                    name=f"{provider} SPF",
                    provider=provider,
                    service_type=service_type,
                    detection_method="spf_record",
                    risk_level=risk,
                    confidence=0.8,
                    metadata={"spf_include": pattern, "record_type": "SPF"}
                )
                services.append(service)
                logging.info(f"[SPF] Detected {provider} via SPF record")
        
        return services
    
    def _analyze_ns_records(self, domain: str) -> List[ProviderService]:
        """Analiza registros NS para identificar proveedores DNS."""
        services = []
        
        try:
            ns_records = self.resolver.resolve(domain, 'NS')
            
            # Patrones de proveedores DNS
            dns_providers = {
                r'.*\.cloudflare\.com': ('Cloudflare DNS', ServiceType.HOSTING, ProviderRisk.MEDIUM),
                r'.*\.awsdns.*\.com': ('Amazon Route 53', ServiceType.CLOUD, ProviderRisk.MEDIUM),
                r'.*\.azure-dns\.com': ('Microsoft Azure DNS', ServiceType.CLOUD, ProviderRisk.MEDIUM),
                r'.*\.googledomains\.com': ('Google Cloud DNS', ServiceType.CLOUD, ProviderRisk.MEDIUM),
                r'.*\.dnsimple\.com': ('DNSimple', ServiceType.HOSTING, ProviderRisk.LOW),
                r'.*\.dnsmadeeasy\.com': ('DNS Made Easy', ServiceType.HOSTING, ProviderRisk.LOW),
            }
            
            for ns in ns_records:
                ns_host = str(ns.target).rstrip('.')
                
                for pattern, (provider, service_type, risk) in dns_providers.items():
                    if re.match(pattern, ns_host, re.IGNORECASE):
                        service = ProviderService(
                            name=provider,
                            provider=provider.split()[0],  # Extract provider name
                            service_type=service_type,
                            detection_method="ns_record",
                            risk_level=risk,
                            confidence=0.9,
                            metadata={"ns_host": ns_host, "record_type": "NS"}
                        )
                        services.append(service)
                        logging.info(f"[NS] Detected {provider} for {domain} via {ns_host}")
                        break
                        
        except dns.exception.DNSException:
            pass  # No NS records found
        except Exception as e:
            logging.warning(f"[NS] Error analyzing NS for {domain}: {e}")
        
        return services
    
    def analyze_subdomain_dependencies(self, subdomain: str) -> List[ProviderService]:
        """
        Analiza un subdominio específico para identificar sus dependencias.
        Similar a analyze_domain_dependencies pero optimizado para subdominios.
        """
        detected_services = []
        
        try:
            # 1. Analizar registros CNAME (muy común en subdominios)
            cname_services = self._analyze_subdomain_cname(subdomain)
            detected_services.extend(cname_services)
            
            # 2. Analizar patrones del nombre del subdominio
            pattern_services = self._analyze_subdomain_name_patterns(subdomain)
            detected_services.extend(pattern_services)
            
            # 3. Analizar registros A (para detectar cloud providers por IP)
            ip_services = self._analyze_subdomain_ips(subdomain)
            detected_services.extend(ip_services)
            
            logging.info(f"[SUBDOMAIN_DETECTION] Found {len(detected_services)} services for {subdomain}")
            
        except Exception as e:
            logging.error(f"[SUBDOMAIN_DETECTION] Error analyzing {subdomain}: {e}")
        
        return detected_services
    
    def _analyze_subdomain_cname(self, subdomain: str) -> List[ProviderService]:
        """Analiza CNAME específico del subdominio."""
        services = []
        
        try:
            cname_records = self.resolver.resolve(subdomain, 'CNAME')
            
            for cname in cname_records:
                cname_target = str(cname.target).rstrip('.')
                
                for pattern, (provider, service_type, risk) in self.cname_providers.items():
                    if re.match(pattern, cname_target, re.IGNORECASE):
                        service = ProviderService(
                            name=f"{provider} {service_type.value.title()}",
                            provider=provider,
                            service_type=service_type,
                            detection_method="subdomain_cname",
                            risk_level=risk,
                            confidence=0.9,
                            metadata={
                                "cname_target": cname_target,
                                "source_subdomain": subdomain,
                                "record_type": "CNAME"
                            }
                        )
                        services.append(service)
                        logging.info(f"[SUBDOMAIN_CNAME] Detected {provider} for {subdomain} -> {cname_target}")
                        break
                        
        except dns.exception.DNSException:
            pass  # No CNAME record
        except Exception as e:
            logging.warning(f"[SUBDOMAIN_CNAME] Error analyzing {subdomain}: {e}")
        
        return services
    
    def _analyze_subdomain_name_patterns(self, subdomain: str) -> List[ProviderService]:
        """Analiza el nombre del subdominio para detectar patrones de servicios."""
        services = []
        
        subdomain_lower = subdomain.lower()
        
        for pattern, (provider, service_type, risk) in self.subdomain_patterns.items():
            if pattern in subdomain_lower:
                service = ProviderService(
                    name=f"{provider} Service",
                    provider=provider,
                    service_type=service_type,
                    detection_method="subdomain_name_pattern",
                    risk_level=risk,
                    confidence=0.7,
                    metadata={
                        "subdomain": subdomain,
                        "detected_pattern": pattern,
                        "method": "name_analysis"
                    }
                )
                services.append(service)
                logging.info(f"[SUBDOMAIN_PATTERN] Detected {provider} in {subdomain}")
        
        return services
    
    def _analyze_subdomain_ips(self, subdomain: str) -> List[ProviderService]:
        """Analiza IPs del subdominio para detectar cloud providers."""
        services = []
        
        try:
            a_records = self.resolver.resolve(subdomain, 'A')
            
            for a_record in a_records:
                ip = str(a_record)
                
                # Aquí se puede integrar con la detección de cloud providers por IP
                # que ya existe en risk_loader_advanced3.py
                cloud_provider = self._detect_cloud_by_ip(ip)
                
                if cloud_provider and cloud_provider != "unknown":
                    service = ProviderService(
                        name=f"{cloud_provider} Hosting",
                        provider=cloud_provider,
                        service_type=ServiceType.CLOUD,
                        detection_method="ip_analysis",
                        risk_level=ProviderRisk.MEDIUM,
                        confidence=0.8,
                        metadata={
                            "ip_address": ip,
                            "subdomain": subdomain,
                            "record_type": "A"
                        }
                    )
                    services.append(service)
                    logging.info(f"[IP_ANALYSIS] Detected {cloud_provider} for {subdomain} ({ip})")
                    
        except dns.exception.DNSException:
            pass  # No A record
        except Exception as e:
            logging.warning(f"[IP_ANALYSIS] Error analyzing {subdomain}: {e}")
        
        return services
    
    def _detect_cloud_by_ip(self, ip: str) -> str:
        """Detecta cloud provider por IP. Integra con sistema existente."""
        try:
            # Importar la función existente
            from risk_loader_advanced3 import detect_cloud_provider_by_ip
            return detect_cloud_provider_by_ip(ip, None, None, None)
        except ImportError:
            return "unknown"
        except Exception:
            return "unknown"


# Función de utilidad para uso directo
def detect_all_dependencies(domain: str, include_subdomains: List[str] = None) -> Dict[str, List[ProviderService]]:
    """
    Detecta todas las dependencias de un dominio y sus subdominios.
    
    Args:
        domain: Dominio base
        include_subdomains: Lista de subdominios adicionales a analizar
        
    Returns:
        Diccionario con dependencias por dominio/subdominio
    """
    detector = ProviderDetector()
    results = {}
    
    # Analizar dominio base
    base_dependencies = detector.analyze_domain_dependencies(domain)
    results[domain] = base_dependencies
    
    # Analizar subdominios
    if include_subdomains:
        for subdomain in include_subdomains:
            subdomain_dependencies = detector.analyze_subdomain_dependencies(subdomain)
            results[subdomain] = subdomain_dependencies
    
    return results


if __name__ == "__main__":
    # Test básico
    detector = ProviderDetector()
    
    test_domain = "bice.cl"
    dependencies = detector.analyze_domain_dependencies(test_domain)
    
    print(f"Dependencies for {test_domain}:")
    for dep in dependencies:
        print(f"  - {dep.provider}: {dep.name} ({dep.service_type.value}) - Risk: {dep.risk_level.value}")