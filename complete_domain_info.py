#!/usr/bin/env python3
"""
Script para completar información faltante en el grafo Neo4j.
Completa TLS, tecnologías y risk scores para dominios y subdominios existentes.
"""

import asyncio
import aiohttp
import logging
from typing import List, Dict, Any, Optional
import json
import time
import sys
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse
# Try to import BeautifulSoup, fall back to basic parsing if not available
try:
    from bs4 import BeautifulSoup
    HAS_BEAUTIFULSOUP = True
except ImportError:
    HAS_BEAUTIFULSOUP = False
    BeautifulSoup = None
from neo4j import GraphDatabase

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('domain_completion.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DomainCompleter:
    def __init__(self, force_update: bool = False, all_subdomains: bool = False):
        self.neo4j_driver = GraphDatabase.driver(
            "bolt://localhost:7687", 
            auth=("neo4j", "test.password")
        )
        self.api_base_url = "http://localhost:8001/api/v1"
        self.report_api_url = "http://localhost:8081/api/v1"
        self.session = None
        self.completed_count = 0
        self.failed_count = 0
        self.batch_size = 5  # Reducido para manejar tareas asíncronas
        self.force_update = force_update
        self.all_subdomains = all_subdomains
        
        # Web scraping configuration
        self.scraping_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Technology detection patterns
        self.tech_patterns = {
            # Web servers
            r'Server:\s*([^\r\n]+)': 'web_server',
            r'X-Powered-By:\s*([^\r\n]+)': 'framework',
            r'X-AspNet-Version:\s*([^\r\n]+)': 'framework',
            r'X-Generator:\s*([^\r\n]+)': 'cms',
            
            # Content patterns
            r'wp-content': 'cms:wordpress',
            r'drupal': 'cms:drupal',
            r'joomla': 'cms:joomla',
            r'bootstrap': 'css_framework:bootstrap',
            r'jquery': 'javascript_library:jquery',
            r'angular': 'javascript_framework:angular',
            r'react': 'javascript_framework:react',
            r'vue\.js': 'javascript_framework:vue',
            
            # Analytics and third-party
            r'google-analytics\.com': 'analytics:google_analytics',
            r'googletagmanager\.com': 'analytics:google_tag_manager',
            r'facebook\.net': 'social:facebook_pixel',
            r'doubleclick\.net': 'advertising:google_doubleclick',
            r'cloudflare': 'cdn:cloudflare',
            r'amazonaws\.com': 'cloud_provider:aws',
            r'azure': 'cloud_provider:azure',
            r'googleapis\.com': 'service:google_apis',
        }
        
        # Provider detection patterns
        self.provider_patterns = {
            # CDN/Security
            r'cloudflare': {'name': 'Cloudflare', 'type': 'cdn_security', 'confidence': 0.9},
            r'amazonaws\.com': {'name': 'Amazon Web Services', 'type': 'cloud_provider', 'confidence': 0.9},
            r'azure': {'name': 'Microsoft Azure', 'type': 'cloud_provider', 'confidence': 0.8},
            r'googlecloud': {'name': 'Google Cloud Platform', 'type': 'cloud_provider', 'confidence': 0.9},
            r'fastly': {'name': 'Fastly', 'type': 'cdn', 'confidence': 0.9},
            r'akamai': {'name': 'Akamai Technologies', 'type': 'cdn', 'confidence': 0.9},
            
            # Analytics/Marketing
            r'google-analytics': {'name': 'Google Analytics', 'type': 'analytics', 'confidence': 0.95},
            r'googletagmanager': {'name': 'Google Tag Manager', 'type': 'analytics', 'confidence': 0.95},
            r'facebook\.net': {'name': 'Meta (Facebook)', 'type': 'social_media', 'confidence': 0.9},
            r'twitter\.com': {'name': 'Twitter', 'type': 'social_media', 'confidence': 0.9},
            r'linkedin\.com': {'name': 'LinkedIn', 'type': 'social_media', 'confidence': 0.9},
            
            # Payment processors
            r'paypal': {'name': 'PayPal', 'type': 'payment_processor', 'confidence': 0.95},
            r'stripe': {'name': 'Stripe', 'type': 'payment_processor', 'confidence': 0.95},
            r'transbank': {'name': 'Transbank', 'type': 'payment_processor', 'confidence': 0.95},
            
            # Other services
            r'mailchimp': {'name': 'Mailchimp', 'type': 'email_marketing', 'confidence': 0.9},
            r'salesforce': {'name': 'Salesforce', 'type': 'crm', 'confidence': 0.9},
            r'zendesk': {'name': 'Zendesk', 'type': 'customer_support', 'confidence': 0.9},
        }
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=300),
            headers=self.scraping_headers
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
        self.neo4j_driver.close()
            
    def get_incomplete_domains(self) -> List[str]:
        """Obtiene dominios base con servicios HTTP/HTTPS sin información completa"""
        with self.neo4j_driver.session() as session:
            if self.force_update:
                # Si force_update está activo, obtener todos los dominios con servicios web
                result = session.run("""
                    MATCH (d:Domain)-[:HAS_SERVICE]->(s:Service) 
                    WHERE (s.name IN ['http', 'https', 'HTTP', 'HTTPS'] OR s.port IN [80, 443])
                    RETURN DISTINCT d.fqdn as fqdn
                    ORDER BY d.fqdn
                """)
            else:
                # Comportamiento normal: solo incompletos
                result = session.run("""
                    MATCH (d:Domain)-[:HAS_SERVICE]->(s:Service) 
                    WHERE (d.hasSSL IS NULL OR d.tlsVersion IS NULL OR d.riskScore IS NULL)
                      AND (s.name IN ['http', 'https', 'HTTP', 'HTTPS'] OR s.port IN [80, 443])
                    RETURN DISTINCT d.fqdn as fqdn
                    ORDER BY d.fqdn
                """)
            return [record["fqdn"] for record in result]
    
    def get_incomplete_subdomains(self) -> List[str]:
        """Obtiene subdominios con servicios HTTP/HTTPS sin información completa"""
        with self.neo4j_driver.session() as session:
            if self.all_subdomains:
                # Si all_subdomains está activo, obtener TODOS los subdominios del grafo
                if self.force_update:
                    result = session.run("""
                        MATCH (s:Subdomain)
                        RETURN DISTINCT s.fqdn as fqdn
                        ORDER BY s.fqdn
                        LIMIT 2000
                    """)
                else:
                    result = session.run("""
                        MATCH (s:Subdomain)
                        WHERE s.hasSSL IS NULL OR s.tlsVersion IS NULL OR s.riskScore IS NULL
                        RETURN DISTINCT s.fqdn as fqdn
                        ORDER BY s.fqdn
                        LIMIT 2000
                    """)
            elif self.force_update:
                # Si force_update está activo, obtener todos los subdominios con servicios web
                result = session.run("""
                    MATCH (s:Subdomain)-[:HAS_SERVICE]->(srv:Service) 
                    WHERE (srv.name IN ['http', 'https', 'HTTP', 'HTTPS'] OR srv.port IN [80, 443])
                    RETURN DISTINCT s.fqdn as fqdn
                    ORDER BY s.fqdn
                    LIMIT 1000
                """)
            else:
                # Comportamiento normal: solo incompletos con servicios web
                result = session.run("""
                    MATCH (s:Subdomain)-[:HAS_SERVICE]->(srv:Service) 
                    WHERE (s.hasSSL IS NULL OR s.tlsVersion IS NULL OR s.riskScore IS NULL)
                      AND (srv.name IN ['http', 'https', 'HTTP', 'HTTPS'] OR srv.port IN [80, 443])
                    RETURN DISTINCT s.fqdn as fqdn
                    ORDER BY s.fqdn
                    LIMIT 1000
                """)
            return [record["fqdn"] for record in result]
            
    async def wait_for_task(self, task_id: str, max_wait: int = 30) -> Optional[Dict]:
        """Espera a que una tarea asíncrona se complete"""
        for _ in range(max_wait):
            try:
                url = f"{self.api_base_url}/tasks/{task_id}"
                async with self.session.get(url) as response:
                    if response.status == 200:
                        task_data = await response.json()
                        if task_data.get('status') == 'completed':
                            return task_data.get('result')
                        elif task_data.get('status') == 'failed':
                            logger.warning(f"Task {task_id} failed: {task_data.get('error')}")
                            return None
                        # Task still running, wait
                        await asyncio.sleep(1)
                    else:
                        logger.warning(f"Error checking task {task_id}: {response.status}")
                        return None
            except Exception as e:
                logger.error(f"Error waiting for task {task_id}: {str(e)}")
                return None
        
        logger.warning(f"Task {task_id} timed out after {max_wait} seconds")
        return None
    
    async def get_tls_info(self, domain: str) -> Optional[Dict]:
        """Obtiene información TLS de un dominio"""
        try:
            url = f"{self.api_base_url}/discover/tls/{domain}"
            async with self.session.post(url) as response:
                if response.status == 200:
                    task_data = await response.json()
                    task_id = task_data.get('task_id')
                    if task_id:
                        result = await self.wait_for_task(task_id)
                        if result:
                            logger.debug(f"TLS info for {domain}: {result}")
                            return result
                    return None
                else:
                    logger.warning(f"TLS API error for {domain}: {response.status}")
                    return None
        except Exception as e:
            logger.error(f"Error getting TLS info for {domain}: {str(e)}")
            return None
            
    async def get_technologies(self, domain: str) -> Optional[List[Dict]]:
        """Obtiene información de tecnologías de un dominio"""
        try:
            url = f"{self.api_base_url}/discover/tech/{domain}"
            async with self.session.post(url) as response:
                if response.status == 200:
                    task_data = await response.json()
                    task_id = task_data.get('task_id')
                    if task_id:
                        result = await self.wait_for_task(task_id)
                        if result and 'technologies' in result:
                            technologies = result['technologies']
                            logger.debug(f"Technologies for {domain}: {len(technologies)}")
                            return technologies
                        elif result:
                            # Si el resultado no tiene el formato esperado, intentar usar el resultado directamente
                            if isinstance(result, list):
                                return result
                            else:
                                logger.warning(f"Unexpected tech result format for {domain}: {result}")
                    return []
                else:
                    logger.warning(f"Tech API error for {domain}: {response.status}")
                    return []
        except Exception as e:
            logger.error(f"Error getting technologies for {domain}: {str(e)}")
            return []
            
    async def get_risk_score(self, domain: str) -> Optional[float]:
        """Obtiene el risk score de un dominio desde la API de reporte"""
        try:
            # Primero intentar obtener desde la API de reporte (más eficiente)
            url = f"{self.report_api_url}/domains/{domain}"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    risk_score = data.get('risk_score')
                    if risk_score is not None:
                        return float(risk_score)
                elif response.status != 404:
                    logger.warning(f"Report API error for {domain}: {response.status}")
            
            # Si no funciona, intentar con la API de cálculo asíncrono
            url = f"{self.api_base_url}/calculate/risk/{domain}"
            async with self.session.post(url) as response:
                if response.status == 200:
                    task_data = await response.json()
                    task_id = task_data.get('task_id')
                    if task_id:
                        result = await self.wait_for_task(task_id)
                        if result and isinstance(result, dict):
                            # Buscar el risk score en diferentes campos posibles
                            for field in ['riskScore', 'risk_score', 'score', 'overall_risk_score']:
                                if field in result:
                                    return float(result[field])
                            logger.warning(f"No risk score found in result for {domain}: {result}")
                    return None
                else:
                    logger.warning(f"Risk calculation API error for {domain}: {response.status}")
                    return None
        except Exception as e:
            logger.error(f"Error getting risk score for {domain}: {str(e)}")
            return None
    
    async def scrape_domain_content(self, domain: str) -> Dict[str, Any]:
        """Realiza web scraping para detectar tecnologías y proveedores"""
        scraped_data = {
            'technologies': [],
            'providers': [],
            'external_links': [],
            'analytics_services': [],
            'scraped_content_length': 0,
            'response_headers': {},
            'status_code': None
        }
        
        try:
            # Try HTTPS first, then HTTP
            for protocol in ['https', 'http']:
                url = f"{protocol}://{domain}"
                try:
                    async with self.session.get(url, allow_redirects=True, ssl=False) as response:
                        scraped_data['status_code'] = response.status
                        scraped_data['response_headers'] = dict(response.headers)
                        
                        if response.status == 200:
                            content = await response.text()
                            scraped_data['scraped_content_length'] = len(content)
                            
                            # Detect technologies from headers
                            self._detect_technologies_from_headers(response.headers, scraped_data)
                            
                            # Parse content - use BeautifulSoup if available, otherwise basic parsing
                            if HAS_BEAUTIFULSOUP:
                                soup = BeautifulSoup(content, 'html.parser')
                                # Detect technologies from content
                                self._detect_technologies_from_content(content, soup, scraped_data)
                                # Extract external links
                                self._extract_external_links(soup, domain, scraped_data)
                            else:
                                # Basic content analysis without BeautifulSoup
                                self._detect_technologies_basic(content, scraped_data)
                                self._extract_external_links_basic(content, domain, scraped_data)
                            
                            # Detect providers from content and headers
                            self._detect_providers_from_content(content, response.headers, scraped_data)
                            
                            logger.info(f"Successfully scraped {domain} via {protocol}: "
                                      f"{len(scraped_data['technologies'])} technologies, "
                                      f"{len(scraped_data['providers'])} providers")
                            break
                            
                except Exception as e:
                    logger.debug(f"Failed to scrape {domain} via {protocol}: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Error scraping {domain}: {e}")
        
        return scraped_data
    
    def _detect_technologies_from_headers(self, headers: Dict, scraped_data: Dict):
        """Detecta tecnologías desde headers HTTP"""
        for header_name, header_value in headers.items():
            header_string = f"{header_name}: {header_value}"
            
            for pattern, category in self.tech_patterns.items():
                if ':' in category:
                    category_name, tech_name = category.split(':', 1)
                else:
                    category_name = category
                    tech_name = None
                
                match = re.search(pattern, header_string, re.IGNORECASE)
                if match:
                    tech_info = {
                        'name': tech_name or match.group(1) if match.groups() else match.group(0),
                        'category': category_name,
                        'confidence': 0.9,
                        'source': 'http_header',
                        'evidence': header_string
                    }
                    
                    if tech_info not in scraped_data['technologies']:
                        scraped_data['technologies'].append(tech_info)
    
    def _detect_technologies_from_content(self, content: str, soup: BeautifulSoup, scraped_data: Dict):
        """Detecta tecnologías desde contenido HTML"""
        # Meta tags
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator and meta_generator.get('content'):
            generator = meta_generator.get('content')
            scraped_data['technologies'].append({
                'name': generator,
                'category': 'cms',
                'confidence': 0.8,
                'source': 'meta_tag',
                'evidence': str(meta_generator)
            })
        
        # Script sources and patterns
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script.get('src', '')
            
            for pattern, category in self.tech_patterns.items():
                if ':' in category:
                    category_name, tech_name = category.split(':', 1)
                else:
                    category_name = category
                    tech_name = None
                
                if re.search(pattern, src, re.IGNORECASE):
                    tech_info = {
                        'name': tech_name or pattern.replace(r'\.', '.').replace(r'\-', '-'),
                        'category': category_name,
                        'confidence': 0.8,
                        'source': 'script_src',
                        'evidence': src
                    }
                    
                    if tech_info not in scraped_data['technologies']:
                        scraped_data['technologies'].append(tech_info)
        
        # Content patterns
        for pattern, category in self.tech_patterns.items():
            if ':' in category:
                category_name, tech_name = category.split(':', 1)
            else:
                category_name = category
                tech_name = None
            
            if re.search(pattern, content, re.IGNORECASE):
                tech_info = {
                    'name': tech_name or pattern.replace(r'\.', '.').replace(r'\-', '-'),
                    'category': category_name,
                    'confidence': 0.7,
                    'source': 'content_analysis',
                    'evidence': f'Pattern found: {pattern}'
                }
                
                if tech_info not in scraped_data['technologies']:
                    scraped_data['technologies'].append(tech_info)
    
    def _detect_providers_from_content(self, content: str, headers: Dict, scraped_data: Dict):
        """Detecta proveedores desde contenido y headers"""
        # Check headers first
        headers_text = ' '.join([f"{k}: {v}" for k, v in headers.items()])
        combined_text = headers_text + ' ' + content
        
        for pattern, provider_info in self.provider_patterns.items():
            if re.search(pattern, combined_text, re.IGNORECASE):
                provider_data = {
                    'name': provider_info['name'],
                    'provider_type': provider_info['type'],
                    'confidence': provider_info['confidence'],
                    'source': 'web_scraping',
                    'evidence': f'Pattern match: {pattern}'
                }
                
                if provider_data not in scraped_data['providers']:
                    scraped_data['providers'].append(provider_data)
    
    def _extract_external_links(self, soup: BeautifulSoup, domain: str, scraped_data: Dict):
        """Extrae links externos para análisis de dependencias"""
        external_links = set()
        
        # Links from <a> tags
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            if href and href.startswith(('http://', 'https://')):
                parsed_url = urlparse(href)
                if parsed_url.netloc and parsed_url.netloc != domain:
                    external_links.add(parsed_url.netloc)
        
        # Links from script sources
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src and src.startswith(('http://', 'https://')):
                parsed_url = urlparse(src)
                if parsed_url.netloc and parsed_url.netloc != domain:
                    external_links.add(parsed_url.netloc)
        
        # Links from link tags (CSS, etc.)
        for link in soup.find_all('link', href=True):
            href = link.get('href')
            if href and href.startswith(('http://', 'https://')):
                parsed_url = urlparse(href)
                if parsed_url.netloc and parsed_url.netloc != domain:
                    external_links.add(parsed_url.netloc)
        
        scraped_data['external_links'] = list(external_links)[:20]  # Limit to 20 links
    
    def _detect_technologies_basic(self, content: str, scraped_data: Dict):
        """Detecta tecnologías usando análisis básico sin BeautifulSoup"""
        # Content patterns matching
        for pattern, category in self.tech_patterns.items():
            if ':' in category:
                category_name, tech_name = category.split(':', 1)
            else:
                category_name = category
                tech_name = None
            
            if re.search(pattern, content, re.IGNORECASE):
                tech_info = {
                    'name': tech_name or pattern.replace(r'\.', '.').replace(r'\-', '-'),
                    'category': category_name,
                    'confidence': 0.6,
                    'source': 'basic_content_analysis',
                    'evidence': f'Pattern found: {pattern}'
                }
                
                if tech_info not in scraped_data['technologies']:
                    scraped_data['technologies'].append(tech_info)
        
        # Basic meta tag detection with regex
        meta_generator_pattern = r'<meta[^>]*name=[\'"]generator[\'"][^>]*content=[\'"]([^\'"]+)[\'"][^>]*>'
        generator_match = re.search(meta_generator_pattern, content, re.IGNORECASE)
        if generator_match:
            generator = generator_match.group(1)
            scraped_data['technologies'].append({
                'name': generator,
                'category': 'cms',
                'confidence': 0.8,
                'source': 'meta_tag_regex',
                'evidence': generator_match.group(0)
            })
        
        # Basic script src detection
        script_pattern = r'<script[^>]*src=[\'"]([^\'"]+)[\'"][^>]*>'
        script_matches = re.findall(script_pattern, content, re.IGNORECASE)
        
        for src in script_matches:
            for pattern, category in self.tech_patterns.items():
                if ':' in category:
                    category_name, tech_name = category.split(':', 1)
                else:
                    category_name = category
                    tech_name = None
                
                if re.search(pattern, src, re.IGNORECASE):
                    tech_info = {
                        'name': tech_name or pattern.replace(r'\.', '.').replace(r'\-', '-'),
                        'category': category_name,
                        'confidence': 0.7,
                        'source': 'script_src_regex',
                        'evidence': src
                    }
                    
                    if tech_info not in scraped_data['technologies']:
                        scraped_data['technologies'].append(tech_info)
    
    def _extract_external_links_basic(self, content: str, domain: str, scraped_data: Dict):
        """Extrae links externos usando regex básico"""
        external_links = set()
        
        # Extract links from href attributes
        href_pattern = r'href=[\'"]https?://([^\'"/?#]+)[^\'"]*[\'"]'
        href_matches = re.findall(href_pattern, content, re.IGNORECASE)
        
        for netloc in href_matches:
            if netloc != domain:
                external_links.add(netloc)
        
        # Extract links from src attributes  
        src_pattern = r'src=[\'"]https?://([^\'"/?#]+)[^\'"]*[\'"]'
        src_matches = re.findall(src_pattern, content, re.IGNORECASE)
        
        for netloc in src_matches:
            if netloc != domain:
                external_links.add(netloc)
        
        scraped_data['external_links'] = list(external_links)[:20]  # Limit to 20 links
    
    async def get_domain_report_info(self, domain: str) -> Optional[Dict]:
        """Obtiene información completa del dominio desde la API de reporte"""
        try:
            url = f"{self.report_api_url}/domains/{domain}"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return data
                elif response.status == 404:
                    logger.debug(f"Domain {domain} not found in report API")
                    return None
                else:
                    logger.warning(f"Report API error for {domain}: {response.status}")
                    return None
        except Exception as e:
            logger.error(f"Error getting domain report for {domain}: {str(e)}")
            return None
    
    def update_domain_tls(self, domain: str, tls_info: Dict):
        """Actualiza información TLS en Neo4j"""
        with self.neo4j_driver.session() as session:
            # Extraer información del formato API actualizado
            metadata = tls_info.get('metadata', {})
            has_ssl = metadata.get('has_valid_cert', False)
            tls_version = tls_info.get('tls_version', metadata.get('tls_version', 'unknown'))
            cert_valid = metadata.get('has_valid_cert', False)
            
            # Actualizar dominio base
            session.run("""
                MATCH (d:Domain {fqdn: $domain})
                SET d.hasSSL = $has_ssl,
                    d.tlsVersion = $tls_version,
                    d.certificateValid = $cert_valid,
                    d.lastTLSCheck = datetime()
            """, domain=domain, has_ssl=has_ssl, tls_version=tls_version, cert_valid=cert_valid)
            
            # Actualizar subdominios relacionados
            session.run("""
                MATCH (d:Domain {fqdn: $domain})<-[:BELONGS_TO]-(s:Subdomain)
                WHERE s.fqdn CONTAINS $domain
                SET s.hasSSL = $has_ssl,
                    s.tlsVersion = $tls_version,
                    s.certificateValid = $cert_valid,
                    s.lastTLSCheck = datetime()
            """, domain=domain, has_ssl=has_ssl, tls_version=tls_version, cert_valid=cert_valid)
    
    def update_subdomain_tls(self, subdomain: str, tls_info: Dict):
        """Actualiza información TLS de un subdominio específico"""
        with self.neo4j_driver.session() as session:
            # Extraer información del formato API actualizado
            metadata = tls_info.get('metadata', {})
            has_ssl = metadata.get('has_valid_cert', False)
            tls_version = tls_info.get('tls_version', metadata.get('tls_version', 'unknown'))
            cert_valid = metadata.get('has_valid_cert', False)
            
            session.run("""
                MATCH (s:Subdomain {fqdn: $subdomain})
                SET s.hasSSL = $has_ssl,
                    s.tlsVersion = $tls_version,
                    s.certificateValid = $cert_valid,
                    s.lastTLSCheck = datetime()
            """, subdomain=subdomain, has_ssl=has_ssl, tls_version=tls_version, cert_valid=cert_valid)
    
    def update_technologies(self, domain: str, technologies: List[Dict]):
        """Actualiza tecnologías usando el modelo mejorado con versiones detalladas"""
        with self.neo4j_driver.session() as session:
            # Actualizar el nodo principal con las tecnologías detectadas
            session.run("""
                MATCH (d:Domain {fqdn: $domain})
                SET d.technologies = $technologies,
                    d.technologiesAnalyzed = datetime()
            """, domain=domain, technologies=json.dumps(technologies))
            
            # Crear nodos Technology específicos con modelo mejorado
            for tech in technologies:
                self._create_enhanced_technology_nodes_in_complete_domain_info(session, tech, domain)
    
    def _create_enhanced_technology_nodes_in_complete_domain_info(self, session, tech, domain):
        """Crea nodos de tecnología mejorados con versiones y proveedores"""
        current_time = datetime.now().isoformat()
        
        # Parsear información de software con versiones
        software_info = self._parse_software_with_version(tech)
        if software_info:
            # Crear nodo Software
            session.run("""
                MERGE (s:Software {name: $software_name})
                SET s.category = $category,
                    s.vendor = $vendor,
                    s.updated_at = $timestamp
            """, 
            software_name=software_info["name"],
            category=software_info["category"],
            vendor=software_info["vendor"],
            timestamp=current_time)
            
            # Crear nodo SoftwareVersion si hay versión
            if software_info["version"]:
                session.run("""
                    MERGE (sv:SoftwareVersion {software_name: $software_name, version: $version})
                    SET sv.confidence = $confidence,
                        sv.detection_source = $source,
                        sv.created_at = coalesce(sv.created_at, $timestamp),
                        sv.updated_at = $timestamp
                """,
                software_name=software_info["name"],
                version=software_info["version"],
                confidence=tech.get("confidence", 0.8),
                source=tech.get("source", "web_scraping"),
                timestamp=current_time)
                
                # Relación: Software <-[:VERSION_OF]- SoftwareVersion
                session.run("""
                    MATCH (s:Software {name: $software_name})
                    MATCH (sv:SoftwareVersion {software_name: $software_name, version: $version})
                    MERGE (sv)-[:VERSION_OF]->(s)
                """,
                software_name=software_info["name"],
                version=software_info["version"])
                
                # Relación: Domain -[:USES]-> SoftwareVersion
                session.run("""
                    MATCH (d {fqdn: $domain})
                    MATCH (sv:SoftwareVersion {software_name: $software_name, version: $version})
                    MERGE (d)-[r:USES]->(sv)
                    SET r.confidence = $confidence,
                        r.detected_at = $timestamp,
                        r.detection_source = $source
                """,
                domain=domain,
                software_name=software_info["name"],
                version=software_info["version"],
                confidence=tech.get("confidence", 0.8),
                source=tech.get("source", "web_scraping"),
                timestamp=current_time)
            else:
                # Relación: Domain -[:USES]-> Software (sin versión específica)
                session.run("""
                    MATCH (d {fqdn: $domain})
                    MATCH (s:Software {name: $software_name})
                    MERGE (d)-[r:USES]->(s)
                    SET r.confidence = $confidence,
                        r.detected_at = $timestamp,
                        r.detection_source = $source
                """,
                domain=domain,
                software_name=software_info["name"],
                confidence=tech.get("confidence", 0.8),
                source=tech.get("source", "web_scraping"),
                timestamp=current_time)
        
        # Mantener también el nodo Technology original para compatibilidad
        tech_name = tech.get('name', 'Unknown')
        category = tech.get('category', 'unknown')
        confidence = tech.get('confidence', 0.5)
        source = tech.get('source', 'unknown')
        version = tech.get('version', None)
        
        # Crear o actualizar nodo Technology tradicional
        session.run("""
            MERGE (t:Technology {name: $tech_name})
            ON CREATE SET t.category = $category,
                         t.first_seen = datetime(),
                         t.confidence = $confidence,
                         t.source = $source
            ON MATCH SET t.last_seen = datetime(),
                        t.confidence = CASE 
                            WHEN $confidence > t.confidence THEN $confidence 
                            ELSE t.confidence 
                        END
        """, tech_name=tech_name, category=category, confidence=confidence, source=source)
        
        # Crear relación tradicional para compatibilidad
        session.run("""
            MATCH (d {fqdn: $domain})
            MATCH (t:Technology {name: $tech_name})
            MERGE (d)-[r:USES_TECHNOLOGY]->(t)
            SET r.confidence = $confidence,
                r.version = $version,
                r.detectedAt = datetime()
        """, domain=domain, tech_name=tech_name, confidence=confidence, version=version)
    
    def _parse_software_with_version(self, tech_data):
        """Parsea información de software con extracción de versión"""
        tech_name = tech_data.get('name', '').lower()
        category = tech_data.get('category', 'unknown')
        
        # Patrones de software para extracción de versiones
        software_patterns = {
            r'apache[/\s]*([\d\.]+)': {'name': 'Apache Web Server', 'vendor': 'Apache Software Foundation', 'category': 'web_server'},
            r'nginx[/\s]*([\d\.]+)': {'name': 'Nginx', 'vendor': 'Nginx Inc.', 'category': 'web_server'},
            r'php[/\s]*([\d\.]+)': {'name': 'PHP', 'vendor': 'PHP Group', 'category': 'programming_language'},
            r'mysql[/\s]*([\d\.]+)': {'name': 'MySQL', 'vendor': 'Oracle Corporation', 'category': 'database'},
            r'wordpress[/\s]*([\d\.]+)': {'name': 'WordPress', 'vendor': 'Automattic', 'category': 'cms'},
            r'jquery[/\s]*([\d\.]+)': {'name': 'jQuery', 'vendor': 'jQuery Foundation', 'category': 'javascript_library'},
            r'bootstrap[/\s]*([\d\.]+)': {'name': 'Bootstrap', 'vendor': 'Twitter', 'category': 'css_framework'},
            r'react[/\s]*([\d\.]+)': {'name': 'React', 'vendor': 'Meta', 'category': 'javascript_framework'},
            r'angular[/\s]*([\d\.]+)': {'name': 'Angular', 'vendor': 'Google', 'category': 'javascript_framework'},
        }
        
        # Intentar extraer versión usando patrones
        for pattern, info in software_patterns.items():
            match = re.search(pattern, tech_name, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else None
                return {
                    "name": info['name'],
                    "category": info['category'],
                    "vendor": info['vendor'],
                    "version": version
                }
        
        # Manejar software conocido sin versión específica
        known_software = {
            'apache': {'name': 'Apache Web Server', 'vendor': 'Apache Software Foundation', 'category': 'web_server'},
            'nginx': {'name': 'Nginx', 'vendor': 'Nginx Inc.', 'category': 'web_server'},
            'cloudflare': {'name': 'Cloudflare', 'vendor': 'Cloudflare Inc.', 'category': 'cdn_security'},
            'wordpress': {'name': 'WordPress', 'vendor': 'Automattic', 'category': 'cms'},
            'jquery': {'name': 'jQuery', 'vendor': 'jQuery Foundation', 'category': 'javascript_library'},
            'bootstrap': {'name': 'Bootstrap', 'vendor': 'Twitter', 'category': 'css_framework'},
            'react': {'name': 'React', 'vendor': 'Meta', 'category': 'javascript_framework'},
            'angular': {'name': 'Angular', 'vendor': 'Google', 'category': 'javascript_framework'},
        }
        
        for key, info in known_software.items():
            if key in tech_name:
                return {
                    "name": info['name'],
                    "category": info['category'], 
                    "vendor": info['vendor'],
                    "version": None
                }
        
        return None
    
    def update_subdomain_technologies(self, subdomain: str, technologies: List[Dict]):
        """Actualiza tecnologías específicas de un subdominio usando modelo mejorado"""
        with self.neo4j_driver.session() as session:
            # Actualizar el nodo subdomain con las tecnologías detectadas
            session.run("""
                MATCH (s:Subdomain {fqdn: $subdomain})
                SET s.technologies = $technologies,
                    s.technologiesAnalyzed = datetime()
            """, subdomain=subdomain, technologies=json.dumps(technologies))
            
            # Crear nodos Technology específicos con modelo mejorado
            for tech in technologies:
                self._create_enhanced_technology_nodes_for_subdomain(session, tech, subdomain)
    
    def _create_enhanced_technology_nodes_for_subdomain(self, session, tech, subdomain):
        """Crea nodos de tecnología mejorados para subdominios"""
        current_time = datetime.now().isoformat()
        
        # Parsear información de software con versiones
        software_info = self._parse_software_with_version(tech)
        if software_info:
            # Crear nodo Software
            session.run("""
                MERGE (s:Software {name: $software_name})
                SET s.category = $category,
                    s.vendor = $vendor,
                    s.updated_at = $timestamp
            """, 
            software_name=software_info["name"],
            category=software_info["category"],
            vendor=software_info["vendor"],
            timestamp=current_time)
            
            # Crear nodo SoftwareVersion si hay versión
            if software_info["version"]:
                session.run("""
                    MERGE (sv:SoftwareVersion {software_name: $software_name, version: $version})
                    SET sv.confidence = $confidence,
                        sv.detection_source = $source,
                        sv.created_at = coalesce(sv.created_at, $timestamp),
                        sv.updated_at = $timestamp
                """,
                software_name=software_info["name"],
                version=software_info["version"],
                confidence=tech.get("confidence", 0.8),
                source=tech.get("source", "web_scraping"),
                timestamp=current_time)
                
                # Relación: Software <-[:VERSION_OF]- SoftwareVersion
                session.run("""
                    MATCH (s:Software {name: $software_name})
                    MATCH (sv:SoftwareVersion {software_name: $software_name, version: $version})
                    MERGE (sv)-[:VERSION_OF]->(s)
                """,
                software_name=software_info["name"],
                version=software_info["version"])
                
                # Relación: Subdomain -[:USES]-> SoftwareVersion
                session.run("""
                    MATCH (d {fqdn: $subdomain})
                    MATCH (sv:SoftwareVersion {software_name: $software_name, version: $version})
                    MERGE (d)-[r:USES]->(sv)
                    SET r.confidence = $confidence,
                        r.detected_at = $timestamp,
                        r.detection_source = $source
                """,
                subdomain=subdomain,
                software_name=software_info["name"],
                version=software_info["version"],
                confidence=tech.get("confidence", 0.8),
                source=tech.get("source", "web_scraping"),
                timestamp=current_time)
            else:
                # Relación: Subdomain -[:USES]-> Software (sin versión específica)
                session.run("""
                    MATCH (d {fqdn: $subdomain})
                    MATCH (s:Software {name: $software_name})
                    MERGE (d)-[r:USES]->(s)
                    SET r.confidence = $confidence,
                        r.detected_at = $timestamp,
                        r.detection_source = $source
                """,
                subdomain=subdomain,
                software_name=software_info["name"],
                confidence=tech.get("confidence", 0.8),
                source=tech.get("source", "web_scraping"),
                timestamp=current_time)
        
        # Mantener también el nodo Technology original para compatibilidad
        tech_name = tech.get('name', 'Unknown')
        category = tech.get('category', 'unknown')
        confidence = tech.get('confidence', 0.5)
        source = tech.get('source', 'unknown')
        version = tech.get('version', None)
        
        # Crear o actualizar nodo Technology tradicional
        session.run("""
            MERGE (t:Technology {name: $tech_name})
            ON CREATE SET t.category = $category,
                         t.first_seen = datetime(),
                         t.confidence = $confidence,
                         t.source = $source
            ON MATCH SET t.last_seen = datetime(),
                        t.confidence = CASE 
                            WHEN $confidence > t.confidence THEN $confidence 
                            ELSE t.confidence 
                        END
        """, tech_name=tech_name, category=category, confidence=confidence, source=source)
        
        # Crear relación tradicional para compatibilidad
        session.run("""
            MATCH (d {fqdn: $subdomain})
            MATCH (t:Technology {name: $tech_name})
            MERGE (d)-[r:USES_TECHNOLOGY]->(t)
            SET r.confidence = $confidence,
                r.version = $version,
                r.detectedAt = datetime()
        """, subdomain=subdomain, tech_name=tech_name, confidence=confidence, version=version)
    
    def create_provider_nodes(self, domain: str, providers: List[Dict]):
        """Crea nodos Provider basados en datos de web scraping"""
        with self.neo4j_driver.session() as session:
            current_time = datetime.now().isoformat()
            
            for provider in providers:
                provider_name = provider.get('name', 'Unknown Provider')
                provider_type = provider.get('provider_type', 'unknown')
                confidence = provider.get('confidence', 0.5)
                source = provider.get('source', 'web_scraping')
                
                # Crear o actualizar nodo Provider
                session.run("""
                    MERGE (p:Provider {name: $name})
                    ON CREATE SET p.type = $type,
                                 p.created_at = $timestamp,
                                 p.confidence = $confidence,
                                 p.detection_source = $source
                    ON MATCH SET p.updated_at = $timestamp,
                                p.confidence = CASE 
                                    WHEN $confidence > p.confidence THEN $confidence 
                                    ELSE p.confidence 
                                END
                """, name=provider_name, type=provider_type, 
                     timestamp=current_time, confidence=confidence, source=source)
                
                # Crear relación entre domain y provider
                session.run("""
                    MATCH (d {fqdn: $domain})
                    MATCH (p:Provider {name: $provider_name})
                    MERGE (d)-[r:USES_PROVIDER]->(p)
                    ON CREATE SET r.detected_at = $timestamp,
                                 r.confidence = $confidence,
                                 r.source = $source
                    ON MATCH SET r.last_seen = $timestamp,
                                r.confidence = CASE 
                                    WHEN $confidence > r.confidence THEN $confidence 
                                    ELSE r.confidence 
                                END
                """, domain=domain, provider_name=provider_name,
                     timestamp=current_time, confidence=confidence, source=source)
                
                logger.info(f"Created/updated provider {provider_name} for {domain}")
    
    def update_risk_score(self, domain: str, risk_score: float, risk_grade: str = None, is_subdomain: bool = False):
        """Actualiza risk score con grading A-E correcto"""
        # Convert risk_score to correct A-E grade if not provided
        if risk_grade is None:
            if risk_score <= 20:
                risk_grade = "A"  # Excellent - Low risk
            elif risk_score <= 40:
                risk_grade = "B"  # Good - Low-Medium risk
            elif risk_score <= 60:
                risk_grade = "C"  # Fair - Medium risk
            elif risk_score <= 80:
                risk_grade = "D"  # Poor - High risk
            else:
                risk_grade = "E"  # Critical - Very High risk
        
        with self.neo4j_driver.session() as session:
            node_type = "Subdomain" if is_subdomain else "Domain"
            session.run(f"""
                MATCH (n:{node_type} {{fqdn: $domain}})
                SET n.riskScore = $risk_score,
                    n.risk_score = $risk_score,
                    n.risk_grade = $risk_grade,
                    n.risk_tier = $risk_grade,
                    n.lastRiskCalculation = datetime()
            """, domain=domain, risk_score=risk_score, risk_grade=risk_grade)
    
    async def complete_domain_info(self, domain: str, is_subdomain: bool = False):
        """Completa toda la información de un dominio"""
        try:
            logger.info(f"Completing info for {'subdomain' if is_subdomain else 'domain'}: {domain}")
            
            # Para dominios base, intentar obtener info desde la API de reporte primero
            report_info = None
            if not is_subdomain:
                report_info = await self.get_domain_report_info(domain)
                
            # Obtener información TLS
            tls_info = None
            if report_info and 'tls_grade' in report_info:
                # Usar información TLS de la API de reporte si está disponible
                tls_info = {
                    'metadata': {
                        'has_valid_cert': report_info.get('tls_grade') not in ['F', 'T'],
                        'tls_version': 'TLSv1.3' if report_info.get('tls_grade') in ['A+', 'A', 'A-'] else 'Unknown'
                    },
                    'tls_version': 'TLSv1.3' if report_info.get('tls_grade') in ['A+', 'A', 'A-'] else 'Unknown'
                }
            else:
                # Obtener via API asíncrona
                tls_info = await self.get_tls_info(domain)
                
            if tls_info:
                if is_subdomain:
                    self.update_subdomain_tls(domain, tls_info)
                else:
                    self.update_domain_tls(domain, tls_info)
                logger.info(f"Updated TLS info for {domain}")
            
            # Obtener tecnologías - combinar API y web scraping
            technologies = []
            scraped_data = {}
            
            # Obtener tecnologías desde API si están disponibles
            if report_info and 'technology_nodes' in report_info:
                # Usar tecnologías de la API de reporte
                tech_nodes = report_info.get('technology_nodes', [])
                technologies = [{'name': tech['name'], 'category': tech['category']} for tech in tech_nodes]
                logger.info(f"Got {len(technologies)} technologies from report API for {domain}")
            else:
                # Obtener via API asíncrona
                api_technologies = await self.get_technologies(domain)
                technologies.extend(api_technologies or [])
            
            # Realizar web scraping para detectar tecnologías adicionales y proveedores
            try:
                scraped_data = await self.scrape_domain_content(domain)
                
                # Agregar tecnologías detectadas por scraping
                if scraped_data.get('technologies'):
                    scraped_technologies = scraped_data['technologies']
                    # Evitar duplicados basándose en el nombre
                    existing_names = set(tech.get('name', '').lower() for tech in technologies)
                    for tech in scraped_technologies:
                        tech_name = tech.get('name', '').lower()
                        if tech_name not in existing_names:
                            technologies.append(tech)
                            existing_names.add(tech_name)
                    
                    logger.info(f"Added {len(scraped_technologies)} technologies from web scraping for {domain}")
                
                # Crear nodos Provider si se detectaron
                if scraped_data.get('providers'):
                    providers = scraped_data['providers']
                    self.create_provider_nodes(domain, providers)
                    logger.info(f"Created {len(providers)} provider nodes for {domain}")
                    
            except Exception as e:
                logger.error(f"Error during web scraping for {domain}: {e}")
                # Continuar con las tecnologías de API si el scraping falla
                
            if technologies:
                if is_subdomain:
                    self.update_subdomain_technologies(domain, technologies)
                else:
                    self.update_technologies(domain, technologies)
                logger.info(f"Updated {len(technologies)} total technologies for {domain}")
            
            # Actualizar información adicional de scraping en Neo4j
            if scraped_data:
                self.update_scraping_metadata(domain, scraped_data, is_subdomain)
            
            # Obtener risk score
            risk_score = None
            if report_info and 'risk_score' in report_info:
                risk_score = float(report_info['risk_score'])
            else:
                risk_score = await self.get_risk_score(domain)
                
            if risk_score is not None:
                # Ensure we have a minimum base risk score to avoid 0.0 scores
                if risk_score == 0.0:
                    risk_score = 15.0  # Base risk for any publicly accessible domain
                    logger.info(f"Applied base risk score for {domain}: {risk_score} (was 0.0)")
                
                self.update_risk_score(domain, risk_score, is_subdomain=is_subdomain)
                logger.info(f"Updated risk score for {domain}: {risk_score}")
            
            self.completed_count += 1
            
            # Pausa más corta si usamos la API de reporte
            await asyncio.sleep(1 if report_info else 2)
            
        except Exception as e:
            logger.error(f"Error completing info for {domain}: {str(e)}")
            self.failed_count += 1
    
    async def process_batch(self, domains: List[str], is_subdomain: bool = False):
        """Procesa un lote de dominios concurrentemente"""
        tasks = []
        for domain in domains:
            task = self.complete_domain_info(domain, is_subdomain)
            tasks.append(task)
            
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def run_completion(self):
        """Ejecuta el proceso completo de completar información"""
        logger.info("Iniciando completado de información de dominios...")
        
        # Completar dominios base con servicios HTTP/HTTPS
        domains = self.get_incomplete_domains()
        status_msg = "con servicios web (FORZADO - todos)" if self.force_update else "con servicios web incompletos"
        logger.info(f"Encontrados {len(domains)} dominios base {status_msg}")
        
        for i in range(0, len(domains), self.batch_size):
            batch = domains[i:i + self.batch_size]
            logger.info(f"Procesando lote {i//self.batch_size + 1} de dominios base ({len(batch)} dominios)")
            await self.process_batch(batch, is_subdomain=False)
            logger.info(f"Completados: {self.completed_count}, Fallidos: {self.failed_count}")
        
        # Completar subdominios con servicios HTTP/HTTPS
        subdomains = self.get_incomplete_subdomains()
        if self.all_subdomains:
            if self.force_update:
                status_msg = "TODOS del grafo (FORZADO)"
            else:
                status_msg = "incompletos del grafo completo"
        else:
            status_msg = "con servicios web (FORZADO - todos)" if self.force_update else "con servicios web incompletos"
        logger.info(f"Encontrados {len(subdomains)} subdominios {status_msg}")
        
        for i in range(0, len(subdomains), self.batch_size):
            batch = subdomains[i:i + self.batch_size]
            logger.info(f"Procesando lote {i//self.batch_size + 1} de subdominios ({len(batch)} subdominios)")
            await self.process_batch(batch, is_subdomain=True)
            logger.info(f"Completados: {self.completed_count}, Fallidos: {self.failed_count}")
        
        logger.info(f"Proceso completado. Total completados: {self.completed_count}, Total fallidos: {self.failed_count}")
    
    def update_scraping_metadata(self, domain: str, scraped_data: Dict, is_subdomain: bool = False):
        """Actualiza metadata de web scraping en Neo4j"""
        with self.neo4j_driver.session() as session:
            node_type = "Subdomain" if is_subdomain else "Domain"
            
            # Actualizar información de scraping
            session.run(f"""
                MATCH (n:{node_type} {{fqdn: $domain}})
                SET n.scraped_content_length = $content_length,
                    n.scraping_status_code = $status_code,
                    n.external_links_count = $links_count,
                    n.scraping_analyzed_at = datetime(),
                    n.updated_at = datetime()
            """, 
            domain=domain,
            content_length=scraped_data.get('scraped_content_length', 0),
            status_code=scraped_data.get('status_code'),
            links_count=len(scraped_data.get('external_links', [])))
            
            # Guardar enlaces externos como JSON si hay alguno
            if scraped_data.get('external_links'):
                session.run(f"""
                    MATCH (n:{node_type} {{fqdn: $domain}})
                    SET n.external_links = $external_links
                """, 
                domain=domain,
                external_links=json.dumps(scraped_data['external_links']))
        
        logger.info(f"Updated scraping metadata for {domain} ({'subdomain' if is_subdomain else 'domain'})")

async def main():
    """Función principal"""
    print("=== Domain Information Completer ===")
    print("Este script completará la información faltante de TLS, tecnologías y risk scores")
    print("para dominios y subdominios CON SERVICIOS HTTP/HTTPS existentes en Neo4j.\n")
    
    # Verificar argumentos de línea de comandos
    force_update = False
    auto_mode = False
    all_subdomains = False
    
    for arg in sys.argv[1:]:
        if arg == '--auto':
            auto_mode = True
            print("Modo automático activado, procediendo sin confirmación...")
        elif arg == '--force':
            force_update = True
            print("Modo FORCE activado: se procesarán TODOS los dominios con servicios web, incluso si ya tienen información completa.")
        elif arg == '--all-subdomains':
            all_subdomains = True
            print("Modo ALL-SUBDOMAINS activado: se procesarán TODOS los subdominios del grafo, no solo los que tienen servicios HTTP/HTTPS.")
        elif arg == '--help':
            print("Opciones disponibles:")
            print("  --auto           : Ejecutar sin confirmación")
            print("  --force          : Procesar TODOS los dominios con servicios web (no solo incompletos)")
            print("  --all-subdomains : Procesar TODOS los subdominios del grafo (no solo los con servicios HTTP/HTTPS)")
            print("  --help           : Mostrar esta ayuda")
            print("\nCombinaciones útiles:")
            print("  --force --all-subdomains : Procesar TODOS los subdominios del grafo, incluso si ya están completos")
            return
    
    if force_update or all_subdomains:
        print("\n⚠️  ADVERTENCIAS ACTIVAS:")
        if force_update:
            print("• Modo --force: Se procesarán TODOS los dominios/subdominios (incluso si ya están completos)")
        if all_subdomains:
            print("• Modo --all-subdomains: Se procesarán TODOS los subdominios del grafo (no solo los con servicios HTTP/HTTPS)")
        print("Esto puede tomar mucho tiempo y hacer muchas consultas a las APIs.\n")
    
    if not auto_mode:
        try:
            response = input("¿Desea continuar? (y/N): ").strip().lower()
            if response != 'y':
                print("Operación cancelada.")
                return
        except EOFError:
            print("Entrada no interactiva detectada. Use --auto para ejecutar automáticamente.")
            return
    
    async with DomainCompleter(force_update=force_update, all_subdomains=all_subdomains) as completer:
        start_time = time.time()
        await completer.run_completion()
        end_time = time.time()
        
        print(f"\nProceso completado en {end_time - start_time:.2f} segundos")
        print(f"Dominios/subdominios completados: {completer.completed_count}")
        print(f"Errores: {completer.failed_count}")

if __name__ == "__main__":
    asyncio.run(main())