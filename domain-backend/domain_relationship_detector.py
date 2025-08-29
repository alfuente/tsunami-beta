#!/usr/bin/env python3
"""
domain_relationship_detector.py - Sistema de detección de relaciones entre dominios durante web scraping

Este módulo extiende el sistema de análisis web existente para detectar y crear relaciones entre dominios
basadas en enlaces encontrados durante el web scraping. Crea relaciones "REFERENCES" que representan
conexiones de contenido (menos robustas que las relaciones técnicas como USES_PROVIDER).

Funcionalidades:
1. Detectar enlaces a otros dominios durante web scraping
2. Extraer dominios base de URLs
3. Identificar subdominio vs dominio base
4. Crear nodos de dominios base y subdominio si no existen
5. Establecer relaciones REFERENCES entre dominios originales y referenciados
6. Diferencias tipos de referencias (navegational, resource, external_service)

Integración con el sistema existente de async_domain_discovery_api.py
"""

import re
import logging
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime
import json

# Neo4j integration
try:
    from neo4j import GraphDatabase
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False

logger = logging.getLogger(__name__)

@dataclass
class DomainReference:
    """Información sobre una referencia de dominio detectada"""
    source_domain: str
    source_subdomain: Optional[str]
    target_url: str
    target_domain: str
    target_subdomain: Optional[str]
    target_base_domain: str
    reference_type: str  # 'link', 'script', 'image', 'form', 'iframe'
    reference_context: str  # 'navigational', 'resource', 'external_service', 'social_media'
    link_text: Optional[str] = None
    confidence: float = 0.8

class DomainRelationshipDetector:
    """Detector de relaciones entre dominios durante web scraping"""
    
    def __init__(self, neo4j_driver=None):
        self.neo4j_driver = neo4j_driver
        
        # Patrones para identificar tipos de referencia
        self.service_patterns = {
            # Social Media
            'facebook.com': 'social_media',
            'twitter.com': 'social_media', 
            'x.com': 'social_media',
            'linkedin.com': 'social_media',
            'instagram.com': 'social_media',
            'youtube.com': 'social_media',
            'tiktok.com': 'social_media',
            
            # Analytics & Tracking
            'google-analytics.com': 'tracking_service',
            'googletagmanager.com': 'tracking_service',
            'hotjar.com': 'tracking_service',
            'segment.com': 'tracking_service',
            'amplitude.com': 'tracking_service',
            
            # CDN & Resources
            'cdnjs.cloudflare.com': 'cdn_resource',
            'unpkg.com': 'cdn_resource',
            'jsdelivr.net': 'cdn_resource',
            'amazonaws.com': 'cloud_resource',
            'cloudfront.net': 'cloud_resource',
            'googleapis.com': 'api_service',
            
            # Payment & Commerce
            'paypal.com': 'payment_service',
            'stripe.com': 'payment_service',
            'mercadopago.com': 'payment_service',
            'webpay.cl': 'payment_service',
            
            # Government & Official
            '.gob.cl': 'government',
            '.gov': 'government',
            '.mil': 'government',
        }
        
        # TLDs que indican dominios base
        self.base_domain_tlds = {
            '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',
            '.cl', '.ar', '.br', '.mx', '.co', '.pe', '.ec', '.uy', '.py', '.bo', '.ve',
            '.com.ar', '.com.br', '.com.mx', '.com.co', '.com.pe',
            '.gob.cl', '.gob.ar', '.gov.br'
        }
    
    def extract_domain_parts(self, url: str) -> Tuple[str, Optional[str], str]:
        """
        Extrae las partes del dominio de una URL
        Returns: (full_domain, subdomain, base_domain)
        """
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return None, None, None
                
            full_domain = parsed.netloc.lower()
            
            # Remover puerto si está presente
            if ':' in full_domain:
                full_domain = full_domain.split(':')[0]
            
            # Determinar dominio base
            base_domain = self._extract_base_domain(full_domain)
            
            # Determinar subdominio
            subdomain = None
            if full_domain != base_domain:
                subdomain = full_domain
            
            return full_domain, subdomain, base_domain
            
        except Exception as e:
            logger.warning(f"Error parsing URL {url}: {e}")
            return None, None, None
    
    def _extract_base_domain(self, full_domain: str) -> str:
        """Extrae el dominio base de un dominio completo"""
        parts = full_domain.split('.')
        
        # Casos especiales para TLDs compuestos
        if len(parts) >= 3:
            # Verificar TLDs de dos partes como .com.ar, .gob.cl
            potential_tld = f".{parts[-2]}.{parts[-1]}"
            if potential_tld in self.base_domain_tlds:
                return f"{parts[-3]}{potential_tld}"
        
        # Caso normal - tomar las últimas dos partes
        if len(parts) >= 2:
            return f"{parts[-2]}.{parts[-1]}"
        
        return full_domain
    
    def classify_reference_context(self, url: str, element_type: str, link_text: str = None) -> str:
        """Clasifica el contexto de la referencia"""
        domain = urlparse(url).netloc.lower()
        
        # Verificar patrones de servicios conocidos
        for pattern, context in self.service_patterns.items():
            if pattern in domain:
                return context
        
        # Clasificar por tipo de elemento
        if element_type == 'script':
            return 'resource'
        elif element_type == 'img':
            return 'resource'
        elif element_type == 'link' and link_text:
            # Analizar el texto del enlace para determinar contexto
            link_text_lower = link_text.lower()
            if any(word in link_text_lower for word in ['login', 'ingresar', 'acceder', 'portal']):
                return 'navigational'
            elif any(word in link_text_lower for word in ['api', 'documentation', 'docs']):
                return 'api_service' 
            elif any(word in link_text_lower for word in ['facebook', 'twitter', 'instagram', 'linkedin']):
                return 'social_media'
            else:
                return 'navigational'
        elif element_type == 'form':
            return 'external_service'
        elif element_type == 'iframe':
            return 'embedded_service'
        
        return 'external_reference'
    
    def _should_filter_reference(self, base_domain: str, element_type: str, link_text: str = None) -> bool:
        """Determina si una referencia debe ser filtrada usando lógica inteligente"""
        
        # 1. NUNCA filtrar dominios de alto valor estratégico
        high_value_domains = {
            # Bancos chilenos
            'bancochile.cl', 'santander.cl', 'bci.cl', 'bancoestado.cl',
            'bancoedwards.cl', 'itau.cl', 'scotiabank.cl', 'bancoconsorcio.cl',
            'bancofalabella.cl', 'bancoripley.cl', 'bancosecurity.cl',
            'bice.cl', 'coopeuch.cl',
            
            # Instituciones financieras
            'sii.cl', 'bcentral.cl', 'cmfchile.cl', 'registrocivil.cl',
            'chileatiende.gob.cl', 'dt.gob.cl', 'minsal.cl',
            
            # Seguros y mutuales
            'mutual.cl', 'achs.cl', 'ist.cl', 'museg.cl',
            
            # Servicios de pago
            'webpay.cl', 'khipu.com', 'flow.cl', 'mercadopago.cl',
            
            # Retailers importantes
            'falabella.com', 'ripley.cl', 'paris.cl', 'lider.cl',
            'jumbo.cl', 'tottus.cl', 'sodimac.cl',
            
            # Telecomunicaciones
            'entel.cl', 'movistar.cl', 'clarochile.cl', 'wom.cl',
            'vtr.com',
            
            # Medios importantes
            'emol.cl', 'cooperativa.cl', 'latercera.cl', 't13.cl',
            'biobiochile.cl', 'elmostrador.cl',
            
            # Universidades importantes
            'uc.cl', 'uchile.cl', 'usach.cl', 'uct.cl', 'udec.cl',
            'puc.cl', 'uai.cl', 'uandes.cl',
            
            # Dominios gubernamentales importantes
            'gob.cl', 'presidencia.gob.cl', 'hacienda.gob.cl',
            'economia.gob.cl', 'interior.gob.cl',
            
            # Dominios internacionales de alto valor para análisis
            'microsoft.com', 'apple.com', 'amazon.com', 'google.com',
            'facebook.com', 'instagram.com', 'linkedin.com', 'twitter.com',
            'whatsapp.com', 'zoom.us', 'salesforce.com', 'oracle.com'
        }
        
        if base_domain in high_value_domains:
            return False  # NUNCA filtrar
        
        # 2. Referencias de contenido CDN/recursos - filtrar solo scripts e imágenes genéricos
        cdn_resource_domains = {
            'cdnjs.cloudflare.com', 'unpkg.com', 'jsdelivr.net',
            'code.jquery.com', 'jquery.com', 'maxcdn.bootstrapcdn.com',
            'fonts.googleapis.com', 'fonts.gstatic.com',
            'ajax.googleapis.com', 'apis.google.com',
            'use.fontawesome.com', 'kit.fontawesome.com',
            'stackpath.bootstrapcdn.com', 'cdn.jsdelivr.net'
        }
        
        # Para CDNs, filtrar solo scripts e imágenes (mantener links navegacionales)
        if base_domain in cdn_resource_domains and element_type in ['script', 'image']:
            return True  # Filtrar recursos CDN
        
        # 3. Tracking y analytics - filtrar solo pixels y scripts de tracking
        tracking_domains = {
            'google-analytics.com', 'googletagmanager.com',
            'doubleclick.net', 'googlesyndication.com',
            'googleadservices.com', 'facebook.net',
            'connect.facebook.net', 'analytics.google.com',
            'gtag.google.com'
        }
        
        if base_domain in tracking_domains and element_type in ['script', 'image']:
            return True  # Filtrar scripts/pixels de tracking
        
        # 4. Dominios de muy poco valor específico
        noise_domains = {
            'gravatar.com',  # Avatars genéricos
            'w3.org',        # Especificaciones web
            'schema.org',    # Metadata schemas
            'creativecommons.org',  # Licencias
        }
        
        if base_domain in noise_domains:
            return True  # Filtrar ruido
        
        # 5. Filtros especiales por contexto
        if link_text:
            link_text_lower = link_text.lower()
            # Mantener enlaces con contexto empresarial/financiero
            business_keywords = [
                'banco', 'financier', 'credito', 'prestamo', 'inversion',
                'seguro', 'mutual', 'afp', 'gobierno', 'portal',
                'servicio', 'empresa', 'corporativ', 'institucional'
            ]
            
            if any(keyword in link_text_lower for keyword in business_keywords):
                return False  # MANTENER referencias con contexto de negocios
        
        # 6. Por defecto, mantener todas las demás referencias
        return False  # NO filtrar por defecto
    
    def detect_domain_references(self, soup, source_domain: str, source_subdomain: Optional[str] = None) -> List[DomainReference]:
        """
        Detecta todas las referencias a otros dominios en el HTML parseado
        Extiende la funcionalidad existente de _extract_external_resources
        """
        references = []
        processed_urls = set()  # Evitar duplicados
        
        # Analizar enlaces (a href)
        links = soup.find_all('a', href=True)
        for link in links:
            href = link.get('href')
            if href and href.startswith('http'):
                ref = self._create_domain_reference(
                    href, source_domain, source_subdomain, 
                    'link', link.get_text()[:100]
                )
                if ref and ref.target_url not in processed_urls:
                    references.append(ref)
                    processed_urls.add(ref.target_url)
        
        # Analizar scripts externos
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script.get('src')
            if src and (src.startswith('http') or src.startswith('//')):
                if src.startswith('//'):
                    src = f"https:{src}"
                ref = self._create_domain_reference(
                    src, source_domain, source_subdomain, 'script'
                )
                if ref and ref.target_url not in processed_urls:
                    references.append(ref)
                    processed_urls.add(ref.target_url)
        
        # Analizar imágenes externas
        images = soup.find_all('img', src=True)
        for img in images:
            src = img.get('src')
            if src and src.startswith('http'):
                ref = self._create_domain_reference(
                    src, source_domain, source_subdomain, 'image'
                )
                if ref and ref.target_url not in processed_urls:
                    references.append(ref)
                    processed_urls.add(ref.target_url)
        
        # Analizar CSS externos
        css_links = soup.find_all('link', rel='stylesheet')
        for css in css_links:
            href = css.get('href')
            if href and href.startswith('http'):
                ref = self._create_domain_reference(
                    href, source_domain, source_subdomain, 'stylesheet'
                )
                if ref and ref.target_url not in processed_urls:
                    references.append(ref)
                    processed_urls.add(ref.target_url)
        
        # Analizar forms con action externo
        forms = soup.find_all('form', action=True)
        for form in forms:
            action = form.get('action')
            if action and action.startswith('http'):
                ref = self._create_domain_reference(
                    action, source_domain, source_subdomain, 'form'
                )
                if ref and ref.target_url not in processed_urls:
                    references.append(ref)
                    processed_urls.add(ref.target_url)
        
        # Analizar iframes
        iframes = soup.find_all('iframe', src=True)
        for iframe in iframes:
            src = iframe.get('src')
            if src and src.startswith('http'):
                ref = self._create_domain_reference(
                    src, source_domain, source_subdomain, 'iframe'
                )
                if ref and ref.target_url not in processed_urls:
                    references.append(ref)
                    processed_urls.add(ref.target_url)
        
        logger.info(f"Detected {len(references)} domain references from {source_domain}")
        return references
    
    def _create_domain_reference(self, url: str, source_domain: str, source_subdomain: Optional[str], 
                                element_type: str, link_text: str = None) -> Optional[DomainReference]:
        """Crea un objeto DomainReference a partir de una URL"""
        full_domain, subdomain, base_domain = self.extract_domain_parts(url)
        
        if not full_domain or not base_domain:
            return None
        
        # Filtrar auto-referencias
        current_source = source_subdomain if source_subdomain else source_domain
        if full_domain == current_source or base_domain == source_domain:
            return None
        
        # Aplicar filtrado inteligente
        if self._should_filter_reference(base_domain, element_type, link_text):
            return None
        
        context = self.classify_reference_context(url, element_type, link_text)
        
        return DomainReference(
            source_domain=source_domain,
            source_subdomain=source_subdomain,
            target_url=url,
            target_domain=full_domain,
            target_subdomain=subdomain,
            target_base_domain=base_domain,
            reference_type=element_type,
            reference_context=context,
            link_text=link_text,
            confidence=0.9 if element_type == 'link' else 0.7
        )
    
    async def save_domain_references_to_neo4j(self, references: List[DomainReference]) -> Dict[str, int]:
        """Guarda las referencias de dominio en Neo4j"""
        if not self.neo4j_driver or not references:
            return {"created_domains": 0, "created_references": 0}
        
        stats = {"created_domains": 0, "created_references": 0, "errors": 0}
        
        try:
            with self.neo4j_driver.session() as session:
                for ref in references:
                    try:
                        # Crear dominio base objetivo si no existe
                        await self._ensure_domain_exists(session, ref.target_base_domain, is_base=True)
                        stats["created_domains"] += 1
                        
                        # Crear subdominio objetivo si es diferente del base
                        if ref.target_subdomain and ref.target_subdomain != ref.target_base_domain:
                            await self._ensure_domain_exists(session, ref.target_subdomain, is_base=False)
                            # Crear relación IS_SUBDOMAIN_OF si no existe
                            await self._create_subdomain_relationship(session, ref.target_subdomain, ref.target_base_domain)
                        
                        # Crear relación REFERENCES
                        await self._create_reference_relationship(session, ref)
                        stats["created_references"] += 1
                        
                    except Exception as e:
                        logger.error(f"Error processing reference {ref.target_url}: {e}")
                        stats["errors"] += 1
                        
        except Exception as e:
            logger.error(f"Error saving domain references to Neo4j: {e}")
            stats["errors"] += 1
        
        return stats
    
    async def _ensure_domain_exists(self, session, domain: str, is_base: bool = False):
        """Asegura que un dominio existe en Neo4j"""
        query = """
        MERGE (d:Domain {fqdn: $domain})
        ON CREATE SET 
            d.created_at = datetime(),
            d.discovered_via = 'domain_reference_detection',
            d.is_base_domain = $is_base
        ON MATCH SET 
            d.last_referenced = datetime()
        """
        session.run(query, domain=domain, is_base=is_base)
    
    async def _create_subdomain_relationship(self, session, subdomain: str, base_domain: str):
        """Crea relación HAS_SUBDOMAIN entre dominio base y subdominio"""
        query = """
        MATCH (base:Domain {fqdn: $base_domain})
        MATCH (sub:Domain {fqdn: $subdomain})
        MERGE (base)-[r:HAS_SUBDOMAIN]->(sub)
        ON CREATE SET 
            r.discovered_at = datetime(),
            r.discovery_source = 'domain_reference_detection'
        """
        session.run(query, base_domain=base_domain, subdomain=subdomain)
    
    async def _create_reference_relationship(self, session, ref: DomainReference):
        """Crea relación REFERENCES entre dominios"""
        
        # Determinar dominio fuente
        source = ref.source_subdomain if ref.source_subdomain else ref.source_domain
        
        # Determinar dominio objetivo (preferir base domain para relaciones más limpias)
        target = ref.target_base_domain
        
        query = """
        MATCH (source:Domain {fqdn: $source_domain})
        MATCH (target:Domain {fqdn: $target_domain})
        MERGE (source)-[r:REFERENCES]->(target)
        ON CREATE SET 
            r.discovered_at = datetime(),
            r.reference_type = $reference_type,
            r.reference_context = $reference_context,
            r.confidence = $confidence,
            r.discovery_source = 'web_scraping'
        ON MATCH SET
            r.last_seen = datetime(),
            r.reference_count = coalesce(r.reference_count, 0) + 1
        """
        
        session.run(query, 
                   source_domain=source,
                   target_domain=target,
                   reference_type=ref.reference_type,
                   reference_context=ref.reference_context,
                   confidence=ref.confidence)
        
        # Si hay información adicional específica, crear relación más detallada
        if ref.link_text or ref.target_subdomain:
            detail_query = """
            MATCH (source:Domain {fqdn: $source_domain})
            MATCH (target:Domain {fqdn: $target_domain})
            MATCH (source)-[r:REFERENCES]->(target)
            SET r.target_url = $target_url,
                r.link_text = $link_text,
                r.target_subdomain = $target_subdomain
            """
            
            session.run(detail_query,
                       source_domain=source,
                       target_domain=target, 
                       target_url=ref.target_url,
                       link_text=ref.link_text,
                       target_subdomain=ref.target_subdomain)

def integrate_with_existing_scraping(soup, domain: str, subdomain: Optional[str] = None, 
                                   neo4j_driver=None) -> Dict[str, any]:
    """
    Función de integración para usar en el sistema existente de web scraping
    Se puede llamar desde run_web_scraping_analysis() en async_domain_discovery_api.py
    """
    detector = DomainRelationshipDetector(neo4j_driver)
    
    # Detectar referencias
    references = detector.detect_domain_references(soup, domain, subdomain)
    
    # Preparar resultado para integración
    result = {
        "total_references": len(references),
        "references_by_type": {},
        "references_by_context": {},
        "unique_domains_referenced": set(),
        "references": []
    }
    
    # Procesar referencias para estadísticas
    for ref in references:
        # Contar por tipo
        if ref.reference_type not in result["references_by_type"]:
            result["references_by_type"][ref.reference_type] = 0
        result["references_by_type"][ref.reference_type] += 1
        
        # Contar por contexto
        if ref.reference_context not in result["references_by_context"]:
            result["references_by_context"][ref.reference_context] = 0
        result["references_by_context"][ref.reference_context] += 1
        
        # Dominios únicos
        result["unique_domains_referenced"].add(ref.target_base_domain)
        
        # Agregar referencia al resultado
        result["references"].append({
            "target_domain": ref.target_base_domain,
            "target_subdomain": ref.target_subdomain,
            "reference_type": ref.reference_type,
            "reference_context": ref.reference_context,
            "confidence": ref.confidence,
            "link_text": ref.link_text
        })
    
    result["unique_domains_referenced"] = list(result["unique_domains_referenced"])
    
    return result, references

# Función de prueba
async def test_domain_relationship_detection():
    """Función de prueba mejorada para el detector con filtrado inteligente"""
    from bs4 import BeautifulSoup
    
    # HTML de ejemplo más complejo que refleja un sitio web chileno real
    test_html = """
    <html>
    <head>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
        <script src="https://google-analytics.com/analytics.js"></script>
        <script src="https://connect.facebook.net/es_ES/fbevents.js"></script>
    </head>
    <body>
        <!-- Enlaces navegacionales de alto valor -->
        <a href="https://www.google.cl">Buscar en Google Chile</a>
        <a href="https://portal.bancochile.cl/login">Portal Banco de Chile</a>
        <a href="https://www.mutual.cl/servicios">Servicios Mutual de Seguridad</a>
        <a href="https://api.mercadolibre.cl/docs">API MercadoLibre</a>
        <a href="https://www.sii.cl/consultas">Consultas SII</a>
        <a href="https://www.entel.cl/empresas">Entel Empresas</a>
        
        <!-- Servicios financieros -->
        <a href="https://www.webpay.cl/portalpagodirecto">Pago con Webpay</a>
        <a href="https://www.coopeuch.cl/creditos">Créditos Coopeuch</a>
        
        <!-- Medios de comunicación -->
        <a href="https://www.emol.cl/economia">Economía Emol</a>
        <a href="https://www.cooperativa.cl/noticias">Noticias Cooperativa</a>
        
        <!-- Recursos CDN (deberían filtrarse para scripts) -->
        <img src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/webfonts/fa-solid-900.woff2" />
        
        <!-- Tracking (debería filtrarse) -->
        <img src="https://www.facebook.com/tr?id=pixel123" />
        <img src="https://google-analytics.com/collect?tid=123" />
        
        <!-- iframes de valor -->
        <iframe src="https://www.youtube.com/embed/video123"></iframe>
        
        <!-- Formularios importantes -->
        <form action="https://secure.webpay.cl/payment"></form>
        <form action="https://portal.bancochile.cl/transferencia"></form>
        
        <!-- Enlaces internacionales de valor -->
        <a href="https://www.microsoft.com/chile">Microsoft Chile</a>
        <a href="https://aws.amazon.com/es/">AWS</a>
    </body>
    </html>
    """
    
    soup = BeautifulSoup(test_html, 'html.parser')
    detector = DomainRelationshipDetector()
    
    references = detector.detect_domain_references(soup, "example.cl")
    
    print(f"\n🧪 TEST: Detector mejorado con filtrado inteligente")
    print(f"Detected {len(references)} domain references:")
    print("=" * 60)
    
    # Agrupar por contexto para análisis
    by_context = {}
    by_type = {}
    
    for ref in references:
        # Por contexto
        if ref.reference_context not in by_context:
            by_context[ref.reference_context] = []
        by_context[ref.reference_context].append(ref)
        
        # Por tipo
        if ref.reference_type not in by_type:
            by_type[ref.reference_type] = []
        by_type[ref.reference_type].append(ref)
        
        print(f"✓ {ref.target_base_domain:25} ({ref.reference_type:10}) - {ref.reference_context}")
    
    print("\n📊 Análisis por contexto:")
    for context, refs in by_context.items():
        print(f"  {context:20}: {len(refs)} referencias")
        for ref in refs[:3]:  # Mostrar primeras 3
            print(f"    → {ref.target_base_domain}")
        if len(refs) > 3:
            print(f"    ... y {len(refs) - 3} más")
    
    print("\n📊 Análisis por tipo:")
    for ref_type, refs in by_type.items():
        print(f"  {ref_type:20}: {len(refs)} referencias")
    
    return references

async def test_filtering_logic():
    """Prueba específica de la lógica de filtrado mejorada"""
    detector = DomainRelationshipDetector()
    
    test_cases = [
        # (domain, element_type, link_text, expected_filtered, reason)
        ("bancochile.cl", "link", "Portal Banco", False, "Banco chileno - alto valor"),
        ("mutual.cl", "link", "Servicios Mutual", False, "Mutual chilena - alto valor"),
        ("google.cl", "link", "Google Chile", False, "Google Chile - alto valor"),
        ("cdnjs.cloudflare.com", "script", None, True, "CDN script - filtrar"),
        ("cdnjs.cloudflare.com", "link", "Cloudflare CDN", False, "CDN link navegacional - mantener"),
        ("google-analytics.com", "script", None, True, "Analytics script - filtrar"),
        ("google-analytics.com", "link", "Analytics", False, "Analytics link - mantener"),
        ("gravatar.com", "image", None, True, "Gravatar - ruido"),
        ("sii.cl", "link", "Consultas SII", False, "Gobierno - alto valor"),
        ("webpay.cl", "form", None, False, "Pago - alto valor"),
        ("jquery.com", "script", None, True, "CDN resource - filtrar"), 
        ("example.com", "link", "Portal Banco Ejemplo", False, "Contexto bancario - mantener")
    ]
    
    print("\n🧪 TEST: Lógica de filtrado específica")
    print("=" * 80)
    print(f"{'Dominio':<25} {'Tipo':<10} {'Filtrado':<10} {'Razón'}")
    print("-" * 80)
    
    for domain, element_type, link_text, expected_filtered, reason in test_cases:
        should_filter = detector._should_filter_reference(domain, element_type, link_text)
        status = "✓ FILTRAR" if should_filter else "✓ MANTENER"
        correct = "✅" if should_filter == expected_filtered else "❌"
        
        print(f"{domain:<25} {element_type:<10} {status:<10} {correct} {reason}")
    
    return True

if __name__ == "__main__":
    import asyncio
    asyncio.run(test_domain_relationship_detection())