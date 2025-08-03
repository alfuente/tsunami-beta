#!/usr/bin/env python3
"""
fix_missing_providers.py - Script para agregar detección de providers faltantes (Microsoft, Google, etc.)

Este script analiza registros MX y otros DNS para detectar providers como Microsoft 365, 
Google Workspace que no están siendo capturados por el proceso actual.

Problemas identificados:
1. Los registros MX no se están procesando ni almacenando
2. Microsoft 365 y Google Workspace no aparecen como providers
3. El código de provider_detection.py existe pero no se ejecuta

Soluciones:
1. Procesar registros MX para todos los dominios existentes
2. Detectar y crear nodos Provider para Microsoft, Google, etc.
3. Establecer relaciones DEPENDS_ON correctas
4. Actualizar propiedades de dominio con información MX
"""

import argparse
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional, Set
import re

# Neo4j imports
try:
    from neo4j import GraphDatabase, Driver
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False

# DNS imports
import dns.resolver
import dns.exception

# Import our provider detection module
try:
    from provider_detection import ProviderDetector, ProviderService
    HAS_PROVIDER_DETECTION = True
except ImportError:
    HAS_PROVIDER_DETECTION = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'fix_providers_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ProviderFixer:
    """Fixer para agregar providers faltantes"""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str):
        if not HAS_NEO4J:
            raise ImportError("Neo4j driver is required. Install with: pip install neo4j")
        
        if not HAS_PROVIDER_DETECTION:
            raise ImportError("provider_detection module is required")
        
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
        self.provider_detector = ProviderDetector()
        
        # DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5.0
        self.resolver.lifetime = 5.0
        
        # Statistics
        self.stats = {
            'domains_processed': 0,
            'mx_records_added': 0,
            'providers_created': 0,
            'dependencies_created': 0,
            'errors': 0
        }
    
    def get_all_domains(self) -> List[str]:
        """Obtiene todos los dominios de la base de datos"""
        with self.driver.session() as session:
            result = session.run("""
                MATCH (d:Domain)
                WHERE d.fqdn IS NOT NULL
                RETURN d.fqdn as fqdn
                ORDER BY d.fqdn
            """)
            return [record['fqdn'] for record in result]
    
    def get_mx_records(self, domain: str) -> List[Dict[str, any]]:
        """Obtiene registros MX para un dominio"""
        mx_records = []
        
        try:
            mx_results = self.resolver.resolve(domain, 'MX')
            
            for mx in mx_results:
                mx_host = str(mx.exchange).rstrip('.')
                priority = mx.preference
                
                mx_records.append({
                    'host': mx_host,
                    'priority': priority,
                    'full_record': f"{priority} {mx_host}"
                })
                
                logger.info(f"   📧 MX: {priority} {mx_host}")
                
        except dns.exception.DNSException as e:
            logger.debug(f"   ⚠️  No MX records for {domain}: {e}")
        except Exception as e:
            logger.warning(f"   ❌ Error getting MX for {domain}: {e}")
            self.stats['errors'] += 1
        
        return mx_records
    
    def detect_providers_from_mx(self, mx_records: List[Dict[str, any]]) -> List[ProviderService]:
        """Detecta providers desde registros MX usando el detector existente"""
        detected_providers = []
        
        # Patrones MX específicos (copiados y expandidos de provider_detection.py)
        mx_patterns = {
            # Microsoft 365
            r'.*\.mail\.protection\.outlook\.com': ('Microsoft 365', 'email', 'medium'),
            r'.*\.outlook\.com': ('Microsoft 365', 'email', 'medium'),
            r'.*-mail\.protection\.outlook\.com': ('Microsoft 365', 'email', 'medium'),
            
            # Google Workspace  
            r'.*\.google\.com': ('Google Workspace', 'email', 'medium'),
            r'.*\.googlemail\.com': ('Google Workspace', 'email', 'medium'),
            r'aspmx.*\.googlemail\.com': ('Google Workspace', 'email', 'medium'),
            r'alt[0-9]+\.aspmx\.l\.google\.com': ('Google Workspace', 'email', 'medium'),
            r'aspmx\.l\.google\.com': ('Google Workspace', 'email', 'medium'),
            
            # ProofPoint
            r'.*\.pphosted\.com': ('ProofPoint', 'email_security', 'high'),
            r'.*\.protection\.pphosted\.com': ('ProofPoint', 'email_security', 'high'),
            
            # IronPort/Cisco Email Security
            r'.*\.iphmx\.com': ('Cisco Email Security', 'email_security', 'high'),
            r'.*\.c3s2\.iphmx\.com': ('Cisco Email Security', 'email_security', 'high'),
            
            # Barracuda
            r'.*\.emailsrvr\.com': ('Barracuda', 'email_security', 'high'),
            r'.*\.barracudanetworks\.com': ('Barracuda', 'email_security', 'high'),
            
            # Mimecast
            r'.*\.mimecast\.com': ('Mimecast', 'email_security', 'high'),
            
            # Amazon SES
            r'.*\.amazonses\.com': ('Amazon SES', 'email', 'medium'),
            
            # Mailgun
            r'.*\.mailgun\.org': ('Mailgun', 'email', 'medium'),
            
            # SendGrid
            r'.*\.sendgrid\.net': ('SendGrid', 'email', 'medium'),
            
            # Zoho
            r'.*\.zoho\.com': ('Zoho Mail', 'email', 'medium'),
            r'.*\.zmxrouting\.net': ('Zoho Mail', 'email', 'medium'),
        }
        
        for mx_record in mx_records:
            mx_host = mx_record['host']
            
            for pattern, (provider_name, service_type, risk_level) in mx_patterns.items():
                if re.match(pattern, mx_host, re.IGNORECASE):
                    # Crear ProviderService object
                    provider_service = {
                        'name': provider_name,
                        'service_type': service_type,
                        'risk_level': risk_level,
                        'detection_method': 'mx_record',
                        'confidence': 0.9,
                        'metadata': {
                            'mx_host': mx_host,
                            'priority': mx_record['priority'],
                            'pattern_matched': pattern
                        }
                    }
                    
                    detected_providers.append(provider_service)
                    logger.info(f"   🎯 Detected provider: {provider_name} via {mx_host}")
                    break
        
        return detected_providers
    
    def create_or_update_provider(self, provider_service: Dict[str, any]) -> str:
        """Crea o actualiza un nodo Provider en Neo4j"""
        provider_name = provider_service['name']
        
        # Normalize provider name for ID
        provider_id = re.sub(r'[^a-z0-9_]', '_', provider_name.lower())
        
        with self.driver.session() as session:
            result = session.run("""
                MERGE (p:Provider {id: $provider_id})
                SET p.name = $provider_name,
                    p.type = $service_type,
                    p.risk_level = $risk_level,
                    p.detection_method = $detection_method,
                    p.confidence = $confidence,
                    p.last_detected = datetime(),
                    p.metadata = $metadata
                RETURN p.id as provider_id
            """,
            provider_id=provider_id,
            provider_name=provider_name,
            service_type=provider_service['service_type'],
            risk_level=provider_service['risk_level'],
            detection_method=provider_service['detection_method'],
            confidence=provider_service['confidence'],
            metadata=str(provider_service['metadata'])
            )
            
            record = result.single()
            if record:
                self.stats['providers_created'] += 1
                return record['provider_id']
            else:
                logger.error(f"   ❌ Failed to create provider: {provider_name}")
                return None
    
    def create_dependency_relationship(self, domain_fqdn: str, provider_id: str, provider_service: Dict[str, any]) -> bool:
        """Crea relación DEPENDS_ON entre dominio y provider"""
        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (d:Domain {fqdn: $domain_fqdn})
                    MATCH (p:Provider {id: $provider_id})
                    MERGE (d)-[r:DEPENDS_ON]->(p)
                    SET r.dependency_type = $dependency_type,
                        r.service_type = $service_type,
                        r.detection_method = $detection_method,
                        r.confidence = $confidence,
                        r.created_at = datetime(),
                        r.metadata = $metadata
                    RETURN count(r) as relationships_created
                """,
                domain_fqdn=domain_fqdn,
                provider_id=provider_id,
                dependency_type='Critical' if provider_service['service_type'] == 'email' else 'Important',
                service_type=provider_service['service_type'],
                detection_method=provider_service['detection_method'],
                confidence=provider_service['confidence'],
                metadata=str(provider_service['metadata'])
                )
                
                record = result.single()
                if record and record['relationships_created'] > 0:
                    self.stats['dependencies_created'] += 1
                    return True
                else:
                    logger.warning(f"   ⚠️  Failed to create dependency for {domain_fqdn} -> {provider_id}")
                    return False
                    
        except Exception as e:
            logger.error(f"   ❌ Error creating dependency {domain_fqdn} -> {provider_id}: {e}")
            self.stats['errors'] += 1
            return False
    
    def update_domain_mx_records(self, domain_fqdn: str, mx_records: List[Dict[str, any]]) -> bool:
        """Actualiza el dominio con información de registros MX"""
        try:
            # Prepare MX data for storage
            mx_hosts = [mx['host'] for mx in mx_records]
            mx_full_records = [mx['full_record'] for mx in mx_records]
            
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (d:Domain {fqdn: $domain_fqdn})
                    SET d.mx_records = $mx_hosts,
                        d.dns_mx_records = $mx_full_records,
                        d.mx_count = $mx_count,
                        d.mx_last_updated = datetime()
                    RETURN d.fqdn as updated_domain
                """,
                domain_fqdn=domain_fqdn,
                mx_hosts=mx_hosts,
                mx_full_records=mx_full_records,
                mx_count=len(mx_records)
                )
                
                record = result.single()
                if record:
                    self.stats['mx_records_added'] += 1
                    return True
                else:
                    logger.warning(f"   ⚠️  Failed to update MX records for {domain_fqdn}")
                    return False
                    
        except Exception as e:
            logger.error(f"   ❌ Error updating MX records for {domain_fqdn}: {e}")
            self.stats['errors'] += 1
            return False
    
    def fix_domain_providers(self, domain_fqdn: str) -> bool:
        """Procesa un dominio para agregar providers faltantes"""
        logger.info(f"\n🔍 Procesando dominio: {domain_fqdn}")
        
        try:
            # 1. Get MX records
            mx_records = self.get_mx_records(domain_fqdn)
            
            if not mx_records:
                logger.info(f"   ⚠️  No MX records found for {domain_fqdn}")
                return True
            
            # 2. Update domain with MX records
            self.update_domain_mx_records(domain_fqdn, mx_records)
            
            # 3. Detect providers from MX records
            detected_providers = self.detect_providers_from_mx(mx_records)
            
            if not detected_providers:
                logger.info(f"   ⚠️  No providers detected from MX records for {domain_fqdn}")
                return True
            
            # 4. Create providers and dependencies
            for provider_service in detected_providers:
                # Create or update provider
                provider_id = self.create_or_update_provider(provider_service)
                
                if provider_id:
                    # Create dependency relationship
                    self.create_dependency_relationship(domain_fqdn, provider_id, provider_service)
                    logger.info(f"   ✅ Created dependency: {domain_fqdn} -> {provider_service['name']}")
            
            self.stats['domains_processed'] += 1
            return True
            
        except Exception as e:
            logger.error(f"   ❌ Error processing {domain_fqdn}: {e}")
            self.stats['errors'] += 1
            return False
    
    def fix_all_domain_providers(self, limit: Optional[int] = None) -> Dict[str, any]:
        """Procesa todos los dominios para agregar providers faltantes"""
        logger.info(f"\n🚀 Iniciando corrección de providers faltantes")
        logger.info("=" * 80)
        
        start_time = time.time()
        
        # Get all domains
        domains = self.get_all_domains()
        
        if limit:
            domains = domains[:limit]
            logger.info(f"   Limitando a {limit} dominios para prueba")
        
        logger.info(f"   Dominios a procesar: {len(domains)}")
        
        # Process each domain
        for i, domain in enumerate(domains, 1):
            logger.info(f"\n[{i}/{len(domains)}] Procesando {domain}")
            self.fix_domain_providers(domain)
            
            # Log progress every 10 domains
            if i % 10 == 0:
                elapsed = time.time() - start_time
                logger.info(f"   📊 Progreso: {i}/{len(domains)} dominios, {elapsed:.1f}s transcurridos")
        
        elapsed_time = time.time() - start_time
        
        # Final statistics
        logger.info(f"\n🎉 Corrección de providers completada!")
        logger.info(f"   Dominios procesados: {self.stats['domains_processed']}")
        logger.info(f"   Registros MX agregados: {self.stats['mx_records_added']}")
        logger.info(f"   Providers creados/actualizados: {self.stats['providers_created']}")
        logger.info(f"   Dependencias creadas: {self.stats['dependencies_created']}")
        logger.info(f"   Errores: {self.stats['errors']}")
        logger.info(f"   Tiempo total: {elapsed_time:.1f} segundos")
        logger.info("=" * 80)
        
        return {
            'domains_processed': self.stats['domains_processed'],
            'mx_records_added': self.stats['mx_records_added'],
            'providers_created': self.stats['providers_created'],
            'dependencies_created': self.stats['dependencies_created'],
            'errors': self.stats['errors'],
            'elapsed_time': elapsed_time
        }
    
    def verify_provider_detection(self) -> Dict[str, any]:
        """Verifica qué providers fueron detectados después de la corrección"""
        logger.info(f"\n🔍 Verificando providers detectados...")
        
        with self.driver.session() as session:
            # Get provider statistics
            result = session.run("""
                MATCH (p:Provider)
                OPTIONAL MATCH (d:Domain)-[:DEPENDS_ON]->(p)
                RETURN 
                    p.name as provider_name,
                    p.type as provider_type,
                    count(DISTINCT d) as domain_count
                ORDER BY domain_count DESC, p.name
            """)
            
            providers = []
            for record in result:
                provider_info = {
                    'name': record['provider_name'],
                    'type': record['provider_type'],
                    'domain_count': record['domain_count']
                }
                providers.append(provider_info)
                
                logger.info(f"   📊 {provider_info['name']} ({provider_info['type']}): {provider_info['domain_count']} dominios")
            
            # Check for Microsoft and Google specifically
            microsoft_found = any('Microsoft' in p['name'] for p in providers)
            google_found = any('Google' in p['name'] for p in providers)
            
            logger.info(f"\n✅ Resultados de verificación:")
            logger.info(f"   Microsoft detectado: {'SÍ' if microsoft_found else 'NO'}")
            logger.info(f"   Google detectado: {'SÍ' if google_found else 'NO'}")
            logger.info(f"   Total providers: {len(providers)}")
            
            return {
                'providers': providers,
                'microsoft_found': microsoft_found,
                'google_found': google_found,
                'total_providers': len(providers)
            }
    
    def close(self):
        """Cierra la conexión a Neo4j"""
        if self.driver:
            self.driver.close()

def main():
    """Función principal"""
    parser = argparse.ArgumentParser(
        description="Corregir providers faltantes (Microsoft, Google, etc.) desde registros MX"
    )
    parser.add_argument("--bolt", default="bolt://localhost:7687", help="Neo4j bolt URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", default="test.password", help="Neo4j password")
    parser.add_argument("--limit", type=int, help="Limitar número de dominios para prueba")
    parser.add_argument("--verify-only", action="store_true", help="Solo verificar providers existentes")
    parser.add_argument("--domain", help="Procesar solo un dominio específico")
    
    args = parser.parse_args()
    
    logger.info(f"🚀 Iniciando corrección de providers faltantes")
    logger.info(f"   Neo4j URI: {args.bolt}")
    logger.info(f"   Verificación solamente: {args.verify_only}")
    logger.info(f"   Dominio específico: {args.domain or 'Todos'}")
    logger.info(f"   Límite: {args.limit or 'Sin límite'}")
    
    fixer = None
    try:
        # Initialize fixer
        fixer = ProviderFixer(args.bolt, args.user, args.password)
        
        if args.verify_only:
            # Only verify existing providers
            fixer.verify_provider_detection()
        elif args.domain:
            # Process single domain
            success = fixer.fix_domain_providers(args.domain)
            if success:
                logger.info(f"✅ Dominio {args.domain} procesado exitosamente")
                fixer.verify_provider_detection()
            else:
                logger.error(f"❌ Error procesando dominio {args.domain}")
                return 1
        else:
            # Process all domains
            results = fixer.fix_all_domain_providers(args.limit)
            
            # Verify results
            fixer.verify_provider_detection()
            
            if results['errors'] > 0:
                logger.warning(f"⚠️  Proceso completado con {results['errors']} errores")
                return 1
            
        return 0
        
    except KeyboardInterrupt:
        logger.info("⏹️  Proceso interrumpido por el usuario")
        return 1
    except Exception as e:
        logger.error(f"❌ Error fatal: {e}")
        return 1
    finally:
        if fixer:
            fixer.close()

if __name__ == "__main__":
    exit(main())