#!/usr/bin/env python3
"""
mass_risk_calculator.py - Script para aplicar cálculo masivo de risk scores

Este script aplica el cálculo de risk score a:
1. Todos los dominios base en el grafo
2. Todos los providers en el grafo (básico)

Características:
- Procesamiento en lotes para eficiencia
- Logging detallado del progreso
- Manejo de errores por dominio individual
- Estadísticas finales del procesamiento
"""

import argparse
import logging
import math
import time
from datetime import datetime
from typing import List, Dict, Any
from dataclasses import dataclass

# Neo4j imports
try:
    from neo4j import GraphDatabase, Driver
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False

# Import the existing risk score updater
from risk_score_updater import RiskScoreUpdater

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'mass_risk_calculation_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class MassCalculationStats:
    """Estadísticas del cálculo masivo"""
    total_domains: int = 0
    successful_domains: int = 0
    failed_domains: int = 0
    total_subdomains: int = 0
    successful_subdomains: int = 0
    failed_subdomains: int = 0
    total_providers: int = 0
    successful_providers: int = 0
    failed_providers: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    
    @property
    def elapsed_time(self) -> float:
        return self.end_time - self.start_time
    
    @property
    def domain_success_rate(self) -> float:
        return (self.successful_domains / self.total_domains * 100) if self.total_domains > 0 else 0.0
    
    @property
    def subdomain_success_rate(self) -> float:
        return (self.successful_subdomains / self.total_subdomains * 100) if self.total_subdomains > 0 else 0.0
    
    @property
    def provider_success_rate(self) -> float:
        return (self.successful_providers / self.total_providers * 100) if self.total_providers > 0 else 0.0

class MassRiskCalculator:
    """Calculador masivo de risk scores"""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str):
        if not HAS_NEO4J:
            raise ImportError("Neo4j driver is required. Install with: pip install neo4j")
        
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
        self.risk_updater = RiskScoreUpdater(neo4j_uri, neo4j_user, neo4j_pass)
        self.stats = MassCalculationStats()
    
    def get_all_base_domains(self) -> List[str]:
        """Obtiene todos los dominios base del grafo"""
        logger.info("🔍 Obteniendo todos los dominios base...")
        
        with self.driver.session() as session:
            result = session.run("""
                MATCH (d:Domain)
                RETURN d.fqdn as fqdn
                ORDER BY d.fqdn
            """)
            
            domains = [record['fqdn'] for record in result if record['fqdn']]
            logger.info(f"   ✓ Encontrados {len(domains)} dominios base")
            return domains
    
    def get_all_subdomains(self) -> List[str]:
        """Obtiene todos los subdominios del grafo"""
        logger.info("🔍 Obteniendo todos los subdominios...")
        
        with self.driver.session() as session:
            result = session.run("""
                MATCH (s:Subdomain)
                RETURN s.fqdn as fqdn
                ORDER BY s.fqdn
            """)
            
            subdomains = [record['fqdn'] for record in result if record['fqdn']]
            logger.info(f"   ✓ Encontrados {len(subdomains)} subdominios")
            return subdomains
    
    def get_all_providers(self) -> List[Dict[str, Any]]:
        """Obtiene todos los providers del grafo"""
        logger.info("🔍 Obteniendo todos los providers...")
        
        with self.driver.session() as session:
            result = session.run("""
                MATCH (p:Provider)
                RETURN 
                    p.id as id,
                    p.name as name,
                    p.display_name as display_name,
                    p.type as type,
                    coalesce(p.risk_score, 0.0) as current_risk_score
                ORDER BY p.name
            """)
            
            providers = []
            for record in result:
                providers.append({
                    'id': record['id'],
                    'name': record['name'],
                    'display_name': record['display_name'],
                    'type': record['type'],
                    'current_risk_score': record['current_risk_score']
                })
            
            logger.info(f"   ✓ Encontrados {len(providers)} providers")
            return providers
    
    def calculate_provider_basic_risk_score(self, provider: Dict[str, Any]) -> float:
        """
        Calcula un risk score básico para providers basado en:
        - Tipo de provider (cloud, cdn, security, etc.)
        - Número de dominios que lo usan
        - Clasificación automática por nombre
        - Confiabilidad por reputación
        """
        provider_id = provider['id']
        provider_type = provider.get('type')
        provider_name = provider.get('name', 'unknown').lower()
        
        # Clasificación automática por nombre si no hay tipo
        if not provider_type or provider_type == 'None':
            if any(x in provider_name for x in ['aws', 'amazon', 'ec2']):
                provider_type = 'cloud'
            elif any(x in provider_name for x in ['cloudflare', 'akamai', 'fastly']):
                provider_type = 'cdn'
            elif any(x in provider_name for x in ['google', 'gcp', 'gmail']):
                provider_type = 'cloud'
            elif any(x in provider_name for x in ['microsoft', 'azure', 'office365']):
                provider_type = 'cloud'
            elif any(x in provider_name for x in ['security', 'proofpoint', 'cisco', 'imperva']):
                provider_type = 'security'
            elif any(x in provider_name for x in ['dns', 'nameserver', 'ns1']):
                provider_type = 'dns'
            elif any(x in provider_name for x in ['hosting', 'server', 'vps']):
                provider_type = 'hosting'
            elif any(x in provider_name for x in ['email', 'mail', 'smtp']):
                provider_type = 'email'
            else:
                provider_type = 'unknown'
        
        # Base score según tipo de provider
        base_scores = {
            'cloud': 25.0,      # Providers cloud tienden a ser más confiables
            'cdn': 20.0,        # CDNs son generalmente estables
            'security': 30.0,   # Servicios de seguridad son especializados pero críticos
            'hosting': 45.0,    # Hosting puede ser más variable
            'dns': 35.0,        # DNS services
            'email': 40.0,      # Email services
            'email_security': 30.0,  # Email security services
            'unknown': 60.0     # Unknown providers son más riesgosos
        }
        
        base_score = base_scores.get(provider_type, 60.0)
        
        # Ajuste por popularidad (más uso = más confiable)
        with self.driver.session() as session:
            usage_result = session.run("""
                MATCH ()-[r]->(p:Provider {id: $provider_id})
                WHERE type(r) IN ['USES_SERVICE', 'HAS_PROVIDER', 'DEPENDS_ON', 'HOSTED_BY']
                RETURN count(r) as usage_count
            """, provider_id=provider_id)
            
            usage_record = usage_result.single()
            usage_count = usage_record['usage_count'] if usage_record else 0
            
            # Reducir riesgo basado en uso (más uso = más confiable)
            # Escala logarítmica para evitar que todos tengan el mismo descuento
            if usage_count > 0:
                usage_discount = min(20.0, 5.0 * math.log(usage_count + 1))
            else:
                usage_discount = 0.0
            base_score -= usage_discount
            
            # Reputación por empresa conocida (más granular)
            reputation_adjustment = 0.0
            if 'aws' in provider_name or 'amazon' in provider_name:
                reputation_adjustment = -15.0  # AWS es muy confiable
            elif 'google' in provider_name or 'gcp' in provider_name:
                reputation_adjustment = -15.0  # Google también
            elif 'microsoft' in provider_name or 'azure' in provider_name:
                reputation_adjustment = -15.0  # Microsoft también
            elif 'cloudflare' in provider_name:
                reputation_adjustment = -12.0  # Cloudflare es confiable
            elif provider_name in ['gtd', 'entel', 'movistar', 'claro']:
                reputation_adjustment = -5.0   # Telcos chilenas conocidas
            elif provider_name in ['bci', 'bice', 'itau', 'santander']:
                reputation_adjustment = -8.0   # Bancos chilenos
            elif 'unknown' in provider_name:
                reputation_adjustment = +10.0  # Providers desconocidos son más riesgosos
            
            # Penalización por duplicados (providers mal configurados)
            duplicate_penalty = 0.0
            duplicate_result = session.run("""
                MATCH (p:Provider {name: $name})
                RETURN count(p) as duplicate_count
            """, name=provider.get('name', 'unknown'))
            
            duplicate_record = duplicate_result.single()
            duplicate_count = duplicate_record['duplicate_count'] if duplicate_record else 1
            
            if duplicate_count > 1:
                duplicate_penalty = min(10.0, duplicate_count * 2.0)  # Penalizar duplicados
            
            final_score = max(0.0, min(100.0, base_score + reputation_adjustment + duplicate_penalty))
            
            logger.debug(f"   Provider {provider_name}: type={provider_type}, base={base_score:.1f}, "
                        f"usage_discount=-{usage_discount:.1f}, reputation={reputation_adjustment:.1f}, "
                        f"duplicates=+{duplicate_penalty:.1f}, final={final_score:.1f}")
            
            return final_score
    
    def update_provider_risk_score(self, provider: Dict[str, Any]) -> bool:
        """Actualiza el risk score de un provider"""
        try:
            provider_id = provider['id']
            provider_name = provider.get('name', 'unknown')
            
            # Calcular risk score
            risk_score = self.calculate_provider_basic_risk_score(provider)
            
            # Actualizar en Neo4j
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (p:Provider {id: $provider_id})
                    SET p.risk_score = $risk_score,
                        p.risk_calculated_at = datetime(),
                        p.risk_calculation_version = 'basic-v1.0'
                    RETURN p.id as updated_provider
                """, 
                provider_id=provider_id,
                risk_score=risk_score
                )
                
                updated = result.single()
                if updated:
                    logger.info(f"   ✅ Provider {provider_name}: risk_score = {risk_score:.2f}")
                    return True
                else:
                    logger.error(f"   ❌ No se pudo actualizar provider {provider_name}")
                    return False
                    
        except Exception as e:
            logger.error(f"   ❌ Error actualizando provider {provider.get('name', 'unknown')}: {e}")
            return False
    
    def calculate_all_domains(self, batch_size: int = 10) -> None:
        """Calcula risk scores para todos los dominios base"""
        logger.info("🎯 INICIANDO CÁLCULO MASIVO DE DOMINIOS")
        logger.info("=" * 80)
        
        domains = self.get_all_base_domains()
        self.stats.total_domains = len(domains)
        
        if not domains:
            logger.warning("⚠️  No se encontraron dominios para procesar")
            return
        
        logger.info(f"📊 Procesando {len(domains)} dominios en lotes de {batch_size}")
        
        for i in range(0, len(domains), batch_size):
            batch = domains[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (len(domains) + batch_size - 1) // batch_size
            
            logger.info(f"\n🔄 Procesando lote {batch_num}/{total_batches} ({len(batch)} dominios)")
            
            for j, domain in enumerate(batch):
                try:
                    logger.info(f"   [{batch_num}.{j+1}] Procesando {domain}...")
                    success = self.risk_updater.update_domain_risk_score(domain)
                    
                    if success:
                        self.stats.successful_domains += 1
                        logger.info(f"   ✅ {domain} completado")
                    else:
                        self.stats.failed_domains += 1
                        logger.error(f"   ❌ {domain} falló")
                        
                except Exception as e:
                    self.stats.failed_domains += 1
                    logger.error(f"   ❌ Error procesando {domain}: {e}")
            
            # Pequeña pausa entre lotes
            time.sleep(1)
            
            # Progress report
            progress = (i + len(batch)) / len(domains) * 100
            logger.info(f"📈 Progreso: {progress:.1f}% "
                       f"(Exitosos: {self.stats.successful_domains}, "
                       f"Fallidos: {self.stats.failed_domains})")
    
    def calculate_all_subdomains(self, batch_size: int = 15) -> None:
        """Calcula risk scores para todos los subdominios"""
        logger.info("\n🌐 INICIANDO CÁLCULO MASIVO DE SUBDOMINIOS")
        logger.info("=" * 80)
        
        subdomains = self.get_all_subdomains()
        self.stats.total_subdomains = len(subdomains)
        
        if not subdomains:
            logger.warning("⚠️  No se encontraron subdominios para procesar")
            return
        
        logger.info(f"📊 Procesando {len(subdomains)} subdominios en lotes de {batch_size}")
        
        for i in range(0, len(subdomains), batch_size):
            batch = subdomains[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (len(subdomains) + batch_size - 1) // batch_size
            
            logger.info(f"\n🔄 Procesando lote {batch_num}/{total_batches} ({len(batch)} subdominios)")
            
            for j, subdomain in enumerate(batch):
                try:
                    logger.info(f"   [{batch_num}.{j+1}] Procesando {subdomain}...")
                    success = self.risk_updater.update_subdomain_risk_score(subdomain)
                    
                    if success:
                        self.stats.successful_subdomains += 1
                        logger.info(f"   ✅ {subdomain} completado")
                    else:
                        self.stats.failed_subdomains += 1
                        logger.error(f"   ❌ {subdomain} falló")
                        
                except Exception as e:
                    self.stats.failed_subdomains += 1
                    logger.error(f"   ❌ Error procesando {subdomain}: {e}")
            
            # Pequeña pausa entre lotes
            time.sleep(1)
            
            # Progress report
            progress = (i + len(batch)) / len(subdomains) * 100
            logger.info(f"📈 Progreso: {progress:.1f}% "
                       f"(Exitosos: {self.stats.successful_subdomains}, "
                       f"Fallidos: {self.stats.failed_subdomains})")
    
    def calculate_all_providers(self, batch_size: int = 20) -> None:
        """Calcula risk scores para todos los providers"""
        logger.info("\n🏭 INICIANDO CÁLCULO MASIVO DE PROVIDERS")
        logger.info("=" * 80)
        
        providers = self.get_all_providers()
        self.stats.total_providers = len(providers)
        
        if not providers:
            logger.warning("⚠️  No se encontraron providers para procesar")
            return
        
        logger.info(f"📊 Procesando {len(providers)} providers en lotes de {batch_size}")
        
        for i in range(0, len(providers), batch_size):
            batch = providers[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (len(providers) + batch_size - 1) // batch_size
            
            logger.info(f"\n🔄 Procesando lote {batch_num}/{total_batches} ({len(batch)} providers)")
            
            for j, provider in enumerate(batch):
                try:
                    provider_name = provider.get('name', 'unknown')
                    logger.info(f"   [{batch_num}.{j+1}] Procesando {provider_name}...")
                    
                    success = self.update_provider_risk_score(provider)
                    
                    if success:
                        self.stats.successful_providers += 1
                    else:
                        self.stats.failed_providers += 1
                        
                except Exception as e:
                    self.stats.failed_providers += 1
                    logger.error(f"   ❌ Error procesando provider {provider.get('name', 'unknown')}: {e}")
            
            # Progress report
            progress = (i + len(batch)) / len(providers) * 100
            logger.info(f"📈 Progreso: {progress:.1f}% "
                       f"(Exitosos: {self.stats.successful_providers}, "
                       f"Fallidos: {self.stats.failed_providers})")
    
    def run_mass_calculation(self, domains: bool = True, subdomains: bool = True, providers: bool = True, 
                           domain_batch_size: int = 10, subdomain_batch_size: int = 15, provider_batch_size: int = 20) -> MassCalculationStats:
        """Ejecuta el cálculo masivo completo"""
        logger.info("🚀 INICIANDO CÁLCULO MASIVO DE RISK SCORES")
        logger.info("=" * 80)
        
        self.stats.start_time = time.time()
        
        try:
            if domains:
                self.calculate_all_domains(domain_batch_size)
            
            if subdomains:
                self.calculate_all_subdomains(subdomain_batch_size)
            
            if providers:
                self.calculate_all_providers(provider_batch_size)
            
            self.stats.end_time = time.time()
            
            # Estadísticas finales
            logger.info("\n" + "=" * 80)
            logger.info("📊 ESTADÍSTICAS FINALES DEL CÁLCULO MASIVO")
            logger.info("=" * 80)
            
            if domains:
                logger.info(f"🌐 DOMINIOS:")
                logger.info(f"   Total procesados: {self.stats.total_domains}")
                logger.info(f"   Exitosos: {self.stats.successful_domains}")
                logger.info(f"   Fallidos: {self.stats.failed_domains}")
                logger.info(f"   Tasa de éxito: {self.stats.domain_success_rate:.1f}%")
            
            if subdomains:
                logger.info(f"🌐 SUBDOMINIOS:")
                logger.info(f"   Total procesados: {self.stats.total_subdomains}")
                logger.info(f"   Exitosos: {self.stats.successful_subdomains}")
                logger.info(f"   Fallidos: {self.stats.failed_subdomains}")
                logger.info(f"   Tasa de éxito: {self.stats.subdomain_success_rate:.1f}%")
            
            if providers:
                logger.info(f"🏭 PROVIDERS:")
                logger.info(f"   Total procesados: {self.stats.total_providers}")
                logger.info(f"   Exitosos: {self.stats.successful_providers}")
                logger.info(f"   Fallidos: {self.stats.failed_providers}")
                logger.info(f"   Tasa de éxito: {self.stats.provider_success_rate:.1f}%")
            
            logger.info(f"⏱️  Tiempo total: {self.stats.elapsed_time:.2f} segundos")
            logger.info("=" * 80)
            
            return self.stats
            
        except KeyboardInterrupt:
            logger.info("⏹️  Proceso interrumpido por el usuario")
            self.stats.end_time = time.time()
            return self.stats
        except Exception as e:
            logger.error(f"❌ Error fatal en cálculo masivo: {e}")
            self.stats.end_time = time.time()
            return self.stats
    
    def close(self):
        """Cierra las conexiones"""
        if self.risk_updater:
            self.risk_updater.close()
        if self.driver:
            self.driver.close()

def main():
    """Función principal"""
    parser = argparse.ArgumentParser(
        description="Cálculo masivo de risk scores para dominios y providers"
    )
    parser.add_argument("--bolt", default="bolt://localhost:7687", help="Neo4j bolt URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", default="test.password", help="Neo4j password")
    parser.add_argument("--domains-only", action="store_true", help="Solo procesar dominios")
    parser.add_argument("--subdomains-only", action="store_true", help="Solo procesar subdominios")  
    parser.add_argument("--providers-only", action="store_true", help="Solo procesar providers")
    parser.add_argument("--domain-batch-size", type=int, default=10, help="Tamaño de lote para dominios")
    parser.add_argument("--subdomain-batch-size", type=int, default=15, help="Tamaño de lote para subdominios")
    parser.add_argument("--provider-batch-size", type=int, default=20, help="Tamaño de lote para providers")
    parser.add_argument("--dry-run", action="store_true", help="Solo mostrar estadísticas, no calcular")
    
    args = parser.parse_args()
    
    # Determine what to process
    exclusive_flags = [args.domains_only, args.subdomains_only, args.providers_only]
    exclusive_count = sum(exclusive_flags)
    
    if exclusive_count > 1:
        logger.error("❌ Solo puedes usar una de las opciones --domains-only, --subdomains-only, --providers-only")
        return 1
    
    if exclusive_count == 0:
        # Process all by default
        process_domains = True
        process_subdomains = True
        process_providers = True
    else:
        process_domains = args.domains_only
        process_subdomains = args.subdomains_only
        process_providers = args.providers_only
    
    logger.info(f"🚀 Iniciando cálculo masivo")
    logger.info(f"   Neo4j URI: {args.bolt}")
    logger.info(f"   Procesar dominios: {process_domains}")
    logger.info(f"   Procesar subdominios: {process_subdomains}")
    logger.info(f"   Procesar providers: {process_providers}")
    logger.info(f"   Dry run: {args.dry_run}")
    
    calculator = None
    try:
        # Initialize calculator
        calculator = MassRiskCalculator(args.bolt, args.user, args.password)
        
        if args.dry_run:
            # Just show stats
            logger.info("🔍 MODO DRY-RUN: Solo mostrando estadísticas")
            domains = calculator.get_all_base_domains() if process_domains else []
            subdomains = calculator.get_all_subdomains() if process_subdomains else []
            providers = calculator.get_all_providers() if process_providers else []
            
            logger.info(f"📊 Dominios a procesar: {len(domains)}")
            logger.info(f"📊 Subdominios a procesar: {len(subdomains)}")
            logger.info(f"📊 Providers a procesar: {len(providers)}")
            
            if domains:
                logger.info(f"   Ejemplos de dominios: {domains[:5]}")
            if subdomains:
                logger.info(f"   Ejemplos de subdominios: {subdomains[:5]}")
            if providers:
                provider_names = [p['name'] for p in providers[:5]]
                logger.info(f"   Ejemplos de providers: {provider_names}")
        else:
            # Run mass calculation
            stats = calculator.run_mass_calculation(
                domains=process_domains,
                subdomains=process_subdomains,
                providers=process_providers,
                domain_batch_size=args.domain_batch_size,
                subdomain_batch_size=args.subdomain_batch_size,
                provider_batch_size=args.provider_batch_size
            )
            
            # Return appropriate exit code
            if (stats.total_domains > 0 and stats.successful_domains == 0) or \
               (stats.total_subdomains > 0 and stats.successful_subdomains == 0) or \
               (stats.total_providers > 0 and stats.successful_providers == 0):
                logger.error("❌ Todos los cálculos fallaron")
                return 1
            elif stats.failed_domains > 0 or stats.failed_subdomains > 0 or stats.failed_providers > 0:
                logger.warning("⚠️  Algunos cálculos fallaron, ver logs para detalles")
                return 2
            else:
                logger.info("✅ Cálculo masivo completado exitosamente")
                return 0
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("⏹️  Proceso interrumpido por el usuario")
        return 1
    except Exception as e:
        logger.error(f"❌ Error fatal: {e}")
        return 1
    finally:
        if calculator:
            calculator.close()

if __name__ == "__main__":
    exit(main())