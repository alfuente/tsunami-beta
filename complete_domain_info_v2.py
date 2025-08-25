#!/usr/bin/env python3
"""
Script optimizado para completar información faltante en el grafo Neo4j.
Versión 2 con mejor manejo de errores y progreso más claro.
"""

import asyncio
import aiohttp
import logging
from typing import List, Dict, Any, Optional
import json
import time
import sys
from neo4j import GraphDatabase

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('domain_completion_v2.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DomainCompleterV2:
    def __init__(self):
        self.neo4j_driver = GraphDatabase.driver(
            "bolt://localhost:7687", 
            auth=("neo4j", "test.password")
        )
        self.api_base_url = "http://localhost:8001/api/v1"
        self.report_api_url = "http://localhost:8081/api/v1"
        self.session = None
        self.completed_count = 0
        self.failed_count = 0
        self.batch_size = 3  # Más conservador
        self.stats = {
            'tls_updated': 0,
            'tech_updated': 0,
            'risk_updated': 0,
            'from_report_api': 0,
            'from_async_api': 0
        }
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=300),
            connector=aiohttp.TCPConnector(limit=10, limit_per_host=5)
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
        self.neo4j_driver.close()
            
    def get_all_domains_needing_completion(self) -> tuple[List[str], List[str]]:
        """Obtiene todos los dominios que necesitan información"""
        with self.neo4j_driver.session() as session:
            # Dominios base
            domains_result = session.run("""
                MATCH (d:Domain) 
                RETURN d.fqdn as fqdn,
                       EXISTS(d.hasSSL) as has_ssl_prop,
                       EXISTS(d.tlsVersion) as has_tls_prop,
                       EXISTS(d.riskScore) as has_risk_prop,
                       d.hasSSL as ssl_val,
                       d.tlsVersion as tls_val,
                       d.riskScore as risk_val
                ORDER BY d.fqdn
            """)
            
            domains_needing_work = []
            for record in domains_result:
                needs_work = (
                    not record['has_ssl_prop'] or record['ssl_val'] is None or
                    not record['has_tls_prop'] or record['tls_val'] is None or
                    not record['has_risk_prop'] or record['risk_val'] is None
                )
                if needs_work:
                    domains_needing_work.append(record['fqdn'])
            
            # Subdominios (primeros 500)
            subdomains_result = session.run("""
                MATCH (s:Subdomain) 
                RETURN s.fqdn as fqdn,
                       EXISTS(s.hasSSL) as has_ssl_prop,
                       EXISTS(s.tlsVersion) as has_tls_prop,
                       EXISTS(s.riskScore) as has_risk_prop,
                       s.hasSSL as ssl_val,
                       s.tlsVersion as tls_val,
                       s.riskScore as risk_val
                ORDER BY s.fqdn
                LIMIT 500
            """)
            
            subdomains_needing_work = []
            for record in subdomains_result:
                needs_work = (
                    not record['has_ssl_prop'] or record['ssl_val'] is None or
                    not record['has_tls_prop'] or record['tls_val'] is None or
                    not record['has_risk_prop'] or record['risk_val'] is None
                )
                if needs_work:
                    subdomains_needing_work.append(record['fqdn'])
                    
            return domains_needing_work, subdomains_needing_work

    async def get_domain_from_report_api(self, domain: str) -> Optional[Dict]:
        """Obtiene información completa desde la API de reporte"""
        try:
            url = f"{self.report_api_url}/domains/{domain}"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    self.stats['from_report_api'] += 1
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

    async def start_async_analysis(self, domain: str, analysis_type: str) -> Optional[str]:
        """Inicia un análisis asíncrono y devuelve el task_id"""
        try:
            endpoint_map = {
                'tls': f"{self.api_base_url}/discover/tls/{domain}",
                'tech': f"{self.api_base_url}/discover/tech/{domain}",
                'risk': f"{self.api_base_url}/calculate/risk/{domain}"
            }
            
            url = endpoint_map.get(analysis_type)
            if not url:
                logger.error(f"Unknown analysis type: {analysis_type}")
                return None
                
            async with self.session.post(url) as response:
                if response.status == 200:
                    task_data = await response.json()
                    task_id = task_data.get('task_id')
                    self.stats['from_async_api'] += 1
                    return task_id
                else:
                    logger.warning(f"{analysis_type.upper()} API error for {domain}: {response.status}")
                    return None
        except Exception as e:
            logger.error(f"Error starting {analysis_type} analysis for {domain}: {str(e)}")
            return None

    async def wait_for_task_completion(self, task_id: str, max_wait: int = 60) -> Optional[Dict]:
        """Espera a que una tarea se complete"""
        for attempt in range(max_wait):
            try:
                url = f"{self.api_base_url}/tasks/{task_id}"
                async with self.session.get(url) as response:
                    if response.status == 200:
                        task_data = await response.json()
                        status = task_data.get('status')
                        
                        if status == 'completed':
                            return task_data.get('result')
                        elif status == 'failed':
                            logger.warning(f"Task {task_id} failed: {task_data.get('error')}")
                            return None
                        
                        # Task still running
                        await asyncio.sleep(1)
                    else:
                        logger.warning(f"Error checking task {task_id}: {response.status}")
                        await asyncio.sleep(1)
                        
            except Exception as e:
                logger.error(f"Error waiting for task {task_id}: {str(e)}")
                await asyncio.sleep(1)
        
        logger.warning(f"Task {task_id} timed out after {max_wait} seconds")
        return None

    def update_domain_info_in_neo4j(self, domain: str, info_dict: Dict, is_subdomain: bool = False):
        """Actualiza información en Neo4j"""
        with self.neo4j_driver.session() as session:
            node_type = "Subdomain" if is_subdomain else "Domain"
            
            # Actualizar propiedades básicas
            updates = []
            params = {"fqdn": domain}
            
            if 'hasSSL' in info_dict:
                updates.append("n.hasSSL = $hasSSL")
                params['hasSSL'] = info_dict['hasSSL']
                
            if 'tlsVersion' in info_dict:
                updates.append("n.tlsVersion = $tlsVersion")
                params['tlsVersion'] = info_dict['tlsVersion']
                
            if 'riskScore' in info_dict:
                updates.append("n.riskScore = $riskScore")
                params['riskScore'] = info_dict['riskScore']
                
            if 'certificateValid' in info_dict:
                updates.append("n.certificateValid = $certificateValid")
                params['certificateValid'] = info_dict['certificateValid']
                
            if updates:
                updates.append("n.lastUpdated = datetime()")
                query = f"""
                    MATCH (n:{node_type} {{fqdn: $fqdn}})
                    SET {', '.join(updates)}
                """
                session.run(query, params)
                
            # Actualizar tecnologías si están presentes
            if 'technologies' in info_dict:
                for tech in info_dict['technologies']:
                    tech_name = tech.get('name', 'Unknown')
                    category = tech.get('category', 'Unknown')
                    confidence = tech.get('confidence', 0.0)
                    version = tech.get('version', '')
                    
                    # Crear tecnología si no existe
                    session.run("""
                        MERGE (t:Technology {name: $tech_name})
                        SET t.category = $category,
                            t.lastUpdated = datetime()
                    """, tech_name=tech_name, category=category)
                    
                    # Crear relación
                    session.run(f"""
                        MATCH (n:{node_type} {{fqdn: $fqdn}})
                        MATCH (t:Technology {{name: $tech_name}})
                        MERGE (n)-[r:USES]->(t)
                        SET r.confidence = $confidence,
                            r.version = $version,
                            r.detectedAt = datetime()
                    """, fqdn=domain, tech_name=tech_name, confidence=confidence, version=version)

    async def process_domain_complete(self, domain: str, is_subdomain: bool = False) -> bool:
        """Procesa un dominio completamente"""
        try:
            logger.info(f"Processing {'subdomain' if is_subdomain else 'domain'}: {domain}")
            info_to_update = {}
            
            # Paso 1: Intentar obtener de la API de reporte (solo para dominios base)
            if not is_subdomain:
                report_data = await self.get_domain_from_report_api(domain)
                if report_data:
                    # Extraer información TLS
                    tls_grade = report_data.get('tls_grade')
                    if tls_grade:
                        info_to_update['hasSSL'] = tls_grade not in ['F', 'T']
                        info_to_update['tlsVersion'] = 'TLSv1.3' if tls_grade in ['A+', 'A'] else 'TLSv1.2'
                        info_to_update['certificateValid'] = tls_grade not in ['F', 'T']
                        self.stats['tls_updated'] += 1
                    
                    # Extraer risk score
                    risk_score = report_data.get('risk_score')
                    if risk_score is not None:
                        info_to_update['riskScore'] = float(risk_score)
                        self.stats['risk_updated'] += 1
                    
                    # Extraer tecnologías
                    tech_nodes = report_data.get('technology_nodes', [])
                    if tech_nodes:
                        technologies = []
                        for tech in tech_nodes:
                            technologies.append({
                                'name': tech.get('name', 'Unknown'),
                                'category': tech.get('category', 'Unknown'),
                                'confidence': tech.get('confidence', 0.8),
                                'version': tech.get('version', '')
                            })
                        info_to_update['technologies'] = technologies
                        self.stats['tech_updated'] += 1
            
            # Paso 2: Completar información faltante con APIs asíncronas
            missing_info = []
            if 'hasSSL' not in info_to_update or 'tlsVersion' not in info_to_update:
                missing_info.append('tls')
            if 'technologies' not in info_to_update:
                missing_info.append('tech')
            if 'riskScore' not in info_to_update:
                missing_info.append('risk')
            
            # Ejecutar análisis asíncronos para información faltante
            for analysis_type in missing_info:
                task_id = await self.start_async_analysis(domain, analysis_type)
                if task_id:
                    result = await self.wait_for_task_completion(task_id)
                    if result:
                        if analysis_type == 'tls':
                            metadata = result.get('metadata', {})
                            info_to_update['hasSSL'] = metadata.get('has_valid_cert', False)
                            info_to_update['tlsVersion'] = result.get('tls_version', 'Unknown')
                            info_to_update['certificateValid'] = metadata.get('has_valid_cert', False)
                            self.stats['tls_updated'] += 1
                            
                        elif analysis_type == 'tech':
                            technologies = result.get('technologies', [])
                            if technologies:
                                info_to_update['technologies'] = technologies
                                self.stats['tech_updated'] += 1
                                
                        elif analysis_type == 'risk':
                            # Buscar risk score en varios campos posibles
                            for field in ['riskScore', 'risk_score', 'score', 'overall_risk_score']:
                                if field in result:
                                    info_to_update['riskScore'] = float(result[field])
                                    self.stats['risk_updated'] += 1
                                    break
            
            # Paso 3: Actualizar en Neo4j
            if info_to_update:
                self.update_domain_info_in_neo4j(domain, info_to_update, is_subdomain)
                logger.info(f"Updated {domain} with: {list(info_to_update.keys())}")
                self.completed_count += 1
                return True
            else:
                logger.warning(f"No information obtained for {domain}")
                self.failed_count += 1
                return False
                
        except Exception as e:
            logger.error(f"Error processing {domain}: {str(e)}")
            self.failed_count += 1
            return False

    async def process_batch(self, domains: List[str], is_subdomain: bool = False):
        """Procesa un lote de dominios con concurrencia limitada"""
        tasks = []
        for domain in domains:
            task = self.process_domain_complete(domain, is_subdomain)
            tasks.append(task)
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Pausa entre lotes
        await asyncio.sleep(3)
        
        return results

    def print_progress_stats(self):
        """Imprime estadísticas de progreso"""
        total_processed = self.completed_count + self.failed_count
        if total_processed > 0:
            success_rate = (self.completed_count / total_processed) * 100
            print(f"\n--- Progress Stats ---")
            print(f"Processed: {total_processed} | Success: {self.completed_count} | Failed: {self.failed_count}")
            print(f"Success Rate: {success_rate:.1f}%")
            print(f"TLS Updated: {self.stats['tls_updated']}")
            print(f"Tech Updated: {self.stats['tech_updated']}")
            print(f"Risk Updated: {self.stats['risk_updated']}")
            print(f"From Report API: {self.stats['from_report_api']}")
            print(f"From Async API: {self.stats['from_async_api']}")
            print("-------------------\n")

    async def run_completion(self):
        """Ejecuta el proceso completo"""
        logger.info("Iniciando Domain Completer V2...")
        
        # Obtener dominios que necesitan trabajo
        domains_needed, subdomains_needed = self.get_all_domains_needing_completion()
        
        logger.info(f"Dominios base que necesitan completar: {len(domains_needed)}")
        logger.info(f"Subdominios que necesitan completar: {len(subdomains_needed)}")
        
        # Procesar dominios base
        logger.info("Procesando dominios base...")
        for i in range(0, len(domains_needed), self.batch_size):
            batch = domains_needed[i:i + self.batch_size]
            batch_num = i // self.batch_size + 1
            total_batches = (len(domains_needed) + self.batch_size - 1) // self.batch_size
            
            logger.info(f"Procesando lote {batch_num}/{total_batches} de dominios base")
            await self.process_batch(batch, is_subdomain=False)
            self.print_progress_stats()
        
        # Procesar subdominios
        logger.info("Procesando subdominios...")
        for i in range(0, len(subdomains_needed), self.batch_size):
            batch = subdomains_needed[i:i + self.batch_size]
            batch_num = i // self.batch_size + 1
            total_batches = (len(subdomains_needed) + self.batch_size - 1) // self.batch_size
            
            logger.info(f"Procesando lote {batch_num}/{total_batches} de subdominios")
            await self.process_batch(batch, is_subdomain=True)
            self.print_progress_stats()
        
        # Resumen final
        logger.info("Proceso completado!")
        self.print_progress_stats()

async def main():
    """Función principal"""
    print("=== Domain Information Completer V2 ===")
    print("Este script completará la información faltante de TLS, tecnologías y risk scores")
    print("para todos los dominios y subdominios existentes en Neo4j.")
    print("Versión optimizada con mejor manejo de APIs y progreso.\n")
    
    response = input("¿Desea continuar? (y/N): ").strip().lower()
    if response != 'y':
        print("Operación cancelada.")
        return
    
    async with DomainCompleterV2() as completer:
        start_time = time.time()
        try:
            await completer.run_completion()
        except KeyboardInterrupt:
            logger.info("Proceso interrumpido por el usuario")
        finally:
            end_time = time.time()
            print(f"\nTiempo transcurrido: {end_time - start_time:.2f} segundos")
            print(f"Total completados: {completer.completed_count}")
            print(f"Total fallidos: {completer.failed_count}")

if __name__ == "__main__":
    asyncio.run(main())