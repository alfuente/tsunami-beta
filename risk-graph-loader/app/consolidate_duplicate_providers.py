#!/usr/bin/env python3
"""
consolidate_duplicate_providers.py - Script para consolidar providers duplicados

Este script identifica y consolida providers duplicados en el grafo:
1. Identifica providers con el mismo nombre
2. Mantiene uno como "master" y redirige las relaciones de los duplicados
3. Elimina los providers duplicados
4. Actualiza estadísticas
"""

import argparse
import logging
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Any

# Neo4j imports
try:
    from neo4j import GraphDatabase, Driver
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'consolidate_providers_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ProviderConsolidator:
    """Consolidador de providers duplicados"""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str):
        if not HAS_NEO4J:
            raise ImportError("Neo4j driver is required. Install with: pip install neo4j")
        
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
    
    def find_duplicate_providers(self) -> Dict[str, List[Dict[str, Any]]]:
        """Encuentra providers duplicados agrupados por nombre"""
        logger.info("🔍 Buscando providers duplicados...")
        
        with self.driver.session() as session:
            result = session.run("""
                MATCH (p:Provider)
                WITH toLower(trim(p.name)) as clean_name, collect(p) as providers
                WHERE size(providers) > 1
                RETURN clean_name, providers
                ORDER BY clean_name
            """)
            
            duplicates = {}
            total_duplicates = 0
            
            for record in result:
                clean_name = record['clean_name']
                providers = record['providers']
                
                if len(providers) > 1:
                    duplicates[clean_name] = []
                    for p in providers:
                        duplicates[clean_name].append({
                            'id': p.get('id'),
                            'name': p.get('name'),
                            'type': p.get('type'),
                            'risk_score': p.get('risk_score', 0.0)
                        })
                    total_duplicates += len(providers) - 1  # -1 porque uno se mantiene
            
            logger.info(f"   ✓ Encontrados {len(duplicates)} grupos de duplicados")
            logger.info(f"   ✓ Total de providers a eliminar: {total_duplicates}")
            
            return duplicates
    
    def get_provider_usage(self, provider_id: str) -> tuple:
        """Obtiene estadísticas de uso de un provider"""
        with self.driver.session() as session:
            result = session.run("""
                MATCH (p:Provider {id: $provider_id})
                OPTIONAL MATCH (d)-[r]->(p)
                WHERE type(r) IN ['USES_SERVICE', 'HAS_PROVIDER', 'DEPENDS_ON', 'HOSTED_BY']
                RETURN 
                    p.id as provider_id,
                    count(d) as usage_count,
                    collect(DISTINCT d.fqdn) as domains
            """, provider_id=provider_id)
            
            record = result.single()
            if record:
                return record['usage_count'] or 0, record['domains'] or []
            return 0, []
    
    def choose_master_provider(self, providers: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Elige el provider "master" que se mantendrá"""
        # Criterios para elegir el master:
        # 1. El que tenga más uso
        # 2. El que tenga risk_score calculado
        # 3. El que tenga type definido
        # 4. El más antiguo (por ID)
        
        best_provider = None
        best_score = -1
        
        for provider in providers:
            score = 0
            usage_count, _ = self.get_provider_usage(provider['id'])
            
            # Bonus por uso
            score += usage_count * 10
            
            # Bonus por tener risk_score
            if provider.get('risk_score', 0) > 0:
                score += 5
            
            # Bonus por tener type definido
            if provider.get('type') and provider['type'] != 'None':
                score += 3
            
            # Bonus por ser más antiguo (ID más pequeño)
            try:
                id_timestamp = int(provider['id'].split('_')[-1])
                score += (2000000000000000 - id_timestamp) / 1000000000000  # Normalizar
            except:
                pass
            
            logger.debug(f"   Provider {provider['id']}: score={score:.2f}, usage={usage_count}")
            
            if score > best_score:
                best_score = score
                best_provider = provider
        
        logger.info(f"   🎯 Master elegido: {best_provider['id']} (score: {best_score:.2f})")
        return best_provider
    
    def consolidate_provider_group(self, clean_name: str, providers: List[Dict[str, Any]], dry_run: bool = False) -> dict:
        """Consolida un grupo de providers duplicados"""
        logger.info(f"\\n🔄 Consolidando '{clean_name}' ({len(providers)} duplicados)")
        
        # Elegir el master
        master = self.choose_master_provider(providers)
        duplicates = [p for p in providers if p['id'] != master['id']]
        
        stats = {
            'master_id': master['id'],
            'duplicates_removed': len(duplicates),
            'relationships_moved': 0,
            'domains_affected': set()
        }
        
        if dry_run:
            logger.info(f"   🏷️  [DRY RUN] Master: {master['id']}")
            for dup in duplicates:
                usage_count, domains = self.get_provider_usage(dup['id'])
                logger.info(f"   🗑️  [DRY RUN] Eliminaría: {dup['id']} ({usage_count} usos)")
                stats['relationships_moved'] += usage_count
                stats['domains_affected'].update(domains)
            return stats
        
        # Mover todas las relaciones de los duplicados al master
        with self.driver.session() as session:
            for duplicate in duplicates:
                dup_id = duplicate['id']
                logger.info(f"   ↗️  Moviendo relaciones de {dup_id} a {master['id']}")
                
                # Obtener dominios que usan este duplicado
                usage_count, domains = self.get_provider_usage(dup_id)
                stats['relationships_moved'] += usage_count
                stats['domains_affected'].update(domains)
                
                if usage_count > 0:
                    # Mover relaciones al master
                    move_result = session.run("""
                        MATCH (d)-[r]->(dup:Provider {id: $dup_id})
                        MATCH (master:Provider {id: $master_id})
                        WHERE type(r) IN ['USES_SERVICE', 'HAS_PROVIDER', 'DEPENDS_ON', 'HOSTED_BY']
                        
                        // Crear nueva relación al master si no existe
                        MERGE (d)-[new_r:HAS_PROVIDER]->(master)
                        ON CREATE SET 
                            new_r.discovered_at = coalesce(r.discovered_at, datetime()),
                            new_r.discovery_method = coalesce(r.discovery_method, 'consolidation'),
                            new_r.consolidated_from = $dup_id
                        
                        // Eliminar relación antigua
                        DELETE r
                        
                        RETURN count(*) as moved_relationships
                    """, dup_id=dup_id, master_id=master['id'])
                    
                    moved = move_result.single()['moved_relationships']
                    logger.info(f"     ✓ Movidas {moved} relaciones")
                
                # Eliminar el provider duplicado
                delete_result = session.run("""
                    MATCH (p:Provider {id: $dup_id})
                    DETACH DELETE p
                    RETURN count(p) as deleted
                """, dup_id=dup_id)
                
                deleted = delete_result.single()['deleted']
                logger.info(f"     🗑️  Eliminado provider duplicado ({deleted} nodos)")
        
        logger.info(f"   ✅ Consolidación completada para '{clean_name}'")
        return stats
    
    def consolidate_all_duplicates(self, dry_run: bool = False) -> dict:
        """Consolida todos los providers duplicados"""
        logger.info("🚀 INICIANDO CONSOLIDACIÓN DE PROVIDERS DUPLICADOS")
        logger.info("=" * 80)
        
        if dry_run:
            logger.info("🔍 MODO DRY-RUN: Solo mostrando qué se haría")
        
        duplicates = self.find_duplicate_providers()
        
        if not duplicates:
            logger.info("✅ No se encontraron providers duplicados")
            return {}
        
        total_stats = {
            'groups_processed': 0,
            'duplicates_removed': 0,
            'relationships_moved': 0,
            'domains_affected': set()
        }
        
        for clean_name, providers in duplicates.items():
            stats = self.consolidate_provider_group(clean_name, providers, dry_run)
            
            total_stats['groups_processed'] += 1
            total_stats['duplicates_removed'] += stats['duplicates_removed']
            total_stats['relationships_moved'] += stats['relationships_moved']
            total_stats['domains_affected'].update(stats['domains_affected'])
        
        # Resumen final
        logger.info("\\n" + "=" * 80)
        logger.info("📊 RESUMEN DE CONSOLIDACIÓN")
        logger.info("=" * 80)
        logger.info(f"🔢 Grupos procesados: {total_stats['groups_processed']}")
        logger.info(f"🗑️  Providers eliminados: {total_stats['duplicates_removed']}")
        logger.info(f"↗️  Relaciones movidas: {total_stats['relationships_moved']}")
        logger.info(f"🌐 Dominios afectados: {len(total_stats['domains_affected'])}")
        
        if not dry_run:
            logger.info("✅ Consolidación completada exitosamente")
        
        return total_stats
    
    def close(self):
        """Cierra la conexión"""
        if self.driver:
            self.driver.close()

def main():
    """Función principal"""
    parser = argparse.ArgumentParser(
        description="Consolidar providers duplicados en el grafo"
    )
    parser.add_argument("--bolt", default="bolt://localhost:7687", help="Neo4j bolt URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", default="test.password", help="Neo4j password")
    parser.add_argument("--dry-run", action="store_true", help="Solo mostrar qué se haría, no ejecutar")
    
    args = parser.parse_args()
    
    logger.info(f"🚀 Iniciando consolidación de providers")
    logger.info(f"   Neo4j URI: {args.bolt}")
    logger.info(f"   Dry run: {args.dry_run}")
    
    consolidator = None
    try:
        consolidator = ProviderConsolidator(args.bolt, args.user, args.password)
        stats = consolidator.consolidate_all_duplicates(args.dry_run)
        
        if stats.get('duplicates_removed', 0) > 0:
            return 0
        else:
            logger.info("ℹ️  No se encontraron duplicados para consolidar")
            return 0
        
    except KeyboardInterrupt:
        logger.info("⏹️  Proceso interrumpido por el usuario")
        return 1
    except Exception as e:
        logger.error(f"❌ Error fatal: {e}")
        return 1
    finally:
        if consolidator:
            consolidator.close()

if __name__ == "__main__":
    exit(main())