#!/usr/bin/env python3
"""
Script para limpiar proveedores inválidos que se crean dinámicamente

Este script:
1. Identifica proveedores que no están en la lista curada
2. Los elimina del grafo junto con sus relaciones
3. Asegura que solo queden los proveedores oficiales
"""

import logging
from neo4j import GraphDatabase
import argparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Lista oficial de proveedores curados
OFFICIAL_PROVIDERS = {
    'amazon', 'google', 'microsoft', 'cloudflare', 'akamai', 'fastly', 
    'salesforce', 'github', 'heroku', 'digitalocean', 'linode', 'vultr', 
    'ovh', 'hetzner', 'godaddy', 'namecheap', 'rackspace'
}

class ProviderCleaner:
    def __init__(self, neo4j_uri="bolt://localhost:7687", neo4j_user="neo4j", neo4j_password="test.password"):
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.session = None
        
    def __enter__(self):
        self.session = self.driver.session()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            self.session.close()
        self.driver.close()
    
    def identify_invalid_providers(self):
        """Identifica proveedores que no están en la lista oficial"""
        query = """
        MATCH (p:Provider)
        WHERE NOT p.id IN $official_ids
        RETURN p.id, p.name, p.type
        ORDER BY p.name
        """
        
        result = self.session.run(query, official_ids=list(OFFICIAL_PROVIDERS))
        invalid_providers = []
        
        for record in result:
            invalid_providers.append({
                'id': record['p.id'],
                'name': record['p.name'],
                'type': record['p.type']
            })
        
        return invalid_providers
    
    def clean_invalid_providers(self, dry_run=False):
        """Limpia proveedores inválidos"""
        invalid_providers = self.identify_invalid_providers()
        
        if not invalid_providers:
            logger.info("✅ No se encontraron proveedores inválidos")
            return 0
        
        logger.info(f"🔍 Encontrados {len(invalid_providers)} proveedores inválidos:")
        for provider in invalid_providers:
            logger.info(f"  - {provider['name']} (id: {provider['id']}, type: {provider['type']})")
        
        if dry_run:
            logger.info("🔍 DRY RUN - No se eliminará nada")
            return len(invalid_providers)
        
        # Eliminar proveedores inválidos
        delete_query = """
        MATCH (p:Provider)
        WHERE NOT p.id IN $official_ids
        DETACH DELETE p
        RETURN count(p) as deleted_count
        """
        
        result = self.session.run(delete_query, official_ids=list(OFFICIAL_PROVIDERS))
        deleted_count = result.single()['deleted_count']
        
        logger.info(f"🗑️ Eliminados {deleted_count} proveedores inválidos")
        return deleted_count
    
    def verify_official_providers(self):
        """Verifica que todos los proveedores oficiales estén presentes"""
        query = """
        MATCH (p:Provider)
        WHERE p.id IN $official_ids
        RETURN p.id, p.name, p.type
        ORDER BY p.type, p.name
        """
        
        result = self.session.run(query, official_ids=list(OFFICIAL_PROVIDERS))
        found_providers = set()
        
        logger.info("📊 Proveedores oficiales encontrados:")
        for record in result:
            found_providers.add(record['p.id'])
            logger.info(f"  ✅ {record['p.name']} ({record['p.type']}) - {record['p.id']}")
        
        missing_providers = OFFICIAL_PROVIDERS - found_providers
        if missing_providers:
            logger.warning(f"⚠️ Proveedores oficiales faltantes: {missing_providers}")
        else:
            logger.info("✅ Todos los proveedores oficiales están presentes")
        
        return len(found_providers), len(missing_providers)
    
    def get_provider_statistics(self):
        """Obtiene estadísticas de proveedores"""
        stats_query = """
        MATCH (p:Provider)
        WITH p.type as provider_type, count(p) as count
        RETURN provider_type, count
        ORDER BY count DESC
        """
        
        result = self.session.run(stats_query)
        stats = list(result)
        
        total_query = "MATCH (p:Provider) RETURN count(p) as total"
        total_result = self.session.run(total_query)
        total = total_result.single()['total']
        
        logger.info(f"📈 Estadísticas de proveedores (Total: {total}):")
        for stat in stats:
            logger.info(f"  {stat['provider_type']}: {stat['count']}")
        
        return stats, total

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Limpiar proveedores inválidos de Neo4j')
    parser.add_argument('--neo4j-uri', default='bolt://localhost:7687', help='Neo4j connection URI')
    parser.add_argument('--neo4j-user', default='neo4j', help='Neo4j username')
    parser.add_argument('--neo4j-password', default='test.password', help='Neo4j password')
    parser.add_argument('--dry-run', action='store_true', help='Solo mostrar qué se eliminaría')
    parser.add_argument('--stats-only', action='store_true', help='Solo mostrar estadísticas')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("LIMPIEZA DE PROVEEDORES INVÁLIDOS")
    print("=" * 60)
    print(f"Neo4j URI: {args.neo4j_uri}")
    print(f"Dry run: {args.dry_run}")
    print(f"Stats only: {args.stats_only}")
    print("=" * 60)
    
    try:
        with ProviderCleaner(args.neo4j_uri, args.neo4j_user, args.neo4j_password) as cleaner:
            
            # Mostrar estadísticas
            stats, total = cleaner.get_provider_statistics()
            
            if args.stats_only:
                cleaner.verify_official_providers()
                return
            
            # Limpiar proveedores inválidos
            deleted_count = cleaner.clean_invalid_providers(dry_run=args.dry_run)
            
            # Verificar proveedores oficiales
            found_count, missing_count = cleaner.verify_official_providers()
            
            print("\n" + "=" * 60)
            print("LIMPIEZA COMPLETADA")
            print("=" * 60)
            print(f"🗑️ Proveedores eliminados: {deleted_count}")
            print(f"✅ Proveedores oficiales encontrados: {found_count}")
            print(f"⚠️ Proveedores oficiales faltantes: {missing_count}")
            print("=" * 60)
            
    except Exception as e:
        logger.error(f"❌ Limpieza falló: {e}")
        raise

if __name__ == "__main__":
    main()