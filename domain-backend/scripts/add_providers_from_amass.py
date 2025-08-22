#!/usr/bin/env python3
"""
Script para agregar proveedores específicos encontrados por amass

Este script:
1. Analiza los datos de amass para encontrar proveedores con evidencia sólida
2. Crea proveedores específicos basados en ASN y organizaciones reales
3. Mantiene la lista curada + proveedores específicos de Chile y otros países
"""

import logging
import json
from neo4j import GraphDatabase
import argparse
from datetime import datetime
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Mapeo de ASN conocidos a proveedores
ASN_PROVIDER_MAPPING = {
    # Telecomunicaciones Chile
    'AS22047': {'name': 'Telefónica Chile', 'type': 'telecom', 'country': 'CL'},
    'AS27651': {'name': 'Entel Chile', 'type': 'telecom', 'country': 'CL'},
    'AS14259': {'name': 'GTD Chile', 'type': 'isp', 'country': 'CL'},
    'AS7418': {'name': 'Telefónica Chile S.A.', 'type': 'telecom', 'country': 'CL'},
    
    # Seguridad
    'AS19551': {'name': 'Incapsula (Imperva)', 'type': 'security', 'country': 'US'},
    'AS13335': {'name': 'Cloudflare', 'type': 'cdn', 'country': 'US'},  # Ya existe pero puede tener ASN específico
    
    # Bancos y financieras
    'AS264730': {'name': 'Banco del Estado de Chile', 'type': 'banking', 'country': 'CL'},
    'AS264729': {'name': 'Banco del Estado de Chile', 'type': 'banking', 'country': 'CL'},
    
    # Otros ISPs
    'AS23700': {'name': 'Linknet-Fastnet', 'type': 'isp', 'country': 'US'},
}

# Organizaciones a proveedores
ORG_PROVIDER_MAPPING = {
    'telefonica chile': {'name': 'Telefónica Chile', 'type': 'telecom', 'country': 'CL'},
    'entel': {'name': 'Entel Chile', 'type': 'telecom', 'country': 'CL'},
    'gtd': {'name': 'GTD Chile', 'type': 'isp', 'country': 'CL'},
    'imperva': {'name': 'Incapsula (Imperva)', 'type': 'security', 'country': 'US'},
    'banco del estado': {'name': 'Banco del Estado de Chile', 'type': 'banking', 'country': 'CL'},
    'servibanca': {'name': 'Servibanca S.A.', 'type': 'banking', 'country': 'CL'},
}

class AmassProviderAdder:
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
    
    def analyze_amass_log(self, log_file: str):
        """Analiza un archivo de log de amass para extraer proveedores"""
        providers_found = {}
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Analizar líneas ASN
                    if ' (ASN) --> managed_by --> ' in line:
                        parts = line.split(' --> ')
                        if len(parts) >= 3:
                            asn = parts[0].split(' ')[0]
                            org = parts[2].split(' (')[0].lower()
                            
                            # Buscar en mapeo ASN
                            if asn in ASN_PROVIDER_MAPPING:
                                provider_data = ASN_PROVIDER_MAPPING[asn].copy()
                                provider_id = self._generate_provider_id(provider_data['name'])
                                providers_found[provider_id] = provider_data
                                providers_found[provider_id]['evidence'] = f"ASN {asn}"
                                logger.info(f"🎯 Found provider via ASN: {provider_data['name']} ({asn})")
                            
                            # Buscar en mapeo organizaciones
                            for org_pattern, provider_data in ORG_PROVIDER_MAPPING.items():
                                if org_pattern in org:
                                    provider_id = self._generate_provider_id(provider_data['name'])
                                    if provider_id not in providers_found:
                                        provider_data_copy = provider_data.copy()
                                        provider_data_copy['evidence'] = f"Organization: {org}"
                                        providers_found[provider_id] = provider_data_copy
                                        logger.info(f"🎯 Found provider via org: {provider_data['name']} ({org})")
        
        except Exception as e:
            logger.error(f"Error analyzing amass log {log_file}: {e}")
        
        return providers_found
    
    def _generate_provider_id(self, name: str) -> str:
        """Genera un ID único para el proveedor"""
        # Convertir a minúsculas, remover caracteres especiales
        provider_id = re.sub(r'[^a-zA-Z0-9]', '_', name.lower())
        provider_id = re.sub(r'_+', '_', provider_id)
        provider_id = provider_id.strip('_')
        return provider_id[:50]  # Limitar longitud
    
    def add_provider_to_neo4j(self, provider_id: str, provider_data: dict):
        """Agrega un proveedor a Neo4j si no existe"""
        
        # Verificar si ya existe
        check_query = "MATCH (p:Provider {id: $provider_id}) RETURN p.name"
        result = self.session.run(check_query, provider_id=provider_id)
        
        if result.single():
            logger.info(f"⚠️ Provider {provider_data['name']} already exists")
            return False
        
        # Crear el proveedor
        create_query = """
        CREATE (p:Provider {
            id: $provider_id,
            name: $name,
            type: $type,
            country: $country,
            evidence: $evidence,
            created_at: $created_at,
            updated_at: $updated_at,
            source: 'amass_discovery',
            aliases: [],
            domains: [],
            ip_ranges: []
        })
        RETURN p.name
        """
        
        self.session.run(create_query,
                        provider_id=provider_id,
                        name=provider_data['name'],
                        type=provider_data['type'],
                        country=provider_data['country'],
                        evidence=provider_data['evidence'],
                        created_at=datetime.now().isoformat(),
                        updated_at=datetime.now().isoformat())
        
        logger.info(f"✅ Added provider: {provider_data['name']} ({provider_id})")
        return True
    
    def process_amass_logs(self, log_files: list):
        """Procesa múltiples archivos de log de amass"""
        all_providers = {}
        
        for log_file in log_files:
            logger.info(f"📄 Processing {log_file}")
            providers = self.analyze_amass_log(log_file)
            all_providers.update(providers)
        
        # Agregar proveedores únicos a Neo4j
        added_count = 0
        for provider_id, provider_data in all_providers.items():
            if self.add_provider_to_neo4j(provider_id, provider_data):
                added_count += 1
        
        logger.info(f"📊 Summary: Found {len(all_providers)} unique providers, added {added_count} new ones")
        return added_count
    
    def get_provider_statistics(self):
        """Obtiene estadísticas actuales de proveedores"""
        query = """
        MATCH (p:Provider)
        RETURN p.type as type, p.country as country, count(*) as count
        ORDER BY count DESC
        """
        
        result = self.session.run(query)
        stats = list(result)
        
        total_query = "MATCH (p:Provider) RETURN count(p) as total"
        total_result = self.session.run(total_query)
        total = total_result.single()['total']
        
        logger.info(f"📈 Current provider statistics (Total: {total}):")
        for stat in stats:
            country = stat['country'] if stat['country'] else 'Global'
            logger.info(f"  {stat['type']} ({country}): {stat['count']}")
        
        return stats, total

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Add providers from amass logs to Neo4j')
    parser.add_argument('--neo4j-uri', default='bolt://localhost:7687', help='Neo4j connection URI')
    parser.add_argument('--neo4j-user', default='neo4j', help='Neo4j username')
    parser.add_argument('--neo4j-password', default='test.password', help='Neo4j password')
    parser.add_argument('--log-file', help='Specific amass log file to process')
    parser.add_argument('--log-dir', default='logs', help='Directory containing amass log files')
    parser.add_argument('--stats-only', action='store_true', help='Only show current statistics')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("AMASS PROVIDER DISCOVERY")
    print("=" * 60)
    print(f"Neo4j URI: {args.neo4j_uri}")
    print("=" * 60)
    
    try:
        with AmassProviderAdder(args.neo4j_uri, args.neo4j_user, args.neo4j_password) as adder:
            
            # Show current statistics
            stats, total = adder.get_provider_statistics()
            
            if args.stats_only:
                return
            
            # Process log files
            log_files = []
            if args.log_file:
                log_files = [args.log_file]
            else:
                import glob
                import os
                if os.path.exists(args.log_dir):
                    log_files = glob.glob(f"{args.log_dir}/amass_*.log")
                
                if not log_files:
                    logger.warning(f"No amass log files found in {args.log_dir}")
                    return
            
            # Process the files
            added_count = adder.process_amass_logs(log_files)
            
            # Show final statistics
            final_stats, final_total = adder.get_provider_statistics()
            
            print("\n" + "=" * 60)
            print("PROVIDER DISCOVERY COMPLETED")
            print("=" * 60)
            print(f"✅ Log files processed: {len(log_files)}")
            print(f"🆕 New providers added: {added_count}")
            print(f"📊 Total providers now: {final_total}")
            print("=" * 60)
            
    except Exception as e:
        logger.error(f"❌ Provider discovery failed: {e}")
        raise

if __name__ == "__main__":
    main()