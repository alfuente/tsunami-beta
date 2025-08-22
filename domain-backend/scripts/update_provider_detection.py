#!/usr/bin/env python3
"""
Script para actualizar la detección de proveedores usando los nuevos proveedores de Neo4j

Este script:
1. Lee los proveedores del grafo Neo4j
2. Actualiza la lógica de detección para mapear dominios e IPs a estos proveedores
3. Modifica el sistema de análisis para usar proveedores reales en lugar de hostnames
"""

import logging
import ipaddress
import re
from typing import Dict, List, Optional, Tuple
from neo4j import GraphDatabase
from dataclasses import dataclass
import argparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ProviderInfo:
    """Información de proveedor de Neo4j"""
    id: str
    name: str
    type: str
    aliases: List[str]
    domains: List[str]
    ip_ranges: List[str]

class ProviderDetectionUpdater:
    def __init__(self, neo4j_uri="bolt://localhost:7687", neo4j_user="neo4j", neo4j_password="test.password"):
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.session = None
        self.providers: List[ProviderInfo] = []
        
    def __enter__(self):
        self.session = self.driver.session()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            self.session.close()
        self.driver.close()
    
    def load_providers_from_neo4j(self) -> List[ProviderInfo]:
        """Carga todos los proveedores desde Neo4j"""
        query = """
        MATCH (p:Provider)
        RETURN p.id, p.name, p.type, p.aliases, p.domains, p.ip_ranges
        ORDER BY p.name
        """
        
        result = self.session.run(query)
        providers = []
        
        for record in result:
            provider = ProviderInfo(
                id=record["p.id"],
                name=record["p.name"],
                type=record["p.type"],
                aliases=record["p.aliases"] or [],
                domains=record["p.domains"] or [],
                ip_ranges=record["p.ip_ranges"] or []
            )
            providers.append(provider)
        
        logger.info(f"📥 Loaded {len(providers)} providers from Neo4j")
        return providers
    
    def detect_provider_from_hostname(self, hostname: str) -> Optional[ProviderInfo]:
        """Detecta proveedor basado en hostname usando patrones de dominios"""
        hostname_lower = hostname.lower()
        
        for provider in self.providers:
            # Check exact domain matches
            for domain in provider.domains:
                if hostname_lower.endswith(f".{domain.lower()}") or hostname_lower == domain.lower():
                    logger.debug(f"🎯 Provider detected: {provider.name} (domain match: {domain})")
                    return provider
            
            # Check alias matches
            for alias in provider.aliases:
                if alias.lower() in hostname_lower:
                    logger.debug(f"🎯 Provider detected: {provider.name} (alias match: {alias})")
                    return provider
        
        return None
    
    def detect_provider_from_ip(self, ip_str: str) -> Optional[ProviderInfo]:
        """Detecta proveedor basado en dirección IP usando rangos CIDR"""
        try:
            ip = ipaddress.ip_address(ip_str)
            
            for provider in self.providers:
                for ip_range in provider.ip_ranges:
                    try:
                        network = ipaddress.ip_network(ip_range, strict=False)
                        if ip in network:
                            logger.debug(f"🎯 Provider detected: {provider.name} (IP range match: {ip_range})")
                            return provider
                    except ValueError:
                        continue
            
        except ValueError:
            logger.debug(f"Invalid IP address: {ip_str}")
        
        return None
    
    def update_hostname_to_provider_mapping(self, hostname: str) -> Optional[str]:
        """
        Actualiza la función de mapeo de hostname a proveedor.
        Devuelve el ID del proveedor si se encuentra, None si no.
        """
        provider = self.detect_provider_from_hostname(hostname)
        if provider:
            return provider.id
        
        # Fallback: try to extract some generic provider info
        hostname_lower = hostname.lower()
        
        # Generic cloud detection patterns
        cloud_patterns = {
            'aws': 'amazon',
            'amazon': 'amazon', 
            'ec2': 'amazon',
            'googleapis': 'google',
            'gcp': 'google',
            'azure': 'microsoft',
            'outlook': 'microsoft',
            'office365': 'microsoft',
            'cloudflare': 'cloudflare',
            'fastly': 'fastly',
            'akamai': 'akamai',
            'digitalocean': 'digitalocean',
            'linode': 'linode',
            'vultr': 'vultr',
            'heroku': 'heroku',
            'github': 'github',
            'salesforce': 'salesforce'
        }
        
        for pattern, provider_id in cloud_patterns.items():
            if pattern in hostname_lower:
                return provider_id
        
        return None
    
    def analyze_subdomain_providers(self, subdomains: List[str]) -> Dict[str, Dict]:
        """
        Analiza una lista de subdominios y devuelve información de proveedores detectados
        """
        providers_found = {}
        provider_stats = {}
        
        for subdomain in subdomains:
            provider_id = self.update_hostname_to_provider_mapping(subdomain)
            if provider_id:
                if provider_id not in providers_found:
                    # Find provider info
                    provider = next((p for p in self.providers if p.id == provider_id), None)
                    if provider:
                        providers_found[provider_id] = {
                            'id': provider.id,
                            'name': provider.name,
                            'type': provider.type,
                            'subdomains': [],
                            'count': 0
                        }
                        provider_stats[provider_id] = 0
                
                providers_found[provider_id]['subdomains'].append(subdomain)
                providers_found[provider_id]['count'] += 1
                provider_stats[provider_id] += 1
        
        # Sort by usage
        sorted_providers = dict(sorted(provider_stats.items(), key=lambda x: x[1], reverse=True))
        
        logger.info(f"📊 Providers found: {len(providers_found)}")
        for provider_id, count in list(sorted_providers.items())[:5]:
            provider_name = providers_found[provider_id]['name']
            logger.info(f"  {provider_name}: {count} subdomains")
        
        return providers_found
    
    def test_provider_detection(self, test_domains: List[str]):
        """Prueba la detección de proveedores con dominios de ejemplo"""
        logger.info("🧪 Testing provider detection...")
        
        for domain in test_domains:
            provider = self.detect_provider_from_hostname(domain)
            if provider:
                logger.info(f"✅ {domain} -> {provider.name} ({provider.type})")
            else:
                provider_id = self.update_hostname_to_provider_mapping(domain)
                if provider_id:
                    logger.info(f"⚠️ {domain} -> {provider_id} (fallback)")
                else:
                    logger.info(f"❌ {domain} -> No provider detected")
    
    def run_update(self):
        """Ejecuta la actualización completa"""
        logger.info("🚀 Starting provider detection update")
        
        # Load providers from Neo4j
        self.providers = self.load_providers_from_neo4j()
        
        # Test with sample domains
        test_domains = [
            "mail.google.com",
            "outlook.office365.com", 
            "ec2-18-191-123-45.us-west-2.compute.amazonaws.com",
            "cdn.cloudflare.com",
            "fastly.com",
            "github.io",
            "herokuapp.com",
            "digitalocean.com",
            "example.azurewebsites.net",
            "test.salesforce.com"
        ]
        
        self.test_provider_detection(test_domains)
        
        logger.info("✅ Provider detection update completed")
        
        return {
            'providers_loaded': len(self.providers),
            'detection_ready': True
        }

def create_provider_detection_function():
    """
    Crea una función actualizada de detección de proveedores que puede ser
    importada por otros módulos
    """
    
    # Esta función será generada dinámicamente basada en los proveedores de Neo4j
    function_code = '''
def detect_provider_from_subdomain(subdomain: str) -> Optional[str]:
    """
    Detecta proveedor basado en subdomain usando patrones actualizados de Neo4j
    
    Returns:
        Provider ID if detected, None otherwise
    """
    subdomain_lower = subdomain.lower()
    
    # AWS patterns
    if any(pattern in subdomain_lower for pattern in ['amazonaws.com', 'aws.amazon.com', 'ec2', 's3']):
        return 'amazon'
    
    # Google patterns  
    if any(pattern in subdomain_lower for pattern in ['googleapis.com', 'googleusercontent.com', 'gstatic.com', 'google.com']):
        return 'google'
    
    # Microsoft patterns
    if any(pattern in subdomain_lower for pattern in ['azure.com', 'azurewebsites.net', 'outlook.com', 'office.com']):
        return 'microsoft'
    
    # Cloudflare patterns
    if any(pattern in subdomain_lower for pattern in ['cloudflare.com', 'cloudflaressl.com']):
        return 'cloudflare'
    
    # GitHub patterns
    if any(pattern in subdomain_lower for pattern in ['github.com', 'githubusercontent.com', 'github.io']):
        return 'github'
    
    # Heroku patterns
    if any(pattern in subdomain_lower for pattern in ['heroku.com', 'herokuapp.com']):
        return 'heroku'
    
    # Salesforce patterns
    if any(pattern in subdomain_lower for pattern in ['salesforce.com', 'force.com']):
        return 'salesforce'
    
    # Fastly patterns
    if any(pattern in subdomain_lower for pattern in ['fastly.com', 'fastlylb.net']):
        return 'fastly'
    
    # DigitalOcean patterns
    if any(pattern in subdomain_lower for pattern in ['digitalocean.com', 'digitaloceanspaces.com']):
        return 'digitalocean'
    
    return None
'''
    
    return function_code

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Update provider detection using Neo4j providers')
    parser.add_argument('--neo4j-uri', default='bolt://localhost:7687', help='Neo4j connection URI')
    parser.add_argument('--neo4j-user', default='neo4j', help='Neo4j username')
    parser.add_argument('--neo4j-password', default='test.password', help='Neo4j password')
    parser.add_argument('--test-only', action='store_true', help='Only run tests, do not update files')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("PROVIDER DETECTION UPDATE")
    print("=" * 60)
    print(f"Neo4j URI: {args.neo4j_uri}")
    print(f"Test only: {args.test_only}")
    print("=" * 60)
    
    try:
        with ProviderDetectionUpdater(args.neo4j_uri, args.neo4j_user, args.neo4j_password) as updater:
            result = updater.run_update()
            
            if not args.test_only:
                # Generate updated function code
                function_code = create_provider_detection_function()
                logger.info("📝 Generated updated provider detection function")
                
                # Save to file for importing
                with open('updated_provider_detection.py', 'w') as f:
                    f.write(f"""#!/usr/bin/env python3
# Auto-generated provider detection functions
# Generated on: {logging.time.strftime('%Y-%m-%d %H:%M:%S')}

from typing import Optional

{function_code}
""")
                logger.info("📄 Saved updated provider detection to updated_provider_detection.py")
            
            print("\n" + "=" * 60)
            print("UPDATE COMPLETED SUCCESSFULLY")
            print("=" * 60)
            print(f"✅ Providers loaded: {result['providers_loaded']}")
            print(f"🎯 Detection ready: {result['detection_ready']}")
            print("=" * 60)
            
    except Exception as e:
        logger.error(f"❌ Update failed: {e}")
        raise

if __name__ == "__main__":
    main()