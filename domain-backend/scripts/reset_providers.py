#!/usr/bin/env python3
"""
Script para resetear y recargar proveedores de hosting/cloud en Neo4j

Este script:
1. Limpia todos los nodos Provider existentes
2. Carga una lista curada de proveedores conocidos (AWS, Google, etc.)
3. Mapea rangos IP y dominios a estos proveedores
"""

import logging
import json
from neo4j import GraphDatabase
import argparse
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Comprehensive list of major cloud/hosting providers
KNOWN_PROVIDERS = {
    # Major Cloud Providers
    "amazon": {
        "name": "Amazon Web Services",
        "type": "cloud",
        "aliases": ["aws", "amazon", "ec2", "s3"],
        "domains": ["amazonaws.com", "aws.amazon.com", "ec2.amazonaws.com"],
        "ip_ranges": ["54.0.0.0/8", "52.0.0.0/8", "18.0.0.0/8", "3.0.0.0/8"]
    },
    "google": {
        "name": "Google Cloud Platform", 
        "type": "cloud",
        "aliases": ["gcp", "google", "googlecloud"],
        "domains": ["googleapis.com", "googleusercontent.com", "gstatic.com", "google.com"],
        "ip_ranges": ["35.0.0.0/8", "34.0.0.0/8", "104.154.0.0/15", "104.196.0.0/14"]
    },
    "microsoft": {
        "name": "Microsoft Azure",
        "type": "cloud", 
        "aliases": ["azure", "microsoft", "outlook", "office365"],
        "domains": ["azure.com", "azurewebsites.net", "cloudapp.net", "outlook.com", "office.com"],
        "ip_ranges": ["20.0.0.0/8", "40.0.0.0/8", "104.40.0.0/13", "137.116.0.0/14"]
    },
    "cloudflare": {
        "name": "Cloudflare",
        "type": "cdn",
        "aliases": ["cloudflare", "cf"],
        "domains": ["cloudflare.com", "cloudflaressl.com"],
        "ip_ranges": ["103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/12"]
    },
    "fastly": {
        "name": "Fastly",
        "type": "cdn",
        "aliases": ["fastly"],
        "domains": ["fastly.com", "fastlylb.net"],
        "ip_ranges": ["23.235.32.0/20", "104.156.80.0/20", "151.101.0.0/16"]
    },
    "akamai": {
        "name": "Akamai Technologies",
        "type": "cdn",
        "aliases": ["akamai"],
        "domains": ["akamai.com", "akamaitechnologies.com", "akamaiedge.net"],
        "ip_ranges": ["23.0.0.0/12", "96.6.0.0/15", "184.24.0.0/13"]
    },
    "digitalocean": {
        "name": "DigitalOcean",
        "type": "cloud",
        "aliases": ["digitalocean", "do"],
        "domains": ["digitalocean.com", "digitaloceanspaces.com"],
        "ip_ranges": ["159.65.0.0/16", "167.99.0.0/16", "138.197.0.0/16", "165.227.0.0/16"]
    },
    "linode": {
        "name": "Linode",
        "type": "cloud",
        "aliases": ["linode"],
        "domains": ["linode.com", "linodeobjects.com"],
        "ip_ranges": ["172.104.0.0/15", "139.162.0.0/16", "45.79.0.0/16"]
    },
    "vultr": {
        "name": "Vultr",
        "type": "cloud",
        "aliases": ["vultr"],
        "domains": ["vultr.com"],
        "ip_ranges": ["149.28.0.0/16", "207.148.0.0/16", "108.61.0.0/16"]
    },
    "salesforce": {
        "name": "Salesforce",
        "type": "saas",
        "aliases": ["salesforce", "sfdc"],
        "domains": ["salesforce.com", "force.com", "my.salesforce.com"],
        "ip_ranges": ["136.146.0.0/16", "182.50.76.0/22", "13.110.0.0/14"]
    },
    "github": {
        "name": "GitHub",
        "type": "saas",
        "aliases": ["github"],
        "domains": ["github.com", "githubusercontent.com", "github.io"],
        "ip_ranges": ["140.82.112.0/20", "185.199.108.0/22", "192.30.252.0/22"]
    },
    "heroku": {
        "name": "Heroku",
        "type": "paas",
        "aliases": ["heroku"],
        "domains": ["heroku.com", "herokuapp.com", "herokudns.com"],
        "ip_ranges": ["50.16.0.0/15", "107.21.0.0/16", "174.129.0.0/16"]
    },
    "rackspace": {
        "name": "Rackspace",
        "type": "cloud",
        "aliases": ["rackspace"],
        "domains": ["rackspace.com", "rackspacecloud.com"],
        "ip_ranges": ["162.242.0.0/16", "166.78.0.0/16", "72.32.0.0/16"]
    },
    "ovh": {
        "name": "OVH",
        "type": "hosting",
        "aliases": ["ovh", "ovhcloud"],
        "domains": ["ovh.com", "ovhcloud.com", "ovh.net"],
        "ip_ranges": ["51.210.0.0/16", "54.36.0.0/16", "137.74.0.0/16"]
    },
    "hetzner": {
        "name": "Hetzner",
        "type": "hosting",
        "aliases": ["hetzner"],
        "domains": ["hetzner.com", "hetzner.de"],
        "ip_ranges": ["5.9.0.0/16", "138.201.0.0/16", "144.76.0.0/16"]
    },
    "godaddy": {
        "name": "GoDaddy",
        "type": "hosting",
        "aliases": ["godaddy"],
        "domains": ["godaddy.com", "secureserver.net"],
        "ip_ranges": ["68.178.0.0/16", "97.74.0.0/16", "184.168.0.0/16"]
    },
    "namecheap": {
        "name": "Namecheap",
        "type": "hosting",
        "aliases": ["namecheap"],
        "domains": ["namecheap.com", "registrar-servers.com"],
        "ip_ranges": ["198.54.112.0/21", "198.199.64.0/18"]
    }
}

class ProviderResetManager:
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
    
    def clear_existing_providers(self):
        """Remove all existing Provider nodes and relationships"""
        logger.info("🗑️ Clearing existing Provider nodes...")
        
        # First, get count of existing providers
        count_query = "MATCH (p:Provider) RETURN count(p) as total"
        result = self.session.run(count_query)
        total_providers = result.single()["total"]
        
        if total_providers == 0:
            logger.info("No existing providers found")
            return
            
        logger.info(f"Found {total_providers} existing providers to remove")
        
        # Remove relationships first, then nodes
        delete_rels_query = """
        MATCH (p:Provider)-[r]-()
        DELETE r
        """
        
        delete_nodes_query = """
        MATCH (p:Provider)
        DELETE p
        """
        
        self.session.run(delete_rels_query)
        logger.info("✅ Removed all Provider relationships")
        
        self.session.run(delete_nodes_query)  
        logger.info("✅ Removed all Provider nodes")
    
    def create_provider_node(self, provider_id, provider_data):
        """Create a single provider node with all its metadata"""
        query = """
        CREATE (p:Provider {
            id: $provider_id,
            name: $name,
            type: $type,
            aliases: $aliases,
            domains: $domains,
            ip_ranges: $ip_ranges,
            created_at: $created_at,
            updated_at: $updated_at
        })
        RETURN p
        """
        
        params = {
            "provider_id": provider_id,
            "name": provider_data["name"],
            "type": provider_data["type"],
            "aliases": provider_data["aliases"],
            "domains": provider_data["domains"],
            "ip_ranges": provider_data.get("ip_ranges", []),
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        result = self.session.run(query, params)
        logger.info(f"✅ Created provider: {provider_data['name']} ({provider_id})")
        return result.single()
    
    def load_all_providers(self):
        """Load all known providers into Neo4j"""
        logger.info(f"📥 Loading {len(KNOWN_PROVIDERS)} providers...")
        
        created_count = 0
        for provider_id, provider_data in KNOWN_PROVIDERS.items():
            try:
                self.create_provider_node(provider_id, provider_data)
                created_count += 1
            except Exception as e:
                logger.error(f"❌ Failed to create provider {provider_id}: {e}")
        
        logger.info(f"✅ Successfully created {created_count}/{len(KNOWN_PROVIDERS)} providers")
        return created_count
    
    def create_provider_indexes(self):
        """Create indexes for efficient provider lookups"""
        indexes = [
            "CREATE INDEX provider_id_index IF NOT EXISTS FOR (p:Provider) ON (p.id)",
            "CREATE INDEX provider_name_index IF NOT EXISTS FOR (p:Provider) ON (p.name)",
            "CREATE INDEX provider_type_index IF NOT EXISTS FOR (p:Provider) ON (p.type)"
        ]
        
        for index_query in indexes:
            try:
                self.session.run(index_query)
                logger.info(f"✅ Created index: {index_query.split()[-1]}")
            except Exception as e:
                logger.warning(f"⚠️ Index creation warning: {e}")
    
    def verify_providers(self):
        """Verify the loaded providers"""
        query = """
        MATCH (p:Provider)
        RETURN p.name, p.type, p.id
        ORDER BY p.type, p.name
        """
        
        result = self.session.run(query)
        providers = list(result)
        
        logger.info(f"📊 Verification: {len(providers)} providers loaded")
        
        # Group by type
        by_type = {}
        for provider in providers:
            ptype = provider["p.type"]
            if ptype not in by_type:
                by_type[ptype] = []
            by_type[ptype].append(provider["p.name"])
        
        for ptype, names in by_type.items():
            logger.info(f"  {ptype}: {len(names)} providers")
            for name in names[:5]:  # Show first 5
                logger.info(f"    - {name}")
            if len(names) > 5:
                logger.info(f"    ... and {len(names) - 5} more")
        
        return providers
    
    def reset_and_reload(self):
        """Complete reset and reload process"""
        logger.info("🚀 Starting provider reset and reload process")
        
        # Step 1: Clear existing
        self.clear_existing_providers()
        
        # Step 2: Create indexes
        self.create_provider_indexes()
        
        # Step 3: Load new providers
        created_count = self.load_all_providers()
        
        # Step 4: Verify
        providers = self.verify_providers()
        
        logger.info("✅ Provider reset and reload completed successfully")
        return {
            "cleared": True,
            "created_count": created_count,
            "total_providers": len(providers),
            "providers_by_type": {}
        }

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Reset and reload cloud/hosting providers in Neo4j')
    parser.add_argument('--neo4j-uri', default='bolt://localhost:7687', help='Neo4j connection URI')
    parser.add_argument('--neo4j-user', default='neo4j', help='Neo4j username')
    parser.add_argument('--neo4j-password', default='test.password', help='Neo4j password')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without executing')
    
    args = parser.parse_args()
    
    if args.dry_run:
        print("🔍 DRY RUN - Providers that would be loaded:")
        for provider_id, provider_data in KNOWN_PROVIDERS.items():
            print(f"  {provider_data['name']} ({provider_data['type']}) - {provider_id}")
        print(f"\nTotal: {len(KNOWN_PROVIDERS)} providers")
        return
    
    print("=" * 60)
    print("PROVIDER RESET AND RELOAD")
    print("=" * 60)
    print(f"Neo4j URI: {args.neo4j_uri}")
    print(f"Neo4j User: {args.neo4j_user}")
    print(f"Providers to load: {len(KNOWN_PROVIDERS)}")
    print("=" * 60)
    
    try:
        with ProviderResetManager(args.neo4j_uri, args.neo4j_user, args.neo4j_password) as manager:
            result = manager.reset_and_reload()
            
            print("\n" + "=" * 60)
            print("RESET COMPLETED SUCCESSFULLY")
            print("=" * 60)
            print(f"✅ Created {result['created_count']} providers")
            print(f"📊 Total providers in database: {result['total_providers']}")
            print("=" * 60)
            
    except Exception as e:
        logger.error(f"❌ Reset failed: {e}")
        raise

if __name__ == "__main__":
    main()