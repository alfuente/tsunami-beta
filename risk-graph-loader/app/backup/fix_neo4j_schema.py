#!/usr/bin/env python3
"""
fix_neo4j_schema.py - Fix Neo4j schema and populate test data

This script:
1. Fixes the Neo4j schema for proper domain/subdomain relationships
2. Creates technology providers with industry classification
3. Populates test data with realistic subdomain discovery
4. Creates proper service and provider relationships
"""

import neo4j
from neo4j import GraphDatabase
import json
from datetime import datetime
import subprocess
import socket
import ssl
import random

class Neo4jSchemaFixer:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        
    def close(self):
        self.driver.close()
    
    def fix_schema(self):
        """Fix and improve the Neo4j schema"""
        print("🔧 Fixing Neo4j schema...")
        
        with self.driver.session() as session:
            # Clear any existing constraints that might conflict
            try:
                session.run("DROP CONSTRAINT tld_name IF EXISTS")
                session.run("DROP CONSTRAINT domain_fqdn IF EXISTS") 
                session.run("DROP CONSTRAINT subdomain_fqdn IF EXISTS")
                session.run("DROP CONSTRAINT ip_address IF EXISTS")
                session.run("DROP CONSTRAINT service_name IF EXISTS")
                session.run("DROP CONSTRAINT provider_name IF EXISTS")
            except Exception as e:
                print(f"⚠️  Some constraints didn't exist: {e}")
            
            # Create improved constraints
            constraints = [
                "CREATE CONSTRAINT tld_name IF NOT EXISTS FOR (t:TLD) REQUIRE t.name IS UNIQUE",
                "CREATE CONSTRAINT domain_fqdn IF NOT EXISTS FOR (d:Domain) REQUIRE d.fqdn IS UNIQUE",
                "CREATE CONSTRAINT subdomain_fqdn IF NOT EXISTS FOR (s:Subdomain) REQUIRE s.fqdn IS UNIQUE", 
                "CREATE CONSTRAINT ip_address IF NOT EXISTS FOR (ip:IPAddress) REQUIRE ip.address IS UNIQUE",
                "CREATE CONSTRAINT service_name IF NOT EXISTS FOR (svc:Service) REQUIRE svc.name IS UNIQUE",
                "CREATE CONSTRAINT provider_name IF NOT EXISTS FOR (p:Provider) REQUIRE p.name IS UNIQUE"
            ]
            
            for constraint in constraints:
                try:
                    session.run(constraint)
                    print(f"✅ Created constraint: {constraint.split('FOR')[1].split('REQUIRE')[0].strip()}")
                except Exception as e:
                    print(f"⚠️  Constraint creation failed: {e}")
    
    def create_technology_providers(self):
        """Create technology provider nodes with industry classification"""
        print("🏭 Creating technology providers...")
        
        providers = [
            # Cloud Providers
            {
                "name": "Amazon Web Services",
                "short_name": "AWS", 
                "industry": "Cloud Computing",
                "category": "Infrastructure",
                "country": "United States",
                "services": ["EC2", "CloudFront", "Route 53", "S3", "ELB"]
            },
            {
                "name": "Cloudflare",
                "short_name": "Cloudflare",
                "industry": "CDN/Security", 
                "category": "Infrastructure",
                "country": "United States",
                "services": ["CDN", "DNS", "DDoS Protection", "WAF"]
            },
            {
                "name": "Akamai Technologies", 
                "short_name": "Akamai",
                "industry": "CDN/Security",
                "category": "Infrastructure", 
                "country": "United States",
                "services": ["CDN", "Security", "DNS", "Performance"]
            },
            {
                "name": "Google Cloud Platform",
                "short_name": "GCP",
                "industry": "Cloud Computing",
                "category": "Infrastructure",
                "country": "United States", 
                "services": ["Compute Engine", "Cloud CDN", "Cloud DNS"]
            },
            {
                "name": "Microsoft Azure",
                "short_name": "Azure", 
                "industry": "Cloud Computing",
                "category": "Infrastructure",
                "country": "United States",
                "services": ["Virtual Machines", "CDN", "DNS", "Load Balancer"]
            },
            # Local Chilean providers
            {
                "name": "VTR Banda Ancha",
                "short_name": "VTR",
                "industry": "Telecommunications",
                "category": "ISP",
                "country": "Chile",
                "services": ["Internet", "Hosting", "DNS"]
            },
            {
                "name": "Telefónica Chile",
                "short_name": "Movistar",
                "industry": "Telecommunications", 
                "category": "ISP",
                "country": "Chile",
                "services": ["Internet", "Hosting", "DNS"]
            },
            {
                "name": "GTD Manquehue",
                "short_name": "GTD",
                "industry": "Telecommunications",
                "category": "ISP", 
                "country": "Chile",
                "services": ["Internet", "Data Center", "Cloud"]
            }
        ]
        
        with self.driver.session() as session:
            for provider in providers:
                session.run("""
                    MERGE (p:Provider {name: $name})
                    SET p.short_name = $short_name,
                        p.industry = $industry,
                        p.category = $category,
                        p.country = $country,
                        p.services = $services,
                        p.last_updated = $timestamp
                    RETURN p
                """, **provider, timestamp=datetime.now().isoformat())
                
                # Create service nodes for each provider
                for service_name in provider["services"]:
                    session.run("""
                        MERGE (s:Service {name: $service_name})
                        SET s.provider = $provider_name,
                            s.category = $category,
                            s.last_updated = $timestamp
                        WITH s
                        MATCH (p:Provider {name: $provider_name})
                        MERGE (p)-[:PROVIDES_SERVICE]->(s)
                    """, service_name=service_name, provider_name=provider["name"], 
                         category=provider["category"], timestamp=datetime.now().isoformat())
        
        print(f"✅ Created {len(providers)} technology providers")
    
    def discover_real_subdomains(self, domain):
        """Discover real subdomains using simple DNS and common patterns"""
        print(f"🔍 Discovering subdomains for {domain}...")
        
        # Common subdomain patterns for financial institutions
        common_subdomains = [
            "www", "portal", "api", "app", "mobile", "m", "secure", "login", 
            "auth", "admin", "mail", "webmail", "ftp", "cdn", "static",
            "images", "assets", "media", "blog", "news", "help", "support",
            "dev", "test", "staging", "uat", "demo", "sandbox"
        ]
        
        discovered = []
        
        for subdomain in common_subdomains:
            fqdn = f"{subdomain}.{domain}"
            try:
                # Try to resolve the subdomain
                socket.gethostbyname(fqdn)
                discovered.append(fqdn)
                print(f"  ✅ Found: {fqdn}")
            except socket.gaierror:
                # Subdomain doesn't exist
                pass
        
        return discovered
    
    def create_realistic_test_data(self):
        """Create realistic test data with proper relationships"""
        print("📊 Creating realistic test data...")
        
        # Chilean FSI domains
        base_domains = [
            "bci.cl", "santander.cl", "bancoestado.cl", "bancochile.cl", "itau.cl",
            "scotiabank.cl", "bancointernacional.cl", "bancoconsorcio.cl", 
            "bancofalabella.cl", "bancoripley.cl"
        ]
        
        current_time = datetime.now().isoformat()
        
        with self.driver.session() as session:
            for domain in base_domains:
                print(f"\\n🏦 Processing {domain}...")
                
                # Extract domain parts
                parts = domain.split('.')
                domain_name = parts[0]
                tld = '.'.join(parts[1:])
                
                # Create TLD
                session.run("""
                    MERGE (tld:TLD {name: $tld})
                    SET tld.last_updated = $timestamp
                """, tld=tld, timestamp=current_time)
                
                # Create Domain
                session.run("""
                    MERGE (d:Domain {fqdn: $fqdn})
                    SET d.domain_name = $domain_name,
                        d.tld = $tld,
                        d.last_analyzed = $timestamp,
                        d.risk_score = $risk_score,
                        d.risk_tier = $risk_tier,
                        d.business_criticality = 'High',
                        d.monitoring_enabled = true,
                        d.last_risk_scoring = $timestamp
                """, fqdn=domain, domain_name=domain_name, tld=tld, 
                     timestamp=current_time, risk_score=random.uniform(60, 85),
                     risk_tier=random.choice(['High', 'Critical']))
                
                # Create TLD -> Domain relationship
                session.run("""
                    MATCH (tld:TLD {name: $tld})
                    MATCH (d:Domain {fqdn: $fqdn})
                    MERGE (tld)-[:CONTAINS_DOMAIN]->(d)
                """, tld=tld, fqdn=domain)
                
                # Discover and create subdomains
                subdomains = self.discover_real_subdomains(domain)
                
                # If no real subdomains found, create some common ones
                if not subdomains:
                    common_subs = ["www", "portal", "api", "app", "secure"]
                    subdomains = [f"{sub}.{domain}" for sub in common_subs]
                    print(f"  📝 Creating simulated subdomains: {subdomains}")
                
                for subdomain_fqdn in subdomains[:10]:  # Limit to 10 subdomains
                    subdomain_name = subdomain_fqdn.split('.')[0]
                    
                    # Create Subdomain
                    session.run("""
                        MERGE (s:Subdomain {fqdn: $fqdn})
                        SET s.subdomain_name = $subdomain_name,
                            s.domain_name = $domain_name,
                            s.tld = $tld,
                            s.last_analyzed = $timestamp,
                            s.risk_score = $risk_score,
                            s.risk_tier = $risk_tier,
                            s.business_criticality = 'Medium',
                            s.last_risk_scoring = $timestamp
                    """, fqdn=subdomain_fqdn, subdomain_name=subdomain_name,
                         domain_name=domain_name, tld=tld, timestamp=current_time,
                         risk_score=random.uniform(30, 70), 
                         risk_tier=random.choice(['Low', 'Medium', 'High']))
                    
                    # Create Domain -> Subdomain relationship
                    session.run("""
                        MATCH (d:Domain {fqdn: $domain_fqdn})
                        MATCH (s:Subdomain {fqdn: $subdomain_fqdn})
                        MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                    """, domain_fqdn=domain, subdomain_fqdn=subdomain_fqdn)
                    
                    # Create IP addresses and provider relationships
                    self.create_ip_and_provider_relationships(subdomain_fqdn, session)
    
    def create_ip_and_provider_relationships(self, fqdn, session):
        """Create IP addresses and provider relationships for a domain/subdomain"""
        
        # Try to get real IP
        try:
            real_ip = socket.gethostbyname(fqdn)
        except:
            # Generate a realistic IP if we can't resolve
            real_ip = f"104.{random.randint(16,31)}.{random.randint(1,254)}.{random.randint(1,254)}"
        
        # Determine provider based on IP range (simplified)
        provider_name = self.detect_provider_by_ip(real_ip)
        
        current_time = datetime.now().isoformat()
        
        # Create IP node
        session.run("""
            MERGE (ip:IPAddress {address: $ip})
            SET ip.provider_detected = $provider,
                ip.last_updated = $timestamp
        """, ip=real_ip, provider=provider_name, timestamp=current_time)
        
        # Create domain/subdomain -> IP relationship
        session.run("""
            MATCH (n {fqdn: $fqdn})
            MATCH (ip:IPAddress {address: $ip})
            WHERE n:Domain OR n:Subdomain
            MERGE (n)-[:RESOLVES_TO]->(ip)
        """, fqdn=fqdn, ip=real_ip)
        
        # Create IP -> Provider relationship if provider exists
        if provider_name != "Unknown":
            session.run("""
                MATCH (ip:IPAddress {address: $ip})
                MATCH (p:Provider {name: $provider_name})
                MERGE (ip)-[:HOSTED_BY]->(p)
            """, ip=real_ip, provider_name=provider_name)
            
            # Create domain/subdomain -> Service relationships
            services = self.get_services_for_provider(provider_name)
            for service_name in services[:3]:  # Limit to 3 services
                session.run("""
                    MATCH (n {fqdn: $fqdn})
                    MATCH (s:Service {name: $service_name})
                    WHERE n:Domain OR n:Subdomain
                    MERGE (n)-[:RUNS]->(s)
                """, fqdn=fqdn, service_name=service_name)
    
    def detect_provider_by_ip(self, ip):
        """Simple provider detection based on IP ranges"""
        if ip.startswith("104.16.") or ip.startswith("104.17."):
            return "Cloudflare"
        elif ip.startswith("52.") or ip.startswith("54.") or ip.startswith("3."):
            return "Amazon Web Services"
        elif ip.startswith("104.18.") or ip.startswith("104.19."):
            return "Cloudflare"
        elif ip.startswith("23."):
            return "Akamai Technologies"
        elif ip.startswith("35."):
            return "Google Cloud Platform"
        elif ip.startswith("200."):
            return "VTR Banda Ancha"
        else:
            return "Unknown"
    
    def get_services_for_provider(self, provider_name):
        """Get services for a given provider"""
        service_map = {
            "Cloudflare": ["CDN", "DNS", "DDoS Protection"],
            "Amazon Web Services": ["EC2", "CloudFront", "Route 53"],
            "Akamai Technologies": ["CDN", "Security", "DNS"],
            "Google Cloud Platform": ["Compute Engine", "Cloud CDN", "Cloud DNS"],
            "Microsoft Azure": ["Virtual Machines", "CDN", "DNS"],
            "VTR Banda Ancha": ["Internet", "Hosting", "DNS"],
            "Telefónica Chile": ["Internet", "Hosting", "DNS"],
            "GTD Manquehue": ["Internet", "Data Center", "Cloud"]
        }
        return service_map.get(provider_name, ["Web Hosting"])
    
    def verify_data(self):
        """Verify the created data structure"""
        print("\\n🔍 Verifying data structure...")
        
        with self.driver.session() as session:
            # Count nodes
            result = session.run("""
                MATCH (n) 
                RETURN labels(n)[0] as label, count(n) as count 
                ORDER BY count DESC
            """)
            
            print("\\n📊 Node counts:")
            for record in result:
                print(f"  {record['label']}: {record['count']}")
            
            # Count relationships
            result = session.run("""
                MATCH ()-[r]->() 
                RETURN type(r) as relationship, count(r) as count 
                ORDER BY count DESC
            """)
            
            print("\\n🔗 Relationship counts:")
            for record in result:
                print(f"  {record['relationship']}: {record['count']}")
            
            # Sample base domain details
            result = session.run("""
                MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                MATCH (s)-[:RESOLVES_TO]->(ip:IPAddress)-[:HOSTED_BY]->(p:Provider)
                OPTIONAL MATCH (s)-[:RUNS]->(svc:Service)
                WITH d.fqdn as domain, count(DISTINCT s) as subdomain_count, 
                     count(DISTINCT svc) as service_count, count(DISTINCT p) as provider_count
                RETURN domain, subdomain_count, service_count, provider_count
                LIMIT 5
            """)
            
            print("\\n🏦 Sample base domain statistics:")
            for record in result:
                print(f"  {record['domain']}: {record['subdomain_count']} subdomains, "
                      f"{record['service_count']} services, {record['provider_count']} providers")

def main():
    # Neo4j connection parameters
    NEO4J_URI = "bolt://localhost:7687"
    NEO4J_USER = "neo4j" 
    NEO4J_PASSWORD = "test.password"
    
    try:
        print("🚀 Starting Neo4j schema fix and data population...")
        
        fixer = Neo4jSchemaFixer(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
        
        # Fix schema
        fixer.fix_schema()
        
        # Create technology providers
        fixer.create_technology_providers()
        
        # Create realistic test data
        fixer.create_realistic_test_data()
        
        # Verify data
        fixer.verify_data()
        
        fixer.close()
        
        print("\\n🎉 Neo4j schema fix and data population completed successfully!")
        print("\\nNext steps:")
        print("1. Check the risk-dashboard to see updated subdomain counts")
        print("2. Use the risk recalculation buttons to update risk scores")
        print("3. View base domain details to see proper service/provider relationships")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())