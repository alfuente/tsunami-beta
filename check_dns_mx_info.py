#!/usr/bin/env python3
"""
Script para verificar qué información DNS y MX existe en Neo4j para bancochile.cl
"""

from neo4j import GraphDatabase
import json

class DNSMXChecker:
    def __init__(self):
        self.neo4j_driver = GraphDatabase.driver(
            "bolt://localhost:7687", 
            auth=("neo4j", "test.password")
        )
    
    def close(self):
        self.neo4j_driver.close()
    
    def check_domain_dns_mx_info(self, domain):
        """Verifica toda la información DNS y MX disponible para un dominio"""
        with self.neo4j_driver.session() as session:
            # Información básica del dominio
            result = session.run("""
                MATCH (d:Domain {fqdn: $domain})
                RETURN d.fqdn as domain,
                       d.hasSSL as hasSSL,
                       d.tlsVersion as tlsVersion,
                       d.riskScore as riskScore,
                       d.dns_records as dns_records,
                       d.mx_records as mx_records,
                       d.nameservers as nameservers,
                       d.spf_record as spf_record,
                       d.dmarc_record as dmarc_record,
                       d.has_spf as has_spf,
                       d.has_dmarc as has_dmarc,
                       keys(d) as all_properties
            """, domain=domain)
            
            domain_info = None
            for record in result:
                domain_info = dict(record)
                break
            
            if not domain_info:
                print(f"❌ Domain {domain} not found in Neo4j")
                return
            
            print(f"🌐 DOMAIN: {domain}")
            print("=" * 50)
            print(f"Risk Score: {domain_info['riskScore']}")
            print(f"Has SSL: {domain_info['hasSSL']}")
            print(f"TLS Version: {domain_info['tlsVersion']}")
            print()
            
            print("📧 EMAIL CONFIGURATION:")
            print("-" * 30)
            print(f"MX Records: {domain_info['mx_records']}")
            print(f"SPF Record: {domain_info['spf_record']}")
            print(f"DMARC Record: {domain_info['dmarc_record']}")
            print(f"Has SPF: {domain_info['has_spf']}")
            print(f"Has DMARC: {domain_info['has_dmarc']}")
            print()
            
            print("🌍 DNS CONFIGURATION:")
            print("-" * 30)
            print(f"DNS Records: {domain_info['dns_records']}")
            print(f"Nameservers: {domain_info['nameservers']}")
            print()
            
            print("🔧 ALL PROPERTIES:")
            print("-" * 30)
            for prop in sorted(domain_info['all_properties']):
                print(f"  {prop}")
            print()
            
            # Buscar nodos DNS relacionados
            dns_nodes = session.run("""
                MATCH (d:Domain {fqdn: $domain})-[r]->(n)
                WHERE 'DNS' in labels(n) OR 'MX' in labels(n) OR 'Nameserver' in labels(n)
                RETURN labels(n) as node_labels, 
                       type(r) as relationship,
                       n as node_data
                LIMIT 10
            """, domain=domain)
            
            print("🔗 RELATED DNS/MX NODES:")
            print("-" * 30)
            dns_found = False
            for record in dns_nodes:
                dns_found = True
                labels = ', '.join(record['node_labels'])
                print(f"  {labels} --[{record['relationship']}]--> Domain")
                node_data = dict(record['node_data'])
                for key, value in node_data.items():
                    if value is not None:
                        print(f"    {key}: {value}")
                print()
            
            if not dns_found:
                print("  ❌ No DNS/MX nodes found")
                print()
            
            # Buscar información MX específica
            mx_info = session.run("""
                MATCH (d:Domain {fqdn: $domain})
                OPTIONAL MATCH (d)-[:HAS_MX_RECORD]->(mx)
                OPTIONAL MATCH (d)-[:HAS_DNS_RECORD]->(dns)
                RETURN collect(DISTINCT {
                    type: 'MX',
                    data: mx
                }) as mx_records,
                collect(DISTINCT {
                    type: 'DNS', 
                    data: dns
                }) as dns_records
            """, domain=domain)
            
            for record in mx_info:
                mx_records = [r for r in record['mx_records'] if r['data'] is not None]
                dns_records = [r for r in record['dns_records'] if r['data'] is not None]
                
                if mx_records:
                    print("📧 MX RECORD NODES:")
                    print("-" * 30)
                    for mx in mx_records:
                        mx_data = dict(mx['data'])
                        for key, value in mx_data.items():
                            print(f"  {key}: {value}")
                        print()
                
                if dns_records:
                    print("🌍 DNS RECORD NODES:")
                    print("-" * 30)
                    for dns in dns_records:
                        dns_data = dict(dns['data'])
                        for key, value in dns_data.items():
                            print(f"  {key}: {value}")
                        print()
                
                if not mx_records and not dns_records:
                    print("❌ No MX or DNS record nodes found")

def main():
    print("=== DNS & MX Information Checker ===\n")
    
    checker = DNSMXChecker()
    
    try:
        # Verificar bancochile.cl
        checker.check_domain_dns_mx_info("bancochile.cl")
        
        print("\n" + "="*70 + "\n")
        
        # Verificar larrainvial.cl para comparar
        checker.check_domain_dns_mx_info("larrainvial.cl")
        
    finally:
        checker.close()

if __name__ == "__main__":
    main()