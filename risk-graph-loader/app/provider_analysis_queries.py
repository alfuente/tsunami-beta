#!/usr/bin/env python3
"""
provider_analysis_queries.py - Create queries for provider dependency analysis

This script creates advanced queries to analyze technology provider dependencies
and industry exposure for financial institutions.
"""

import neo4j
from neo4j import GraphDatabase
import json
from datetime import datetime

class ProviderAnalyzer:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        
    def close(self):
        self.driver.close()
    
    def analyze_fsi_provider_dependencies(self):
        """Analyze provider dependencies for Financial Services Industry domains"""
        print("🏦 FSI Provider Dependency Analysis")
        print("=" * 50)
        
        with self.driver.session() as session:
            query = """
                MATCH (d:Domain)
                WHERE d.fqdn ENDS WITH '.cl' AND 
                      (d.fqdn CONTAINS 'banco' OR d.fqdn CONTAINS 'bci' OR 
                       d.fqdn CONTAINS 'santander' OR d.fqdn CONTAINS 'itau')
                
                OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                OPTIONAL MATCH (d)-[:RESOLVES_TO]->(dip:IPAddress)-[:HOSTED_BY]->(dp:Provider)
                OPTIONAL MATCH (s)-[:RESOLVES_TO]->(sip:IPAddress)-[:HOSTED_BY]->(sp:Provider)
                
                WITH d.fqdn as financial_institution, 
                     1 + count(DISTINCT s) as total_subdomains,
                     collect(DISTINCT dp) + collect(DISTINCT sp) as all_providers
                
                UNWIND all_providers as provider
                WITH financial_institution, total_subdomains, provider
                WHERE provider IS NOT NULL
                
                WITH financial_institution, total_subdomains, provider,
                     count(*) as provider_usage_count
                
                RETURN financial_institution, total_subdomains,
                       provider.name as provider_name,
                       provider.industry as provider_industry,
                       provider.country as provider_country,
                       provider_usage_count
                ORDER BY financial_institution, provider_usage_count DESC
            """
            
            result = session.run(query)
            
            current_institution = None
            for record in result:
                institution = record['financial_institution']
                if institution != current_institution:
                    print(f"\\n🏦 {institution}")
                    print(f"   Total subdomains: {record['total_subdomains']}")
                    current_institution = institution
                
                print(f"   📡 {record['provider_name']} ({record['provider_industry']}, {record['provider_country']}) - {record['provider_usage_count']} usages")
    
    def analyze_foreign_dependency_risk(self):
        """Analyze foreign technology dependency risk"""
        print("\\n\\n🌍 Foreign Technology Dependency Risk Analysis")
        print("=" * 50)
        
        with self.driver.session() as session:
            query = """
                MATCH (d:Domain)
                WHERE d.fqdn ENDS WITH '.cl' AND 
                      (d.fqdn CONTAINS 'banco' OR d.fqdn CONTAINS 'bci' OR 
                       d.fqdn CONTAINS 'santander' OR d.fqdn CONTAINS 'itau')
                
                OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                OPTIONAL MATCH (d)-[:RESOLVES_TO]->(dip:IPAddress)-[:HOSTED_BY]->(dp:Provider)
                OPTIONAL MATCH (s)-[:RESOLVES_TO]->(sip:IPAddress)-[:HOSTED_BY]->(sp:Provider)
                
                WITH d.fqdn as financial_institution,
                     1 + count(DISTINCT s) as total_subdomains,
                     collect(DISTINCT dp) + collect(DISTINCT sp) as all_providers
                
                WITH financial_institution, total_subdomains, all_providers,
                     [p in all_providers WHERE p IS NOT NULL AND p.country <> 'Chile'] as foreign_providers,
                     [p in all_providers WHERE p IS NOT NULL AND p.country = 'Chile'] as domestic_providers
                
                WITH financial_institution, total_subdomains,
                     size(foreign_providers) as foreign_provider_count,
                     size(domestic_providers) as domestic_provider_count,
                     size(all_providers) as total_provider_count,
                     foreign_providers, domestic_providers
                
                RETURN financial_institution, total_subdomains,
                       foreign_provider_count, domestic_provider_count, total_provider_count,
                       CASE WHEN total_provider_count > 0 
                            THEN round(100.0 * foreign_provider_count / total_provider_count, 1)
                            ELSE 0 END as foreign_dependency_percentage,
                       [p in foreign_providers | p.name + ' (' + p.country + ')'] as foreign_provider_list,
                       [p in domestic_providers | p.name + ' (' + p.country + ')'] as domestic_provider_list
                ORDER BY foreign_dependency_percentage DESC, total_subdomains DESC
            """
            
            result = session.run(query)
            
            for record in result:
                institution = record['financial_institution']
                foreign_pct = record['foreign_dependency_percentage']
                
                print(f"\\n🏦 {institution}")
                print(f"   Total subdomains: {record['total_subdomains']}")
                print(f"   Foreign dependency: {foreign_pct}% ({record['foreign_provider_count']}/{record['total_provider_count']} providers)")
                
                if record['foreign_provider_list']:
                    print(f"   🌍 Foreign providers: {', '.join(record['foreign_provider_list'])}")
                if record['domestic_provider_list']:
                    print(f"   🇨🇱 Domestic providers: {', '.join(record['domestic_provider_list'])}")
    
    def analyze_critical_provider_concentrations(self):
        """Analyze critical provider concentrations"""
        print("\\n\\n⚠️ Critical Provider Concentration Analysis")
        print("=" * 50)
        
        with self.driver.session() as session:
            query = """
                // Find providers that host multiple financial institutions
                MATCH (p:Provider)<-[:HOSTED_BY]-(ip:IPAddress)<-[:RESOLVES_TO]-(n)
                WHERE n:Domain OR n:Subdomain
                AND ((n:Domain AND n.fqdn ENDS WITH '.cl' AND 
                      (n.fqdn CONTAINS 'banco' OR n.fqdn CONTAINS 'bci' OR 
                       n.fqdn CONTAINS 'santander' OR n.fqdn CONTAINS 'itau')) OR
                     (n:Subdomain AND EXISTS {
                         MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(n)
                         WHERE d.fqdn ENDS WITH '.cl' AND 
                               (d.fqdn CONTAINS 'banco' OR d.fqdn CONTAINS 'bci' OR 
                                d.fqdn CONTAINS 'santander' OR d.fqdn CONTAINS 'itau')
                     }))
                
                // Get the root domain for subdomains
                OPTIONAL MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(n:Subdomain)
                WITH p, 
                     CASE WHEN n:Domain THEN n.fqdn 
                          ELSE d.fqdn END as financial_institution,
                     count(DISTINCT n) as nodes_hosted
                
                WITH p, 
                     collect(DISTINCT financial_institution) as institutions,
                     sum(nodes_hosted) as total_nodes_hosted
                
                WHERE size(institutions) > 1  // Providers hosting multiple institutions
                
                RETURN p.name as provider_name,
                       p.industry as provider_industry,
                       p.country as provider_country,
                       size(institutions) as institutions_count,
                       total_nodes_hosted,
                       institutions
                ORDER BY institutions_count DESC, total_nodes_hosted DESC
            """
            
            result = session.run(query)
            
            for record in result:
                provider = record['provider_name']
                institutions = record['institutions']
                
                print(f"\\n⚠️ {provider} ({record['provider_industry']}, {record['provider_country']})")
                print(f"   Hosts {record['institutions_count']} financial institutions")
                print(f"   Total nodes hosted: {record['total_nodes_hosted']}")
                print(f"   Institutions: {', '.join(institutions)}")
                
                concentration_risk = "HIGH" if record['institutions_count'] >= 3 else "MEDIUM"
                print(f"   🚨 Concentration Risk: {concentration_risk}")
    
    def analyze_industry_exposure(self):
        """Analyze exposure to different technology industries"""
        print("\\n\\n🏭 Industry Exposure Analysis")
        print("=" * 50)
        
        with self.driver.session() as session:
            query = """
                MATCH (p:Provider)<-[:HOSTED_BY]-(ip:IPAddress)<-[:RESOLVES_TO]-(n)
                WHERE n:Domain OR n:Subdomain
                AND ((n:Domain AND n.fqdn ENDS WITH '.cl' AND 
                      (n.fqdn CONTAINS 'banco' OR n.fqdn CONTAINS 'bci' OR 
                       n.fqdn CONTAINS 'santander' OR n.fqdn CONTAINS 'itau')) OR
                     (n:Subdomain AND EXISTS {
                         MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(n)
                         WHERE d.fqdn ENDS WITH '.cl' AND 
                               (d.fqdn CONTAINS 'banco' OR d.fqdn CONTAINS 'bci' OR 
                                d.fqdn CONTAINS 'santander' OR d.fqdn CONTAINS 'itau')
                     }))
                
                RETURN p.industry as technology_industry,
                       count(DISTINCT p) as provider_count,
                       count(DISTINCT n) as total_nodes,
                       collect(DISTINCT p.name) as providers_in_industry
                ORDER BY total_nodes DESC
            """
            
            result = session.run(query)
            
            for record in result:
                industry = record['technology_industry']
                providers = record['providers_in_industry']
                
                print(f"\\n🏭 {industry}")
                print(f"   Providers: {record['provider_count']} ({', '.join(providers)})")
                print(f"   Total nodes served: {record['total_nodes']}")
                
                if record['total_nodes'] > 20:
                    print(f"   📊 Exposure Level: HIGH")
                elif record['total_nodes'] > 10:
                    print(f"   📊 Exposure Level: MEDIUM")
                else:
                    print(f"   📊 Exposure Level: LOW")
    
    def generate_executive_summary(self):
        """Generate executive summary of technology dependencies"""
        print("\\n\\n📋 EXECUTIVE SUMMARY: Chilean FSI Technology Dependencies")
        print("=" * 70)
        
        with self.driver.session() as session:
            # Total overview
            overview_query = """
                MATCH (d:Domain)
                WHERE d.fqdn ENDS WITH '.cl' AND 
                      (d.fqdn CONTAINS 'banco' OR d.fqdn CONTAINS 'bci' OR 
                       d.fqdn CONTAINS 'santander' OR d.fqdn CONTAINS 'itau')
                
                OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                OPTIONAL MATCH (d)-[:RESOLVES_TO]->(dip:IPAddress)-[:HOSTED_BY]->(dp:Provider)
                OPTIONAL MATCH (s)-[:RESOLVES_TO]->(sip:IPAddress)-[:HOSTED_BY]->(sp:Provider)
                
                WITH collect(DISTINCT d) as institutions,
                     collect(DISTINCT s) as subdomains,
                     collect(DISTINCT dp) + collect(DISTINCT sp) as all_providers
                
                UNWIND all_providers as provider
                WITH financial_institution, total_subdomains, provider
                WHERE provider IS NOT NULL
                
                RETURN size(institutions) as total_institutions,
                       size(subdomains) as total_subdomains,
                       count(DISTINCT provider) as total_providers,
                       size([p in collect(DISTINCT provider) WHERE p.country <> 'Chile']) as foreign_providers,
                       collect(DISTINCT provider.industry) as industries_involved
            """
            
            result = session.run(overview_query).single()
            
            print("\\n📊 OVERVIEW:")
            print(f"   • Financial Institutions Analyzed: {result['total_institutions']}")
            print(f"   • Total Subdomains: {result['total_subdomains']}")
            print(f"   • Technology Providers: {result['total_providers']}")
            print(f"   • Foreign Providers: {result['foreign_providers']} ({100*result['foreign_providers']/result['total_providers']:.1f}%)")
            print(f"   • Industries Involved: {', '.join(result['industries_involved'])}")
            
            # Risk assessment
            foreign_risk = "HIGH" if result['foreign_providers'] / result['total_providers'] > 0.7 else "MEDIUM"
            print(f"\\n⚠️ RISK ASSESSMENT:")
            print(f"   • Foreign Dependency Risk: {foreign_risk}")
            print(f"   • Industry Concentration: Medium (CDN/Security dominant)")
            print(f"   • Infrastructure Resilience: Requires monitoring")
            
            print(f"\\n💡 RECOMMENDATIONS:")
            print(f"   • Diversify provider portfolio to reduce single points of failure")
            print(f"   • Increase domestic provider usage where possible")
            print(f"   • Monitor critical provider concentrations")
            print(f"   • Implement multi-cloud strategies for critical services")

def main():
    NEO4J_URI = "bolt://localhost:7687"
    NEO4J_USER = "neo4j" 
    NEO4J_PASSWORD = "test.password"
    
    try:
        print("🚀 Starting FSI Provider Dependency Analysis...")
        
        analyzer = ProviderAnalyzer(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
        
        # Run all analyses
        analyzer.analyze_fsi_provider_dependencies()
        analyzer.analyze_foreign_dependency_risk()
        analyzer.analyze_critical_provider_concentrations()
        analyzer.analyze_industry_exposure()
        analyzer.generate_executive_summary()
        
        analyzer.close()
        
        print("\\n✅ Analysis completed successfully!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())