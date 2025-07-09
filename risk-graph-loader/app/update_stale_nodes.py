#!/usr/bin/env python3
"""
update_stale_nodes.py - Update stale nodes based on graph queries

This script replaces the SQLite queue system with graph-based node discovery.
It finds nodes that haven't been analyzed or risk-scored recently and updates them.
"""

import argparse
from datetime import datetime, timedelta
from neo4j import GraphDatabase
from typing import List, Dict
import sys
import os

# Add the current directory to Python path to import from risk_loader_improved
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from risk_loader_improved import EnhancedGraphIngester, process_domain_enhanced

class StaleNodeUpdater:
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str, ipinfo_token: str = None):
        self.ingester = EnhancedGraphIngester(neo4j_uri, neo4j_user, neo4j_pass, ipinfo_token)
    
    def find_stale_analysis_nodes(self, days_old: int = 7) -> List[Dict]:
        """Find nodes that haven't been analyzed recently."""
        print(f"Finding nodes not analyzed in {days_old} days...")
        
        nodes = self.ingester.get_nodes_needing_analysis(days_old)
        print(f"Found {len(nodes)} nodes needing analysis")
        
        return nodes
    
    def find_stale_risk_scoring_nodes(self, days_old: int = 7) -> List[Dict]:
        """Find nodes that haven't had risk scoring recently."""
        print(f"Finding nodes not risk-scored in {days_old} days...")
        
        nodes = self.ingester.get_nodes_needing_risk_scoring(days_old)
        print(f"Found {len(nodes)} nodes needing risk scoring")
        
        return nodes
    
    def update_analysis_for_nodes(self, nodes: List[Dict], depth: int = 2, max_depth: int = 4):
        """Update analysis for a list of nodes."""
        print(f"Updating analysis for {len(nodes)} nodes...")
        
        for i, node in enumerate(nodes):
            fqdn = node['fqdn']
            node_type = node['node_type']
            
            print(f"[{i+1}/{len(nodes)}] Processing {node_type}: {fqdn}")
            
            try:
                # Process the domain/subdomain
                stats = process_domain_enhanced(fqdn, depth, self.ingester, max_depth)
                
                print(f"  ✓ Stats: {stats}")
                
            except Exception as e:
                print(f"  ✗ Error processing {fqdn}: {e}")
    
    def update_risk_scoring_for_nodes(self, nodes: List[Dict]):
        """Update risk scoring timestamps for nodes."""
        print(f"Updating risk scoring for {len(nodes)} nodes...")
        
        for i, node in enumerate(nodes):
            fqdn = node['fqdn']
            node_type = node['node_type']
            
            print(f"[{i+1}/{len(nodes)}] Updating risk scoring for {node_type}: {fqdn}")
            
            try:
                # Update risk scoring timestamp
                self.ingester.update_risk_scoring_timestamp(fqdn, node_type)
                
                # Here you would typically also recalculate risk scores
                # For now, we just update the timestamp
                print(f"  ✓ Risk scoring timestamp updated")
                
            except Exception as e:
                print(f"  ✗ Error updating risk scoring for {fqdn}: {e}")
    
    def get_domains_without_providers(self) -> List[Dict]:
        """Find domains/subdomains that don't have provider information."""
        print("Finding domains without provider information...")
        
        with self.ingester.drv.session() as s:
            result = s.run("""
                MATCH (n)
                WHERE (n:Domain OR n:Subdomain)
                AND NOT EXISTS((n)-[:RESOLVES_TO]->(:IPAddress)-[:HOSTED_BY]->(:Service))
                RETURN labels(n)[0] as node_type, n.fqdn as fqdn
                ORDER BY n.fqdn
                LIMIT 100
            """)
            
            nodes = [dict(record) for record in result]
            print(f"Found {len(nodes)} domains/subdomains without provider info")
            return nodes
    
    def ensure_provider_discovery(self, nodes: List[Dict], max_depth: int = 4):
        """Ensure provider discovery for domains/subdomains."""
        print(f"Ensuring provider discovery for {len(nodes)} nodes...")
        
        for i, node in enumerate(nodes):
            fqdn = node['fqdn']
            node_type = node['node_type']
            
            print(f"[{i+1}/{len(nodes)}] Ensuring providers for {node_type}: {fqdn}")
            
            try:
                # Process with higher depth to ensure provider discovery
                stats = process_domain_enhanced(fqdn, max_depth, self.ingester, max_depth)
                
                # Check if we now have provider information
                has_providers = self.ingester.ensure_provider_discovery_depth(fqdn, max_depth)
                
                if has_providers:
                    print(f"  ✓ Provider discovery successful")
                else:
                    print(f"  ! Still no providers found for {fqdn}")
                
            except Exception as e:
                print(f"  ✗ Error ensuring providers for {fqdn}: {e}")
    
    def run_maintenance_cycle(self, analysis_days: int = 7, risk_days: int = 7, 
                            depth: int = 2, max_depth: int = 4):
        """Run a complete maintenance cycle."""
        print("Starting maintenance cycle...")
        
        # 1. Update stale analysis nodes
        stale_analysis = self.find_stale_analysis_nodes(analysis_days)
        if stale_analysis:
            self.update_analysis_for_nodes(stale_analysis, depth, max_depth)
        
        # 2. Update stale risk scoring nodes
        stale_risk = self.find_stale_risk_scoring_nodes(risk_days)
        if stale_risk:
            self.update_risk_scoring_for_nodes(stale_risk)
        
        # 3. Ensure provider discovery for nodes without providers
        no_providers = self.get_domains_without_providers()
        if no_providers:
            self.ensure_provider_discovery(no_providers, max_depth)
        
        print("✓ Maintenance cycle completed")
    
    def show_statistics(self):
        """Show current graph statistics."""
        print("Current graph statistics:")
        
        with self.ingester.drv.session() as s:
            # Basic counts
            stats = {}
            
            stats['tlds'] = s.run("MATCH (t:TLD) RETURN COUNT(t) as count").single()['count']
            stats['domains'] = s.run("MATCH (d:Domain) RETURN COUNT(d) as count").single()['count']
            stats['subdomains'] = s.run("MATCH (s:Subdomain) RETURN COUNT(s) as count").single()['count']
            stats['ips'] = s.run("MATCH (ip:IPAddress) RETURN COUNT(ip) as count").single()['count']
            stats['services'] = s.run("MATCH (svc:Service) RETURN COUNT(svc) as count").single()['count']
            
            # Relationship counts
            stats['domain_subdomain_rels'] = s.run("MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain) RETURN COUNT(*) as count").single()['count']
            stats['resolution_rels'] = s.run("MATCH (n)-[:RESOLVES_TO]->(ip:IPAddress) RETURN COUNT(*) as count").single()['count']
            stats['hosting_rels'] = s.run("MATCH (ip:IPAddress)-[:HOSTED_BY]->(svc:Service) RETURN COUNT(*) as count").single()['count']
            
            # Analysis status
            cutoff_7_days = (datetime.now() - timedelta(days=7)).isoformat()
            stats['stale_analysis'] = s.run("""
                MATCH (n) WHERE (n:Domain OR n:Subdomain) 
                AND (n.last_analyzed IS NULL OR n.last_analyzed < $cutoff)
                RETURN COUNT(n) as count
            """, cutoff=cutoff_7_days).single()['count']
            
            stats['stale_risk'] = s.run("""
                MATCH (n) WHERE (n:Domain OR n:Subdomain) 
                AND (n.last_risk_scoring IS NULL OR n.last_risk_scoring < $cutoff)
                RETURN COUNT(n) as count
            """, cutoff=cutoff_7_days).single()['count']
            
            stats['no_providers'] = s.run("""
                MATCH (n) WHERE (n:Domain OR n:Subdomain)
                AND NOT EXISTS((n)-[:RESOLVES_TO]->(:IPAddress)-[:HOSTED_BY]->(:Service))
                RETURN COUNT(n) as count
            """).single()['count']
            
            # Print statistics
            print(f"  TLDs: {stats['tlds']}")
            print(f"  Domains: {stats['domains']}")
            print(f"  Subdomains: {stats['subdomains']}")
            print(f"  IP Addresses: {stats['ips']}")
            print(f"  Services: {stats['services']}")
            print(f"  Domain -> Subdomain relationships: {stats['domain_subdomain_rels']}")
            print(f"  Resolution relationships: {stats['resolution_rels']}")
            print(f"  Hosting relationships: {stats['hosting_rels']}")
            print(f"  Nodes needing analysis (7 days): {stats['stale_analysis']}")
            print(f"  Nodes needing risk scoring (7 days): {stats['stale_risk']}")
            print(f"  Nodes without providers: {stats['no_providers']}")
    
    def close(self):
        """Close connections."""
        self.ingester.close()

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Update stale nodes in risk graph")
    parser.add_argument("--bolt", default="bolt://localhost:7687", help="Neo4j bolt URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", required=True, help="Neo4j password")
    parser.add_argument("--ipinfo-token", help="IPInfo token")
    parser.add_argument("--analysis-days", type=int, default=7, help="Days before analysis is stale")
    parser.add_argument("--risk-days", type=int, default=7, help="Days before risk scoring is stale")
    parser.add_argument("--depth", type=int, default=2, help="Analysis depth")
    parser.add_argument("--max-depth", type=int, default=4, help="Maximum depth for provider discovery")
    parser.add_argument("--stats-only", action="store_true", help="Only show statistics")
    parser.add_argument("--analysis-only", action="store_true", help="Only update analysis")
    parser.add_argument("--risk-only", action="store_true", help="Only update risk scoring")
    parser.add_argument("--providers-only", action="store_true", help="Only ensure provider discovery")
    
    args = parser.parse_args()
    
    updater = StaleNodeUpdater(args.bolt, args.user, args.password, args.ipinfo_token)
    
    try:
        if args.stats_only:
            updater.show_statistics()
        elif args.analysis_only:
            nodes = updater.find_stale_analysis_nodes(args.analysis_days)
            if nodes:
                updater.update_analysis_for_nodes(nodes, args.depth, args.max_depth)
        elif args.risk_only:
            nodes = updater.find_stale_risk_scoring_nodes(args.risk_days)
            if nodes:
                updater.update_risk_scoring_for_nodes(nodes)
        elif args.providers_only:
            nodes = updater.get_domains_without_providers()
            if nodes:
                updater.ensure_provider_discovery(nodes, args.max_depth)
        else:
            # Run complete maintenance cycle
            updater.run_maintenance_cycle(args.analysis_days, args.risk_days, args.depth, args.max_depth)
            
        # Always show final statistics
        print("\n" + "="*50)
        updater.show_statistics()
        
    finally:
        updater.close()

if __name__ == "__main__":
    main()