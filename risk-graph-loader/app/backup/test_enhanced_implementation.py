#!/usr/bin/env python3
"""
test_enhanced_implementation.py - Test script for enhanced domain processing

This script tests the new enhanced implementation with proper TLD/subdomain distinction.
"""

import sys
import os
from datetime import datetime
import tempfile

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from risk_loader_improved import EnhancedGraphIngester, DomainInfo, process_domain_enhanced

def test_domain_info_parsing():
    """Test the DomainInfo.from_fqdn method."""
    print("Testing DomainInfo parsing...")
    
    test_cases = [
        ("bci.cl", True, "bci", "cl", ""),
        ("www.bci.cl", False, "bci", "cl", "www"),
        ("api.bci.cl", False, "bci", "cl", "api"),
        ("mail.api.bci.cl", False, "bci", "cl", "mail.api"),
        ("google.com", True, "google", "com", ""),
        ("docs.google.com", False, "google", "com", "docs"),
        ("subdomain.example.co.uk", False, "example", "co.uk", "subdomain"),
    ]
    
    for fqdn, expected_is_tld, expected_domain, expected_tld, expected_subdomain in test_cases:
        domain_info = DomainInfo.from_fqdn(fqdn)
        
        success = (
            domain_info.is_tld_domain == expected_is_tld and
            domain_info.domain == expected_domain and
            domain_info.tld == expected_tld and
            domain_info.subdomain == expected_subdomain
        )
        
        status = "✓" if success else "✗"
        print(f"  {status} {fqdn}: TLD={domain_info.is_tld_domain}, Domain={domain_info.domain}, TLD={domain_info.tld}, Sub={domain_info.subdomain}")
        
        if not success:
            print(f"    Expected: TLD={expected_is_tld}, Domain={expected_domain}, TLD={expected_tld}, Sub={expected_subdomain}")

def test_graph_creation():
    """Test creating nodes in the graph."""
    print("\nTesting graph creation...")
    
    # Use a test Neo4j instance - adjust connection as needed
    try:
        ingester = EnhancedGraphIngester(
            "bolt://localhost:7687", 
            "neo4j", 
            "test"  # Adjust password as needed
        )
        
        # Test domains
        test_domains = [
            "bci.cl",
            "www.bci.cl",
            "api.bci.cl",
            "mail.api.bci.cl"
        ]
        
        print("  Creating test domains...")
        for domain in test_domains:
            try:
                domain_info = ingester.merge_tld_domain_subdomain(domain)
                print(f"    ✓ Created: {domain} (TLD domain: {domain_info.is_tld_domain})")
            except Exception as e:
                print(f"    ✗ Failed to create {domain}: {e}")
        
        # Test querying stale nodes
        print("  Testing stale node queries...")
        stale_analysis = ingester.get_nodes_needing_analysis(0)  # Get all nodes
        print(f"    Found {len(stale_analysis)} nodes needing analysis")
        
        stale_risk = ingester.get_nodes_needing_risk_scoring(0)  # Get all nodes
        print(f"    Found {len(stale_risk)} nodes needing risk scoring")
        
        ingester.close()
        
    except Exception as e:
        print(f"  ✗ Graph test failed: {e}")
        print("  Make sure Neo4j is running and credentials are correct")

def test_stale_node_discovery():
    """Test the stale node discovery system."""
    print("\nTesting stale node discovery...")
    
    try:
        from update_stale_nodes import StaleNodeUpdater
        
        updater = StaleNodeUpdater(
            "bolt://localhost:7687",
            "neo4j", 
            "test"  # Adjust password as needed
        )
        
        # Test statistics
        print("  Getting graph statistics...")
        updater.show_statistics()
        
        # Test finding stale nodes
        print("  Testing stale node discovery...")
        stale_analysis = updater.find_stale_analysis_nodes(7)
        print(f"    Found {len(stale_analysis)} nodes needing analysis")
        
        stale_risk = updater.find_stale_risk_scoring_nodes(7)
        print(f"    Found {len(stale_risk)} nodes needing risk scoring")
        
        no_providers = updater.get_domains_without_providers()
        print(f"    Found {len(no_providers)} nodes without providers")
        
        updater.close()
        
    except Exception as e:
        print(f"  ✗ Stale node discovery test failed: {e}")

def test_migration_script():
    """Test the migration script."""
    print("\nTesting migration script...")
    
    try:
        from migrate_to_enhanced_model import GraphMigrator
        
        migrator = GraphMigrator(
            "bolt://localhost:7687",
            "neo4j",
            "test"  # Adjust password as needed
        )
        
        # Test validation only
        print("  Running migration validation...")
        migrator.validate_migration()
        
        migrator.close()
        
    except Exception as e:
        print(f"  ✗ Migration test failed: {e}")

def test_process_domain_enhanced():
    """Test the enhanced domain processing function."""
    print("\nTesting enhanced domain processing...")
    
    try:
        ingester = EnhancedGraphIngester(
            "bolt://localhost:7687",
            "neo4j",
            "test"  # Adjust password as needed
        )
        
        # Test with a simple domain
        test_domain = "example.com"
        print(f"  Processing domain: {test_domain}")
        
        stats = process_domain_enhanced(test_domain, 1, ingester, 2)
        print(f"    Stats: {stats}")
        
        # Verify the domain was created properly
        domain_info = DomainInfo.from_fqdn(test_domain)
        print(f"    Domain type: {'TLD domain' if domain_info.is_tld_domain else 'Subdomain'}")
        
        ingester.close()
        
    except Exception as e:
        print(f"  ✗ Enhanced processing test failed: {e}")

def test_api_integration():
    """Test API integration with new endpoints."""
    print("\nTesting API integration...")
    
    try:
        import requests
        import json
        
        # Test the new endpoints (assuming API is running on localhost:8000)
        base_url = "http://localhost:8000"
        
        # Test migration endpoint
        migration_payload = {
            "validate_only": True,
            "bolt": "bolt://localhost:7687",
            "user": "neo4j",
            "password": "test"
        }
        
        response = requests.post(f"{base_url}/tasks/migration", json=migration_payload)
        if response.status_code == 200:
            task_id = response.json()["task_id"]
            print(f"    ✓ Migration task created: {task_id}")
        else:
            print(f"    ✗ Migration task failed: {response.status_code}")
        
        # Test stale update endpoint
        stale_payload = {
            "analysis_days": 7,
            "risk_days": 7,
            "stats_only": True,
            "bolt": "bolt://localhost:7687",
            "user": "neo4j",
            "password": "test"
        }
        
        response = requests.post(f"{base_url}/tasks/stale-update", json=stale_payload)
        if response.status_code == 200:
            task_id = response.json()["task_id"]
            print(f"    ✓ Stale update task created: {task_id}")
        else:
            print(f"    ✗ Stale update task failed: {response.status_code}")
            
    except Exception as e:
        print(f"  ✗ API integration test failed: {e}")
        print("  Make sure the API is running on localhost:8000")

def main():
    """Run all tests."""
    print("Enhanced Implementation Test Suite")
    print("=" * 50)
    
    # Run tests
    test_domain_info_parsing()
    test_graph_creation()
    test_stale_node_discovery()
    test_migration_script()
    test_process_domain_enhanced()
    test_api_integration()
    
    print("\n" + "=" * 50)
    print("Test suite completed!")
    print("\nNext steps:")
    print("1. Run migration: python3 migrate_to_enhanced_model.py --password YOUR_PASSWORD")
    print("2. Test with domains: python3 risk_loader_improved.py --domains test_domains.txt --password YOUR_PASSWORD")
    print("3. Update stale nodes: python3 update_stale_nodes.py --password YOUR_PASSWORD")
    print("4. Use API endpoints for automated operations")

if __name__ == "__main__":
    main()