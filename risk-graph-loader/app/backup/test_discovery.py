#!/usr/bin/env python3

"""
Test script to verify subdomain discovery is working properly
"""

import sqlite3
import sys
from pathlib import Path

# Add the app directory to the path
sys.path.insert(0, str(Path(__file__).parent))

from risk_loader_advanced3 import SQLiteQueueManager, run_amass_local

def test_subdomain_discovery():
    """Test that subdomain discovery and SQLite recording works"""
    
    # Initialize queue manager
    db_path = "test_discovery.db"
    if Path(db_path).exists():
        Path(db_path).unlink()
    
    queue_manager = SQLiteQueueManager(db_path)
    
    # Test domain
    test_domain = "santander.cl"
    
    print(f"[*] Testing subdomain discovery for {test_domain}")
    
    # Run Amass to get results
    try:
        amass_results = run_amass_local(test_domain, sample_mode=True)
        print(f"[*] Amass found {len(amass_results)} entries")
        
        # Process results and add to database
        subdomain_count = 0
        for entry in amass_results:
            name = entry.get("name")
            if name and name != test_domain:
                # Record the discovered domain
                queue_manager.add_discovered_domain(test_domain, name, 'amass')
                subdomain_count += 1
                print(f"[+] Discovered: {name}")
        
        # Check database statistics
        stats = queue_manager.get_queue_stats()
        print(f"\n[*] Database stats: {stats}")
        
        # Verify some entries were recorded
        with sqlite3.connect(db_path) as conn:
            cursor = conn.execute("SELECT * FROM discovered_domains LIMIT 10")
            print(f"\n[*] Sample discovered domains:")
            for row in cursor.fetchall():
                print(f"    {row[1]} -> {row[2]} (via {row[3]})")
        
        print(f"\n[✓] Test completed. Found {subdomain_count} subdomains")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        return False
    
    finally:
        # Cleanup
        if Path(db_path).exists():
            Path(db_path).unlink()
    
    return True

if __name__ == "__main__":
    test_subdomain_discovery()