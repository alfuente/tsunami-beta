#!/usr/bin/env python3

"""
Discovery-only version that tests subdomain discovery without Neo4j
"""

import argparse
import subprocess
import tempfile
import sqlite3
import threading
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict

# Simple Amass runner
def run_amass_local(domain: str, sample_mode: bool = True) -> List[dict]:
    """Run Amass locally and return parsed results."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.txt"
        cmd = ["amass", "enum", "-v", "-d", domain, "-o", str(out)]
        
        if sample_mode:
            cmd.extend(["-timeout", "5"])
            print(f"[AMASS LOCAL SAMPLE] {domain}")
        else:
            print(f"[AMASS LOCAL] {domain}")
            
        try:
            result = subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            print(f"[AMASS] Completed for {domain}")
            return parse_amass_output(out)
        except subprocess.CalledProcessError as e:
            print(f"[!] Amass error for {domain}: {e}")
            return []
        except subprocess.TimeoutExpired as e:
            print(f"[!] Amass timeout for {domain}: {e}")
            return []

def parse_amass_output(output_path: Path) -> List[dict]:
    """Parse Amass output and extract subdomain relationships."""
    entries = []
    domains = set()
    
    total_lines = 0
    
    with output_path.open() as fh:
        for line in fh:
            total_lines += 1
            line = line.strip()
            if not line or "The enumeration has finished" in line or "DNS wildcard detected:" in line:
                continue
            
            # Look for node relationships (subdomain discovery)
            if " --> " in line and " node " in line:
                parts = line.split(" --> ")
                if len(parts) == 3:
                    source, relation, target = parts
                    
                    # Extract clean names
                    if " (" in source:
                        source_clean = source.split(" (")[0].strip()
                    else:
                        source_clean = source.strip()
                    
                    if " (" in target:
                        target_clean = target.split(" (")[0].strip()
                    else:
                        target_clean = target.strip()
                    
                    if relation.strip() == "node":
                        print(f"[DISCOVERED] {source_clean} -> {target_clean}")
                        entries.append({
                            "name": target_clean,
                            "parent": source_clean
                        })
                        domains.add(source_clean)
                        domains.add(target_clean)
    
    print(f"[PARSE] Processed {total_lines} lines, found {len(entries)} subdomain relationships")
    return entries

# Simple SQLite manager
class SimpleQueueManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS discovered_domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    parent_domain TEXT NOT NULL,
                    discovered_domain TEXT NOT NULL,
                    discovery_method TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(parent_domain, discovered_domain)
                )
            """)
            conn.commit()
    
    def add_discovered_domain(self, parent_domain: str, discovered_domain: str, method: str = 'amass') -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                now = datetime.now().isoformat()
                cursor = conn.execute("""
                    INSERT OR IGNORE INTO discovered_domains 
                    (parent_domain, discovered_domain, discovery_method, created_at)
                    VALUES (?, ?, ?, ?)
                """, (parent_domain, discovered_domain, method, now))
                conn.commit()
                changes = conn.total_changes
                if changes > 0:
                    print(f"[DB] ✓ Recorded: {parent_domain} -> {discovered_domain}")
                else:
                    print(f"[DB] - Already exists: {parent_domain} -> {discovered_domain}")
                return changes > 0
        except sqlite3.Error as e:
            print(f"[!] Database error: {e}")
            return False
    
    def get_stats(self) -> dict:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM discovered_domains")
                total = cursor.fetchone()[0]
                
                cursor = conn.execute("SELECT COUNT(DISTINCT discovered_domain) FROM discovered_domains")
                unique = cursor.fetchone()[0]
                
                return {'total_discovered': total, 'unique_discovered': unique}
        except sqlite3.Error as e:
            print(f"[!] Error getting stats: {e}")
            return {}

def process_domain(domain: str, queue_manager: SimpleQueueManager, sample_mode: bool = True):
    """Process a single domain for subdomain discovery."""
    print(f"\\n[*] Processing domain: {domain}")
    
    # Run Amass
    amass_results = run_amass_local(domain, sample_mode)
    print(f"[*] Amass returned {len(amass_results)} results")
    
    # Process results
    subdomain_count = 0
    for entry in amass_results:
        name = entry.get("name")
        parent = entry.get("parent", domain)
        
        if name and name != domain:
            success = queue_manager.add_discovered_domain(parent, name, 'amass')
            if success:
                subdomain_count += 1
    
    print(f"[*] Recorded {subdomain_count} new subdomains")
    
    # Show stats
    stats = queue_manager.get_stats()
    print(f"[*] Total database stats: {stats}")

def main():
    parser = argparse.ArgumentParser(description="Test subdomain discovery without Neo4j")
    parser.add_argument("--domains", required=True, help="File with seed domains")
    parser.add_argument("--sample", action="store_true", help="Use sample mode (faster)")
    args = parser.parse_args()
    
    # Initialize database
    db_path = "discovery_test.db"
    if Path(db_path).exists():
        Path(db_path).unlink()
    
    queue_manager = SimpleQueueManager(db_path)
    
    # Load domains
    seeds = [d.strip() for d in Path(args.domains).read_text().splitlines() if d.strip()]
    print(f"[*] Loaded {len(seeds)} seed domains")
    
    # Process each domain
    for domain in seeds:
        try:
            process_domain(domain, queue_manager, args.sample)
        except Exception as e:
            print(f"[!] Error processing {domain}: {e}")
    
    # Final stats
    final_stats = queue_manager.get_stats()
    print(f"\\n[FINAL] Discovery completed: {final_stats}")
    
    # Show sample results
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.execute("SELECT * FROM discovered_domains LIMIT 10")
            print("\\n[SAMPLE] Discovered domains:")
            for row in cursor.fetchall():
                print(f"  {row[1]} -> {row[2]}")
    except Exception as e:
        print(f"[!] Error showing results: {e}")

if __name__ == "__main__":
    main()