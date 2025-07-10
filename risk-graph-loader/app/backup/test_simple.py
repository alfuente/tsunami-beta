#!/usr/bin/env python3

"""
Simple test to verify subdomain discovery is working
"""

import sqlite3
import subprocess
import tempfile
import json
from pathlib import Path
from datetime import datetime

# SQLite database configuration
DB_PATH = "test_simple.db"
DB_TIMEOUT = 30.0

def run_amass_local(domain: str, sample_mode: bool = True):
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
            subprocess.run(cmd, check=True, stdout=None, stderr=None)
            return parse_amass_output(out)
        except subprocess.CalledProcessError as e:
            print(f"[!] Amass error: {e}")
            return []

def parse_amass_output(output_path: Path):
    """Parse Amass output and return list of domains."""
    domains = set()
    entries = []
    
    with output_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line or "The enumeration has finished" in line:
                continue
            
            # Simple domain extraction
            if " --> " not in line and "." in line and not line.startswith("["):
                if line.count(".") >= 1:
                    domains.add(line)
                    entries.append({"name": line})
    
    print(f"[DEBUG] Found {len(entries)} domains: {list(domains)[:5]}...")
    return entries

def init_database():
    """Initialize SQLite database."""
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        
        # Discovered domains table
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

def add_discovered_domain(parent_domain: str, discovered_domain: str, method: str = 'amass'):
    """Record a discovered domain."""
    try:
        with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
            now = datetime.now().isoformat()
            result = conn.execute("""
                INSERT OR IGNORE INTO discovered_domains 
                (parent_domain, discovered_domain, discovery_method, created_at)
                VALUES (?, ?, ?, ?)
            """, (parent_domain, discovered_domain, method, now))
            conn.commit()
            changes = conn.total_changes
            print(f"[DB] Recorded: {parent_domain} -> {discovered_domain} (changes: {changes})")
            return changes > 0
    except sqlite3.Error as e:
        print(f"[!] Database error: {e}")
        return False

def test_discovery():
    """Test subdomain discovery."""
    # Clean up
    if Path(DB_PATH).exists():
        Path(DB_PATH).unlink()
    
    # Initialize database
    init_database()
    
    # Test domain
    test_domain = "google.com"
    print(f"[*] Testing discovery for {test_domain}")
    
    # Run Amass
    amass_results = run_amass_local(test_domain, sample_mode=True)
    print(f"[*] Amass returned {len(amass_results)} results")
    
    # Process results
    subdomain_count = 0
    for entry in amass_results:
        name = entry.get("name")
        if name and name != test_domain:
            print(f"[+] Processing subdomain: {name}")
            success = add_discovered_domain(test_domain, name, 'amass')
            if success:
                subdomain_count += 1
    
    # Check database
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("SELECT COUNT(*) FROM discovered_domains")
        total = cursor.fetchone()[0]
        print(f"[*] Database shows {total} discovered domains")
        
        cursor = conn.execute("SELECT * FROM discovered_domains LIMIT 5")
        print("[*] Sample entries:")
        for row in cursor.fetchall():
            print(f"    {row[1]} -> {row[2]}")
    
    print(f"[✓] Test completed. Processed {subdomain_count} subdomains")

if __name__ == "__main__":
    test_discovery()