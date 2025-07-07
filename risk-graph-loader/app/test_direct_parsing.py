#!/usr/bin/env python3

"""
Direct test of parsing and database insertion
"""

import sqlite3
from pathlib import Path
from datetime import datetime

def parse_amass_output(output_path: Path) -> list:
    """Parse Amass output and extract subdomain relationships."""
    entries = []
    
    with output_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            
            print(f"Processing: {line}")
            
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
                        print(f"  ✓ Found subdomain: {source_clean} -> {target_clean}")
                        entries.append({
                            "name": target_clean,
                            "parent": source_clean
                        })
    
    return entries

def init_database(db_path: str):
    """Initialize test database."""
    with sqlite3.connect(db_path) as conn:
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

def add_discovered_domain(db_path: str, parent_domain: str, discovered_domain: str, method: str = 'amass') -> bool:
    """Record a discovered domain."""
    try:
        with sqlite3.connect(db_path) as conn:
            now = datetime.now().isoformat()
            cursor = conn.execute("""
                INSERT OR IGNORE INTO discovered_domains 
                (parent_domain, discovered_domain, discovery_method, created_at)
                VALUES (?, ?, ?, ?)
            """, (parent_domain, discovered_domain, method, now))
            conn.commit()
            changes = conn.total_changes
            if changes > 0:
                print(f"  ✓ Recorded in DB: {parent_domain} -> {discovered_domain}")
            else:
                print(f"  - Already in DB: {parent_domain} -> {discovered_domain}")
            return changes > 0
    except sqlite3.Error as e:
        print(f"  ✗ Database error: {e}")
        return False

def test_direct_parsing():
    """Test direct parsing and database insertion."""
    
    # Setup
    test_file = Path("sample_santander_output.txt")
    db_path = "test_direct.db"
    
    # Clean up
    if Path(db_path).exists():
        Path(db_path).unlink()
    
    # Initialize database
    init_database(db_path)
    
    print("=== TESTING DIRECT PARSING ===")
    
    # Parse file
    print(f"\\n1. Parsing {test_file}...")
    entries = parse_amass_output(test_file)
    print(f"Found {len(entries)} subdomain entries")
    
    # Insert into database
    print(f"\\n2. Inserting into database...")
    inserted_count = 0
    for entry in entries:
        name = entry.get("name")
        parent = entry.get("parent")
        if name and parent:
            success = add_discovered_domain(db_path, parent, name, 'amass')
            if success:
                inserted_count += 1
    
    # Check database
    print(f"\\n3. Checking database...")
    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute("SELECT COUNT(*) FROM discovered_domains")
        total = cursor.fetchone()[0]
        print(f"Database contains {total} records")
        
        cursor = conn.execute("SELECT * FROM discovered_domains")
        print("All records:")
        for row in cursor.fetchall():
            print(f"  {row[1]} -> {row[2]} (via {row[3]})")
    
    print(f"\\n=== RESULTS ===")
    print(f"Parsed entries: {len(entries)}")
    print(f"Inserted records: {inserted_count}")
    print(f"Database records: {total}")
    
    # Cleanup
    if Path(db_path).exists():
        Path(db_path).unlink()

if __name__ == "__main__":
    test_direct_parsing()