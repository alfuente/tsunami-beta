#!/usr/bin/env python3

"""
Mock discovery mode - uses simulated Amass data to test the full pipeline
"""

import argparse
import sqlite3
import threading
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict
import random

# Database configuration
DB_PATH = "mock_discovery.db"
DB_TIMEOUT = 30.0

class DiscoveryManager:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.init_database()
    
    def init_database(self):
        with sqlite3.connect(self.db_path, timeout=DB_TIMEOUT) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS domain_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    depth INTEGER NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending',
                    priority INTEGER NOT NULL DEFAULT 1,
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    max_retries INTEGER NOT NULL DEFAULT 3,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    error_message TEXT,
                    worker_id TEXT,
                    UNIQUE(domain, depth)
                )
            """)
            
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
            
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domain_queue_state ON domain_queue(state)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_discovered_parent ON discovered_domains(parent_domain)")
            conn.commit()
    
    def add_domain(self, domain: str, depth: int, priority: int = 1) -> bool:
        with self.lock:
            try:
                with sqlite3.connect(self.db_path, timeout=DB_TIMEOUT) as conn:
                    now = datetime.now().isoformat()
                    conn.execute("""
                        INSERT OR IGNORE INTO domain_queue 
                        (domain, depth, state, priority, created_at, updated_at)
                        VALUES (?, ?, 'pending', ?, ?, ?)
                    """, (domain, depth, priority, now, now))
                    conn.commit()
                    return conn.total_changes > 0
            except sqlite3.Error as e:
                print(f"[!] Error adding domain {domain}: {e}")
                return False
    
    def get_next_domain(self, worker_id: str):
        with self.lock:
            try:
                with sqlite3.connect(self.db_path, timeout=DB_TIMEOUT) as conn:
                    cursor = conn.execute("""
                        SELECT id, domain, depth FROM domain_queue 
                        WHERE state = 'pending' 
                        ORDER BY priority DESC, created_at ASC
                        LIMIT 1
                    """)
                    
                    row = cursor.fetchone()
                    if not row:
                        return None
                    
                    domain_id, domain, depth = row
                    
                    # Mark as processing
                    now = datetime.now().isoformat()
                    conn.execute("""
                        UPDATE domain_queue 
                        SET state = 'processing', worker_id = ?, updated_at = ?, started_at = ?
                        WHERE id = ?
                    """, (worker_id, now, now, domain_id))
                    conn.commit()
                    
                    return {"domain": domain, "depth": depth}
            except sqlite3.Error as e:
                print(f"[!] Error getting next domain: {e}")
                return None
    
    def mark_completed(self, domain: str, depth: int, worker_id: str, stats: dict = None) -> bool:
        with self.lock:
            try:
                with sqlite3.connect(self.db_path, timeout=DB_TIMEOUT) as conn:
                    now = datetime.now().isoformat()
                    conn.execute("""
                        UPDATE domain_queue 
                        SET state = 'completed', updated_at = ?, completed_at = ?
                        WHERE domain = ? AND depth = ? AND worker_id = ?
                    """, (now, now, domain, depth, worker_id))
                    conn.commit()
                    return conn.total_changes > 0
            except sqlite3.Error as e:
                print(f"[!] Error marking domain {domain} as completed: {e}")
                return False
    
    def mark_error(self, domain: str, depth: int, worker_id: str, error_message: str) -> bool:
        with self.lock:
            try:
                with sqlite3.connect(self.db_path, timeout=DB_TIMEOUT) as conn:
                    now = datetime.now().isoformat()
                    conn.execute("""
                        UPDATE domain_queue 
                        SET state = 'error', updated_at = ?, error_message = ?, worker_id = NULL
                        WHERE domain = ? AND depth = ? AND worker_id = ?
                    """, (now, error_message, domain, depth, worker_id))
                    conn.commit()
                    return conn.total_changes > 0
            except sqlite3.Error as e:
                print(f"[!] Error marking domain {domain} as error: {e}")
                return False
    
    def add_discovered_domain(self, parent_domain: str, discovered_domain: str, method: str = 'amass') -> bool:
        try:
            with sqlite3.connect(self.db_path, timeout=DB_TIMEOUT) as conn:
                now = datetime.now().isoformat()
                cursor = conn.execute("""
                    INSERT OR IGNORE INTO discovered_domains 
                    (parent_domain, discovered_domain, discovery_method, created_at)
                    VALUES (?, ?, ?, ?)
                """, (parent_domain, discovered_domain, method, now))
                conn.commit()
                changes = conn.total_changes
                return changes > 0
        except sqlite3.Error as e:
            print(f"[!] Error recording discovered domain: {e}")
            return False
    
    def get_stats(self) -> dict:
        try:
            with sqlite3.connect(self.db_path, timeout=DB_TIMEOUT) as conn:
                cursor = conn.execute("""
                    SELECT state, COUNT(*) as count 
                    FROM domain_queue 
                    GROUP BY state
                """)
                
                stats = {}
                for state, count in cursor.fetchall():
                    stats[state] = count
                
                cursor = conn.execute("SELECT COUNT(*) FROM discovered_domains")
                discovered_count = cursor.fetchone()[0]
                stats['total_discovered'] = discovered_count
                
                cursor = conn.execute("SELECT COUNT(DISTINCT discovered_domain) FROM discovered_domains")
                unique_discovered = cursor.fetchone()[0]
                stats['unique_discovered'] = unique_discovered
                
                return stats
        except sqlite3.Error as e:
            print(f"[!] Error getting stats: {e}")
            return {}

def mock_amass_results(domain: str) -> List[dict]:
    """Generate realistic mock subdomain discovery results."""
    
    # Define realistic subdomain patterns for different domain types
    patterns = {
        'santander.cl': [
            'www', 'mail', 'ftp', 'api', 'app', 'mobile', 'secure', 'admin', 'portal',
            'webmail', 'smtp', 'pop', 'imap', 'vpn', 'remote', 'test', 'dev', 'staging',
            'banca', 'empresas', 'personas', 'sucursales', 'cajeros', 'inversiones'
        ],
        'google.com': [
            'www', 'mail', 'calendar', 'drive', 'docs', 'sheets', 'slides', 'photos',
            'youtube', 'maps', 'translate', 'news', 'books', 'scholar', 'images',
            'accounts', 'myaccount', 'support', 'developers', 'cloud', 'firebase'
        ],
        'microsoft.com': [
            'www', 'outlook', 'office', 'teams', 'azure', 'docs', 'support',
            'developer', 'store', 'xbox', 'surface', 'windows', 'onedrive',
            'sharepoint', 'exchange', 'skype', 'bing', 'msn', 'live'
        ]
    }
    
    # Get base domain (remove subdomains if any)
    domain_parts = domain.split('.')
    if len(domain_parts) >= 2:
        base_domain = '.'.join(domain_parts[-2:])
    else:
        base_domain = domain
    
    # Select appropriate pattern
    if base_domain in patterns:
        subdomain_prefixes = patterns[base_domain]
    else:
        # Generic patterns
        subdomain_prefixes = [
            'www', 'mail', 'ftp', 'api', 'admin', 'portal', 'secure', 'app',
            'mobile', 'test', 'dev', 'staging', 'blog', 'shop', 'store'
        ]
    
    # Generate random number of subdomains (realistic range)
    num_subdomains = random.randint(5, min(15, len(subdomain_prefixes)))
    selected_prefixes = random.sample(subdomain_prefixes, num_subdomains)
    
    results = []
    for prefix in selected_prefixes:
        subdomain = f"{prefix}.{domain}"
        results.append({
            "name": subdomain,
            "parent": domain
        })
    
    return results

def process_domain(domain: str, depth: int, manager: DiscoveryManager, worker_id: str):
    """Process a single domain for subdomain discovery."""
    print(f"[{worker_id}] Processing: {domain} (depth={depth})")
    
    start_time = time.time()
    subdomain_count = 0
    
    try:
        # Simulate Amass execution time
        processing_time = random.uniform(1.0, 3.0)
        time.sleep(processing_time)
        
        # Get mock results
        amass_results = mock_amass_results(domain)
        print(f"[{worker_id}] Mock Amass found {len(amass_results)} entries for {domain}")
        
        # Process results
        for entry in amass_results:
            name = entry.get("name")
            parent = entry.get("parent", domain)
            
            if name and name != domain:
                # Record discovered domain
                success = manager.add_discovered_domain(parent, name, 'mock_amass')
                if success:
                    subdomain_count += 1
                    print(f"[{worker_id}] ✓ Discovered: {parent} -> {name}")
                
                # Add to queue if depth allows
                if depth > 0:
                    manager.add_domain(name, depth - 1)
                    print(f"[{worker_id}] + Added to queue: {name} (depth={depth-1})")
        
        total_time = time.time() - start_time
        print(f"[{worker_id}] ✓ Completed {domain} in {total_time:.2f}s - {subdomain_count} subdomains")
        
        # Mark as completed
        manager.mark_completed(domain, depth, worker_id)
        
    except Exception as e:
        error_msg = f"Error processing {domain}: {e}"
        print(f"[{worker_id}] ✗ {error_msg}")
        manager.mark_error(domain, depth, worker_id, error_msg)

def worker(manager: DiscoveryManager, worker_id: str, shutdown_flag: threading.Event):
    """Worker thread function."""
    print(f"[{worker_id}] Worker started")
    
    while not shutdown_flag.is_set():
        # Get next domain
        domain_task = manager.get_next_domain(worker_id)
        
        if not domain_task:
            # No domains available, wait a bit
            time.sleep(1)
            continue
        
        domain = domain_task["domain"]
        depth = domain_task["depth"]
        
        # Process domain
        process_domain(domain, depth, manager, worker_id)
    
    print(f"[{worker_id}] Worker finished")

def stats_monitor(manager: DiscoveryManager, shutdown_flag: threading.Event, interval: int = 10):
    """Monitor and display statistics."""
    while not shutdown_flag.is_set():
        if shutdown_flag.wait(interval):
            break
        
        stats = manager.get_stats()
        
        print("\\n" + "="*60)
        print(f"[STATS] {datetime.now().strftime('%H:%M:%S')}")
        print(f"Queue: {stats}")
        
        # Check if finished
        if (stats.get('pending', 0) == 0 and stats.get('processing', 0) == 0):
            print("[*] All domains processed!")
            shutdown_flag.set()
            break
        
        print("="*60)

def main():
    parser = argparse.ArgumentParser(description="Mock discovery mode - demonstrates full pipeline")
    parser.add_argument("--domains", required=True, help="File with seed domains")
    parser.add_argument("--depth", type=int, default=1, help="Recursion depth")
    parser.add_argument("--threads", type=int, default=2, help="Number of worker threads")
    parser.add_argument("--reset-db", action="store_true", help="Reset database")
    parser.add_argument("--stats-interval", type=int, default=10, help="Stats interval seconds")
    args = parser.parse_args()
    
    # Initialize database
    if args.reset_db and Path(DB_PATH).exists():
        Path(DB_PATH).unlink()
        print(f"[*] Database reset: {DB_PATH}")
    
    manager = DiscoveryManager(DB_PATH)
    
    # Load domains
    seeds = [d.strip() for d in Path(args.domains).read_text().splitlines() if d.strip()]
    print(f"[*] Loaded {len(seeds)} seed domains")
    
    # Add seeds to queue
    added_count = 0
    for domain in seeds:
        if manager.add_domain(domain, args.depth, priority=10):
            added_count += 1
    
    print(f"[*] Added {added_count} domains to queue")
    
    # Show initial stats
    initial_stats = manager.get_stats()
    print(f"[*] Initial stats: {initial_stats}")
    
    # Shutdown flag
    shutdown_flag = threading.Event()
    
    try:
        # Start stats monitor
        stats_thread = threading.Thread(target=stats_monitor, 
                                       args=(manager, shutdown_flag, args.stats_interval))
        stats_thread.start()
        
        # Start worker threads
        threads = []
        for i in range(args.threads):
            worker_id = f"worker-{i+1}"
            t = threading.Thread(target=worker, 
                               args=(manager, worker_id, shutdown_flag))
            t.start()
            threads.append(t)
        
        print(f"[*] Started {args.threads} workers")
        print("[*] Using MOCK data (not real Amass)")
        
        # Wait for completion
        try:
            stats_thread.join()
        except KeyboardInterrupt:
            print("\\n[*] Interrupted, shutting down...")
            shutdown_flag.set()
        
        # Wait for workers
        for t in threads:
            t.join(timeout=5)
        
        # Final stats
        final_stats = manager.get_stats()
        print(f"\\n[FINAL] {final_stats}")
        
        # Show sample results
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.execute("SELECT * FROM discovered_domains ORDER BY created_at LIMIT 20")
            print("\\n[SAMPLE] Discovered domains:")
            for row in cursor.fetchall():
                print(f"  {row[1]} -> {row[2]}")
            
            # Show queue status
            cursor = conn.execute("SELECT domain, depth, state FROM domain_queue ORDER BY created_at LIMIT 10")
            print("\\n[QUEUE] Sample queue entries:")
            for row in cursor.fetchall():
                print(f"  {row[0]} (depth={row[1]}, state={row[2]})")
        
    except Exception as e:
        print(f"[!] Main error: {e}")
        shutdown_flag.set()

if __name__ == "__main__":
    main()