#!/usr/bin/env python3

"""
Risk Loader Optimized - Versión mejorada con configuración optimizada de Amass
y múltiples fallbacks para descubrimiento de subdominios.
"""

import argparse
import subprocess
import tempfile
import sqlite3
import threading
import time
import socket
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict
import sys

# Database configuration
DB_PATH = "risk_loader_optimized.db"
DB_TIMEOUT = 30.0

class OptimizedQueueManager:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.init_database()
    
    def init_database(self):
        with sqlite3.connect(self.db_path, timeout=DB_TIMEOUT) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            
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
                    processing_time_seconds REAL,
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
    
    def add_discovered_domain(self, parent_domain: str, discovered_domain: str, method: str = 'amass', processing_time: float = 0.0) -> bool:
        try:
            with sqlite3.connect(self.db_path, timeout=DB_TIMEOUT) as conn:
                now = datetime.now().isoformat()
                cursor = conn.execute("""
                    INSERT OR IGNORE INTO discovered_domains 
                    (parent_domain, discovered_domain, discovery_method, created_at, processing_time_seconds)
                    VALUES (?, ?, ?, ?, ?)
                """, (parent_domain, discovered_domain, method, now, processing_time))
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
                
                # Get method breakdown
                cursor = conn.execute("""
                    SELECT discovery_method, COUNT(*) 
                    FROM discovered_domains 
                    GROUP BY discovery_method
                """)
                for method, count in cursor.fetchall():
                    stats[f'method_{method}'] = count
                
                return stats
        except sqlite3.Error as e:
            print(f"[!] Error getting stats: {e}")
            return {}

def run_optimized_amass(domain: str, sample_mode: bool = True) -> List[dict]:
    """Run Amass with optimized configuration."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.txt"
        
        # Build optimized command
        cmd = [
            "amass", "enum", 
            "-d", domain, 
            "-o", str(out),
            "-max-dns-queries", "20",
            "-max-depth", "1",
            "-r", "8.8.8.8,1.1.1.1,9.9.9.9"
        ]
        
        if sample_mode:
            timeout_arg = "15"
            cmd.extend(["-timeout", timeout_arg])
            cmd.extend(["-passive"])
            cmd.extend(["-exclude", "crtsh,dnsdumpster,hackertarget,threatcrowd,virustotal"])
            print(f"[AMASS] {domain} (passive, {timeout_arg}s)")
        else:
            cmd.extend(["-timeout", "120"])
            print(f"[AMASS] {domain} (active, 120s)")
        
        try:
            timeout_seconds = 20 if sample_mode else 150
            result = subprocess.run(
                cmd, 
                check=True, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                text=True
            )
            
            return parse_amass_output(out)
            
        except subprocess.TimeoutExpired:
            print(f"[AMASS] Timeout for {domain} - checking partial results")
            if out.exists():
                return parse_amass_output(out)
            return []
            
        except subprocess.CalledProcessError as e:
            print(f"[AMASS] Error for {domain}: {e.stderr if e.stderr else 'Unknown error'}")
            if out.exists():
                return parse_amass_output(out)
            return []
        
        except FileNotFoundError:
            print(f"[AMASS] Not found in PATH")
            return []

def parse_amass_output(output_path: Path) -> List[dict]:
    """Parse Amass output to extract subdomain relationships."""
    entries = []
    
    if not output_path.exists():
        return entries
    
    with output_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line or "The enumeration has finished" in line or "DNS wildcard detected:" in line:
                continue
            
            # Look for node relationships
            if " --> " in line and " node " in line:
                parts = line.split(" --> ")
                if len(parts) == 3:
                    source, relation, target = parts
                    
                    if " (" in source:
                        source_clean = source.split(" (")[0].strip()
                    else:
                        source_clean = source.strip()
                    
                    if " (" in target:
                        target_clean = target.split(" (")[0].strip()
                    else:
                        target_clean = target.strip()
                    
                    if relation.strip() == "node":
                        entries.append({
                            "name": target_clean,
                            "parent": source_clean
                        })
    
    return entries

def run_subfinder_fallback(domain: str) -> List[dict]:
    """Fallback using subfinder if available."""
    try:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "subfinder_out.txt"
            cmd = ["subfinder", "-d", domain, "-o", str(out), "-silent", "-timeout", "10"]
            
            result = subprocess.run(
                cmd, 
                check=True, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL,
                timeout=15
            )
            
            entries = []
            if out.exists():
                with out.open() as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain and subdomain != domain:
                            entries.append({
                                "name": subdomain,
                                "parent": domain
                            })
            
            print(f"[SUBFINDER] Found {len(entries)} subdomains for {domain}")
            return entries
            
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return []

def run_basic_dns_enumeration(domain: str) -> List[dict]:
    """Basic DNS enumeration using common subdomains."""
    common_subdomains = [
        'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 
        'mx', 'test', 'staging', 'dev', 'admin', 'api', 'blog', 'shop', 
        'app', 'mobile', 'secure', 'ssl', 'portal', 'support', 'help'
    ]
    
    entries = []
    print(f"[DNS ENUM] Testing {len(common_subdomains)} common subdomains for {domain}")
    
    for sub in common_subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            entries.append({
                "name": subdomain,
                "parent": domain
            })
        except socket.gaierror:
            pass
        except Exception:
            pass
    
    print(f"[DNS ENUM] Found {len(entries)} valid subdomains for {domain}")
    return entries

def discover_subdomains(domain: str, sample_mode: bool = True) -> tuple:
    """Discover subdomains using multiple methods with fallbacks."""
    start_time = time.time()
    results = []
    method_used = "none"
    
    # 1. Try Amass first
    try:
        results = run_optimized_amass(domain, sample_mode)
        if results:
            method_used = "amass"
            print(f"[✓] Amass found {len(results)} subdomains for {domain}")
            return results, method_used, time.time() - start_time
    except Exception as e:
        print(f"[!] Amass failed for {domain}: {e}")
    
    # 2. Fallback to Subfinder
    try:
        results = run_subfinder_fallback(domain)
        if results:
            method_used = "subfinder"
            print(f"[✓] Subfinder found {len(results)} subdomains for {domain}")
            return results, method_used, time.time() - start_time
    except Exception as e:
        print(f"[!] Subfinder failed for {domain}: {e}")
    
    # 3. Fallback to basic DNS enumeration
    try:
        results = run_basic_dns_enumeration(domain)
        if results:
            method_used = "dns_enum"
            print(f"[✓] DNS enum found {len(results)} subdomains for {domain}")
            return results, method_used, time.time() - start_time
    except Exception as e:
        print(f"[!] DNS enum failed for {domain}: {e}")
    
    # 4. No results found
    print(f"[!] No discovery methods succeeded for {domain}")
    return [], "none", time.time() - start_time

def process_domain(domain: str, depth: int, manager: OptimizedQueueManager, worker_id: str, sample_mode: bool = True):
    """Process a single domain for subdomain discovery."""
    print(f"[{worker_id}] Processing: {domain} (depth={depth})")
    
    start_time = time.time()
    subdomain_count = 0
    
    try:
        # Discover subdomains
        subdomains, method_used, discovery_time = discover_subdomains(domain, sample_mode)
        
        # Process results
        for entry in subdomains:
            name = entry.get("name")
            parent = entry.get("parent", domain)
            
            if name and name != domain:
                # Record discovered domain
                success = manager.add_discovered_domain(parent, name, method_used, discovery_time)
                if success:
                    subdomain_count += 1
                    print(f"[{worker_id}] ✓ {parent} -> {name}")
                
                # Add to queue if depth allows
                if depth > 0:
                    manager.add_domain(name, depth - 1)
        
        total_time = time.time() - start_time
        print(f"[{worker_id}] ✓ Completed {domain} in {total_time:.2f}s - {subdomain_count} subdomains via {method_used}")
        
        # Mark as completed
        manager.mark_completed(domain, depth, worker_id)
        
    except Exception as e:
        error_msg = f"Error processing {domain}: {e}"
        print(f"[{worker_id}] ✗ {error_msg}")
        manager.mark_error(domain, depth, worker_id, error_msg)

def worker(manager: OptimizedQueueManager, worker_id: str, sample_mode: bool, shutdown_flag: threading.Event):
    """Worker thread function."""
    print(f"[{worker_id}] Worker started")
    
    while not shutdown_flag.is_set():
        domain_task = manager.get_next_domain(worker_id)
        
        if not domain_task:
            time.sleep(2)
            continue
        
        domain = domain_task["domain"]
        depth = domain_task["depth"]
        
        process_domain(domain, depth, manager, worker_id, sample_mode)
    
    print(f"[{worker_id}] Worker finished")

def stats_monitor(manager: OptimizedQueueManager, shutdown_flag: threading.Event, interval: int = 15):
    """Monitor and display statistics."""
    while not shutdown_flag.is_set():
        if shutdown_flag.wait(interval):
            break
        
        stats = manager.get_stats()
        
        print("\\n" + "="*70)
        print(f"[STATS] {datetime.now().strftime('%H:%M:%S')}")
        print(f"Queue: {stats}")
        
        # Check if finished
        if (stats.get('pending', 0) == 0 and stats.get('processing', 0) == 0):
            print("[*] All domains processed!")
            shutdown_flag.set()
            break
        
        print("="*70)

def main():
    parser = argparse.ArgumentParser(description="Optimized Risk Loader with multiple discovery methods")
    parser.add_argument("--domains", required=True, help="File with seed domains")
    parser.add_argument("--depth", type=int, default=1, help="Recursion depth")
    parser.add_argument("--sample", action="store_true", help="Use sample mode (faster)")
    parser.add_argument("--threads", type=int, default=2, help="Number of worker threads")
    parser.add_argument("--reset-db", action="store_true", help="Reset database")
    parser.add_argument("--stats-interval", type=int, default=15, help="Stats interval seconds")
    args = parser.parse_args()
    
    # Initialize database
    if args.reset_db and Path(DB_PATH).exists():
        Path(DB_PATH).unlink()
        print(f"[*] Database reset: {DB_PATH}")
    
    manager = OptimizedQueueManager(DB_PATH)
    
    # Load domains
    seeds = [d.strip() for d in Path(args.domains).read_text().splitlines() if d.strip()]
    print(f"[*] Loaded {len(seeds)} seed domains")
    
    # Add seeds to queue
    added_count = 0
    for domain in seeds:
        if manager.add_domain(domain, args.depth, priority=10):
            added_count += 1
    
    print(f"[*] Added {added_count} domains to queue")
    print(f"[*] Using {args.threads} worker threads")
    print(f"[*] Discovery methods: Amass -> Subfinder -> DNS enumeration")
    
    # Show initial stats
    initial_stats = manager.get_stats()
    print(f"[*] Initial stats: {initial_stats}")
    
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
                               args=(manager, worker_id, args.sample, shutdown_flag))
            t.start()
            threads.append(t)
        
        print(f"[*] Started {args.threads} workers")
        
        # Wait for completion
        try:
            stats_thread.join()
        except KeyboardInterrupt:
            print("\\n[*] Interrupted, shutting down...")
            shutdown_flag.set()
        
        # Wait for workers
        for t in threads:
            t.join(timeout=5)
        
        # Final stats and results
        final_stats = manager.get_stats()
        print(f"\\n[FINAL] {final_stats}")
        
        # Show sample results
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.execute("SELECT * FROM discovered_domains ORDER BY created_at LIMIT 20")
            print("\\n[SAMPLE] Discovered domains:")
            for row in cursor.fetchall():
                print(f"  {row[1]} -> {row[2]} (via {row[3]}, {row[5]:.2f}s)")
        
    except Exception as e:
        print(f"[!] Main error: {e}")
        shutdown_flag.set()

if __name__ == "__main__":
    main()