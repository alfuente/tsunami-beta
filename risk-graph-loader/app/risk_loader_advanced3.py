
#!/usr/bin/env python3
"""
risk_loader_advanced.py  –  Ingesta recursiva + enriquecimiento

Uso:
  python risk_loader_advanced.py --domains dominios.txt --depth 2 \
         --bolt bolt://localhost:7687 --user neo4j --password test \
         --ipinfo-token YOUR_TOKEN_HERE

• Amass via local enumera subdominios e IPs con relaciones ASN/Netblock.
• dnspython resuelve A/AAAA/NS/MX/TXT/CNAME/PTR.
• cryptography extrae información del certificado TLS (puerto 443).
• ipinfo.io detecta proveedores cloud con precisión (con token).
• Se crea el grafo completo en Neo4j siguiendo el modelo.
"""

from __future__ import annotations
import argparse, json, subprocess, tempfile, sys, socket, ssl, re
from collections import deque, defaultdict
from pathlib import Path
from datetime import datetime, timedelta
from typing import Iterable, Mapping, Any, List, Dict, Set, Tuple, Optional
import threading
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import multiprocessing as mp
import sqlite3
import time
import queue
from dataclasses import dataclass
from enum import Enum

import dns.resolver, dns.exception, tldextract, whois, requests, logging
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID, ExtensionOID
from neo4j import GraphDatabase, Driver
import maxminddb
import csv
import ipaddress

AMASS_IMAGE = "caffix/amass:latest"
RESOLVER = dns.resolver.Resolver(configure=True)

# Configuración de base de datos MMDB
IPINFO_MMDB_PATH = "ipinfo_data/ipinfo.mmdb"

# Configuración de base de datos CSV
IPINFO_CSV_PATH = "ipinfo_data/ipinfo.csv"

# Suppress whois connection error messages
logging.getLogger('whois.whois').setLevel(logging.CRITICAL)
RESOLVER.lifetime = RESOLVER.timeout = 5.0

# SQLite database configuration
DB_PATH = "risk_loader_queue.db"
DB_TIMEOUT = 30.0

# Domain processing states
class DomainState(Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    ERROR = "error"
    SKIPPED = "skipped"

@dataclass
class DomainTask:
    domain: str
    depth: int
    state: DomainState
    priority: int = 1
    retry_count: int = 0
    max_retries: int = 3
    created_at: str = None
    updated_at: str = None
    error_message: str = None
    worker_id: str = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()
        if self.updated_at is None:
            self.updated_at = datetime.now().isoformat()

# --- SQLite Queue Manager -----------------------------------------------------

class SQLiteQueueManager:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with required tables."""
        with sqlite3.connect(self.db_path, timeout=DB_TIMEOUT) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=10000")
            conn.execute("PRAGMA temp_store=MEMORY")
            
            # Domains queue table
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
            
            # Discovered domains table (for tracking relationships)
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
            
            # Processing stats table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS processing_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    worker_id TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    processing_time_seconds REAL,
                    subdomain_count INTEGER DEFAULT 0,
                    ip_count INTEGER DEFAULT 0,
                    error_count INTEGER DEFAULT 0,
                    completed_at TEXT NOT NULL
                )
            """)
            
            # Create indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domain_queue_state ON domain_queue(state)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domain_queue_priority ON domain_queue(priority DESC, created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_discovered_parent ON discovered_domains(parent_domain)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_stats_worker ON processing_stats(worker_id)")
            
            conn.commit()
    
    def add_domain(self, domain: str, depth: int, priority: int = 1) -> bool:
        """Add a domain to the processing queue."""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path, timeout=DB_TIMEOUT) as conn:
                    now = datetime.now().isoformat()
                    # First try to insert new domain
                    cursor = conn.execute("""
                        INSERT OR IGNORE INTO domain_queue 
                        (domain, depth, state, priority, created_at, updated_at)
                        VALUES (?, ?, 'pending', ?, ?, ?)
                    """, (domain, depth, priority, now, now))
                    
                    # If domain already exists, check if it's in error state and reset it
                    if cursor.rowcount == 0:
                        cursor = conn.execute("""
                            UPDATE domain_queue 
                            SET state = 'pending', priority = ?, updated_at = ?, worker_id = NULL
                            WHERE domain = ? AND depth = ? AND state = 'error'
                        """, (priority, now, domain, depth))
                    
                    conn.commit()
                    return cursor.rowcount > 0
            except sqlite3.Error as e:
                print(f"[!] Error adding domain {domain}: {e}")
                return False
    
    def get_next_domain(self, worker_id: str) -> Optional[DomainTask]:
        """Get the next domain to process and mark it as processing."""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path, timeout=DB_TIMEOUT) as conn:
                    # Get next pending domain with highest priority
                    cursor = conn.execute("""
                        SELECT id, domain, depth, state, priority, retry_count, max_retries, 
                               created_at, updated_at, error_message
                        FROM domain_queue 
                        WHERE state = 'pending' OR (state = 'error' AND retry_count < max_retries)
                        ORDER BY priority DESC, created_at ASC
                        LIMIT 1
                    """)
                    
                    row = cursor.fetchone()
                    if not row:
                        return None
                    
                    domain_id, domain, depth, state, priority, retry_count, max_retries, created_at, updated_at, error_message = row
                    
                    # Mark as processing
                    now = datetime.now().isoformat()
                    conn.execute("""
                        UPDATE domain_queue 
                        SET state = 'processing', worker_id = ?, updated_at = ?, started_at = ?
                        WHERE id = ?
                    """, (worker_id, now, now, domain_id))
                    conn.commit()
                    
                    return DomainTask(
                        domain=domain,
                        depth=depth,
                        state=DomainState.PROCESSING,
                        priority=priority,
                        retry_count=retry_count,
                        max_retries=max_retries,
                        created_at=created_at,
                        updated_at=updated_at,
                        error_message=error_message,
                        worker_id=worker_id
                    )
            except sqlite3.Error as e:
                print(f"[!] Error getting next domain: {e}")
                return None
    
    def mark_completed(self, domain: str, depth: int, worker_id: str, stats: dict = None) -> bool:
        """Mark a domain as completed."""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path, timeout=DB_TIMEOUT) as conn:
                    now = datetime.now().isoformat()
                    conn.execute("""
                        UPDATE domain_queue 
                        SET state = 'completed', updated_at = ?, completed_at = ?
                        WHERE domain = ? AND depth = ? AND worker_id = ?
                    """, (now, now, domain, depth, worker_id))
                    
                    # Add processing stats if provided
                    if stats:
                        conn.execute("""
                            INSERT INTO processing_stats 
                            (worker_id, domain, processing_time_seconds, subdomain_count, ip_count, error_count, completed_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (worker_id, domain, stats.get('processing_time', 0), 
                              stats.get('subdomain_count', 0), stats.get('ip_count', 0), 
                              stats.get('error_count', 0), now))
                    
                    conn.commit()
                    return conn.total_changes > 0
            except sqlite3.Error as e:
                print(f"[!] Error marking domain {domain} as completed: {e}")
                return False
    
    def mark_error(self, domain: str, depth: int, worker_id: str, error_message: str) -> bool:
        """Mark a domain as error and potentially retry."""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path, timeout=DB_TIMEOUT) as conn:
                    now = datetime.now().isoformat()
                    
                    # Get current retry count
                    cursor = conn.execute(
                        "SELECT retry_count, max_retries FROM domain_queue WHERE domain = ? AND depth = ?",
                        (domain, depth)
                    )
                    row = cursor.fetchone()
                    if not row:
                        return False
                    
                    retry_count, max_retries = row
                    new_retry_count = retry_count + 1
                    
                    # Determine new state
                    if new_retry_count >= max_retries:
                        new_state = 'error'
                    else:
                        new_state = 'pending'  # Will be retried
                    
                    conn.execute("""
                        UPDATE domain_queue 
                        SET state = ?, retry_count = ?, updated_at = ?, error_message = ?, worker_id = NULL
                        WHERE domain = ? AND depth = ? AND worker_id = ?
                    """, (new_state, new_retry_count, now, error_message, domain, depth, worker_id))
                    
                    conn.commit()
                    return conn.total_changes > 0
            except sqlite3.Error as e:
                print(f"[!] Error marking domain {domain} as error: {e}")
                return False
    
    def add_discovered_domain(self, parent_domain: str, discovered_domain: str, method: str = 'amass') -> bool:
        """Record a discovered domain relationship."""
        try:
            with sqlite3.connect(self.db_path, timeout=DB_TIMEOUT) as conn:
                now = datetime.now().isoformat()
                result = conn.execute("""
                    INSERT OR IGNORE INTO discovered_domains 
                    (parent_domain, discovered_domain, discovery_method, created_at)
                    VALUES (?, ?, ?, ?)
                """, (parent_domain, discovered_domain, method, now))
                conn.commit()
                changes = conn.total_changes
                if changes > 0:
                    debug_log(f"[DB] Recorded discovered domain: {parent_domain} -> {discovered_domain}")
                else:
                    debug_log(f"[DB] Domain already recorded: {parent_domain} -> {discovered_domain}")
                return changes > 0
        except sqlite3.Error as e:
            print(f"[!] Error recording discovered domain {parent_domain} -> {discovered_domain}: {e}")
            return False
    
    def get_queue_stats(self) -> dict:
        """Get current queue statistics."""
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
                
                # Get total discovered domains
                cursor = conn.execute("SELECT COUNT(*) FROM discovered_domains")
                discovered_count = cursor.fetchone()[0]
                stats['total_discovered'] = discovered_count
                
                # Get unique discovered domains count
                cursor = conn.execute("SELECT COUNT(DISTINCT discovered_domain) FROM discovered_domains")
                unique_discovered = cursor.fetchone()[0]
                stats['unique_discovered'] = unique_discovered
                
                return stats
        except sqlite3.Error as e:
            print(f"[!] Error getting queue stats: {e}")
            return {}
    
    def get_processing_stats(self) -> dict:
        """Get processing performance statistics."""
        try:
            with sqlite3.connect(self.db_path, timeout=DB_TIMEOUT) as conn:
                cursor = conn.execute("""
                    SELECT 
                        COUNT(*) as total_processed,
                        AVG(processing_time_seconds) as avg_processing_time,
                        SUM(subdomain_count) as total_subdomains,
                        SUM(ip_count) as total_ips,
                        SUM(error_count) as total_errors
                    FROM processing_stats
                """)
                
                row = cursor.fetchone()
                if row:
                    total_processed, avg_time, total_subs, total_ips, total_errors = row
                    return {
                        'total_processed': total_processed or 0,
                        'avg_processing_time': round(avg_time or 0, 2),
                        'total_subdomains': total_subs or 0,
                        'total_ips': total_ips or 0,
                        'total_errors': total_errors or 0
                    }
                return {}
        except sqlite3.Error as e:
            print(f"[!] Error getting processing stats: {e}")
            return {}
    
    def cleanup_stale_processing(self, timeout_minutes: int = 30):
        """Reset domains that have been in processing state too long."""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path, timeout=DB_TIMEOUT) as conn:
                    timeout_time = datetime.now() - timedelta(minutes=timeout_minutes)
                    timeout_str = timeout_time.isoformat()
                    
                    cursor = conn.execute("""
                        UPDATE domain_queue 
                        SET state = 'pending', worker_id = NULL, updated_at = ?
                        WHERE state = 'processing' AND started_at < ?
                    """, (datetime.now().isoformat(), timeout_str))
                    
                    if cursor.rowcount > 0:
                        print(f"[*] Reset {cursor.rowcount} stale processing domains")
                    
                    conn.commit()
            except sqlite3.Error as e:
                print(f"[!] Error cleaning up stale processing: {e}")

# --- Utilidades ----------------------------------------------------------------

def thread_log(message: str) -> None:
    """Log con prefijo de thread ID."""
    thread_id = threading.current_thread().ident
    thread_name = threading.current_thread().name
    print(f"[T-{thread_id}:{thread_name}] {message}")


def debug_log(message: str) -> None:
    """Log de debug con thread ID."""
    thread_id = threading.current_thread().ident
    thread_name = threading.current_thread().name
    print(f"[DEBUG-T-{thread_id}:{thread_name}] {message}")


def parse_amass_output(output_path: Path) -> List[dict]:
    """Parsea la salida de texto de amass y devuelve lista de diccionarios completa."""
    entries = []
    domains = set()
    dns_records = []
    asn_data = {}
    netblock_data = {}
    org_data = {}
    
    total_lines = 0
    processed_lines = 0
    
    with output_path.open() as fh:
        for line in fh:
            total_lines += 1
            line = line.strip()
            if not line or "The enumeration has finished" in line or "DNS wildcard detected:" in line:
                continue
            
            processed_lines += 1
            
            # Si la línea parece ser solo un dominio/subdominio (formato simple)
            if " --> " not in line and "." in line and not line.startswith("["):
                # Formato simple: solo dominios, uno por línea
                if line.count(".") >= 1:  # Al menos un punto (dominio válido)
                    domains.add(line)
                    # Si no está ya en entries, agregarlo
                    if not any(e.get("name") == line for e in entries):
                        # Intentar determinar el dominio padre
                        domain_parts = line.split(".")
                        if len(domain_parts) > 2:
                            # Es un subdominio, el padre sería sin el primer componente
                            parent = ".".join(domain_parts[1:])
                            entries.append({"name": line, "parent": parent})
                            domains.add(parent)
                        else:
                            # Es un dominio raíz
                            entries.append({"name": line})
                continue
                
            # Parsear diferentes tipos de relaciones (formato complejo)
            if " --> " in line:
                parts = line.split(" --> ")
                if len(parts) == 3:
                    source, relation, target = parts
                    
                    # Extraer tipos de nodos
                    source_type = None
                    target_type = None
                    if " (" in source:
                        source_clean = source.split(" (")[0].strip()
                        source_type = source.split(" (")[1].replace(")", "").strip()
                    else:
                        source_clean = source.strip()
                    
                    if " (" in target:
                        target_clean = target.split(" (")[0].strip()
                        target_type = target.split(" (")[1].replace(")", "").strip()
                    else:
                        target_clean = target.strip()
                    
                    # Procesar según el tipo de relación
                    if relation == "a_record":
                        # A record: dominio -> IP
                        # Solo agregar como entrada si no existe ya
                        if not any(e.get("name") == source_clean for e in entries):
                            entries.append({
                                "name": source_clean,
                                "addresses": [{"ip": target_clean}]
                            })
                        else:
                            # Agregar IP a entrada existente
                            for entry in entries:
                                if entry.get("name") == source_clean:
                                    if "addresses" not in entry:
                                        entry["addresses"] = []
                                    entry["addresses"].append({"ip": target_clean})
                                    break
                        domains.add(source_clean)
                        dns_records.append({
                            "source": source_clean,
                            "target": target_clean,
                            "type": "A"
                        })
                        
                    elif relation == "aaaa_record":
                        # AAAA record: dominio -> IPv6
                        # Solo agregar como entrada si no existe ya
                        if not any(e.get("name") == source_clean for e in entries):
                            entries.append({
                                "name": source_clean,
                                "addresses": [{"ip": target_clean, "version": 6}]
                            })
                        else:
                            # Agregar IP a entrada existente
                            for entry in entries:
                                if entry.get("name") == source_clean:
                                    if "addresses" not in entry:
                                        entry["addresses"] = []
                                    entry["addresses"].append({"ip": target_clean, "version": 6})
                                    break
                        domains.add(source_clean)
                        dns_records.append({
                            "source": source_clean,
                            "target": target_clean,
                            "type": "AAAA"
                        })
                        
                    elif relation == "cname_record":
                        # CNAME record: alias -> target
                        dns_records.append({
                            "source": source_clean,
                            "target": target_clean,
                            "type": "CNAME"
                        })
                        domains.add(source_clean)
                        domains.add(target_clean)
                        
                    elif relation == "mx_record":
                        # MX record: dominio -> servidor de correo
                        dns_records.append({
                            "source": source_clean,
                            "target": target_clean,
                            "type": "MX"
                        })
                        domains.add(source_clean)
                        domains.add(target_clean)
                        
                    elif relation == "ns_record":
                        # NS record: dominio -> servidor DNS
                        dns_records.append({
                            "source": source_clean,
                            "target": target_clean,
                            "type": "NS"
                        })
                        domains.add(source_clean)
                        domains.add(target_clean)
                        
                    elif relation == "ptr_record":
                        # PTR record: IP -> dominio
                        dns_records.append({
                            "source": source_clean,
                            "target": target_clean,
                            "type": "PTR"
                        })
                        
                    elif relation == "node":
                        # Node: dominio padre -> subdominio
                        entries.append({
                            "name": target_clean,
                            "parent": source_clean
                        })
                        domains.add(source_clean)
                        domains.add(target_clean)
                        print(f"[AMASS] Found subdomain: {source_clean} -> {target_clean}")
                        
                    elif relation == "contains":
                        # Netblock contains IP
                        if source_type == "Netblock" and target_type == "IPAddress":
                            netblock_data[source_clean] = netblock_data.get(source_clean, {"ips": []})
                            netblock_data[source_clean]["ips"].append(target_clean)
                            
                    elif relation == "announces":
                        # ASN announces Netblock
                        if source_type == "ASN" and target_type == "Netblock":
                            asn_data[source_clean] = asn_data.get(source_clean, {"netblocks": []})
                            asn_data[source_clean]["netblocks"].append(target_clean)
                            
                    elif relation == "managed_by":
                        # ASN managed by Organization
                        if source_type == "ASN" and target_type == "RIROrganization":
                            if source_clean not in asn_data:
                                asn_data[source_clean] = {}
                            asn_data[source_clean]["organization"] = target_clean
                            org_data[target_clean] = {"type": "RIROrganization"}
    
    # Agregar metadatos adicionales a las entradas
    for entry in entries:
        entry["dns_records"] = [r for r in dns_records if r["source"] == entry["name"]]
        
    # Agregar dominios encontrados como entradas básicas
    for domain in domains:
        if not any(e.get("name") == domain for e in entries):
            entry = {"name": domain}
            entry["dns_records"] = [r for r in dns_records if r["source"] == domain]
            entries.append(entry)
    
    # Agregar información de ASN y Netblocks
    for entry in entries:
        entry["asn_data"] = asn_data
        entry["netblock_data"] = netblock_data
        entry["org_data"] = org_data
    
    print(f"[DEBUG] Parse Amass: {total_lines} líneas totales, {processed_lines} procesadas, {len(entries)} entradas, {len(domains)} dominios")
    
    return entries


def run_amass_local(domain: str, sample_mode: bool = False) -> List[dict]:
    """Ejecuta Amass local con configuración optimizada."""
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



def run_amass_parallel_worker(domain_info: Tuple[str, bool]) -> Tuple[str, List[dict]]:
    """Worker function para ejecutar Amass en paralelo con mejor manejo de errores."""
    domain, sample_mode = domain_info
    try:
        results = run_amass_local(domain, sample_mode)
        print(f"[AMASS WORKER] {domain}: {len(results)} entries found")
        return domain, results
    except Exception as e:
        print(f"[!] Error en Amass worker para {domain}: {e}")
        return domain, []


def run_amass_batch_parallel(domains: List[str], sample_mode: bool = False, max_workers: int = 4) -> Dict[str, List[dict]]:
    """Ejecuta múltiples llamadas Amass en paralelo usando procesos."""
    print(f"[*] Ejecutando Amass en paralelo para {len(domains)} dominios con {max_workers} procesos")
    
    domain_infos = [(domain, sample_mode) for domain in domains]
    results = {}
    
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        # Enviar todos los trabajos
        future_to_domain = {
            executor.submit(run_amass_parallel_worker, domain_info): domain_info[0] 
            for domain_info in domain_infos
        }
        
        # Recoger resultados conforme van completándose
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                domain_result, amass_results = future.result()
                results[domain_result] = amass_results
                print(f"[✓] Completado Amass para {domain_result}: {len(amass_results)} entradas")
            except Exception as e:
                print(f"[!] Error procesando resultado para {domain}: {e}")
                results[domain] = []
    
    return results


def run_amass(domain: str) -> List[dict]:
    """Ejecuta Amass (Docker) y devuelve la lista JSON."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.json"
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{tmp}:/out",
            AMASS_IMAGE,
            "enum", "-d", domain, "-ojson", "/out/out.json",
            "-nocolor"
        ]
        print(f"[AMASS] {domain}")
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
        return json.loads(out.read_text())


def dns_query(domain: str, rdtype: str) -> list[str]:
    """Retorna los registros DNS solicitados (vacío si no existen)."""
    try:
        return [r.to_text() for r in RESOLVER.resolve(domain, rdtype)]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.exception.DNSException):
        return []


def get_ip_info_from_mmdb(ip: str, mmdb_path: str = IPINFO_MMDB_PATH) -> Optional[Dict[str, Any]]:
    """Obtiene información de IP desde base de datos MMDB local."""
    try:
        if not Path(mmdb_path).exists():
            return None
            
        with maxminddb.open_database(mmdb_path) as reader:
            result = reader.get(ip)
            if result:
                # Extraer información relevante del resultado MMDB
                info = {}
                
                # Información básica
                if 'country' in result and isinstance(result['country'], dict):
                    info['country'] = result['country'].get('iso_code') or result['country'].get('code')
                    info['country_name'] = result['country'].get('names', {}).get('en')
                
                if 'city' in result and isinstance(result['city'], dict):
                    info['city'] = result['city'].get('names', {}).get('en')
                
                if 'subdivisions' in result and result['subdivisions'] and isinstance(result['subdivisions'][0], dict):
                    info['region'] = result['subdivisions'][0].get('names', {}).get('en')
                
                if 'postal' in result and isinstance(result['postal'], dict):
                    info['postal'] = result['postal'].get('code')
                
                if 'location' in result and isinstance(result['location'], dict):
                    info['latitude'] = result['location'].get('latitude')
                    info['longitude'] = result['location'].get('longitude')
                    info['timezone'] = result['location'].get('time_zone')
                
                # Información de ASN/Organización
                if 'asn' in result and isinstance(result['asn'], dict):
                    info['asn'] = str(result['asn'].get('asn'))
                    info['org_name'] = result['asn'].get('name')
                    info['organization'] = result['asn'].get('name')
                elif 'autonomous_system_organization' in result:
                    info['org_name'] = result['autonomous_system_organization']
                    info['organization'] = result['autonomous_system_organization']
                
                if 'autonomous_system_number' in result:
                    info['asn'] = str(result['autonomous_system_number'])
                
                # Información específica de IPinfo
                if 'org' in result and isinstance(result['org'], str):
                    info['organization'] = result['org']
                    # Extraer ASN del campo org si tiene formato "AS13335 Cloudflare, Inc."
                    if result['org'].startswith('AS'):
                        parts = result['org'].split()
                        if len(parts) > 1:
                            info['asn'] = parts[0][2:]  # Remover "AS"
                            info['org_name'] = ' '.join(parts[1:])
                
                if 'hostname' in result and isinstance(result['hostname'], str):
                    info['hostname'] = result['hostname']
                
                if 'anycast' in result:
                    info['anycast'] = result['anycast']
                
                if 'company' in result and isinstance(result['company'], dict):
                    info['company'] = result['company'].get('name')
                    info['company_domain'] = result['company'].get('domain')
                    info['company_type'] = result['company'].get('type')
                
                if 'carrier' in result and isinstance(result['carrier'], dict):
                    info['carrier'] = result['carrier'].get('name')
                
                if 'privacy' in result:
                    info['privacy'] = result['privacy']
                
                if 'abuse' in result:
                    info['abuse'] = result['abuse']
                
                if 'domains' in result:
                    info['domains'] = result['domains']
                
                info['source'] = 'mmdb_local'
                return info
                
    except Exception as e:
        print(f"[!] Error leyendo base de datos MMDB: {e}")
        pass
    
    return None


def get_ip_info_from_csv(ip: str, csv_path: str = IPINFO_CSV_PATH) -> Optional[Dict[str, Any]]:
    """Obtiene información de IP desde base de datos CSV local."""
    try:
        if not Path(csv_path).exists():
            return None
            
        target_ip = ipaddress.ip_address(ip)
        
        with open(csv_path, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            
            # Buscar por rango de IP en el CSV
            for row in reader:
                try:
                    # Asumimos que el CSV tiene columnas como: start_ip, end_ip, country, region, city, org, etc.
                    # Ajusta los nombres de columnas según tu archivo CSV específico
                    start_ip = row.get('start_ip', row.get('ip_start', ''))
                    end_ip = row.get('end_ip', row.get('ip_end', ''))
                    
                    # Si solo hay una IP específica en lugar de rango
                    if not start_ip and not end_ip:
                        single_ip = row.get('ip', row.get('ip_address', ''))
                        if single_ip == ip:
                            return _parse_csv_row(row)
                        continue
                    
                    # Verificar si la IP está en el rango
                    if start_ip and end_ip:
                        start_addr = ipaddress.ip_address(start_ip)
                        end_addr = ipaddress.ip_address(end_ip)
                        
                        if start_addr <= target_ip <= end_addr:
                            return _parse_csv_row(row)
                    
                    # Verificar si hay CIDR
                    cidr = row.get('cidr', row.get('network', ''))
                    if cidr and '/' in cidr:
                        network = ipaddress.ip_network(cidr, strict=False)
                        if target_ip in network:
                            return _parse_csv_row(row)
                            
                except (ValueError, ipaddress.AddressValueError):
                    continue
                    
    except Exception as e:
        print(f"[!] Error leyendo base de datos CSV: {e}")
        pass
    
    return None


def _parse_csv_row(row: Dict[str, str]) -> Dict[str, Any]:
    """Parsea una fila del CSV y extrae información relevante."""
    info = {}
    
    # Información básica de ubicación
    info['country'] = row.get('country', row.get('country_code', ''))
    info['country_name'] = row.get('country_name', '')
    info['region'] = row.get('region', row.get('subdivision_1_name', ''))
    info['city'] = row.get('city', row.get('city_name', ''))
    info['postal'] = row.get('postal', row.get('postal_code', ''))
    info['latitude'] = row.get('latitude', row.get('lat', ''))
    info['longitude'] = row.get('longitude', row.get('lon', ''))
    info['timezone'] = row.get('timezone', row.get('time_zone', ''))
    
    # Información de organización/ASN
    org = row.get('org', row.get('organization', ''))
    if org:
        info['organization'] = org
        # Extraer ASN del campo org si tiene formato "AS13335 Cloudflare, Inc."
        if org.startswith('AS'):
            parts = org.split()
            if len(parts) > 1:
                info['asn'] = parts[0][2:]  # Remover "AS"
                info['org_name'] = ' '.join(parts[1:])
        else:
            info['org_name'] = org
    
    # ASN específico
    asn = row.get('asn', row.get('autonomous_system_number', ''))
    if asn:
        info['asn'] = str(asn).replace('AS', '')
    
    # Información adicional
    hostname = row.get('hostname', '')
    if hostname:
        info['hostname'] = hostname
    
    anycast = row.get('anycast', '')
    if anycast:
        info['anycast'] = anycast.lower() in ('true', '1', 'yes')
    
    carrier = row.get('carrier', '')
    if carrier:
        info['carrier'] = carrier
    
    privacy = row.get('privacy', '')
    if privacy:
        info['privacy'] = privacy.lower() in ('true', '1', 'yes')
    
    company = row.get('company', row.get('company_name', ''))
    if company:
        info['company'] = company
    
    company_domain = row.get('company_domain', '')
    if company_domain:
        info['company_domain'] = company_domain
    
    company_type = row.get('company_type', '')
    if company_type:
        info['company_type'] = company_type
    
    abuse = row.get('abuse', row.get('abuse_email', ''))
    if abuse:
        info['abuse'] = abuse
    
    # Dominios asociados
    domains = row.get('domains', '')
    if domains:
        info['domains'] = domains.split(',') if ',' in domains else [domains]
    
    info['source'] = 'csv_local'
    
    # Limpiar valores vacíos
    return {k: v for k, v in info.items() if v}


def get_asn_info(ip: str, mmdb_path: str = IPINFO_MMDB_PATH, csv_path: str = IPINFO_CSV_PATH) -> Optional[Dict[str, Any]]:
    """Obtiene información de ASN para una IP usando base de datos local primero, luego servicios públicos."""
    # Primero intentar con base de datos MMDB local
    mmdb_info = get_ip_info_from_mmdb(ip, mmdb_path)
    if mmdb_info:
        return mmdb_info
    
    # Fallback a base de datos CSV local
    csv_info = get_ip_info_from_csv(ip, csv_path)
    if csv_info:
        return csv_info
    
    try:
        # Intentar con ipinfo.io
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if 'org' in data:
                # Formato típico: "AS13335 Cloudflare, Inc."
                org = data['org']
                if org.startswith('AS'):
                    asn = org.split()[0][2:]  # Remove "AS" prefix
                    org_name = ' '.join(org.split()[1:])
                    return {
                        'asn': asn,
                        'org_name': org_name,
                        'country': data.get('country'),
                        'region': data.get('region'),
                        'city': data.get('city')
                    }
    except Exception:
        pass
    
    try:
        # Intentar con ipapi.co como fallback
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if 'asn' in data:
                return {
                    'asn': str(data['asn']),
                    'org_name': data.get('org', ''),
                    'country': data.get('country_name'),
                    'region': data.get('region'),
                    'city': data.get('city')
                }
    except Exception:
        pass
    
    return None


def get_cloud_provider_info(ip: str, ipinfo_token: str = None, mmdb_path: str = IPINFO_MMDB_PATH, csv_path: str = IPINFO_CSV_PATH) -> Optional[Dict[str, Any]]:
    """Obtiene información específica del proveedor cloud usando múltiples servicios."""
    provider_info = {}
    
    # Primero intentar con base de datos MMDB local
    mmdb_info = get_ip_info_from_mmdb(ip, mmdb_path)
    if mmdb_info:
        provider_info.update(mmdb_info)
        # Detectar proveedor usando información MMDB
        org = provider_info.get('organization', '')
        hostname = provider_info.get('hostname', '')
        
        # Si ya tenemos información suficiente de MMDB, detectar proveedor
        cloud_mappings = {
            'amazon': 'aws',
            'amazonaws': 'aws', 
            'microsoft': 'azure',
            'google': 'gcp',
            'cloudflare': 'cloudflare',
            'akamai': 'akamai',
            'fastly': 'fastly',
            'digitalocean': 'digitalocean',
            'linode': 'linode',
            'vultr': 'vultr',
            'ovh': 'ovh',
            'hetzner': 'hetzner',
            'github': 'github',
            'netlify': 'netlify',
            'vercel': 'vercel',
            'heroku': 'heroku'
        }
        
        # Detectar proveedor por organización
        for keyword, provider in cloud_mappings.items():
            if keyword.lower() in org.lower() or keyword.lower() in hostname.lower():
                provider_info['provider'] = provider
                return provider_info
    
    # Fallback a base de datos CSV local
    csv_info = get_ip_info_from_csv(ip, csv_path)
    if csv_info:
        provider_info.update(csv_info)
        # Detectar proveedor usando información CSV
        org = provider_info.get('organization', '')
        hostname = provider_info.get('hostname', '')
        
        # Si ya tenemos información suficiente de CSV, detectar proveedor
        cloud_mappings = {
            'amazon': 'aws',
            'amazonaws': 'aws', 
            'microsoft': 'azure',
            'google': 'gcp',
            'cloudflare': 'cloudflare',
            'akamai': 'akamai',
            'fastly': 'fastly',
            'digitalocean': 'digitalocean',
            'linode': 'linode',
            'vultr': 'vultr',
            'ovh': 'ovh',
            'hetzner': 'hetzner',
            'github': 'github',
            'netlify': 'netlify',
            'vercel': 'vercel',
            'heroku': 'heroku'
        }
        
        # Detectar proveedor por organización
        for keyword, provider in cloud_mappings.items():
            if keyword.lower() in org.lower() or keyword.lower() in hostname.lower():
                provider_info['provider'] = provider
                return provider_info
    
    # Mapear organizaciones conocidas a proveedores cloud
    cloud_mappings = {
        'amazon': 'aws',
        'amazonaws': 'aws', 
        'microsoft': 'azure',
        'google': 'gcp',
        'cloudflare': 'cloudflare',
        'akamai': 'akamai',
        'fastly': 'fastly',
        'digitalocean': 'digitalocean',
        'linode': 'linode',
        'vultr': 'vultr',
        'ovh': 'ovh',
        'hetzner': 'hetzner',
        'github': 'github',
        'netlify': 'netlify',
        'vercel': 'vercel',
        'heroku': 'heroku'
    }
    
    # 1. Usar ipinfo.io para obtener información detallada
    try:
        # Construir URL con token si está disponible
        if ipinfo_token:
            url = f"https://ipinfo.io/{ip}/json?token={ipinfo_token}"
        else:
            url = f"https://ipinfo.io/{ip}/json"
            
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            org = data.get('org', '')
            
            # Con token obtenemos más información
            provider_info.update({
                'organization': org,
                'asn': data.get('org', '').split()[0] if data.get('org', '').startswith('AS') else None,
                'country': data.get('country'),
                'region': data.get('region'),
                'city': data.get('city'),
                'postal': data.get('postal'),
                'timezone': data.get('timezone'),
                'hostname': data.get('hostname'),
                'anycast': data.get('anycast', False),
                'source': 'ipinfo.io'
            })
            
            # Intentar detectar el proveedor
            for keyword, provider in cloud_mappings.items():
                if keyword.lower() in org.lower():
                    provider_info['provider'] = provider
                    return provider_info
                    
            # Si el token está disponible, verificar campos adicionales
            if ipinfo_token:
                hostname = data.get('hostname', '')
                for keyword, provider in cloud_mappings.items():
                    if keyword.lower() in hostname.lower():
                        provider_info['provider'] = provider
                        return provider_info
                        
        elif response.status_code == 429:
            print(f"[!] Rate limit reached for ipinfo.io. Consider upgrading plan or using token.")
        elif response.status_code == 401:
            print(f"[!] Invalid ipinfo.io token provided.")
            
    except Exception as e:
        print(f"[!] Error querying ipinfo.io: {e}")
        pass
    
    # 2. Usar ip-api.com para verificación adicional
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,org,as,hosting", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                org = data.get('org', '')
                is_hosting = data.get('hosting', False)
                
                # Si es hosting/cloud provider
                if is_hosting:
                    provider_info.update({
                        'organization': org,
                        'asn': data.get('as', '').split()[0] if data.get('as', '').startswith('AS') else None,
                        'country': data.get('country'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'is_hosting': True,
                        'source': 'ip-api.com'
                    })
                    
                    # Intentar mapear a proveedor conocido
                    for keyword, provider in cloud_mappings.items():
                        if keyword.lower() in org.lower():
                            provider_info['provider'] = provider
                            return provider_info
    except Exception:
        pass
    
    # 3. Usar shodan.io si hay API key disponible (opcional)
    shodan_api_key = None  # Configurar si se tiene API key
    if shodan_api_key:
        try:
            response = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={shodan_api_key}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                provider_info.update({
                    'organization': data.get('org'),
                    'isp': data.get('isp'),
                    'asn': data.get('asn'),
                    'country': data.get('country_name'),
                    'region': data.get('region_code'),
                    'city': data.get('city'),
                    'source': 'shodan.io'
                })
        except Exception:
            pass
    
    return provider_info if provider_info else None


def detect_cloud_provider_by_ip(ip: str, ipinfo_token: str = None, mmdb_path: str = IPINFO_MMDB_PATH, csv_path: str = IPINFO_CSV_PATH) -> str:
    """Detecta el proveedor cloud usando servicios externos y patrones."""
    # Primero intentar con servicios externos
    cloud_info = get_cloud_provider_info(ip, ipinfo_token, mmdb_path, csv_path)
    if cloud_info and cloud_info.get('provider'):
        return cloud_info['provider']
    
    # Fallback a detección por patrones
    return guess_provider(ip)


def get_netblock_info(ip: str) -> Optional[Dict[str, Any]]:
    """Obtiene información de netblock para una IP."""
    try:
        # Usar whois para obtener información del netblock
        import ipaddress
        import subprocess
        
        # Ejecutar whois en la IP
        result = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            output = result.stdout
            
            # Buscar líneas que contengan CIDR o netblock
            for line in output.split('\n'):
                line = line.strip()
                if ('CIDR:' in line or 'NetRange:' in line or 'inetnum:' in line) and '/' in line:
                    # Extraer CIDR
                    parts = line.split()
                    for part in parts:
                        if '/' in part:
                            try:
                                # Validar que sea un CIDR válido
                                ipaddress.ip_network(part, strict=False)
                                return {'cidr': part}
                            except ValueError:
                                continue
    except Exception:
        pass
    
    return None


def detect_wildcard_dns(domain: str, resolver: str = "8.8.8.8") -> bool:
    """Detecta si un dominio tiene wildcard DNS configurado."""
    try:
        import random
        import string
        
        # Generar un subdominio aleatorio que no debería existir
        random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        test_domain = f"{random_sub}.{domain}"
        
        # Configurar resolver específico
        test_resolver = dns.resolver.Resolver()
        test_resolver.nameservers = [resolver]
        
        # Intentar resolver el dominio aleatorio
        try:
            answers = test_resolver.resolve(test_domain, 'A')
            if answers:
                print(f"DNS wildcard detected: Resolver {resolver}: *.{domain}")
                return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # Es normal que no exista, no es wildcard
            pass
        except dns.exception.DNSException:
            # Error de DNS, no podemos determinar
            pass
            
    except Exception:
        pass
    
    return False


def fetch_certificate(host: str, port: int = 443, timeout: int = 5
                      ) -> Optional[x509.Certificate]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if der:
                    return x509.load_der_x509_certificate(der)
    except Exception:
        pass
    return None


def cert_to_dict(cert: x509.Certificate) -> dict:
    """Extrae campos de interés del cert X.509."""
    def _get_attr(name):
        try:
            return cert.subject.get_attributes_for_oid(name)[0].value
        except Exception:
            return ""
    issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    san = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        pass
    return {
        "serial": hex(cert.serial_number),
        "issuer": issuer,
        "valid_from": cert.not_valid_before_utc.isoformat(),
        "valid_to": cert.not_valid_after_utc.isoformat(),
        "algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "",
        "san": san,
        "key_size": cert.public_key().key_size
    }


def guess_provider(host_or_ip: str) -> str:
    """Detección avanzada de proveedores de infraestructura."""
    patterns = {
        "akamai": r"\b(akamai|edgekey|akamaiedge|akamaitechnologies|akadns)\b",
        "aws": r"\b(amazonaws|cloudfront|awsdns|awsglobalconfig|elb\.amazonaws|ec2\.amazonaws)\b",
        "azure": r"\b(azure|windows\.net|azuredns|cloudapp\.azure|azurewebsites|trafficmanager)\b",
        "gcp": r"\b(googleapis|googleusercontent|gvt1|ggpht|googlehosted|appspot)\b",
        "cloudflare": r"\b(cloudflare|cf-ipv6)\b",
        "fastly": r"\b(fastly|fastlylb)\b",
        "digitalocean": r"\b(digitalocean|droplet)\b",
        "linode": r"\b(linode|linodeusercontent)\b",
        "heroku": r"\b(heroku|herokuapp)\b",
        "netlify": r"\b(netlify)\b",
        "vercel": r"\b(vercel|now\.sh)\b",
        "github": r"\b(github\.io|githubusercontent)\b",
        "maxcdn": r"\b(maxcdn|stackpathdns)\b",
        "incapsula": r"\b(incapsula|imperva)\b",
        "sucuri": r"\b(sucuri)\b",
        "godaddy": r"\b(godaddy|secureserver)\b",
        "ovh": r"\b(ovh\.net|ovhcloud)\b",
        "hetzner": r"\b(hetzner)\b",
        "vultr": r"\b(vultr)\b"
    }
    
    # Detección por rangos de IP conocidos
    ip_ranges = {
        "cloudflare": [
            r"^104\.1[6-9]\.|^104\.2[0-7]\.",  # 104.16.0.0/12
            r"^172\.64\.|^172\.6[5-7]\.",      # 172.64.0.0/13  
            r"^173\.245\.",                     # 173.245.48.0/20
            r"^108\.162\."                      # 108.162.192.0/18
        ],
        "akamai": [
            r"^23\.(19[2-9]|2[0-5][0-9])\.",   # Varios rangos Akamai
            r"^95\.100\.",
            r"^184\.24\.|^184\.2[5-9]\.",
            r"^104\.94\.|^104\.11[1-9]\."
        ],
        "aws": [
            r"^52\.",                           # Amplio rango AWS
            r"^54\.",
            r"^3\.",
            r"^13\.",
            r"^18\.",
            r"^35\.",
            r"^99\."
        ]
    }
    
    # Primero intentar por nombre de host/dominio
    for prov, pat in patterns.items():
        if re.search(pat, host_or_ip, re.I):
            return prov
    
    # Si parece una IP, intentar detección por rango
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host_or_ip):
        for prov, ranges in ip_ranges.items():
            for range_pattern in ranges:
                if re.match(range_pattern, host_or_ip):
                    return prov
    
    return "unknown"


# --- Persistencia Neo4j ---------------------------------------------------------


class GraphIngester:
    def __init__(self, drv: Driver, ipinfo_token: str = None, mmdb_path: str = IPINFO_MMDB_PATH, csv_path: str = IPINFO_CSV_PATH):
        self.drv = drv
        self.ipinfo_token = ipinfo_token
        self.mmdb_path = mmdb_path
        self.csv_path = csv_path

    # dominios ------------------------------------------------------------------
    def merge_domain(self, fqdn: str, who: Optional[Mapping[str, Any]] = None, tx=None):
        debug_log(f"Creando nodo Domain: {fqdn}")
        if tx is None:
            with self.drv.session() as s:
                with s.begin_transaction() as tx:
                    result = tx.run("""
MERGE (d:Domain {fqdn:$fqdn})
SET d.tld = $tld,
    d.registered_date = coalesce($created, d.registered_date),
    d.expiry_date     = coalesce($expires, d.expiry_date)
RETURN d
""",
                          fqdn=fqdn,
                          tld=fqdn.split('.')[-1],
                          created=who.get("creation_date") if who else None,
                          expires=who.get("expiration_date") if who else None)
                    tx.commit()
        else:
            result = tx.run("""
MERGE (d:Domain {fqdn:$fqdn})
SET d.tld = $tld,
    d.registered_date = coalesce($created, d.registered_date),
    d.expiry_date     = coalesce($expires, d.expiry_date)
RETURN d
""",
                      fqdn=fqdn,
                      tld=fqdn.split('.')[-1],
                      created=who.get("creation_date") if who else None,
                      expires=who.get("expiration_date") if who else None)
        debug_log(f"✓ Nodo Domain creado/actualizado: {fqdn}")

    def relate_subdomain(self, parent: str, child: str, tx=None):
        debug_log(f"Creando relación subdomain: {parent} -> {child}")
        if tx is None:
            with self.drv.session() as s:
                with s.begin_transaction() as tx:
                    tx.run("""
MERGE (p:Domain {fqdn:$parent})
MERGE (c:Domain {fqdn:$child})
MERGE (p)-[:HAS_SUBDOMAIN]->(c)
""", parent=parent, child=child)
                    tx.commit()
        else:
            tx.run("""
MERGE (p:Domain {fqdn:$parent})
MERGE (c:Domain {fqdn:$child})
MERGE (p)-[:HAS_SUBDOMAIN]->(c)
""", parent=parent, child=child)
        debug_log(f"✓ Relación subdomain creada: {parent} -> {child}")

    # ip ------------------------------------------------------------------------
    def merge_ip(self, domain: str, ip: str, tx=None):
        debug_log(f"Creando nodo IP: {ip} para dominio {domain}")
        # Usar detección avanzada de proveedor con token
        prov = detect_cloud_provider_by_ip(ip, self.ipinfo_token, self.mmdb_path, self.csv_path)
        cloud_info = get_cloud_provider_info(ip, self.ipinfo_token, self.mmdb_path, self.csv_path)
        debug_log(f"Proveedor detectado para {ip}: {prov}")
        
        if tx is None:
            with self.drv.session() as s:
                with s.begin_transaction() as tx:
                    # Crear IP con información detallada del proveedor
                    tx.run("""
MERGE (d:Domain {fqdn:$fqdn})
MERGE (i:IP {ip:$ip})
ON CREATE SET i.provider_name = $prov,
              i.organization = $org,
              i.country = $country,
              i.region = $region,
              i.city = $city,
              i.postal = $postal,
              i.timezone = $timezone,
              i.hostname = $hostname,
              i.anycast = $anycast,
              i.detection_source = $source,
              i.detected_at = datetime()
MERGE (d)-[:RESOLVES_TO]->(i)
""", fqdn=domain, ip=ip, prov=prov,
    org=cloud_info.get('organization') if cloud_info else None,
    country=cloud_info.get('country') if cloud_info else None,
    region=cloud_info.get('region') if cloud_info else None,
    city=cloud_info.get('city') if cloud_info else None,
    postal=cloud_info.get('postal') if cloud_info else None,
    timezone=cloud_info.get('timezone') if cloud_info else None,
    hostname=cloud_info.get('hostname') if cloud_info else None,
    anycast=cloud_info.get('anycast') if cloud_info else False,
    source=cloud_info.get('source') if cloud_info else 'pattern_matching')
                    tx.commit()
                    
                    # Si detectamos un proveedor conocido, crear nodo Provider con información detallada
                    if prov != "unknown":
                        self.merge_provider_detailed(prov, ip, cloud_info)
        else:
            # Crear IP con información detallada del proveedor
            tx.run("""
MERGE (d:Domain {fqdn:$fqdn})
MERGE (i:IP {ip:$ip})
ON CREATE SET i.provider_name = $prov,
              i.organization = $org,
              i.country = $country,
              i.region = $region,
              i.city = $city,
              i.postal = $postal,
              i.timezone = $timezone,
              i.hostname = $hostname,
              i.anycast = $anycast,
              i.detection_source = $source,
              i.detected_at = datetime()
MERGE (d)-[:RESOLVES_TO]->(i)
""", fqdn=domain, ip=ip, prov=prov,
    org=cloud_info.get('organization') if cloud_info else None,
    country=cloud_info.get('country') if cloud_info else None,
    region=cloud_info.get('region') if cloud_info else None,
    city=cloud_info.get('city') if cloud_info else None,
    postal=cloud_info.get('postal') if cloud_info else None,
    timezone=cloud_info.get('timezone') if cloud_info else None,
    hostname=cloud_info.get('hostname') if cloud_info else None,
    anycast=cloud_info.get('anycast') if cloud_info else False,
    source=cloud_info.get('source') if cloud_info else 'pattern_matching')
            
            # Si detectamos un proveedor conocido, crear nodo Provider con información detallada
            if prov != "unknown":
                self.merge_provider_detailed(prov, ip, cloud_info, tx)
        debug_log(f"✓ Nodo IP creado: {ip} con proveedor {prov}")

    def merge_provider_detailed(self, provider_name: str, host_or_ip: str, cloud_info: dict = None, tx=None):
        """Crea nodo Provider con información detallada del servicio externo."""
        if tx is None:
            with self.drv.session() as s:
                # Crear nodo Provider con información detallada
                s.run("""
MERGE (p:Provider {name:$provider_name})
ON CREATE SET p.type = 'Cloud',
              p.tier = 1,
              p.detected_from = 'api_service',
              p.created_at = datetime()
ON MATCH SET p.organization = coalesce($org, p.organization),
             p.detection_source = coalesce($source, p.detection_source),
             p.last_verified = datetime()
""", provider_name=provider_name, 
    org=cloud_info.get('organization') if cloud_info else None,
    source=cloud_info.get('source') if cloud_info else 'pattern_matching')
                
                # Si es una IP, crear relación Provider -> IP
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", host_or_ip):
                    s.run("""
MERGE (p:Provider {name:$provider_name})
MERGE (i:IP {ip:$host_or_ip})
MERGE (p)-[:MANAGES {
    detected_at: datetime(),
    confidence: $confidence,
    source: $source
}]->(i)
""", provider_name=provider_name, host_or_ip=host_or_ip,
    confidence='high' if cloud_info and cloud_info.get('source') else 'medium',
    source=cloud_info.get('source') if cloud_info else 'pattern_matching')
                else:
                    # Si es un hostname, crear como Service
                    s.run("""
MERGE (p:Provider {name:$provider_name})
MERGE (svc:Service {name:$host_or_ip, type:'Infrastructure'})
ON CREATE SET svc.category = 'Cloud',
              svc.provider_name = $provider_name,
              svc.detected_at = datetime(),
              svc.organization = $org
MERGE (p)-[:PROVIDES {
    detected_at: datetime(),
    confidence: $confidence,
    source: $source
}]->(svc)
""", provider_name=provider_name, host_or_ip=host_or_ip,
    org=cloud_info.get('organization') if cloud_info else None,
    confidence='high' if cloud_info and cloud_info.get('source') else 'medium',
    source=cloud_info.get('source') if cloud_info else 'pattern_matching')
        else:
            # Crear nodo Provider con información detallada usando transacción pasada
            tx.run("""
MERGE (p:Provider {name:$provider_name})
ON CREATE SET p.type = 'Cloud',
              p.tier = 1,
              p.detected_from = 'api_service',
              p.created_at = datetime()
ON MATCH SET p.organization = coalesce($org, p.organization),
             p.detection_source = coalesce($source, p.detection_source),
             p.last_verified = datetime()
""", provider_name=provider_name, 
    org=cloud_info.get('organization') if cloud_info else None,
    source=cloud_info.get('source') if cloud_info else 'pattern_matching')
            
            # Si es una IP, crear relación Provider -> IP
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", host_or_ip):
                tx.run("""
MERGE (p:Provider {name:$provider_name})
MERGE (i:IP {ip:$host_or_ip})
MERGE (p)-[:MANAGES {
    detected_at: datetime(),
    confidence: $confidence,
    source: $source
}]->(i)
""", provider_name=provider_name, host_or_ip=host_or_ip,
    confidence='high' if cloud_info and cloud_info.get('source') else 'medium',
    source=cloud_info.get('source') if cloud_info else 'pattern_matching')
            else:
                # Si es un hostname, crear como Service
                tx.run("""
MERGE (p:Provider {name:$provider_name})
MERGE (svc:Service {name:$host_or_ip, type:'Infrastructure'})
ON CREATE SET svc.category = 'Cloud',
              svc.provider_name = $provider_name,
              svc.detected_at = datetime(),
              svc.organization = $org
MERGE (p)-[:PROVIDES {
    detected_at: datetime(),
    confidence: $confidence,
    source: $source
}]->(svc)
""", provider_name=provider_name, host_or_ip=host_or_ip,
    org=cloud_info.get('organization') if cloud_info else None,
    confidence='high' if cloud_info and cloud_info.get('source') else 'medium',
    source=cloud_info.get('source') if cloud_info else 'pattern_matching')

    def merge_provider(self, provider_name: str, host_or_ip: str):
        """Crea nodo Provider básico (fallback)."""
        self.merge_provider_detailed(provider_name, host_or_ip, None)

    # dns -----------------------------------------------------------------------
    def merge_dns_record(self, domain: str, rdtype: str, value: str):
        with self.drv.session() as s:
            if rdtype == "NS":
                prov = guess_provider(value)
                # Mejorar con información detallada del proveedor
                cloud_info = get_cloud_provider_info(value, self.ipinfo_token, self.mmdb_path, self.csv_path)
                s.run("""
MERGE (svc:Service {name:$host, type:'DNS'})
ON CREATE SET svc.category = 'Infrastructure',
              svc.hostname = $host,
              svc.provider_name = $prov,
              svc.organization = $org,
              svc.detection_source = $source,
              svc.created_at = datetime()
ON MATCH SET svc.last_verified = datetime()
MERGE (d:Domain {fqdn:$fqdn})
MERGE (d)-[:DEPENDS_ON {dependency_type:'Critical', service_level:'DNS', record_type:'NS', detected_at: datetime()}]->(svc)
MERGE (svc)-[:HOSTS {service_type:'DNS', confidence:'high'}]->(d)
""", host=value, fqdn=domain, prov=prov,
    org=cloud_info.get('organization') if cloud_info else None,
    source=cloud_info.get('source') if cloud_info else 'dns_lookup')
                # Crear nodo Provider si es detectado
                if prov != "unknown":
                    self.merge_provider_detailed(prov, value, cloud_info)
                    
            elif rdtype == "MX":
                prio, host = value.split() if " " in value else ("10", value)
                prov = guess_provider(host)
                # Mejorar con información detallada del proveedor
                cloud_info = get_cloud_provider_info(host, self.ipinfo_token, self.mmdb_path, self.csv_path)
                s.run("""
MERGE (svc:Service {name:$host, type:'Email'})
ON CREATE SET svc.category = 'Infrastructure',
              svc.provider_name = $prov,
              svc.organization = $org,
              svc.detection_source = $source,
              svc.created_at = datetime()
ON MATCH SET svc.last_verified = datetime()
MERGE (d:Domain {fqdn:$fqdn})
MERGE (d)-[:DEPENDS_ON {dependency_type:'Critical', service_level:'MX', priority:toInteger($prio), record_type:'MX', detected_at: datetime()}]->(svc)
MERGE (svc)-[:HOSTS {service_type:'Email', priority:toInteger($prio), confidence:'high'}]->(d)
""", host=host, prov=prov, fqdn=domain, prio=prio,
    org=cloud_info.get('organization') if cloud_info else None,
    source=cloud_info.get('source') if cloud_info else 'dns_lookup')
                # Crear nodo Provider si es detectado
                if prov != "unknown":
                    self.merge_provider_detailed(prov, host, cloud_info)
                    
            elif rdtype == "TXT":
                s.run("MERGE (d:Domain {fqdn:$fqdn}) SET d.txt = coalesce(d.txt,'') + $txt + '\\n'",
                      fqdn=domain, txt=value)
                      
            elif rdtype == "CNAME":
                prov = guess_provider(value)
                cloud_info = get_cloud_provider_info(value, self.ipinfo_token, self.mmdb_path, self.csv_path)
                s.run("""
MERGE (alias:Domain {fqdn:$fqdn})
MERGE (target:Domain {fqdn:$target})
ON CREATE SET target.provider_name = $prov,
              target.organization = $org,
              target.detection_source = $source
MERGE (alias)-[:CNAME_TO {detected_at: datetime()}]->(target)
""", fqdn=domain, target=value, prov=prov,
    org=cloud_info.get('organization') if cloud_info else None,
    source=cloud_info.get('source') if cloud_info else 'dns_lookup')
                # Crear nodo Provider si es detectado
                if prov != "unknown":
                    self.merge_provider_detailed(prov, value, cloud_info)
                    
            elif rdtype == "PTR":
                s.run("""
MERGE (i:IP {ip:$ip})
MERGE (d:Domain {fqdn:$fqdn})
MERGE (i)-[:PTR_TO]->(d)
""", ip=domain, fqdn=value)

    # tls -----------------------------------------------------------------------
    def merge_certificate(self, domain: str, certinfo: Mapping[str, Any]):
        with self.drv.session() as s:
            s.run("""
MERGE (c:Certificate {serial_number:$serial})
SET c.issuer_cn=$issuer,
    c.valid_from=datetime($valid_from),
    c.valid_to=datetime($valid_to),
    c.signature_algorithm=$alg,
    c.key_size=$key
WITH c
MATCH (d:Domain {fqdn:$fqdn})
MERGE (d)-[:SECURED_BY]->(c)
""", fqdn=domain, serial=certinfo["serial"], issuer=certinfo["issuer"],
                   valid_from=certinfo["valid_from"], valid_to=certinfo["valid_to"],
                   alg=certinfo["algorithm"], key=certinfo["key_size"])

    # service-domain relationships ----------------------------------------------
    def merge_service_domain_relationship(self, service_name: str, service_type: str, domain: str, relationship_type: str = "HOSTS"):
        """Crea relaciones bidireccionales entre servicios y dominios/subdominios."""
        with self.drv.session() as s:
            s.run("""
MERGE (svc:Service {name:$service_name, type:$service_type})
MERGE (d:Domain {fqdn:$domain})
MERGE (svc)-[:""" + relationship_type + """ {
    detected_at: datetime(),
    confidence: 'high'
}]->(d)
MERGE (d)-[:DEPENDS_ON {
    dependency_type: 'Critical',
    service_type: $service_type,
    detected_at: datetime()
}]->(svc)
""", service_name=service_name, service_type=service_type, domain=domain)

    def associate_service_with_subdomains(self, service_name: str, service_type: str, parent_domain: str):
        """Asocia un servicio con todos los subdominios de un dominio padre."""
        with self.drv.session() as s:
            # Encontrar todos los subdominios del dominio padre
            result = s.run("""
MATCH (parent:Domain {fqdn:$parent_domain})-[:HAS_SUBDOMAIN]->(subdomain:Domain)
RETURN subdomain.fqdn as subdomain_fqdn
""", parent_domain=parent_domain)
            
            # Asociar el servicio con cada subdominio
            for record in result:
                subdomain = record["subdomain_fqdn"]
                self.merge_service_domain_relationship(service_name, service_type, subdomain, "HOSTS")

    def process_service_subdomain_associations(self, domain: str):
        """Procesa automáticamente las asociaciones de servicios con subdominios después del descubrimiento."""
        with self.drv.session() as s:
            # Encontrar todos los servicios asociados con el dominio padre
            result = s.run("""
MATCH (parent:Domain {fqdn:$domain})-[:DEPENDS_ON]->(svc:Service)
RETURN svc.name as service_name, svc.type as service_type
""", domain=domain)
            
            # Para cada servicio, asociarlo con todos los subdominios
            for record in result:
                service_name = record["service_name"]
                service_type = record["service_type"]
                self.associate_service_with_subdomains(service_name, service_type, domain)

    def enhance_provider_relationships(self):
        """Mejora las relaciones entre proveedores y servicios basándose en patrones de organización."""
        with self.drv.session() as s:
            # Encontrar servicios sin proveedor asignado pero con organización
            s.run("""
MATCH (svc:Service) 
WHERE svc.provider_name IS NULL AND svc.organization IS NOT NULL
WITH svc, svc.organization as org
MERGE (p:Provider {name: org})
ON CREATE SET p.type = 'Inferred',
              p.tier = 2,
              p.detected_from = 'organization_analysis',
              p.created_at = datetime()
MERGE (p)-[:PROVIDES {
    detected_at: datetime(),
    confidence: 'medium',
    source: 'organization_analysis'
}]->(svc)
SET svc.provider_name = org
""")

    # asn/netblock/organization -------------------------------------------------
    def merge_asn(self, asn: str, org_name: str = None):
        with self.drv.session() as s:
            s.run("""
MERGE (a:ASN {asn:$asn})
ON CREATE SET a.org_name = $org_name
""", asn=asn, org_name=org_name)

    def merge_netblock(self, netblock: str, asn: str = None):
        with self.drv.session() as s:
            s.run("""
MERGE (n:Netblock {cidr:$netblock})
""", netblock=netblock)
            if asn:
                s.run("""
MERGE (a:ASN {asn:$asn})
MERGE (n:Netblock {cidr:$netblock})
MERGE (a)-[:ANNOUNCES]->(n)
""", asn=asn, netblock=netblock)

    def merge_ip_netblock(self, ip: str, netblock: str):
        with self.drv.session() as s:
            s.run("""
MERGE (i:IP {ip:$ip})
MERGE (n:Netblock {cidr:$netblock})
MERGE (n)-[:CONTAINS]->(i)
""", ip=ip, netblock=netblock)

    def merge_asn_org(self, asn: str, org_name: str):
        with self.drv.session() as s:
            s.run("""
MERGE (a:ASN {asn:$asn})
MERGE (o:Organization {name:$org_name, type:'RIROrganization'})
MERGE (a)-[:MANAGED_BY]->(o)
""", asn=asn, org_name=org_name)
    
    def merge_organization(self, org_name: str, org_type: str = 'RIROrganization'):
        with self.drv.session() as s:
            s.run("""
MERGE (o:Organization {name:$org_name})
ON CREATE SET o.type = $org_type,
              o.created_at = datetime()
""", org_name=org_name, org_type=org_type)
    
    # Métodos para procesar datos complejos de AMASS
    def process_amass_data(self, asn_data: dict, netblock_data: dict, org_data: dict):
        """Procesa todos los datos de ASN, Netblock y Organizaciones de AMASS."""
        # Crear organizaciones
        for org_name, org_info in org_data.items():
            self.merge_organization(org_name, org_info.get('type', 'RIROrganization'))
        
        # Crear ASNs y sus relaciones con organizaciones
        for asn, asn_info in asn_data.items():
            org_name = asn_info.get('organization')
            self.merge_asn(asn, org_name)
            if org_name:
                self.merge_asn_org(asn, org_name)
            
            # Crear netblocks anunciados por este ASN
            for netblock in asn_info.get('netblocks', []):
                self.merge_netblock(netblock, asn)
        
        # Crear relaciones netblock -> IP
        for netblock, nb_info in netblock_data.items():
            for ip in nb_info.get('ips', []):
                self.merge_ip_netblock(ip, netblock)
    
    def process_dns_records(self, domain: str, dns_records: list):
        """Procesa todos los registros DNS de un dominio."""
        for record in dns_records:
            if record['type'] in ['CNAME', 'MX', 'NS', 'PTR']:
                self.merge_dns_record(domain, record['type'], record['target'])
            elif record['type'] in ['A', 'AAAA']:
                # Ya se procesa en merge_ip
                pass

    # wildcard detection -------------------------------------------------------
    def log_wildcard_detection(self, domain: str, resolver: str):
        with self.drv.session() as s:
            s.run("""
MERGE (d:Domain {fqdn:$domain})
SET d.wildcard_detected = true,
    d.wildcard_resolver = $resolver,
    d.wildcard_timestamp = datetime()
""", domain=domain, resolver=resolver)


# --- Carga masiva --------------------------------------------------------------

def enrich_and_ingest_domain_transaction(domain: str, depth: int, ing: GraphIngester,
                                        queue_manager: SQLiteQueueManager, sample_mode: bool = False, 
                                        worker_id: str = None, amass_results: List[dict] = None) -> dict:
    """Procesa un dominio completo usando una sola transacción para mejor consistencia."""
    start_time = time.time()
    stats = {
        'subdomain_count': 0,
        'ip_count': 0,
        'error_count': 0,
        'processing_time': 0
    }
    debug_log(f"[{worker_id}] Iniciando procesamiento con transacción única para {domain} (depth={depth})")

    # WHOIS (opcional, ignora errores)
    try:
        w = whois.whois(domain)
    except Exception:
        w = {}

    # Usar una sola transacción para todo el procesamiento del dominio
    with ing.drv.session() as s:
        with s.begin_transaction() as tx:
            try:
                # Crear el dominio principal
                ing.merge_domain(domain, w, tx)

                # Detectar wildcard DNS
                if detect_wildcard_dns(domain):
                    tx.run("""
MERGE (d:Domain {fqdn:$domain})
SET d.wildcard_detected = true,
    d.wildcard_resolver = '8.8.8.8',
    d.wildcard_timestamp = datetime()
""", domain=domain)

                # DNS A/AAAA + ASN/Netblock enrichment
                for rdtype in ("A", "AAAA"):
                    for addr in dns_query(domain, rdtype):
                        ing.merge_ip(domain, addr, tx)
                        stats['ip_count'] += 1
                        
                        # Enriquecer con información de ASN
                        asn_info = get_asn_info(addr, ing.mmdb_path, ing.csv_path)
                        if asn_info and asn_info.get('asn'):
                            asn = asn_info['asn']
                            org_name = asn_info.get('org_name', '')
                            tx.run("MERGE (a:ASN {asn:$asn}) ON CREATE SET a.org_name = $org_name", asn=asn, org_name=org_name)
                            if org_name:
                                tx.run("""
MERGE (a:ASN {asn:$asn})
MERGE (o:Organization {name:$org_name, type:'RIROrganization'})
MERGE (a)-[:MANAGED_BY]->(o)
""", asn=asn, org_name=org_name)
                        
                        # Enriquecer con información de netblock
                        netblock_info = get_netblock_info(addr)
                        if netblock_info:
                            asn = asn_info.get('asn') if asn_info else None
                            tx.run("MERGE (n:Netblock {cidr:$netblock})", netblock=netblock_info['cidr'])
                            if asn:
                                tx.run("""
MERGE (a:ASN {asn:$asn})
MERGE (n:Netblock {cidr:$netblock})
MERGE (a)-[:ANNOUNCES]->(n)
""", asn=asn, netblock=netblock_info['cidr'])
                            tx.run("""
MERGE (i:IP {ip:$ip})
MERGE (n:Netblock {cidr:$netblock})
MERGE (n)-[:CONTAINS]->(i)
""", ip=addr, netblock=netblock_info['cidr'])

                # NS / MX / TXT / CNAME - procesar dentro de la transacción
                for rtype in ("NS", "MX", "TXT", "CNAME"):
                    for rec in dns_query(domain, rtype):
                        if rtype == "NS":
                            prov = guess_provider(rec)
                            cloud_info = get_cloud_provider_info(rec, ing.ipinfo_token, ing.mmdb_path, ing.csv_path)
                            tx.run("""
MERGE (svc:Service {name:$host, type:'DNS'})
ON CREATE SET svc.category = 'Infrastructure',
              svc.hostname = $host,
              svc.provider_name = $prov,
              svc.organization = $org,
              svc.detection_source = $source,
              svc.created_at = datetime()
ON MATCH SET svc.last_verified = datetime()
MERGE (d:Domain {fqdn:$fqdn})
MERGE (d)-[:DEPENDS_ON {dependency_type:'Critical', service_level:'DNS', record_type:'NS', detected_at: datetime()}]->(svc)
MERGE (svc)-[:HOSTS {service_type:'DNS', confidence:'high'}]->(d)
""", host=rec, fqdn=domain, prov=prov,
    org=cloud_info.get('organization') if cloud_info else None,
    source=cloud_info.get('source') if cloud_info else 'dns_lookup')
                            # Crear nodo Provider si es detectado
                            if prov != "unknown":
                                ing.merge_provider_detailed(prov, rec, cloud_info, tx)
                        elif rtype == "MX":
                            prio, host = rec.split() if " " in rec else ("10", rec)
                            prov = guess_provider(host)
                            cloud_info = get_cloud_provider_info(host, ing.ipinfo_token, ing.mmdb_path, ing.csv_path)
                            tx.run("""
MERGE (svc:Service {name:$host, type:'Email'})
ON CREATE SET svc.category = 'Infrastructure',
              svc.provider_name = $prov,
              svc.organization = $org,
              svc.detection_source = $source,
              svc.created_at = datetime()
ON MATCH SET svc.last_verified = datetime()
MERGE (d:Domain {fqdn:$fqdn})
MERGE (d)-[:DEPENDS_ON {dependency_type:'Critical', service_level:'MX', priority:toInteger($prio), record_type:'MX', detected_at: datetime()}]->(svc)
MERGE (svc)-[:HOSTS {service_type:'Email', priority:toInteger($prio), confidence:'high'}]->(d)
""", host=host, prov=prov, fqdn=domain, prio=prio,
    org=cloud_info.get('organization') if cloud_info else None,
    source=cloud_info.get('source') if cloud_info else 'dns_lookup')
                            # Crear nodo Provider si es detectado
                            if prov != "unknown":
                                ing.merge_provider_detailed(prov, host, cloud_info, tx)
                        elif rtype == "TXT":
                            tx.run("MERGE (d:Domain {fqdn:$fqdn}) SET d.txt = coalesce(d.txt,'') + $txt + '\\n'", fqdn=domain, txt=rec)
                        elif rtype == "CNAME":
                            prov = guess_provider(rec)
                            cloud_info = get_cloud_provider_info(rec, ing.ipinfo_token, ing.mmdb_path, ing.csv_path)
                            tx.run("""
MERGE (alias:Domain {fqdn:$fqdn})
MERGE (target:Domain {fqdn:$target})
ON CREATE SET target.provider_name = $prov,
              target.organization = $org,
              target.detection_source = $source
MERGE (alias)-[:CNAME_TO {detected_at: datetime()}]->(target)
""", fqdn=domain, target=rec, prov=prov,
    org=cloud_info.get('organization') if cloud_info else None,
    source=cloud_info.get('source') if cloud_info else 'dns_lookup')
                            # Crear nodo Provider si es detectado
                            if prov != "unknown":
                                ing.merge_provider_detailed(prov, rec, cloud_info, tx)

                # Certificado TLS
                cert = fetch_certificate(domain)
                if cert:
                    cert_dict = cert_to_dict(cert)
                    tx.run("""
MERGE (c:Certificate {serial_number:$serial})
SET c.issuer_cn=$issuer,
    c.valid_from=datetime($valid_from),
    c.valid_to=datetime($valid_to),
    c.signature_algorithm=$alg,
    c.key_size=$key
WITH c
MATCH (d:Domain {fqdn:$fqdn})
MERGE (d)-[:SECURED_BY]->(c)
""", fqdn=domain, serial=cert_dict["serial"], issuer=cert_dict["issuer"],
                           valid_from=cert_dict["valid_from"], valid_to=cert_dict["valid_to"],
                           alg=cert_dict["algorithm"], key=cert_dict["key_size"])

                # Procesar subdominios descubiertos por Amass
                if amass_results:
                    # Procesar datos de ASN, Netblocks y Organizaciones una sola vez
                    first_entry = amass_results[0]
                    if 'asn_data' in first_entry:
                        # Procesar organizaciones
                        for org_name, org_info in first_entry.get('org_data', {}).items():
                            tx.run("""
MERGE (o:Organization {name:$org_name})
ON CREATE SET o.type = $org_type,
              o.created_at = datetime()
""", org_name=org_name, org_type=org_info.get('type', 'RIROrganization'))
                        
                        # Procesar ASNs
                        for asn, asn_info in first_entry.get('asn_data', {}).items():
                            org_name = asn_info.get('organization')
                            tx.run("MERGE (a:ASN {asn:$asn}) ON CREATE SET a.org_name = $org_name", asn=asn, org_name=org_name)
                            if org_name:
                                tx.run("""
MERGE (a:ASN {asn:$asn})
MERGE (o:Organization {name:$org_name, type:'RIROrganization'})
MERGE (a)-[:MANAGED_BY]->(o)
""", asn=asn, org_name=org_name)
                    
                    for entry in amass_results:
                        name = entry.get("name")
                        if name and name != domain:
                            # Crear subdominio
                            ing.merge_domain(name, {}, tx)
                            
                            # Verificar si es un subdominio directo
                            parent = entry.get("parent")
                            if parent:
                                ing.relate_subdomain(parent, name, tx)
                            else:
                                ing.relate_subdomain(domain, name, tx)
                            
                            # Siempre registrar el subdominio descubierto
                            debug_log(f"[{worker_id}] Registrando subdominio: {domain} -> {name}")
                            stats['subdomain_count'] += 1
                            
                            # Procesar direcciones IP
                            for addr in entry.get("addresses", []):
                                ip = addr.get("ip")
                                if ip:
                                    ing.merge_ip(name, ip, tx)
                                    stats['ip_count'] += 1
                            
                            # Procesar registros DNS adicionales
                            dns_records = entry.get("dns_records", [])
                            for record in dns_records:
                                if record['type'] in ['CNAME', 'MX', 'NS', 'PTR']:
                                    # Procesar dentro de la transacción
                                    if record['type'] == "NS":
                                        prov = guess_provider(record['target'])
                                        tx.run("""
MERGE (svc:Service {name:$host, type:'DNS'})
ON CREATE SET svc.category = 'Infrastructure',
              svc.hostname = $host,
              svc.provider_name = $prov
MERGE (d:Domain {fqdn:$fqdn})
MERGE (d)-[:DEPENDS_ON {dependency_type:'Critical', service_level:'DNS', record_type:'NS'}]->(svc)
""", host=record['target'], fqdn=name, prov=prov)
                
                # Commit de la transacción completa
                tx.commit()
                debug_log(f"[{worker_id}] ✓ Transacción completa para {domain}")
                
            except Exception as e:
                debug_log(f"[{worker_id}] ✗ Error en transacción para {domain}: {e}")
                tx.rollback()
                stats['error_count'] += 1
                raise e

    # Ahora agregar a la cola fuera de la transacción
    if amass_results:
        for entry in amass_results:
            name = entry.get("name")
            if name and name != domain:
                # Registrar en SQLite
                success = queue_manager.add_discovered_domain(domain, name, 'amass')
                if success:
                    debug_log(f"[{worker_id}] ✓ Registrado en SQLite: {name}")
                else:
                    debug_log(f"[{worker_id}] ! Ya existe en SQLite: {name}")
                
                # Agregar a cola solo si tenemos profundidad restante
                if depth > 0:
                    debug_log(f"[{worker_id}] Agregando a cola: {name} (depth={depth-1})")
                    queue_manager.add_domain(name, depth - 1)
                else:
                    debug_log(f"[{worker_id}] Subdominio descubierto (sin profundidad): {name}")

    # Procesar asociaciones automáticas de servicios con subdominios
    try:
        ing.process_service_subdomain_associations(domain)
        debug_log(f"[{worker_id}] ✓ Procesadas asociaciones servicio-subdominio para {domain}")
    except Exception as e:
        debug_log(f"[{worker_id}] ! Error procesando asociaciones servicio-subdominio: {e}")
    
    # Mejorar relaciones de proveedores
    try:
        ing.enhance_provider_relationships()
        debug_log(f"[{worker_id}] ✓ Mejoradas relaciones de proveedores")
    except Exception as e:
        debug_log(f"[{worker_id}] ! Error mejorando relaciones de proveedores: {e}")

    # Calculate processing time
    stats['processing_time'] = time.time() - start_time
    debug_log(f"[{worker_id}] ✓ Completado {domain} en {stats['processing_time']:.2f}s")
    
    return stats


def enrich_and_ingest_sqlite(domain: str, depth: int, ing: GraphIngester,
                            queue_manager: SQLiteQueueManager, sample_mode: bool = False, 
                            worker_id: str = None) -> dict:
    """Resuelve DNS, obtiene TLS y carga todo en Neo4j usando SQLite queue."""
    start_time = time.time()
    stats = {
        'subdomain_count': 0,
        'ip_count': 0,
        'error_count': 0,
        'processing_time': 0
    }
    debug_log(f"[{worker_id}] Iniciando procesamiento de {domain} (depth={depth})")

    # WHOIS (opcional, ignora errores)
    try:
        w = whois.whois(domain)
    except Exception:
        w = {}

    ing.merge_domain(domain, w)

    # Detectar wildcard DNS
    if detect_wildcard_dns(domain):
        ing.log_wildcard_detection(domain, "8.8.8.8")

    # DNS A/AAAA + ASN/Netblock enrichment
    for rdtype in ("A", "AAAA"):
        for addr in dns_query(domain, rdtype):
            ing.merge_ip(domain, addr)
            
            # Enriquecer con información de ASN
            asn_info = get_asn_info(addr, ing.mmdb_path, ing.csv_path)
            if asn_info and asn_info.get('asn'):
                asn = asn_info['asn']
                org_name = asn_info.get('org_name', '')
                ing.merge_asn(asn, org_name)
                if org_name:
                    ing.merge_asn_org(asn, org_name)
            
            # Enriquecer con información de netblock
            netblock_info = get_netblock_info(addr)
            if netblock_info:
                asn = asn_info.get('asn') if asn_info else None
                ing.merge_netblock(netblock_info['cidr'], asn)
                ing.merge_ip_netblock(addr, netblock_info['cidr'])

    # NS / MX / TXT / CNAME
    for rtype in ("NS", "MX", "TXT", "CNAME"):
        for rec in dns_query(domain, rtype):
            ing.merge_dns_record(domain, rtype, rec)
    
    # PTR records (reverse DNS lookup para IPs encontradas)
    for rdtype in ("A", "AAAA"):
        for addr in dns_query(domain, rdtype):
            try:
                ptr_records = dns_query(addr, "PTR")
                for ptr in ptr_records:
                    ing.merge_dns_record(addr, "PTR", ptr)
            except Exception:
                pass

    # Certificado TLS
    cert = fetch_certificate(domain)
    if cert:
        ing.merge_certificate(domain, cert_to_dict(cert))

    # Encola subdominios descubiertos por Amass
    try:
        amass_results = run_amass_local(domain, sample_mode)
        if amass_results:
            # Procesar datos de ASN, Netblocks y Organizaciones una sola vez
            first_entry = amass_results[0]
            if 'asn_data' in first_entry:
                ing.process_amass_data(
                    first_entry.get('asn_data', {}),
                    first_entry.get('netblock_data', {}),
                    first_entry.get('org_data', {})
                )
            
            for entry in amass_results:
                name = entry.get("name")
                if name and name != domain:
                    # Verificar si es un subdominio directo
                    parent = entry.get("parent")
                    if parent:
                        ing.relate_subdomain(parent, name)
                    else:
                        ing.relate_subdomain(domain, name)
                    # Siempre registrar el subdominio descubierto
                    debug_log(f"[{worker_id}] Intentando registrar: {domain} -> {name}")
                    success = queue_manager.add_discovered_domain(domain, name, 'amass')
                    if success:
                        debug_log(f"[{worker_id}] ✓ Registrado subdominio: {name}")
                    else:
                        debug_log(f"[{worker_id}] ! Ya existe subdominio: {name}")
                    stats['subdomain_count'] += 1
                    
                    # Agregar a cola solo si tenemos profundidad restante
                    if depth > 0:
                        debug_log(f"[{worker_id}] Agregando a cola: {name} (depth={depth-1})")
                        queue_manager.add_domain(name, depth - 1)
                    else:
                        debug_log(f"[{worker_id}] Subdominio descubierto (sin profundidad): {name}")
                
                # Procesar direcciones IP (incluyendo IPv6)
                for addr in entry.get("addresses", []):
                    ip = addr.get("ip")
                    if ip:
                        ing.merge_ip(name or domain, ip)
                        stats['ip_count'] += 1
                
                # Procesar registros DNS adicionales
                dns_records = entry.get("dns_records", [])
                if dns_records:
                    ing.process_dns_records(name or domain, dns_records)
                    
    except subprocess.CalledProcessError as e:
        error_msg = f"Amass error for {domain}: {e}"
        print(f"[!] {error_msg}", file=sys.stderr)
        stats['error_count'] += 1
    except Exception as e:
        error_msg = f"General error processing {domain}: {e}"
        print(f"[!] {error_msg}", file=sys.stderr)
        stats['error_count'] += 1
    
    # Calculate processing time
    stats['processing_time'] = time.time() - start_time
    debug_log(f"[{worker_id}] ✓ Completado {domain} en {stats['processing_time']:.2f}s")
    
    return stats


def enrich_and_ingest_with_amass_results_sqlite(domain: str, depth: int, ing: GraphIngester,
                                               queue_manager: SQLiteQueueManager, 
                                               sample_mode: bool = False, 
                                               worker_id: str = None,
                                               amass_results: List[dict] = None) -> dict:
    """Versión optimizada que usa resultados de Amass ya obtenidos con SQLite queue."""
    start_time = time.time()
    stats = {
        'subdomain_count': 0,
        'ip_count': 0,
        'error_count': 0,
        'processing_time': 0
    }
    debug_log(f"[{worker_id}] Iniciando enriquecimiento para {domain} con {len(amass_results or [])} resultados de Amass")

    # WHOIS (opcional, ignora errores)
    try:
        w = whois.whois(domain)
    except Exception:
        w = {}

    ing.merge_domain(domain, w)

    # Detectar wildcard DNS
    if detect_wildcard_dns(domain):
        ing.log_wildcard_detection(domain, "8.8.8.8")

    # DNS A/AAAA + ASN/Netblock enrichment
    for rdtype in ("A", "AAAA"):
        for addr in dns_query(domain, rdtype):
            ing.merge_ip(domain, addr)
            
            # Enriquecer con información de ASN
            asn_info = get_asn_info(addr, ing.mmdb_path, ing.csv_path)
            if asn_info and asn_info.get('asn'):
                asn = asn_info['asn']
                org_name = asn_info.get('org_name', '')
                ing.merge_asn(asn, org_name)
                if org_name:
                    ing.merge_asn_org(asn, org_name)
            
            # Enriquecer con información de netblock
            netblock_info = get_netblock_info(addr)
            if netblock_info:
                asn = asn_info.get('asn') if asn_info else None
                ing.merge_netblock(netblock_info['cidr'], asn)
                ing.merge_ip_netblock(addr, netblock_info['cidr'])

    # NS / MX / TXT / CNAME
    for rtype in ("NS", "MX", "TXT", "CNAME"):
        for rec in dns_query(domain, rtype):
            ing.merge_dns_record(domain, rtype, rec)
    
    # PTR records (reverse DNS lookup para IPs encontradas)
    for rdtype in ("A", "AAAA"):
        for addr in dns_query(domain, rdtype):
            try:
                ptr_records = dns_query(addr, "PTR")
                for ptr in ptr_records:
                    ing.merge_dns_record(addr, "PTR", ptr)
            except Exception:
                pass

    # Certificado TLS
    cert = fetch_certificate(domain)
    if cert:
        ing.merge_certificate(domain, cert_to_dict(cert))

    # Usar resultados de Amass ya obtenidos (en lugar de ejecutar Amass nuevamente)
    subdominios_encontrados = 0
    if amass_results:
        debug_log(f"Procesando {len(amass_results)} entradas de Amass para {domain}")
        
        # Procesar datos de ASN, Netblocks y Organizaciones una sola vez
        first_entry = amass_results[0]
        if 'asn_data' in first_entry:
            ing.process_amass_data(
                first_entry.get('asn_data', {}),
                first_entry.get('netblock_data', {}),
                first_entry.get('org_data', {})
            )
        
        for entry in amass_results:
            name = entry.get("name")
            if name and name != domain:
                subdominios_encontrados += 1
                debug_log(f"Subdominio encontrado: {name}")
                
                # Verificar si es un subdominio directo
                parent = entry.get("parent")
                if parent:
                    ing.relate_subdomain(parent, name)
                else:
                    ing.relate_subdomain(domain, name)
                # Siempre registrar el subdominio descubierto
                debug_log(f"[{worker_id}] Intentando registrar: {domain} -> {name}")
                success = queue_manager.add_discovered_domain(domain, name, 'amass')
                if success:
                    debug_log(f"[{worker_id}] ✓ Registrado subdominio: {name}")
                else:
                    debug_log(f"[{worker_id}] ! Ya existe subdominio: {name}")
                stats['subdomain_count'] += 1
                
                # Agregar a cola solo si tenemos profundidad restante
                if depth > 0:
                    debug_log(f"[{worker_id}] Agregando a cola: {name} (depth={depth-1})")
                    queue_manager.add_domain(name, depth - 1)
                else:
                    debug_log(f"[{worker_id}] Subdominio descubierto (sin profundidad): {name}")
            
            # Procesar direcciones IP (incluyendo IPv6)
            for addr in entry.get("addresses", []):
                ip = addr.get("ip")
                if ip:
                    debug_log(f"[{worker_id}] IP encontrada: {ip} para {name or domain}")
                    ing.merge_ip(name or domain, ip)
                    stats['ip_count'] += 1
            
            # Procesar registros DNS adicionales
            dns_records = entry.get("dns_records", [])
            if dns_records:
                debug_log(f"[{worker_id}] Procesando {len(dns_records)} registros DNS para {name or domain}")
                ing.process_dns_records(name or domain, dns_records)
    
    # Calculate processing time
    stats['processing_time'] = time.time() - start_time
    debug_log(f"[{worker_id}] ✓ Enriquecimiento completado para {domain}: {subdominios_encontrados} subdominios encontrados en {stats['processing_time']:.2f}s")
    
    return stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domains", required=True,
                    help="Archivo con dominios semilla (uno por línea)")
    ap.add_argument("--depth", type=int, default=1,
                    help="Profundidad de recursión")
    ap.add_argument("--sample", action="store_true",
                    help="Modo prueba: procesa solo el primer dominio con ejecución rápida")
    ap.add_argument("--bolt", default="bolt://localhost:7687")
    ap.add_argument("--user", default="neo4j")
    ap.add_argument("--password", default="test.password")
    ap.add_argument("--ipinfo-token", 
                    help="Token de ipinfo.io para obtener información detallada de IPs (opcional)",default="0bf607ce2c13ac")
    ap.add_argument("--mmdb-path", default=IPINFO_MMDB_PATH,
                    help="Ruta al archivo MMDB de IPinfo para consultas locales (opcional)")
    ap.add_argument("--csv-path", default=IPINFO_CSV_PATH,
                    help="Ruta al archivo CSV de IPinfo para consultas locales (opcional)")
    ap.add_argument("--threads", type=int, default=4,
                    help="Número de threads para procesamiento paralelo (default: 4)")
    ap.add_argument("--amass-processes", type=int, default=2,
                    help="Número de procesos paralelos para Amass (default: 2)")
    ap.add_argument("--batch-size", type=int, default=10,
                    help="Tamaño del lote para procesamiento paralelo de Amass (default: 10)")
    ap.add_argument("--db-path", default=DB_PATH,
                    help="Ruta a la base de datos SQLite para cola de procesamiento")
    ap.add_argument("--reset-db", action="store_true",
                    help="Resetear la base de datos SQLite (eliminar progreso anterior)")
    ap.add_argument("--stats-interval", type=int, default=30,
                    help="Intervalo en segundos para mostrar estadísticas (default: 30)")
    ap.add_argument("--amass-timeout", type=int, default=30,
                    help="Timeout para Amass en modo sample (default: 30)")
    ap.add_argument("--amass-passive", action="store_true",
                    help="Usar solo fuentes pasivas en Amass (más rápido)")
    ap.add_argument("--disable-amass", action="store_true",
                    help="Deshabilitar Amass y usar solo fallbacks")
    ap.add_argument("--enable-dns-enum", action="store_true", default=True,
                    help="Habilitar enumeración DNS básica como fallback")
    args = ap.parse_args()

    # Initialize SQLite queue manager
    if args.reset_db and Path(args.db_path).exists():
        Path(args.db_path).unlink()
        print(f"[*] Base de datos SQLite resetada: {args.db_path}")
    
    queue_manager = SQLiteQueueManager(args.db_path)
    
    # Load seed domains
    seeds = [d.strip() for d in Path(args.domains).read_text().splitlines() if d.strip()]
    
    # En modo sample, usar solo el primer dominio
    if args.sample:
        seeds = seeds[:1]
        print(f"[*] Modo sample: procesando solo {seeds[0]}")
    
    # Add seed domains to queue
    added_count = 0
    for domain in seeds:
        if queue_manager.add_domain(domain, args.depth, priority=10):  # High priority for seeds
            added_count += 1
    
    print(f"[*] Agregados {added_count} dominios semilla a la cola")
    
    # Clean up any stale processing domains
    queue_manager.cleanup_stale_processing()
    
    # Show initial stats
    initial_stats = queue_manager.get_queue_stats()
    print(f"[*] Estado inicial de la cola: {initial_stats}")

    # Initialize Neo4j connection
    driver = GraphDatabase.driver(args.bolt, auth=(args.user, args.password))
    ing = GraphIngester(driver, args.ipinfo_token, args.mmdb_path, args.csv_path)
    
    # Print configuration
    if args.ipinfo_token:
        print(f"[*] Usando token de ipinfo.io para detección avanzada de proveedores")
    else:
        print(f"[*] Usando detección básica de proveedores (sin token ipinfo.io)")
    
    if Path(args.mmdb_path).exists():
        print(f"[*] Base de datos MMDB encontrada: {args.mmdb_path}")
    elif Path(args.csv_path).exists():
        print(f"[*] Base de datos CSV encontrada: {args.csv_path}")
    else:
        print(f"[*] Bases de datos locales no encontradas - usando solo servicios online")

    print(f"[*] Usando {args.threads} threads para procesamiento paralelo")
    print(f"[*] Base de datos SQLite: {args.db_path}")
    print(f"[*] Estadísticas cada {args.stats_interval} segundos")
    
    # Mostrar configuración de discovery
    if args.disable_amass:
        print(f"[*] Amass: DESHABILITADO")
    else:
        mode = "pasivo" if args.amass_passive else "activo"
        print(f"[*] Amass: habilitado (modo {mode}, timeout {args.amass_timeout}s)")
    
    print(f"[*] DNS enum: {'habilitado' if args.enable_dns_enum else 'deshabilitado'}")

    # Cache global de resultados de Amass para evitar re-ejecución
    amass_cache = {}
    amass_cache_lock = threading.Lock()
    
    # Worker statistics
    worker_stats = {}
    worker_stats_lock = threading.Lock()
    
    # Shutdown flag
    shutdown_flag = threading.Event()
    
    def run_subfinder_fallback(domain: str) -> List[dict]:
        """Fallback usando subfinder si está disponible."""
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
                
                # Parsear output de subfinder (formato simple: un dominio por línea)
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
            print(f"[SUBFINDER] Not available or failed for {domain}")
            return []

    def run_basic_dns_enumeration(domain: str) -> List[dict]:
        """Fallback básico usando DNS común."""
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'dns', 'dns1', 'dns2',
            'mx', 'mx1', 'mx2', 'ns', 'test', 'staging', 'dev', 'www2', 'admin', 'api',
            'blog', 'shop', 'forum', 'help', 'support', 'secure', 'ssl', 'app', 'mobile'
        ]
        
        entries = []
        print(f"[DNS ENUM] Testing common subdomains for {domain}")
        
        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                # Intentar resolver DNS
                socket.gethostbyname(subdomain)
                entries.append({
                    "name": subdomain,
                    "parent": domain
                })
                print(f"[DNS ENUM] Found: {subdomain}")
            except socket.gaierror:
                # Subdominio no existe
                pass
            except Exception:
                # Otros errores DNS
                pass
        
        print(f"[DNS ENUM] Found {len(entries)} valid subdomains for {domain}")
        return entries

    def get_amass_results_cached(domain: str) -> List[dict]:
        """Obtiene resultados usando Amass con fallbacks si falla."""
        with amass_cache_lock:
            if domain in amass_cache:
                debug_log(f"Usando resultados desde cache para {domain}")
                return amass_cache[domain]
        
        results = []
        
        # 1. Intentar Amass primero
        debug_log(f"Intentando Amass para {domain}")
        try:
            results = run_amass_local(domain, args.sample)
            if results:
                debug_log(f"Amass exitoso para {domain}: {len(results)} resultados")
                with amass_cache_lock:
                    amass_cache[domain] = results
                return results
        except Exception as e:
            thread_log(f"Amass falló para {domain}: {e}")
        
        # 2. Fallback a Subfinder
        debug_log(f"Intentando Subfinder para {domain}")
        try:
            results = run_subfinder_fallback(domain)
            if results:
                debug_log(f"Subfinder exitoso para {domain}: {len(results)} resultados")
                with amass_cache_lock:
                    amass_cache[domain] = results
                return results
        except Exception as e:
            thread_log(f"Subfinder falló para {domain}: {e}")
        
        # 3. Fallback a enumeración DNS básica
        debug_log(f"Intentando enumeración DNS básica para {domain}")
        try:
            results = run_basic_dns_enumeration(domain)
            debug_log(f"DNS enum completado para {domain}: {len(results)} resultados")
            with amass_cache_lock:
                amass_cache[domain] = results
            return results
        except Exception as e:
            thread_log(f"DNS enum falló para {domain}: {e}")
        
        # 4. Si todo falla, devolver lista vacía
        thread_log(f"Todos los métodos fallaron para {domain}, continuando sin subdominios")
        with amass_cache_lock:
            amass_cache[domain] = []
        return []

    def worker():
        """Función worker para procesar dominios usando SQLite queue."""
        worker_id = f"worker-{threading.current_thread().ident}"
        thread_log(f"Worker iniciado: {worker_id}")
        
        # Initialize worker stats
        with worker_stats_lock:
            worker_stats[worker_id] = {
                'processed_count': 0,
                'error_count': 0,
                'start_time': time.time(),
                'last_activity': time.time()
            }
        
        while not shutdown_flag.is_set():
            # Get next domain from queue
            domain_task = queue_manager.get_next_domain(worker_id)
            
            if not domain_task:
                # No domains available, wait a bit
                time.sleep(1)
                continue
            
            domain = domain_task.domain
            depth = domain_task.depth
            
            # Update worker stats
            with worker_stats_lock:
                worker_stats[worker_id]['last_activity'] = time.time()
            
            queue_stats = queue_manager.get_queue_stats()
            thread_log(f"[{worker_id}] Procesando: {domain} (depth={depth}) [Pending: {queue_stats.get('pending', 0)}]")
            
            try:
                # Get Amass results (with cache)
                amass_results = get_amass_results_cached(domain)
                debug_log(f"[{worker_id}] Usando {len(amass_results)} resultados de Amass para {domain}")
                
                # DEBUG: Log some sample results
                if amass_results:
                    sample_count = min(3, len(amass_results))
                    for i in range(sample_count):
                        entry = amass_results[i]
                        entry_name = entry.get('name', 'NO_NAME')
                        debug_log(f"[{worker_id}] Sample Amass entry {i}: {entry_name}")
                
                # Process the domain with single transaction
                processing_stats = enrich_and_ingest_domain_transaction(
                    domain, depth, ing, queue_manager, args.sample, worker_id, amass_results
                )
                
                # DEBUG: Check what was actually processed
                subdomain_count = processing_stats.get('subdomain_count', 0)
                debug_log(f"[{worker_id}] Processing resulted in {subdomain_count} subdomain discoveries")
                
                # Mark as completed
                queue_manager.mark_completed(domain, depth, worker_id, processing_stats)
                
                # Update worker stats
                with worker_stats_lock:
                    worker_stats[worker_id]['processed_count'] += 1
                
                thread_log(f"[{worker_id}] ✓ Completado: {domain}")
                
            except Exception as e:
                error_msg = f"Error procesando {domain}: {e}"
                thread_log(f"[{worker_id}] ERROR: {error_msg}")
                
                # Mark as error
                queue_manager.mark_error(domain, depth, worker_id, error_msg)
                
                # Update worker stats
                with worker_stats_lock:
                    worker_stats[worker_id]['error_count'] += 1
        
        thread_log(f"[{worker_id}] Worker finalizado")

    def stats_monitor():
        """Monitor thread para mostrar estadísticas periódicamente."""
        while not shutdown_flag.is_set():
            try:
                # Wait for stats interval or shutdown
                if shutdown_flag.wait(args.stats_interval):
                    break
                
                # Get queue stats
                queue_stats = queue_manager.get_queue_stats()
                processing_stats = queue_manager.get_processing_stats()
                
                # Get worker stats
                current_worker_stats = {}
                with worker_stats_lock:
                    current_worker_stats = worker_stats.copy()
                
                # Display stats
                print("\n" + "="*80)
                print(f"[STATS] Tiempo: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"[STATS] Cola: {queue_stats}")
                print(f"[STATS] Procesamiento: {processing_stats}")
                
                # Worker stats
                active_workers = 0
                total_processed = 0
                total_errors = 0
                
                for worker_id, stats in current_worker_stats.items():
                    if time.time() - stats['last_activity'] < 60:  # Active in last minute
                        active_workers += 1
                    total_processed += stats['processed_count']
                    total_errors += stats['error_count']
                
                # Show discovered domains info
                discovered = queue_stats.get('total_discovered', 0)
                unique_discovered = queue_stats.get('unique_discovered', 0)
                
                print(f"[STATS] Workers activos: {active_workers}/{args.threads}")
                print(f"[STATS] Total procesado: {total_processed}, Errores: {total_errors}")
                print(f"[STATS] Subdominios descubiertos: {discovered} (únicos: {unique_discovered})")
                
                # Check if all domains are processed
                if (queue_stats.get('pending', 0) == 0 and 
                    queue_stats.get('processing', 0) == 0):
                    print("[*] Todos los dominios han sido procesados")
                    shutdown_flag.set()
                    break
                
                print("="*80)
                
            except Exception as e:
                print(f"[!] Error en monitor de estadísticas: {e}")
    
    try:
        # Start stats monitor thread
        stats_thread = threading.Thread(target=stats_monitor, name="StatsMonitor")
        stats_thread.start()
        
        # Start worker threads
        threads = []
        for i in range(args.threads):
            t = threading.Thread(target=worker, name=f"Worker-{i}")
            t.start()
            threads.append(t)
        
        print(f"[*] Iniciados {args.threads} workers")
        
        # Wait for completion or interruption
        try:
            # Wait for stats thread to signal completion
            stats_thread.join()
        except KeyboardInterrupt:
            print("\n[*] Interrupción detectada, finalizando...")
            shutdown_flag.set()
        
        # Wait for all worker threads to finish
        for t in threads:
            t.join(timeout=10)
        
        # Final statistics
        final_stats = queue_manager.get_queue_stats()
        final_processing_stats = queue_manager.get_processing_stats()
        
        print("\n" + "="*80)
        print("[FINAL] Estadísticas finales:")
        print(f"[FINAL] Cola: {final_stats}")
        print(f"[FINAL] Procesamiento: {final_processing_stats}")
        
        discovered = final_stats.get('total_discovered', 0)
        unique_discovered = final_stats.get('unique_discovered', 0)
        print(f"[FINAL] Subdominios descubiertos: {discovered} (únicos: {unique_discovered})")
        print("="*80)
        
    except Exception as e:
        print(f"[!] Error en main: {e}")
        shutdown_flag.set()
    finally:
        driver.close()
        print("✓ Finalizado")


if __name__ == "__main__":
    main()
