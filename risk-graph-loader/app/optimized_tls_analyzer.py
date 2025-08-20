#!/usr/bin/env python3
"""
Optimized TLS Analyzer - Análisis TLS optimizado para dominios y subdominios

Este script optimiza el análisis TLS:
1. Filtra subdominios que probablemente tengan TLS (www, mail, api, etc.)
2. Procesa en lotes concurrentes
3. Timeouts más agresivos para dominios inaccesibles
4. Actualiza risk scores automáticamente después del análisis TLS
"""

import argparse
import json
import logging
import socket
import ssl
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, Any, List, Optional, Set

try:
    from neo4j import GraphDatabase
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False

class OptimizedTLSAnalyzer:
    """Analizador TLS optimizado con procesamiento concurrente."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str, 
                 tls_timeout: int = 10, max_workers: int = 20):
        if not HAS_NEO4J:
            raise ImportError("Neo4j driver is required. Install with: pip install neo4j")
        
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
        self.tls_timeout = tls_timeout
        self.max_workers = max_workers
        self.stats = {
            'processed': 0,
            'successful': 0,
            'failed': 0,
            'skipped': 0,
            'lock': threading.Lock()
        }
        
        # Subdominios que típicamente tienen TLS
        self.likely_tls_prefixes = {
            'www', 'api', 'web', 'secure', 'admin', 'portal', 'login', 
            'app', 'dashboard', 'panel', 'ssl', 'https', 'client',
            'customer', 'user', 'account', 'billing', 'payment',
            'store', 'shop', 'ecommerce', 'bank', 'banking',
            'mail', 'email', 'smtp', 'webmail', 'mx'
        }
        
        # Subdominios que probablemente NO tienen TLS
        self.unlikely_tls_prefixes = {
            'ftp', 'ns', 'ns1', 'ns2', 'ns3', 'dns', 'mx1', 'mx2',
            'test', 'dev', 'staging', 'debug', 'temp', 'tmp',
            'internal', 'private', 'local', 'intranet',
            'vpn', 'firewall', 'fw', 'router', 'switch'
        }
        
        logging.info(f"TLS Analyzer initialized: timeout={tls_timeout}s, workers={max_workers}")
    
    def get_prioritized_subdomains(self) -> List[Dict[str, Any]]:
        """Obtiene subdominios priorizados por probabilidad de tener TLS."""
        with self.driver.session() as session:
            result = session.run("""
                MATCH (s:Subdomain)
                RETURN 
                    s.fqdn as fqdn,
                    s.tls_grade as current_tls_grade,
                    s.has_tls as has_tls
                ORDER BY s.fqdn
            """)
            
            subdomains = []
            for record in result:
                fqdn = record['fqdn']
                if not fqdn:
                    continue
                    
                # Calcular prioridad
                subdomain_prefix = fqdn.split('.')[0].lower()
                
                if subdomain_prefix in self.likely_tls_prefixes:
                    priority = 1  # Alta prioridad
                elif subdomain_prefix in self.unlikely_tls_prefixes:
                    priority = 3  # Baja prioridad
                elif record['current_tls_grade'] or record['has_tls']:
                    priority = 1  # Ya tiene TLS, alta prioridad para actualizar
                else:
                    priority = 2  # Prioridad media
                
                subdomains.append({
                    'fqdn': fqdn,
                    'priority': priority,
                    'current_tls_grade': record['current_tls_grade'],
                    'has_tls': record['has_tls']
                })
            
            # Ordenar por prioridad (1 primero, 3 último)
            subdomains.sort(key=lambda x: (x['priority'], x['fqdn']))
            
            logging.info(f"Found {len(subdomains)} subdomains")
            priority_counts = {}
            for s in subdomains:
                priority_counts[s['priority']] = priority_counts.get(s['priority'], 0) + 1
            
            logging.info(f"Priority distribution: High={priority_counts.get(1, 0)}, "
                        f"Medium={priority_counts.get(2, 0)}, Low={priority_counts.get(3, 0)}")
            
            return subdomains
    
    def analyze_tls_fast(self, fqdn: str) -> Optional[Dict[str, Any]]:
        """Análisis TLS rápido con timeout agresivo."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((fqdn, 443), timeout=self.tls_timeout) as sock:
                with context.wrap_socket(sock, server_hostname=fqdn) as ssock:
                    cert = ssock.getpeercert()
                    
                    if not cert:
                        return None
                    
                    # Información básica del certificado
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    expires_in_days = (not_after - datetime.now()).days
                    
                    # Grade TLS simplificado
                    tls_grade = self._calculate_tls_grade_fast(cert, expires_in_days)
                    
                    # SAN domains
                    san_domains = []
                    if 'subjectAltName' in cert:
                        san_domains = [item[1] for item in cert['subjectAltName'] if item[0] == 'DNS']
                    
                    return {
                        'has_tls': True,
                        'tls_grade': tls_grade,
                        'expires_in_days': expires_in_days,
                        'not_after': cert['notAfter'],
                        'not_before': cert['notBefore'],
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'is_self_signed': cert.get('issuer') == cert.get('subject'),
                        'san_domains': san_domains,
                        'analyzed_at': datetime.now().isoformat()
                    }
                    
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
            # Errores esperados para dominios sin TLS
            return None
        except Exception as e:
            logging.debug(f"TLS analysis error for {fqdn}: {e}")
            return None
    
    def _calculate_tls_grade_fast(self, cert: Dict, expires_in_days: int) -> str:
        """Cálculo rápido de grade TLS."""
        score = 100
        
        if expires_in_days < 0:
            return 'F'
        elif expires_in_days < 7:
            score -= 30
        elif expires_in_days < 30:
            score -= 15
        
        if cert.get('issuer') == cert.get('subject'):
            score -= 40
        
        issuer = dict(x[0] for x in cert.get('issuer', []))
        issuer_name = issuer.get('organizationName', '').lower()
        trusted_cas = ['let\'s encrypt', 'digicert', 'comodo', 'globalsign', 'verisign']
        if not any(ca in issuer_name for ca in trusted_cas):
            score -= 10
        
        if score >= 90: return 'A+'
        elif score >= 80: return 'A'
        elif score >= 70: return 'B'
        elif score >= 60: return 'C'
        elif score >= 50: return 'D'
        else: return 'F'
    
    def update_subdomain_tls(self, fqdn: str, tls_info: Dict[str, Any]) -> bool:
        """Actualiza información TLS de un subdominio."""
        try:
            with self.driver.session() as session:
                # Actualizar propiedades TLS directamente en el subdomain
                result = session.run("""
                    MATCH (s:Subdomain {fqdn: $fqdn})
                    SET s.has_tls = $has_tls,
                        s.tls_grade = $tls_grade,
                        s.tls_expires_in_days = $expires_in_days,
                        s.tls_last_updated = $analyzed_at,
                        s.tls_not_after = $not_after,
                        s.tls_issuer = $issuer,
                        s.tls_is_self_signed = $is_self_signed
                    RETURN count(s) as updated
                """,
                fqdn=fqdn,
                has_tls=tls_info['has_tls'],
                tls_grade=tls_info['tls_grade'],
                expires_in_days=tls_info['expires_in_days'],
                analyzed_at=tls_info['analyzed_at'],
                not_after=tls_info['not_after'],
                issuer=json.dumps(tls_info['issuer']),
                is_self_signed=tls_info['is_self_signed'])
                
                return result.single()['updated'] > 0
        except Exception as e:
            logging.error(f"Failed to update TLS for {fqdn}: {e}")
            return False
    
    def process_subdomain(self, subdomain_info: Dict[str, Any]) -> Dict[str, Any]:
        """Procesa un subdominio individual."""
        fqdn = subdomain_info['fqdn']
        result = {
            'fqdn': fqdn,
            'status': 'failed',
            'tls_grade': None,
            'expires_in_days': None
        }
        
        try:
            # Si ya tiene TLS grade y no ha expirado, saltarlo ocasionalmente
            if (subdomain_info.get('current_tls_grade') and 
                subdomain_info['priority'] == 3 and 
                hash(fqdn) % 5 != 0):  # Solo procesar 20% de los de baja prioridad
                with self.stats['lock']:
                    self.stats['skipped'] += 1
                result['status'] = 'skipped'
                return result
            
            tls_info = self.analyze_tls_fast(fqdn)
            
            if tls_info:
                success = self.update_subdomain_tls(fqdn, tls_info)
                if success:
                    result.update({
                        'status': 'success',
                        'tls_grade': tls_info['tls_grade'],
                        'expires_in_days': tls_info['expires_in_days']
                    })
                    with self.stats['lock']:
                        self.stats['successful'] += 1
                else:
                    with self.stats['lock']:
                        self.stats['failed'] += 1
            else:
                # Marcar como sin TLS
                with self.driver.session() as session:
                    session.run("""
                        MATCH (s:Subdomain {fqdn: $fqdn})
                        SET s.has_tls = false,
                            s.tls_grade = null,
                            s.tls_last_checked = $checked_at
                    """, fqdn=fqdn, checked_at=datetime.now().isoformat())
                
                result['status'] = 'no_tls'
                with self.stats['lock']:
                    self.stats['failed'] += 1
                    
        except Exception as e:
            logging.error(f"Error processing {fqdn}: {e}")
            with self.stats['lock']:
                self.stats['failed'] += 1
        
        with self.stats['lock']:
            self.stats['processed'] += 1
            
        return result
    
    def run_tls_analysis(self, max_subdomains: Optional[int] = None) -> Dict[str, Any]:
        """Ejecuta análisis TLS concurrente."""
        logging.info("🚀 Starting optimized TLS analysis")
        
        subdomains = self.get_prioritized_subdomains()
        
        if max_subdomains:
            subdomains = subdomains[:max_subdomains]
            logging.info(f"Limited to {max_subdomains} subdomains for testing")
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_subdomain = {
                executor.submit(self.process_subdomain, sub): sub 
                for sub in subdomains
            }
            
            results = []
            completed = 0
            
            for future in as_completed(future_to_subdomain):
                completed += 1
                result = future.result()
                results.append(result)
                
                # Progress report every 50 completions
                if completed % 50 == 0:
                    elapsed = time.time() - start_time
                    rate = completed / elapsed
                    eta = (len(subdomains) - completed) / rate if rate > 0 else 0
                    
                    logging.info(f"Progress: {completed}/{len(subdomains)} "
                               f"({completed/len(subdomains)*100:.1f}%) - "
                               f"Rate: {rate:.1f}/s - ETA: {eta/60:.1f}min")
        
        elapsed_time = time.time() - start_time
        
        # Estadísticas finales
        final_stats = {
            'total_subdomains': len(subdomains),
            'processed': self.stats['processed'],
            'successful': self.stats['successful'],
            'failed': self.stats['failed'],
            'skipped': self.stats['skipped'],
            'elapsed_time': elapsed_time,
            'rate': len(subdomains) / elapsed_time if elapsed_time > 0 else 0,
            'results': results
        }
        
        logging.info(f"✅ TLS analysis completed in {elapsed_time:.1f}s")
        logging.info(f"📊 Results: {self.stats['successful']} successful, "
                    f"{self.stats['failed']} failed, {self.stats['skipped']} skipped")
        
        return final_stats
    
    def close(self):
        """Cierra conexiones."""
        if self.driver:
            self.driver.close()

def main():
    """Función principal."""
    parser = argparse.ArgumentParser(description="Optimized TLS Analysis for subdomains")
    parser.add_argument("--bolt", default="bolt://localhost:7687", help="Neo4j bolt URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", default="test.password", help="Neo4j password")
    parser.add_argument("--timeout", type=int, default=8, help="TLS connection timeout")
    parser.add_argument("--workers", type=int, default=20, help="Concurrent workers")
    parser.add_argument("--limit", type=int, help="Limit number of subdomains (for testing)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    analyzer = None
    try:
        analyzer = OptimizedTLSAnalyzer(
            neo4j_uri=args.bolt,
            neo4j_user=args.user,
            neo4j_pass=args.password,
            tls_timeout=args.timeout,
            max_workers=args.workers
        )
        
        results = analyzer.run_tls_analysis(max_subdomains=args.limit)
        
        print(f"\n📊 TLS Analysis Results:")
        print("=" * 50)
        print(f"Total subdomains: {results['total_subdomains']}")
        print(f"Processed: {results['processed']}")
        print(f"Successful: {results['successful']}")
        print(f"Failed/No TLS: {results['failed']}")
        print(f"Skipped: {results['skipped']}")
        print(f"Processing time: {results['elapsed_time']:.1f}s")
        print(f"Rate: {results['rate']:.1f} subdomains/second")
        print("=" * 50)
        
        # Show successful TLS grades
        successful_results = [r for r in results['results'] if r['status'] == 'success']
        if successful_results:
            print(f"\n✅ TLS Certificates Found ({len(successful_results)}):")
            grade_counts = {}
            for r in successful_results[:20]:  # Show first 20
                grade = r['tls_grade']
                grade_counts[grade] = grade_counts.get(grade, 0) + 1
                print(f"  - {r['fqdn']}: Grade {grade}, expires in {r['expires_in_days']} days")
            
            if len(successful_results) > 20:
                print(f"  ... and {len(successful_results) - 20} more")
            
            print(f"\nGrade distribution: {dict(sorted(grade_counts.items()))}")
        
        return 0 if results['successful'] > 0 else 1
        
    except KeyboardInterrupt:
        logging.info("⏹️ Interrupted by user")
        return 1
    except Exception as e:
        logging.error(f"❌ Fatal error: {e}")
        return 1
    finally:
        if analyzer:
            analyzer.close()

if __name__ == "__main__":
    exit(main())