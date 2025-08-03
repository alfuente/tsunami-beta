#!/usr/bin/env python3
"""
TLS Updater - Script que solo actualiza los TLS de los dominios pasados en --domains

Este script se enfoca exclusivamente en actualizar la información TLS/SSL de dominios
y subdominios existentes en la base de datos Neo4j, sin modificar otros aspectos.

Características:
- Lee dominios desde un archivo
- Solo actualiza información TLS/SSL existente
- No crea nuevos nodos de dominio/subdomain
- Mantiene logging detallado de las actualizaciones
- Soporte para timeouts y reintentos configurables
"""

import argparse
import json
import logging
import socket
import ssl
import sys
import time
from datetime import datetime
from typing import Dict, Any, List, Optional

try:
    from neo4j import GraphDatabase
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False


class TLSUpdater:
    """Actualizador dedicado para información TLS/SSL de dominios existentes."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str, 
                 tls_timeout: int = 30, tls_retries: int = 2):
        if not HAS_NEO4J:
            raise ImportError("Neo4j driver is required. Install with: pip install neo4j")
        
        self.drv = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
        self.tls_timeout = tls_timeout
        self.tls_retries = tls_retries
        
        logging.info(f"TLS Updater initialized with timeout={tls_timeout}s, retries={tls_retries}")
    
    def get_existing_subdomains_only(self, domain_list: List[str]) -> List[str]:
        """Obtiene SOLO subdominios existentes en la base de datos que coincidan con la lista.
        No incluye dominios base para evitar análisis TLS en dominios que no deberían tenerlo."""
        subdomains = []
        
        with self.drv.session() as session:
            for domain in domain_list:
                # Buscar subdominios que coincidan exactamente (ej: www.bice.cl)
                subdomain_result = session.run("""
                    MATCH (s:Subdomain {fqdn: $fqdn})
                    RETURN s.fqdn as fqdn
                """, fqdn=domain)
                
                if subdomain_result.single():
                    subdomains.append(domain)
                    logging.debug(f"Found exact subdomain match: {domain}")
                
                # También buscar subdominios que pertenezcan al dominio base
                # Solo si el dominio parece ser un dominio base (sin subdominios)
                domain_parts = domain.split('.')
                if len(domain_parts) >= 2:  # bice.cl -> buscar *.bice.cl
                    related_subdomains = session.run("""
                        MATCH (s:Subdomain)
                        WHERE s.fqdn ENDS WITH $domain_suffix
                        AND s.fqdn <> $domain_suffix
                        RETURN s.fqdn as fqdn
                    """, domain_suffix=f".{domain}", domain=domain)
                    
                    for record in related_subdomains:
                        subdomain = record['fqdn']
                        if subdomain not in subdomains:
                            subdomains.append(subdomain)
                            logging.debug(f"Found related subdomain: {subdomain} for base domain {domain}")
        
        # Filtrar solo subdominios reales (que tengan al menos 3 partes: www.example.com)
        filtered_subdomains = []
        for subdomain in subdomains:
            parts = subdomain.split('.')
            if len(parts) >= 3:  # www.bice.cl tiene 3 partes, bice.cl tiene 2
                filtered_subdomains.append(subdomain)
                logging.debug(f"✅ Including subdomain for TLS analysis: {subdomain}")
            else:
                logging.info(f"⏭️ Skipping base domain (no TLS analysis): {subdomain}")
        
        logging.info(f"Found {len(filtered_subdomains)} subdomains to update (excluding {len(subdomains) - len(filtered_subdomains)} base domains)")
        return filtered_subdomains
    
    def analyze_tls_certificate(self, fqdn: str) -> Optional[Dict[str, Any]]:
        """Analiza el certificado TLS de un dominio."""
        for attempt in range(self.tls_retries + 1):
            try:
                logging.debug(f"TLS analysis attempt {attempt + 1}/{self.tls_retries + 1} for {fqdn}")
                
                context = ssl.create_default_context()
                context.check_hostname = False  # Para evitar problemas con certificados
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((fqdn, 443), timeout=self.tls_timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=fqdn) as ssock:
                        cert = ssock.getpeercert()
                        
                        if not cert:
                            logging.warning(f"No certificate received for {fqdn}")
                            continue
                        
                        # Extraer información del certificado
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                        expires_in_days = (not_after - datetime.now()).days
                        
                        # Calcular grade TLS (simplificado)
                        tls_grade = self._calculate_tls_grade(cert, expires_in_days)
                        
                        # Obtener información adicional
                        cipher_suite = ssock.cipher()[0] if ssock.cipher() else 'Unknown'
                        tls_version = ssock.version() if hasattr(ssock, 'version') else 'Unknown'
                        
                        # Subject Alternative Names
                        san_domains = []
                        if 'subjectAltName' in cert:
                            san_domains = [item[1] for item in cert['subjectAltName'] if item[0] == 'DNS']
                        
                        result = {
                            'has_tls': True,
                            'tls_grade': tls_grade,
                            'expires_in_days': expires_in_days,
                            'not_after': cert['notAfter'],
                            'not_before': cert['notBefore'],
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'serial_number': cert.get('serialNumber', ''),
                            'is_self_signed': cert.get('issuer') == cert.get('subject'),
                            'cipher_suite': cipher_suite,
                            'tls_version': tls_version,
                            'san_domains': san_domains,
                            'analyzed_at': datetime.now().isoformat()
                        }
                        
                        logging.info(f"✅ TLS certificate analyzed for {fqdn}: Grade {tls_grade}, expires in {expires_in_days} days")
                        return result
                        
            except socket.timeout:
                logging.warning(f"⏰ TLS timeout for {fqdn} (attempt {attempt + 1})")
                if attempt == self.tls_retries:
                    logging.error(f"❌ TLS analysis failed for {fqdn}: Final timeout after {self.tls_retries + 1} attempts")
                    return None
                time.sleep(2 ** attempt)  # Exponential backoff
                
            except Exception as e:
                logging.warning(f"⚠️ TLS analysis error for {fqdn} (attempt {attempt + 1}): {e}")
                if attempt == self.tls_retries:
                    logging.error(f"❌ TLS analysis failed for {fqdn}: {e}")
                    return None
                continue
        
        return None
    
    def _calculate_tls_grade(self, cert: Dict, expires_in_days: int) -> str:
        """Calcula un grade simplificado para el certificado TLS."""
        score = 100
        
        # Penalizar por expiración cercana
        if expires_in_days < 0:
            return 'F'  # Certificado expirado
        elif expires_in_days < 7:
            score -= 30
        elif expires_in_days < 30:
            score -= 15
        
        # Penalizar certificados auto-firmados
        if cert.get('issuer') == cert.get('subject'):
            score -= 40
        
        # Evaluar issuer
        issuer = dict(x[0] for x in cert.get('issuer', []))
        issuer_name = issuer.get('organizationName', '').lower()
        
        trusted_cas = ['let\'s encrypt', 'digicert', 'comodo', 'globalsign', 'verisign']
        if not any(ca in issuer_name for ca in trusted_cas):
            score -= 10
        
        # Convertir score a grade
        if score >= 90:
            return 'A+'
        elif score >= 80:
            return 'A'
        elif score >= 70:
            return 'B'
        elif score >= 60:
            return 'C'
        elif score >= 50:
            return 'D'
        else:
            return 'F'
    
    def update_domain_tls(self, fqdn: str, tls_info: Dict[str, Any]) -> bool:
        """Actualiza la información TLS de un dominio en Neo4j."""
        try:
            with self.drv.session() as session:
                with session.begin_transaction() as tx:
                    # Crear o actualizar certificado
                    cert_id = f"{fqdn}_cert_{int(time.time())}"
                    
                    tx.run("""
                        MERGE (c:Certificate {fqdn: $fqdn})
                        SET c.id = $cert_id,
                            c.tls_grade = $tls_grade,
                            c.expires_in_days = $expires_in_days,
                            c.not_after = $not_after,
                            c.not_before = $not_before,
                            c.issuer = $issuer,
                            c.subject = $subject,
                            c.serial_number = $serial_number,
                            c.is_self_signed = $is_self_signed,
                            c.cipher_suite = $cipher_suite,
                            c.tls_version = $tls_version,
                            c.san_domains = $san_domains,
                            c.last_updated = $analyzed_at
                    """,
                    fqdn=fqdn,
                    cert_id=cert_id,
                    tls_grade=tls_info['tls_grade'],
                    expires_in_days=tls_info['expires_in_days'],
                    not_after=tls_info['not_after'],
                    not_before=tls_info['not_before'],
                    issuer=json.dumps(tls_info['issuer']),
                    subject=json.dumps(tls_info['subject']),
                    serial_number=tls_info['serial_number'],
                    is_self_signed=tls_info['is_self_signed'],
                    cipher_suite=tls_info['cipher_suite'],
                    tls_version=tls_info['tls_version'],
                    san_domains=tls_info['san_domains'],
                    analyzed_at=tls_info['analyzed_at'])
                    
                    # Vincular certificado a dominio (intentar ambos Domain y Subdomain)
                    domain_linked = tx.run("""
                        MATCH (d:Domain {fqdn: $fqdn})
                        MATCH (c:Certificate {fqdn: $fqdn})
                        MERGE (d)-[:SECURED_BY]->(c)
                        RETURN COUNT(d) as count
                    """, fqdn=fqdn).single()['count']
                    
                    subdomain_linked = tx.run("""
                        MATCH (s:Subdomain {fqdn: $fqdn})
                        MATCH (c:Certificate {fqdn: $fqdn})
                        MERGE (s)-[:SECURED_BY]->(c)
                        RETURN COUNT(s) as count
                    """, fqdn=fqdn).single()['count']
                    
                    # Actualizar propiedades TLS en el nodo del dominio/subdomain
                    if domain_linked > 0:
                        tx.run("""
                            MATCH (d:Domain {fqdn: $fqdn})
                            SET d.has_tls = true,
                                d.tls_grade = $tls_grade,
                                d.tls_expires_in_days = $expires_in_days,
                                d.tls_last_updated = $analyzed_at
                        """, fqdn=fqdn, tls_grade=tls_info['tls_grade'], 
                        expires_in_days=tls_info['expires_in_days'], analyzed_at=tls_info['analyzed_at'])
                        
                    if subdomain_linked > 0:
                        tx.run("""
                            MATCH (s:Subdomain {fqdn: $fqdn})
                            SET s.has_tls = true,
                                s.tls_grade = $tls_grade,
                                s.tls_expires_in_days = $expires_in_days,
                                s.tls_last_updated = $analyzed_at
                        """, fqdn=fqdn, tls_grade=tls_info['tls_grade'], 
                        expires_in_days=tls_info['expires_in_days'], analyzed_at=tls_info['analyzed_at'])
                    
                    tx.commit()
                    
                    if domain_linked == 0 and subdomain_linked == 0:
                        logging.warning(f"⚠️ No Domain or Subdomain node found for {fqdn}, but certificate was created")
                    
                    return True
                    
        except Exception as e:
            logging.error(f"❌ Failed to update TLS info for {fqdn}: {e}")
            return False
    
    def update_tls_for_domains(self, domain_list: List[str]) -> Dict[str, Any]:
        """Actualiza TLS SOLO para subdominios (no dominios base)."""
        results = {
            'total_domains': len(domain_list),
            'successful_updates': 0,
            'failed_updates': 0,
            'no_tls_found': 0,
            'skipped_base_domains': 0,
            'details': []
        }
        
        # Obtener SOLO subdominios existentes (excluir dominios base)
        subdomains_only = self.get_existing_subdomains_only(domain_list)
        
        if not subdomains_only:
            logging.warning("No existing subdomains found in database for the provided list")
            logging.info("Note: TLS analysis is only performed on subdomains (e.g., www.example.com), not base domains (e.g., example.com)")
            return results
        
        # Calcular cuántos dominios base fueron omitidos
        results['skipped_base_domains'] = len(domain_list) - len(subdomains_only)
        
        logging.info(f"Starting TLS updates for {len(subdomains_only)} subdomains (skipped {results['skipped_base_domains']} base domains)")
        
        for i, fqdn in enumerate(subdomains_only, 1):
            logging.info(f"[{i}/{len(subdomains_only)}] Updating TLS for {fqdn}")
            
            try:
                tls_info = self.analyze_tls_certificate(fqdn)
                
                if tls_info:
                    success = self.update_domain_tls(fqdn, tls_info)
                    if success:
                        results['successful_updates'] += 1
                        results['details'].append({
                            'fqdn': fqdn,
                            'status': 'success',
                            'tls_grade': tls_info['tls_grade'],
                            'expires_in_days': tls_info['expires_in_days']
                        })
                        logging.info(f"✅ TLS updated successfully for {fqdn}")
                    else:
                        results['failed_updates'] += 1
                        results['details'].append({
                            'fqdn': fqdn,
                            'status': 'db_error',
                            'error': 'Failed to save to database'
                        })
                else:
                    results['no_tls_found'] += 1
                    results['details'].append({
                        'fqdn': fqdn,
                        'status': 'no_tls',
                        'error': 'No TLS certificate found or accessible'
                    })
                    logging.warning(f"⚠️ No TLS certificate found for {fqdn}")
                    
            except Exception as e:
                results['failed_updates'] += 1
                results['details'].append({
                    'fqdn': fqdn,
                    'status': 'error',
                    'error': str(e)
                })
                logging.error(f"❌ Error processing {fqdn}: {e}")
        
        return results
    
    def close(self):
        """Cerrar conexión a Neo4j."""
        if self.drv:
            self.drv.close()


def main():
    """Función principal del TLS Updater."""
    parser = argparse.ArgumentParser(description="Update TLS information for existing domains")
    
    # Parámetros requeridos
    parser.add_argument("--domains", required=True, help="File with list of domains to update")
    parser.add_argument("--password", required=True, help="Neo4j password")
    
    # Parámetros de conexión
    parser.add_argument("--bolt", default="bolt://localhost:7687", help="Neo4j bolt URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    
    # Parámetros TLS
    parser.add_argument("--tls-timeout", type=int, default=30, help="TLS connection timeout in seconds")
    parser.add_argument("--tls-retries", type=int, default=2, help="Number of TLS connection retries")
    
    # Logging
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--quiet", action="store_true", help="Suppress info logging")
    
    args = parser.parse_args()
    
    # Configurar logging
    log_level = logging.DEBUG if args.debug else (logging.WARNING if args.quiet else logging.INFO)
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Leer lista de dominios
    try:
        with open(args.domains, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        
        if not domains:
            logging.error(f"No domains found in file: {args.domains}")
            sys.exit(1)
            
        logging.info(f"Loaded {len(domains)} domains from {args.domains}")
        
    except FileNotFoundError:
        logging.error(f"Domain file not found: {args.domains}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading domain file: {e}")
        sys.exit(1)
    
    # Inicializar TLS Updater
    try:
        updater = TLSUpdater(
            neo4j_uri=args.bolt,
            neo4j_user=args.user,
            neo4j_pass=args.password,
            tls_timeout=args.tls_timeout,
            tls_retries=args.tls_retries
        )
        
        # Ejecutar actualizaciones
        start_time = time.time()
        results = updater.update_tls_for_domains(domains)
        elapsed_time = time.time() - start_time
        
        # Mostrar resultados
        print(f"\n📊 TLS Update Results:")
        print("=" * 50)
        print(f"Total domains in list: {results['total_domains']}")
        print(f"Subdomains processed: {results['successful_updates'] + results['failed_updates'] + results['no_tls_found']}")
        print(f"Base domains skipped: {results['skipped_base_domains']}")
        print(f"Successful updates: {results['successful_updates']}")
        print(f"Failed updates: {results['failed_updates']}")
        print(f"No TLS found: {results['no_tls_found']}")
        print(f"Processing time: {elapsed_time:.1f} seconds")
        print(f"\n💡 Note: TLS analysis is only performed on subdomains (e.g., www.example.com)")
        print(f"   Base domains (e.g., example.com) are automatically skipped.")
        
        # Mostrar detalles si hay errores
        if results['failed_updates'] > 0 and not args.quiet:
            print(f"\n❌ Failed Updates:")
            for detail in results['details']:
                if detail['status'] in ['error', 'db_error']:
                    print(f"  - {detail['fqdn']}: {detail.get('error', 'Unknown error')}")
        
        # Mostrar certificados exitosos si está en modo debug
        if args.debug and results['successful_updates'] > 0:
            print(f"\n✅ Successful Updates:")
            for detail in results['details']:
                if detail['status'] == 'success':
                    print(f"  - {detail['fqdn']}: Grade {detail['tls_grade']}, expires in {detail['expires_in_days']} days")
        
        print("=" * 50)
        
        # Exit code basado en resultados
        if results['failed_updates'] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)
    finally:
        try:
            updater.close()
        except:
            pass


if __name__ == "__main__":
    main()