#!/usr/bin/env python3
"""
Script para actualizar información TLS de dominios principales conocidos
"""

import socket
import ssl
import json
from datetime import datetime
from neo4j import GraphDatabase

def get_tls_info(domain):
    """Obtiene información TLS real de un dominio"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    expires_in_days = (not_after - datetime.now()).days
                    
                    # Calcular grade
                    score = 100
                    if expires_in_days < 0:
                        grade = 'F'
                    elif expires_in_days < 7:
                        score -= 30
                        grade = 'D'
                    elif expires_in_days < 30:
                        score -= 15
                        grade = 'B'
                    else:
                        grade = 'A'
                    
                    # Verificar si es auto-firmado
                    if cert.get('issuer') == cert.get('subject'):
                        grade = 'F'
                    
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))
                    
                    return {
                        'has_tls': True,
                        'tls_grade': grade,
                        'expires_in_days': expires_in_days,
                        'not_after': cert['notAfter'],
                        'not_before': cert['notBefore'],
                        'issuer': issuer,
                        'subject': subject,
                        'is_self_signed': cert.get('issuer') == cert.get('subject'),
                        'analyzed_at': datetime.now().isoformat()
                    }
    except Exception as e:
        print(f"Error getting TLS for {domain}: {e}")
        return None

def update_domain_tls_in_neo4j(driver, fqdn, tls_info):
    """Actualiza información TLS en Neo4j"""
    with driver.session() as session:
        # Actualizar Domain
        domain_result = session.run("""
            MATCH (d:Domain {fqdn: $fqdn})
            SET d.has_tls = $has_tls,
                d.tls_grade = $tls_grade,
                d.tls_expires_in_days = $expires_in_days,
                d.tls_last_updated = $analyzed_at,
                d.tls_issuer = $issuer
            RETURN count(d) as updated
        """, 
        fqdn=fqdn,
        has_tls=tls_info['has_tls'],
        tls_grade=tls_info['tls_grade'],
        expires_in_days=tls_info['expires_in_days'],
        analyzed_at=tls_info['analyzed_at'],
        issuer=json.dumps(tls_info['issuer']))
        
        domain_updated = domain_result.single()['updated']
        
        # Actualizar Subdomain si existe (ej: www.bci.cl)
        subdomain_result = session.run("""
            MATCH (s:Subdomain {fqdn: $fqdn})
            SET s.has_tls = $has_tls,
                s.tls_grade = $tls_grade,
                s.tls_expires_in_days = $expires_in_days,
                s.tls_last_updated = $analyzed_at,
                s.tls_issuer = $issuer
            RETURN count(s) as updated
        """, 
        fqdn=fqdn,
        has_tls=tls_info['has_tls'],
        tls_grade=tls_info['tls_grade'],
        expires_in_days=tls_info['expires_in_days'],
        analyzed_at=tls_info['analyzed_at'],
        issuer=json.dumps(tls_info['issuer']))
        
        subdomain_updated = subdomain_result.single()['updated']
        
        return domain_updated + subdomain_updated

def main():
    driver = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', 'test.password'))
    
    # Dominios principales chilenos conocidos  
    main_domains = [
        'www.bci.cl',
        'www.bancochile.cl', 
        'www.santander.cl',
        'www.bancoestado.cl',
        'www.itau.cl',
        'www.scotiabank.cl'
    ]
    
    successful = 0
    for domain in main_domains:
        print(f"Updating TLS for {domain}...")
        tls_info = get_tls_info(domain)
        
        if tls_info:
            updated = update_domain_tls_in_neo4j(driver, domain, tls_info)
            if updated > 0:
                print(f"✅ {domain}: Grade {tls_info['tls_grade']}, expires in {tls_info['expires_in_days']} days")
                successful += 1
            else:
                print(f"⚠️ {domain}: TLS data obtained but no matching node in database")
        else:
            print(f"❌ {domain}: Failed to get TLS info")
    
    print(f"\n📊 Updated {successful}/{len(main_domains)} domains with TLS information")
    driver.close()

if __name__ == "__main__":
    main()