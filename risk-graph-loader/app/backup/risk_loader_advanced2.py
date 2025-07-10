
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
from datetime import datetime
from typing import Iterable, Mapping, Any, List, Dict, Set, Tuple, Optional
import threading
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import multiprocessing as mp

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
                        entries.append({
                            "name": source_clean,
                            "addresses": [{"ip": target_clean}]
                        })
                        domains.add(source_clean)
                        dns_records.append({
                            "source": source_clean,
                            "target": target_clean,
                            "type": "A"
                        })
                        
                    elif relation == "aaaa_record":
                        # AAAA record: dominio -> IPv6
                        entries.append({
                            "name": source_clean,
                            "addresses": [{"ip": target_clean, "version": 6}]
                        })
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
                                asn_data[source_clean] = {"netblocks": []}
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
    """Ejecuta Amass local y devuelve la lista parseada."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.txt"
        cmd = ["amass", "enum", "-v", "-d", domain, "-o", str(out)]
        
        if sample_mode:
            cmd.extend(["-timeout", "2"])
            print(f"[AMASS LOCAL SAMPLE] {domain}")
        else:
            print(f"[AMASS LOCAL] {domain}")
            
        subprocess.run(cmd, check=True, stdout=None, stderr=None)
        return parse_amass_output(out)


def run_amass_parallel_worker(domain_info: Tuple[str, bool]) -> Tuple[str, List[dict]]:
    """Worker function para ejecutar Amass en paralelo."""
    domain, sample_mode = domain_info
    try:
        results = run_amass_local(domain, sample_mode)
        return domain, results
    except Exception as e:
        print(f"[!] Error en Amass para {domain}: {e}")
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
    def merge_domain(self, fqdn: str, who: Optional[Mapping[str, Any]] = None):
        debug_log(f"Creando nodo Domain: {fqdn}")
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
            debug_log(f"✓ Nodo Domain creado/actualizado: {fqdn}")

    def relate_subdomain(self, parent: str, child: str):
        debug_log(f"Creando relación subdomain: {parent} -> {child}")
        with self.drv.session() as s:
            with s.begin_transaction() as tx:
                tx.run("""
MERGE (p:Domain {fqdn:$parent})
MERGE (c:Domain {fqdn:$child})
MERGE (p)-[:HAS_SUBDOMAIN]->(c)
""", parent=parent, child=child)
                tx.commit()
            debug_log(f"✓ Relación subdomain creada: {parent} -> {child}")

    # ip ------------------------------------------------------------------------
    def merge_ip(self, domain: str, ip: str):
        debug_log(f"Creando nodo IP: {ip} para dominio {domain}")
        # Usar detección avanzada de proveedor con token
        prov = detect_cloud_provider_by_ip(ip, self.ipinfo_token, self.mmdb_path, self.csv_path)
        cloud_info = get_cloud_provider_info(ip, self.ipinfo_token, self.mmdb_path, self.csv_path)
        debug_log(f"Proveedor detectado para {ip}: {prov}")
        
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
            debug_log(f"✓ Nodo IP creado: {ip} con proveedor {prov}")
            
            # Si detectamos un proveedor conocido, crear nodo Provider con información detallada
            if prov != "unknown":
                self.merge_provider_detailed(prov, ip, cloud_info)

    def merge_provider_detailed(self, provider_name: str, host_or_ip: str, cloud_info: dict = None):
        """Crea nodo Provider con información detallada del servicio externo."""
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

    def merge_provider(self, provider_name: str, host_or_ip: str):
        """Crea nodo Provider básico (fallback)."""
        self.merge_provider_detailed(provider_name, host_or_ip, None)

    # dns -----------------------------------------------------------------------
    def merge_dns_record(self, domain: str, rdtype: str, value: str):
        with self.drv.session() as s:
            if rdtype == "NS":
                prov = guess_provider(value)
                s.run("""
MERGE (svc:Service {name:$host, type:'DNS'})
ON CREATE SET svc.category = 'Infrastructure',
              svc.hostname = $host,
              svc.provider_name = $prov
MERGE (d:Domain {fqdn:$fqdn})
MERGE (d)-[:DEPENDS_ON {dependency_type:'Critical', service_level:'DNS', record_type:'NS'}]->(svc)
""", host=value, fqdn=domain, prov=prov)
                # Crear nodo Provider si es detectado
                if prov != "unknown":
                    self.merge_provider(prov, value)
                    
            elif rdtype == "MX":
                prio, host = value.split() if " " in value else ("10", value)
                prov = guess_provider(host)
                s.run("""
MERGE (svc:Service {name:$host, type:'Email'})
ON CREATE SET svc.category = 'Infrastructure',
              svc.provider_name = $prov
MERGE (d:Domain {fqdn:$fqdn})
MERGE (d)-[:DEPENDS_ON {dependency_type:'Critical', service_level:'MX', priority:toInteger($prio), record_type:'MX'}]->(svc)
""", host=host, prov=prov, fqdn=domain, prio=prio)
                # Crear nodo Provider si es detectado
                if prov != "unknown":
                    self.merge_provider(prov, host)
                    
            elif rdtype == "TXT":
                s.run("MERGE (d:Domain {fqdn:$fqdn}) SET d.txt = coalesce(d.txt,'') + $txt + '\\n'",
                      fqdn=domain, txt=value)
                      
            elif rdtype == "CNAME":
                prov = guess_provider(value)
                s.run("""
MERGE (alias:Domain {fqdn:$fqdn})
MERGE (target:Domain {fqdn:$target})
ON CREATE SET target.provider_name = $prov
MERGE (alias)-[:CNAME_TO]->(target)
""", fqdn=domain, target=value, prov=prov)
                # Crear nodo Provider si es detectado
                if prov != "unknown":
                    self.merge_provider(prov, value)
                    
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


def enrich_and_ingest(domain: str, depth: int, ing: GraphIngester,
                      queue: deque[Tuple[str, int]], processed: Set[str], sample_mode: bool = False, 
                      queue_lock: threading.Lock = None, processed_lock: threading.Lock = None):
    """Resuelve DNS, obtiene TLS y carga todo en Neo4j."""
    # Thread-safe check para evitar procesamiento duplicado
    if processed_lock:
        with processed_lock:
            if domain in processed:
                return
            processed.add(domain)
    else:
        if domain in processed:
            return
        processed.add(domain)

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
                    if depth > 0:
                        print(f"    [DEBUG] Agregando a cola: {name} (depth={depth-1})")
                        if queue_lock:
                            with queue_lock:
                                queue.append((name, depth - 1))
                        else:
                            queue.append((name, depth - 1))
                
                # Procesar direcciones IP (incluyendo IPv6)
                for addr in entry.get("addresses", []):
                    ip = addr.get("ip")
                    if ip:
                        ing.merge_ip(name or domain, ip)
                
                # Procesar registros DNS adicionales
                dns_records = entry.get("dns_records", [])
                if dns_records:
                    ing.process_dns_records(name or domain, dns_records)
                    
    except subprocess.CalledProcessError as e:
        print(f"[!] Amass error for {domain}: {e}", file=sys.stderr)


def enrich_and_ingest_with_amass_results(domain: str, depth: int, ing: GraphIngester,
                                        queue: deque[Tuple[str, int]], processed: Set[str], 
                                        sample_mode: bool = False, 
                                        queue_lock: threading.Lock = None, 
                                        processed_lock: threading.Lock = None,
                                        amass_results: List[dict] = None):
    """Versión optimizada que usa resultados de Amass ya obtenidos."""
    debug_log(f"Iniciando enriquecimiento para {domain} con {len(amass_results or [])} resultados de Amass")
    
    # Thread-safe check para evitar procesamiento duplicado
    if processed_lock:
        with processed_lock:
            if domain in processed:
                debug_log(f"Dominio {domain} ya procesado")
                return
            processed.add(domain)
    else:
        if domain in processed:
            debug_log(f"Dominio {domain} ya procesado")
            return
        processed.add(domain)

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
                if depth > 0:
                    debug_log(f"Agregando a cola: {name} (depth={depth-1})")
                    if queue_lock:
                        with queue_lock:
                            queue.append((name, depth - 1))
                    else:
                        queue.append((name, depth - 1))
            
            # Procesar direcciones IP (incluyendo IPv6)
            for addr in entry.get("addresses", []):
                ip = addr.get("ip")
                if ip:
                    debug_log(f"IP encontrada: {ip} para {name or domain}")
                    ing.merge_ip(name or domain, ip)
            
            # Procesar registros DNS adicionales
            dns_records = entry.get("dns_records", [])
            if dns_records:
                debug_log(f"Procesando {len(dns_records)} registros DNS para {name or domain}")
                ing.process_dns_records(name or domain, dns_records)
    
    debug_log(f"✓ Enriquecimiento completado para {domain}: {subdominios_encontrados} subdominios encontrados")


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
    args = ap.parse_args()

    seeds = [d.strip() for d in Path(args.domains).read_text().splitlines() if d.strip()]
    
    # En modo sample, usar solo el primer dominio
    if args.sample:
        seeds = seeds[:1]
        print(f"[*] Modo sample: procesando solo {seeds[0]}")
    
    # Sistema de checkpoint para progreso - MOVER AQUÍ ANTES
    checkpoint_file = "checkpoint_progress.json"
    checkpoint_lock = threading.Lock()
    domains_completed = set()
    
    # Cargar checkpoint si existe
    if Path(checkpoint_file).exists():
        try:
            with open(checkpoint_file, 'r') as f:
                checkpoint_data = json.load(f)
                domains_completed = set(checkpoint_data.get('completed', []))
                print(f"[*] Checkpoint cargado: {len(domains_completed)} dominios ya procesados")
        except Exception as e:
            print(f"[!] Error cargando checkpoint: {e}")
    
    # Filtrar dominios ya completados
    seeds_filtered = [s for s in seeds if s not in domains_completed]
    if len(seeds_filtered) < len(seeds):
        print(f"[*] Saltando {len(seeds) - len(seeds_filtered)} dominios ya completados")
    
    queue: deque[Tuple[str, int]] = deque((s, args.depth) for s in seeds_filtered)
    processed: Set[str] = set()
    queue_lock = threading.Lock()
    processed_lock = threading.Lock()

    driver = GraphDatabase.driver(args.bolt, auth=(args.user, args.password))
    ing = GraphIngester(driver, args.ipinfo_token, args.mmdb_path, args.csv_path)
    
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
    print(f"[*] Usando {args.amass_processes} procesos paralelos para Amass")

    # Cache global de resultados de Amass para evitar re-ejecución
    amass_cache = {}
    amass_cache_lock = threading.Lock()
    
    def save_checkpoint():
        """Guarda el progreso actual."""
        try:
            with checkpoint_lock:
                checkpoint_data = {
                    'completed': list(domains_completed),
                    'timestamp': datetime.now().isoformat(),
                    'total_processed': len(domains_completed)
                }
                with open(checkpoint_file, 'w') as f:
                    json.dump(checkpoint_data, f, indent=2)
                debug_log(f"Checkpoint guardado: {len(domains_completed)} dominios completados")
        except Exception as e:
            thread_log(f"Error guardando checkpoint: {e}")
    
    def mark_domain_completed(domain: str):
        """Marca un dominio como completado y guarda checkpoint cada 10 dominios."""
        with checkpoint_lock:
            domains_completed.add(domain)
            if len(domains_completed) % 10 == 0:  # Checkpoint cada 10 dominios
                save_checkpoint()

    def get_amass_results_cached(domain: str) -> List[dict]:
        """Obtiene resultados de Amass usando cache o ejecutándolo si es necesario."""
        with amass_cache_lock:
            if domain in amass_cache:
                debug_log(f"Usando resultados de Amass desde cache para {domain}")
                return amass_cache[domain]
        
        # No está en cache, ejecutar Amass
        debug_log(f"Ejecutando Amass para {domain}")
        try:
            results = run_amass_local(domain, args.sample)
            with amass_cache_lock:
                amass_cache[domain] = results
            return results
        except Exception as e:
            thread_log(f"Error ejecutando Amass para {domain}: {e}")
            return []

    def worker():
        """Función worker para procesar dominios individualmente en paralelo."""
        thread_log("Worker iniciado")
        processed_count = 0
        
        while True:
            # Tomar un dominio de la cola
            domain_info = None
            with queue_lock:
                if queue:
                    domain_info = queue.popleft()
                    
            if not domain_info:
                thread_log("No hay más dominios en cola, terminando worker")
                break
                
            domain, depth = domain_info
            
            # Verificar si ya fue procesado
            with processed_lock:
                if domain in processed:
                    thread_log(f"Dominio {domain} ya procesado, saltando")
                    continue
                processed.add(domain)
            
            # Verificar si ya está en checkpoint
            if domain in domains_completed:
                thread_log(f"Dominio {domain} ya completado en checkpoint, saltando")
                continue
            
            processed_count += 1
            thread_log(f"Procesando dominio #{processed_count}: {domain} (depth={depth}) [Cola: {len(queue)}]")
            
            try:
                # Obtener resultados de Amass (con cache)
                amass_results = get_amass_results_cached(domain)
                debug_log(f"Usando {len(amass_results)} resultados de Amass para {domain}")
                
                # Procesar el dominio
                enrich_and_ingest_with_amass_results(
                    domain, depth, ing, queue, processed, 
                    args.sample, queue_lock, processed_lock, amass_results
                )
                
                # Marcar como completado
                mark_domain_completed(domain)
                thread_log(f"✓ Completado procesamiento de {domain}")
                
            except Exception as e:
                thread_log(f"ERROR procesando {domain}: {e}")
        
        thread_log(f"Worker finalizado - procesó {processed_count} dominios")

    try:
        # Crear y ejecutar threads
        threads = []
        for i in range(args.threads):
            t = threading.Thread(target=worker, name=f"Worker-{i}")
            t.start()
            threads.append(t)
        
        # Esperar a que terminen todos los threads
        for t in threads:
            t.join()
        
        # Guardar checkpoint final
        save_checkpoint()
        print(f"[*] Progreso final guardado: {len(domains_completed)} dominios completados")
            
    finally:
        driver.close()
        print("✓ Finalizado")


if __name__ == "__main__":
    main()
