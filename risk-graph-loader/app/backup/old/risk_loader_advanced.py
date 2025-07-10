
#!/usr/bin/env python3
"""risk_amass_loader.py

Carga masiva de datos de dominios en Neo4j utilizando Amass (vía Docker).

Uso:
    python risk_amass_loader.py --domains dominios.txt --depth 2 \
        --neo4j bolt://localhost:7687 --user neo4j --password test

Requisitos:
  * Python 3.12
  * Docker CLI instalado (para ejecutar Amass)
  * cypher-shell o el controlador Neo4j Bolt (`pip install neo4j`)
"""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Set, Dict, List
from collections import deque

try:
    from neo4j import GraphDatabase
except ImportError:
    print("Se requiere el paquete neo4j. Instala con: pip install neo4j", file=sys.stderr)
    sys.exit(1)


AMASS_IMAGE = "caffix/amass:latest"


def run_amass_local(domain: str, out_json: Path, sample_mode: bool = False):
    """Ejecuta Amass local para un dominio y guarda resultado JSON."""
    cmd = [
        "amass", "enum", "-v", "-d", domain, "-o", str(out_json)
    ]
    
    # En modo sample, usar configuración rápida
    if sample_mode:
        cmd.extend(["-timeout", "2"])  # Timeout de 2 minutos
        print(f"[+] Ejecutando Amass local (modo sample) para {domain} ...", file=sys.stderr)
    else:
        print(f"[+] Ejecutando Amass local para {domain} ...", file=sys.stderr)
    
    subprocess.run(cmd, check=True, stdout=None, stderr=None)


def run_amass(domain: str, out_json: Path):
    """Ejecuta Amass para un dominio y guarda resultado JSON."""
    cmd = [
        "docker", "run", "--rm", "-v", "/tmp/amass:/.config/amass:rw",
        AMASS_IMAGE,
        "enum", "-v", "-d",
         "-o /out/result.json", domain
    ]
    # Monta un volumen temporal
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir)
        docker_cmd = cmd.copy()
        docker_cmd.insert(2, "-v")
        docker_cmd.insert(3, f"{out_dir}:/out")
        print(f"[+] Ejecutando Amass para {domain} ...", file=sys.stderr)
        subprocess.run(docker_cmd, check=True)
        result_file = out_dir / "result.json"
        out_json.write_bytes(result_file.read_bytes())


def parse_amass(output_path: Path) -> List[Dict]:
    """Devuelve lista de entradas Amass parseadas desde formato texto."""
    entries = []
    domains = set()
    
    with output_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line or "The enumeration has finished" in line:
                continue
                
            # Parsear diferentes tipos de relaciones
            if " --> " in line:
                parts = line.split(" --> ")
                if len(parts) == 3:
                    source, relation, target = parts
                    
                    # Limpiar etiquetas de tipo
                    source_clean = source.replace(" (FQDN)", "").replace(" (IPAddress)", "").replace(" (Netblock)", "").replace(" (ASN)", "").replace(" (RIROrganization)", "").strip()
                    target_clean = target.replace(" (FQDN)", "").replace(" (IPAddress)", "").replace(" (Netblock)", "").replace(" (ASN)", "").replace(" (RIROrganization)", "").strip()
                    
                    # Procesar según el tipo de relación
                    if relation == "a_record":
                        # A record: dominio -> IP
                        entries.append({
                            "name": source_clean,
                            "addresses": [{"ip": target_clean}]
                        })
                        domains.add(source_clean)
                        
                    elif relation == "node":
                        # Node: dominio padre -> subdominio
                        entries.append({
                            "name": source_clean,
                            "subdomains": [target_clean]
                        })
                        domains.add(source_clean)
                        domains.add(target_clean)
                        
                    elif relation == "cname_record":
                        # CNAME: dominio -> canonical name
                        entries.append({
                            "name": source_clean,
                            "cname": target_clean
                        })
                        domains.add(source_clean)
                        
                    elif relation == "contains":
                        # Contains: netblock -> IP
                        entries.append({
                            "name": source_clean,
                            "contains": target_clean
                        })
                        
                    elif relation == "announces":
                        # Announces: ASN -> netblock
                        entries.append({
                            "name": source_clean,
                            "announces": target_clean
                        })
                        
                    elif relation == "managed_by":
                        # Managed by: ASN -> organization
                        entries.append({
                            "name": source_clean,
                            "managed_by": target_clean
                        })
    
    # Agregar dominios encontrados como entradas básicas
    for domain in domains:
        if not any(e.get("name") == domain for e in entries):
            entries.append({"name": domain})
    
    return entries


class Neo4jLoader:
    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def add_domain(self, domain: str):
        cypher = "MERGE (:Domain {fqdn:$fqdn})"
        with self.driver.session() as s:
            s.run(cypher, fqdn=domain)

    def add_subdomain(self, parent: str, sub: str):
        cypher = """MERGE (p:Domain {fqdn:$parent})
                   MERGE (c:Domain {fqdn:$child})
                   MERGE (p)-[:HAS_SUBDOMAIN]->(c)"""
        with self.driver.session() as s:
            s.run(cypher, parent=parent, child=sub)

    def add_ip(self, domain: str, ip: str):
        cypher = """MERGE (d:Domain {fqdn:$fqdn})
                   MERGE (i:IP {ip:$ip})
                   MERGE (d)-[:RESOLVES_TO]->(i)"""
        with self.driver.session() as s:
            s.run(cypher, fqdn=domain, ip=ip)


def main():
    parser = argparse.ArgumentParser(description="Bulk domain loader via Amass")
    parser.add_argument("--domains", required=True,
                        help="Archivo con lista de dominios (uno por línea)")
    parser.add_argument("--depth", type=int, default=1,
                        help="Profundidad de recursión (default: 1)")
    parser.add_argument("--sample", action="store_true",
                        help="Modo prueba: procesa solo el primer dominio con ejecución rápida")
    parser.add_argument("--neo4j", default="bolt://localhost:7687")
    parser.add_argument("--user", default="neo4j")
    parser.add_argument("--password", default="test.password",)
    args = parser.parse_args()

    start_domains = [d.strip() for d in Path(args.domains).read_text().splitlines() if d.strip()]
    
    # En modo sample, usar solo el primer dominio
    if args.sample:
        start_domains = start_domains[:1]
        print(f"[*] Modo sample: procesando solo {start_domains[0]}", file=sys.stderr)
    
    processed: Set[str] = set()
    queue = deque([(d, 0) for d in start_domains])

    loader = Neo4jLoader(args.neo4j, args.user, args.password)

    try:
        while queue:
            domain, depth = queue.popleft()
            if domain in processed or depth > args.depth:
                continue
            processed.add(domain)

            # Ejecuta Amass
            tmp_json = Path(tempfile.mktemp(suffix=".json"))
            try:
                run_amass_local(domain, tmp_json, args.sample)
            except subprocess.CalledProcessError as e:
                print(f"[!] Error Amass {domain}: {e}", file=sys.stderr)
                continue

            amass_data = parse_amass(tmp_json)
            loader.add_domain(domain)

            for entry in amass_data:
                name = entry.get("name")
                if not name:
                    continue
                    
                # Agregar dominio si no existe
                if name != domain:
                    loader.add_domain(name)
                
                # Manejar subdominios (relación node)
                subdomains = entry.get("subdomains", [])
                for subdomain in subdomains:
                    loader.add_subdomain(name, subdomain)
                    if depth + 1 <= args.depth:
                        queue.append((subdomain, depth + 1))

                # Manejar direcciones IP (relación a_record)
                addresses = entry.get("addresses", [])
                for addr in addresses:
                    ip = addr.get("ip")
                    if ip:
                        loader.add_ip(name, ip)

            print(f"[✓] {domain} procesado: {len(amass_data)} descubrimientos", file=sys.stderr)
    finally:
        loader.close()


if __name__ == "__main__":
    main()
