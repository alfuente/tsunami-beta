#!/usr/bin/env python3
"""
get_latam_top_domains.py
------------------------
Extrae los N dominios mejor rankeados de cada país latinoamericano
a partir de una lista Tranco (KW2XW por defecto) y:

1. Guarda un CSV por país con columnas rank_global,domain,sector.
2. Genera un archivo combinado (TXT) con SOLO los dominios.

Uso:
    python get_latam_top_domains.py                     # 200 dom. por país
    python get_latam_top_domains.py --limit 100         # 100 por país
    python get_latam_top_domains.py --list-id ABCD      # otra lista
"""

import argparse
import csv
import datetime as dt
import io
import re
import zipfile
from pathlib import Path
from typing import Dict, List, Tuple

import requests

# --------------------------------------------------------------------------- #
# Configuración
# --------------------------------------------------------------------------- #

DEFAULT_LIST_ID = "KW2XW"            # Lista Tranco (05-jul-2025)
DEFAULT_LIMIT   = 200                # Nº de dominios por país

CSV_URL = "https://tranco-list.eu/download/{id}/1000000"
ZIP_URL = "https://tranco-list.eu/download_daily/{id}"

LATAM_CC_TLDS: Dict[str, str] = {
    "Argentina": "ar",  "Bolivia": "bo",      "Brazil": "br",   "Chile": "cl",
    "Colombia": "co",    "Ecuador": "ec",    
    "Mexico": "mx",      "Paraguay": "py",
    "Peru": "pe",        "Uruguay": "uy",  
}

FIN_KEYWORDS = [
    "bank", "banco", "bbva", "santander", "itau", "scotiabank",
    "bradesco", "caixa", "bcp", ".bank"
]
PUB_PATTERN = re.compile(r"\.(gob|gov|edu)\.", re.IGNORECASE)

# --------------------------------------------------------------------------- #
# Descarga de la lista
# --------------------------------------------------------------------------- #

def _stream_csv(url: str) -> io.TextIOBase:
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    return io.StringIO(resp.text)

def _stream_zip(url: str) -> io.TextIOBase:
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    name = zf.namelist()[0]
    return io.TextIOWrapper(zf.open(name), encoding="utf-8")

def open_tranco_stream(list_id: str) -> io.TextIOBase:
    try:
        return _stream_csv(CSV_URL.format(id=list_id))
    except Exception:
        return _stream_zip(ZIP_URL.format(id=list_id))

# --------------------------------------------------------------------------- #
# Clasificación sector
# --------------------------------------------------------------------------- #

def sector(domain: str) -> str:
    d = domain.lower()
    if PUB_PATTERN.search(d):
        return "public"
    if any(k in d for k in FIN_KEYWORDS):
        return "financial"
    return "private"

# --------------------------------------------------------------------------- #
# Principal
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="Genera listados de dominios LATAM desde Tranco"
    )
    parser.add_argument("--list-id", default=DEFAULT_LIST_ID,
                        help="ID de lista Tranco (p.ej. KW2XW)")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                        help="Dominios por país (default 200)")
    args = parser.parse_args()

    reader = csv.reader(open_tranco_stream(args.list_id))

    buckets: Dict[str, List[Tuple[str, str, str]]] = {c: [] for c in LATAM_CC_TLDS}

    for global_rank, domain in reader:
        for country, tld in LATAM_CC_TLDS.items():
            if domain.endswith(f".{tld}") and len(buckets[country]) < args.limit:
                buckets[country].append((global_rank, domain, sector(domain)))
        if all(len(lst) == args.limit for lst in buckets.values()):
            break

    out_dir = Path("output")
    out_dir.mkdir(exist_ok=True)
    today = dt.date.today().isoformat()

    # --- 1) CSV por país -----------------------------------------------------
    for country, rows in buckets.items():
        csv_path = out_dir / f"{country.replace(' ', '_')}_{args.list_id}_{today}.csv"
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["rank_global", "domain", "sector"])
            w.writerows(rows)

    # --- 2) Archivo combinado solo con dominios -----------------------------
    combined_path = out_dir / f"latam_domains_{args.list_id}_{today}.txt"
    with combined_path.open("w", encoding="utf-8") as fh:
        for rows in buckets.values():
            for _rank, dom, _sec in rows:
                fh.write(dom + "\n")

    print(f"Generados {len(buckets)} CSV por país + archivo combinado:")
    print(f" └─ {combined_path}")

if __name__ == "__main__":
    main()
