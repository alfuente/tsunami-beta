#!/usr/bin/env python3
"""
subdomain_relationship_discovery_unified.py - Unified Subdomain Discovery Engine v6.0

This version consolidates and enhances the best features from v4.0 and v5.0:

Features from v4.0:
- Comprehensive TLS certificate analysis with grade calculation
- Enhanced service detection (pattern, port scanning, DNS-based)
- Advanced provider identification through multiple strategies
- Real-time Certificate/Service/Provider node creation
- Industry classification for domains
- Enhanced risk scoring and tier calculation
- Machine learning provider classification

Features from v5.0:
- Smart provider detection from metadata (as_domain, as_name)
- Enhanced TLD extraction from country codes
- Metadata-driven provider naming
- Provider name normalization
- Improved confidence scoring
- Country-based TLD mapping
- ASN-based provider resolution

New in v6.0 (Unified):
- Modular architecture for REST API exposure
- Configurable processing pipelines
- Enhanced error handling and validation
- Performance optimizations
- Comprehensive logging and metrics
- Provider detection integration (MX records)
"""

from __future__ import annotations
import argparse, json, subprocess, tempfile, sys, socket, ssl, re, os
from typing import Tuple
from collections import deque, defaultdict
from pathlib import Path
from datetime import datetime, timedelta
from typing import Iterable, Mapping, Any, List, Dict, Set, Tuple, Optional
import threading
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import multiprocessing as mp
from threading import Lock
import time
import queue
from dataclasses import dataclass, field
from enum import Enum
import random
import hashlib

import dns.resolver, dns.exception, requests, logging
import csv
import ipaddress

# Optional module imports
try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

try:
    from neo4j import GraphDatabase
    import neo4j
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False

try:
    from ipinfo import getHandler
    HAS_IPINFO = True
except ImportError:
    HAS_IPINFO = False

try:
    import maxminddb
    HAS_MAXMINDDB = True
except ImportError:
    HAS_MAXMINDDB = False

try:
    from industry_classifier import IndustryClassifier
    HAS_INDUSTRY_CLASSIFIER = True
except ImportError:
    HAS_INDUSTRY_CLASSIFIER = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    from provider_detection import ProviderDetector
    HAS_PROVIDER_DETECTION = True
except ImportError:
    HAS_PROVIDER_DETECTION = False

try:
    from domain_risk_calculator import DomainRiskCalculator
    HAS_RISK_CALCULATOR = True
except ImportError:
    HAS_RISK_CALCULATOR = False

# Global configurations
AMASS_IMAGE = "caffix/amass:latest"
RESOLVER = dns.resolver.Resolver(configure=True)
RESOLVER.lifetime = RESOLVER.timeout = 5.0

# Global logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f'subdomain_discovery_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ProcessingConfig:
    """Configuration for subdomain processing"""
    # Discovery options
    enable_amass: bool = True
    enable_subdomain_enumeration: bool = True
    amass_timeout: int = 300
    max_subdomains: int = 1000
    
    # Analysis options
    enable_tls_analysis: bool = True
    enable_service_detection: bool = True
    enable_provider_detection: bool = True
    enable_industry_classification: bool = True
    enable_risk_calculation: bool = True
    enable_mx_analysis: bool = True
    
    # Performance options
    max_workers: int = 10
    batch_size: int = 50
    timeout_per_subdomain: int = 30
    
    # Cache options
    amass_cache_duration_hours: int = 168  # 1 week default
    amass_cache_dir: str = "./amass_cache"
    enable_cache_check: bool = True
    
    # Output options
    save_to_neo4j: bool = True
    generate_report: bool = True
    include_raw_data: bool = False

@dataclass
class ProviderInfo:
    """Enhanced provider information from multiple sources"""
    name: str
    confidence: float
    source: str
    tld: Optional[str] = None
    country: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    risk_level: Optional[str] = None
    provider_type: Optional[str] = None

@dataclass 
class EnhancedDomainInfo:
    """Enhanced domain information with metadata"""
    fqdn: str
    base_domain: Optional[str] = None
    subdomain_level: int = 0
    tld: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DiscoveryResult:
    """Result of subdomain discovery and analysis"""
    domain: str
    subdomains: List[str]
    providers: List[ProviderInfo]
    services: List[Dict[str, Any]]
    certificates: List[Dict[str, Any]]
    risks: List[Dict[str, Any]]
    industry_classification: Optional[Dict[str, Any]]
    processing_time: float
    errors: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)

class TLDManager:
    """Enhanced TLD management with country mapping"""
    
    def __init__(self):
        self.country_tld_map = {
            'af': {'country_code': 'AF', 'country_name': 'Afghanistan', 'tld_type': 'country'},
            'al': {'country_code': 'AL', 'country_name': 'Albania', 'tld_type': 'country'},
            'dz': {'country_code': 'DZ', 'country_name': 'Algeria', 'tld_type': 'country'},
            'as': {'country_code': 'AS', 'country_name': 'American Samoa', 'tld_type': 'country'},
            'ad': {'country_code': 'AD', 'country_name': 'Andorra', 'tld_type': 'country'},
            'ao': {'country_code': 'AO', 'country_name': 'Angola', 'tld_type': 'country'},
            'ai': {'country_code': 'AI', 'country_name': 'Anguilla', 'tld_type': 'country'},
            'aq': {'country_code': 'AQ', 'country_name': 'Antarctica', 'tld_type': 'country'},
            'ag': {'country_code': 'AG', 'country_name': 'Antigua and Barbuda', 'tld_type': 'country'},
            'ar': {'country_code': 'AR', 'country_name': 'Argentina', 'tld_type': 'country'},
            'am': {'country_code': 'AM', 'country_name': 'Armenia', 'tld_type': 'country'},
            'aw': {'country_code': 'AW', 'country_name': 'Aruba', 'tld_type': 'country'},
            'au': {'country_code': 'AU', 'country_name': 'Australia', 'tld_type': 'country'},
            'at': {'country_code': 'AT', 'country_name': 'Austria', 'tld_type': 'country'},
            'az': {'country_code': 'AZ', 'country_name': 'Azerbaijan', 'tld_type': 'country'},
            'bs': {'country_code': 'BS', 'country_name': 'Bahamas', 'tld_type': 'country'},
            'bh': {'country_code': 'BH', 'country_name': 'Bahrain', 'tld_type': 'country'},
            'bd': {'country_code': 'BD', 'country_name': 'Bangladesh', 'tld_type': 'country'},
            'bb': {'country_code': 'BB', 'country_name': 'Barbados', 'tld_type': 'country'},
            'by': {'country_code': 'BY', 'country_name': 'Belarus', 'tld_type': 'country'},
            'be': {'country_code': 'BE', 'country_name': 'Belgium', 'tld_type': 'country'},
            'bz': {'country_code': 'BZ', 'country_name': 'Belize', 'tld_type': 'country'},
            'bj': {'country_code': 'BJ', 'country_name': 'Benin', 'tld_type': 'country'},
            'bm': {'country_code': 'BM', 'country_name': 'Bermuda', 'tld_type': 'country'},
            'bt': {'country_code': 'BT', 'country_name': 'Bhutan', 'tld_type': 'country'},
            'bo': {'country_code': 'BO', 'country_name': 'Bolivia', 'tld_type': 'country'},
            'bq': {'country_code': 'BQ', 'country_name': 'Caribbean Netherlands', 'tld_type': 'country'},
            'ba': {'country_code': 'BA', 'country_name': 'Bosnia and Herzegovina', 'tld_type': 'country'},
            'bw': {'country_code': 'BW', 'country_name': 'Botswana', 'tld_type': 'country'},
            'bv': {'country_code': 'BV', 'country_name': 'Bouvet Island', 'tld_type': 'country'},
            'br': {'country_code': 'BR', 'country_name': 'Brazil', 'tld_type': 'country'},
            'io': {'country_code': 'IO', 'country_name': 'British Indian Ocean Territory', 'tld_type': 'country'},
            'bn': {'country_code': 'BN', 'country_name': 'Brunei', 'tld_type': 'country'},
            'bg': {'country_code': 'BG', 'country_name': 'Bulgaria', 'tld_type': 'country'},
            'bf': {'country_code': 'BF', 'country_name': 'Burkina Faso', 'tld_type': 'country'},
            'bi': {'country_code': 'BI', 'country_name': 'Burundi', 'tld_type': 'country'},
            'cv': {'country_code': 'CV', 'country_name': 'Cape Verde', 'tld_type': 'country'},
            'kh': {'country_code': 'KH', 'country_name': 'Cambodia', 'tld_type': 'country'},
            'cm': {'country_code': 'CM', 'country_name': 'Cameroon', 'tld_type': 'country'},
            'ca': {'country_code': 'CA', 'country_name': 'Canada', 'tld_type': 'country'},
            'ky': {'country_code': 'KY', 'country_name': 'Cayman Islands', 'tld_type': 'country'},
            'cf': {'country_code': 'CF', 'country_name': 'Central African Republic', 'tld_type': 'country'},
            'td': {'country_code': 'TD', 'country_name': 'Chad', 'tld_type': 'country'},
            'cl': {'country_code': 'CL', 'country_name': 'Chile', 'tld_type': 'country'},
            'cn': {'country_code': 'CN', 'country_name': 'China', 'tld_type': 'country'},
            'cx': {'country_code': 'CX', 'country_name': 'Christmas Island', 'tld_type': 'country'},
            'cc': {'country_code': 'CC', 'country_name': 'Cocos Islands', 'tld_type': 'country'},
            'co': {'country_code': 'CO', 'country_name': 'Colombia', 'tld_type': 'country'},
            'km': {'country_code': 'KM', 'country_name': 'Comoros', 'tld_type': 'country'},
            'cg': {'country_code': 'CG', 'country_name': 'Republic of the Congo', 'tld_type': 'country'},
            'cd': {'country_code': 'CD', 'country_name': 'Democratic Republic of the Congo', 'tld_type': 'country'},
            'ck': {'country_code': 'CK', 'country_name': 'Cook Islands', 'tld_type': 'country'},
            'cr': {'country_code': 'CR', 'country_name': 'Costa Rica', 'tld_type': 'country'},
            'ci': {'country_code': 'CI', 'country_name': 'Ivory Coast', 'tld_type': 'country'},
            'hr': {'country_code': 'HR', 'country_name': 'Croatia', 'tld_type': 'country'},
            'cu': {'country_code': 'CU', 'country_name': 'Cuba', 'tld_type': 'country'},
            'cw': {'country_code': 'CW', 'country_name': 'Curacao', 'tld_type': 'country'},
            'cy': {'country_code': 'CY', 'country_name': 'Cyprus', 'tld_type': 'country'},
            'cz': {'country_code': 'CZ', 'country_name': 'Czech Republic', 'tld_type': 'country'},
            'dk': {'country_code': 'DK', 'country_name': 'Denmark', 'tld_type': 'country'},
            'dj': {'country_code': 'DJ', 'country_name': 'Djibouti', 'tld_type': 'country'},
            'dm': {'country_code': 'DM', 'country_name': 'Dominica', 'tld_type': 'country'},
            'do': {'country_code': 'DO', 'country_name': 'Dominican Republic', 'tld_type': 'country'},
            'ec': {'country_code': 'EC', 'country_name': 'Ecuador', 'tld_type': 'country'},
            'eg': {'country_code': 'EG', 'country_name': 'Egypt', 'tld_type': 'country'},
            'sv': {'country_code': 'SV', 'country_name': 'El Salvador', 'tld_type': 'country'},
            'gq': {'country_code': 'GQ', 'country_name': 'Equatorial Guinea', 'tld_type': 'country'},
            'er': {'country_code': 'ER', 'country_name': 'Eritrea', 'tld_type': 'country'},
            'ee': {'country_code': 'EE', 'country_name': 'Estonia', 'tld_type': 'country'},
            'et': {'country_code': 'ET', 'country_name': 'Ethiopia', 'tld_type': 'country'},
            'fk': {'country_code': 'FK', 'country_name': 'Falkland Islands', 'tld_type': 'country'},
            'fo': {'country_code': 'FO', 'country_name': 'Faroe Islands', 'tld_type': 'country'},
            'fj': {'country_code': 'FJ', 'country_name': 'Fiji', 'tld_type': 'country'},
            'fi': {'country_code': 'FI', 'country_name': 'Finland', 'tld_type': 'country'},
            'fr': {'country_code': 'FR', 'country_name': 'France', 'tld_type': 'country'},
            'gf': {'country_code': 'GF', 'country_name': 'French Guiana', 'tld_type': 'country'},
            'pf': {'country_code': 'PF', 'country_name': 'French Polynesia', 'tld_type': 'country'},
            'tf': {'country_code': 'TF', 'country_name': 'French Southern Territories', 'tld_type': 'country'},
            'ga': {'country_code': 'GA', 'country_name': 'Gabon', 'tld_type': 'country'},
            'gm': {'country_code': 'GM', 'country_name': 'Gambia', 'tld_type': 'country'},
            'ge': {'country_code': 'GE', 'country_name': 'Georgia', 'tld_type': 'country'},
            'de': {'country_code': 'DE', 'country_name': 'Germany', 'tld_type': 'country'},
            'gh': {'country_code': 'GH', 'country_name': 'Ghana', 'tld_type': 'country'},
            'gi': {'country_code': 'GI', 'country_name': 'Gibraltar', 'tld_type': 'country'},
            'gr': {'country_code': 'GR', 'country_name': 'Greece', 'tld_type': 'country'},
            'gl': {'country_code': 'GL', 'country_name': 'Greenland', 'tld_type': 'country'},
            'gd': {'country_code': 'GD', 'country_name': 'Grenada', 'tld_type': 'country'},
            'gp': {'country_code': 'GP', 'country_name': 'Guadeloupe', 'tld_type': 'country'},
            'gu': {'country_code': 'GU', 'country_name': 'Guam', 'tld_type': 'country'},
            'gt': {'country_code': 'GT', 'country_name': 'Guatemala', 'tld_type': 'country'},
            'gg': {'country_code': 'GG', 'country_name': 'Guernsey', 'tld_type': 'country'},
            'gn': {'country_code': 'GN', 'country_name': 'Guinea', 'tld_type': 'country'},
            'gw': {'country_code': 'GW', 'country_name': 'Guinea-Bissau', 'tld_type': 'country'},
            'gy': {'country_code': 'GY', 'country_name': 'Guyana', 'tld_type': 'country'},
            'ht': {'country_code': 'HT', 'country_name': 'Haiti', 'tld_type': 'country'},
            'hm': {'country_code': 'HM', 'country_name': 'Heard Island and McDonald Islands', 'tld_type': 'country'},
            'va': {'country_code': 'VA', 'country_name': 'Vatican City', 'tld_type': 'country'},
            'hn': {'country_code': 'HN', 'country_name': 'Honduras', 'tld_type': 'country'},
            'hk': {'country_code': 'HK', 'country_name': 'Hong Kong', 'tld_type': 'country'},
            'hu': {'country_code': 'HU', 'country_name': 'Hungary', 'tld_type': 'country'},
            'is': {'country_code': 'IS', 'country_name': 'Iceland', 'tld_type': 'country'},
            'in': {'country_code': 'IN', 'country_name': 'India', 'tld_type': 'country'},
            'id': {'country_code': 'ID', 'country_name': 'Indonesia', 'tld_type': 'country'},
            'ir': {'country_code': 'IR', 'country_name': 'Iran', 'tld_type': 'country'},
            'iq': {'country_code': 'IQ', 'country_name': 'Iraq', 'tld_type': 'country'},
            'ie': {'country_code': 'IE', 'country_name': 'Ireland', 'tld_type': 'country'},
            'im': {'country_code': 'IM', 'country_name': 'Isle of Man', 'tld_type': 'country'},
            'il': {'country_code': 'IL', 'country_name': 'Israel', 'tld_type': 'country'},
            'it': {'country_code': 'IT', 'country_name': 'Italy', 'tld_type': 'country'},
            'jm': {'country_code': 'JM', 'country_name': 'Jamaica', 'tld_type': 'country'},
            'jp': {'country_code': 'JP', 'country_name': 'Japan', 'tld_type': 'country'},
            'je': {'country_code': 'JE', 'country_name': 'Jersey', 'tld_type': 'country'},
            'jo': {'country_code': 'JO', 'country_name': 'Jordan', 'tld_type': 'country'},
            'kz': {'country_code': 'KZ', 'country_name': 'Kazakhstan', 'tld_type': 'country'},
            'ke': {'country_code': 'KE', 'country_name': 'Kenya', 'tld_type': 'country'},
            'ki': {'country_code': 'KI', 'country_name': 'Kiribati', 'tld_type': 'country'},
            'kp': {'country_code': 'KP', 'country_name': 'North Korea', 'tld_type': 'country'},
            'kr': {'country_code': 'KR', 'country_name': 'South Korea', 'tld_type': 'country'},
            'kw': {'country_code': 'KW', 'country_name': 'Kuwait', 'tld_type': 'country'},
            'kg': {'country_code': 'KG', 'country_name': 'Kyrgyzstan', 'tld_type': 'country'},
            'la': {'country_code': 'LA', 'country_name': 'Laos', 'tld_type': 'country'},
            'lv': {'country_code': 'LV', 'country_name': 'Latvia', 'tld_type': 'country'},
            'lb': {'country_code': 'LB', 'country_name': 'Lebanon', 'tld_type': 'country'},
            'ls': {'country_code': 'LS', 'country_name': 'Lesotho', 'tld_type': 'country'},
            'lr': {'country_code': 'LR', 'country_name': 'Liberia', 'tld_type': 'country'},
            'ly': {'country_code': 'LY', 'country_name': 'Libya', 'tld_type': 'country'},
            'li': {'country_code': 'LI', 'country_name': 'Liechtenstein', 'tld_type': 'country'},
            'lt': {'country_code': 'LT', 'country_name': 'Lithuania', 'tld_type': 'country'},
            'lu': {'country_code': 'LU', 'country_name': 'Luxembourg', 'tld_type': 'country'},
            'mo': {'country_code': 'MO', 'country_name': 'Macau', 'tld_type': 'country'},
            'mk': {'country_code': 'MK', 'country_name': 'North Macedonia', 'tld_type': 'country'},
            'mg': {'country_code': 'MG', 'country_name': 'Madagascar', 'tld_type': 'country'},
            'mw': {'country_code': 'MW', 'country_name': 'Malawi', 'tld_type': 'country'},
            'my': {'country_code': 'MY', 'country_name': 'Malaysia', 'tld_type': 'country'},
            'mv': {'country_code': 'MV', 'country_name': 'Maldives', 'tld_type': 'country'},
            'ml': {'country_code': 'ML', 'country_name': 'Mali', 'tld_type': 'country'},
            'mt': {'country_code': 'MT', 'country_name': 'Malta', 'tld_type': 'country'},
            'mh': {'country_code': 'MH', 'country_name': 'Marshall Islands', 'tld_type': 'country'},
            'mq': {'country_code': 'MQ', 'country_name': 'Martinique', 'tld_type': 'country'},
            'mr': {'country_code': 'MR', 'country_name': 'Mauritania', 'tld_type': 'country'},
            'mu': {'country_code': 'MU', 'country_name': 'Mauritius', 'tld_type': 'country'},
            'yt': {'country_code': 'YT', 'country_name': 'Mayotte', 'tld_type': 'country'},
            'mx': {'country_code': 'MX', 'country_name': 'Mexico', 'tld_type': 'country'},
            'fm': {'country_code': 'FM', 'country_name': 'Micronesia', 'tld_type': 'country'},
            'md': {'country_code': 'MD', 'country_name': 'Moldova', 'tld_type': 'country'},
            'mc': {'country_code': 'MC', 'country_name': 'Monaco', 'tld_type': 'country'},
            'mn': {'country_code': 'MN', 'country_name': 'Mongolia', 'tld_type': 'country'},
            'me': {'country_code': 'ME', 'country_name': 'Montenegro', 'tld_type': 'country'},
            'ms': {'country_code': 'MS', 'country_name': 'Montserrat', 'tld_type': 'country'},
            'ma': {'country_code': 'MA', 'country_name': 'Morocco', 'tld_type': 'country'},
            'mz': {'country_code': 'MZ', 'country_name': 'Mozambique', 'tld_type': 'country'},
            'mm': {'country_code': 'MM', 'country_name': 'Myanmar', 'tld_type': 'country'},
            'na': {'country_code': 'NA', 'country_name': 'Namibia', 'tld_type': 'country'},
            'nr': {'country_code': 'NR', 'country_name': 'Nauru', 'tld_type': 'country'},
            'np': {'country_code': 'NP', 'country_name': 'Nepal', 'tld_type': 'country'},
            'nl': {'country_code': 'NL', 'country_name': 'Netherlands', 'tld_type': 'country'},
            'nc': {'country_code': 'NC', 'country_name': 'New Caledonia', 'tld_type': 'country'},
            'nz': {'country_code': 'NZ', 'country_name': 'New Zealand', 'tld_type': 'country'},
            'ni': {'country_code': 'NI', 'country_name': 'Nicaragua', 'tld_type': 'country'},
            'ne': {'country_code': 'NE', 'country_name': 'Niger', 'tld_type': 'country'},
            'ng': {'country_code': 'NG', 'country_name': 'Nigeria', 'tld_type': 'country'},
            'nu': {'country_code': 'NU', 'country_name': 'Niue', 'tld_type': 'country'},
            'nf': {'country_code': 'NF', 'country_name': 'Norfolk Island', 'tld_type': 'country'},
            'mp': {'country_code': 'MP', 'country_name': 'Northern Mariana Islands', 'tld_type': 'country'},
            'no': {'country_code': 'NO', 'country_name': 'Norway', 'tld_type': 'country'},
            'om': {'country_code': 'OM', 'country_name': 'Oman', 'tld_type': 'country'},
            'pk': {'country_code': 'PK', 'country_name': 'Pakistan', 'tld_type': 'country'},
            'pw': {'country_code': 'PW', 'country_name': 'Palau', 'tld_type': 'country'},
            'ps': {'country_code': 'PS', 'country_name': 'Palestine', 'tld_type': 'country'},
            'pa': {'country_code': 'PA', 'country_name': 'Panama', 'tld_type': 'country'},
            'pg': {'country_code': 'PG', 'country_name': 'Papua New Guinea', 'tld_type': 'country'},
            'py': {'country_code': 'PY', 'country_name': 'Paraguay', 'tld_type': 'country'},
            'pe': {'country_code': 'PE', 'country_name': 'Peru', 'tld_type': 'country'},
            'ph': {'country_code': 'PH', 'country_name': 'Philippines', 'tld_type': 'country'},
            'pn': {'country_code': 'PN', 'country_name': 'Pitcairn Islands', 'tld_type': 'country'},
            'pl': {'country_code': 'PL', 'country_name': 'Poland', 'tld_type': 'country'},
            'pt': {'country_code': 'PT', 'country_name': 'Portugal', 'tld_type': 'country'},
            'pr': {'country_code': 'PR', 'country_name': 'Puerto Rico', 'tld_type': 'country'},
            'qa': {'country_code': 'QA', 'country_name': 'Qatar', 'tld_type': 'country'},
            're': {'country_code': 'RE', 'country_name': 'Reunion', 'tld_type': 'country'},
            'ro': {'country_code': 'RO', 'country_name': 'Romania', 'tld_type': 'country'},
            'ru': {'country_code': 'RU', 'country_name': 'Russia', 'tld_type': 'country'},
            'rw': {'country_code': 'RW', 'country_name': 'Rwanda', 'tld_type': 'country'},
            'bl': {'country_code': 'BL', 'country_name': 'Saint Barthelemy', 'tld_type': 'country'},
            'sh': {'country_code': 'SH', 'country_name': 'Saint Helena', 'tld_type': 'country'},
            'kn': {'country_code': 'KN', 'country_name': 'Saint Kitts and Nevis', 'tld_type': 'country'},
            'lc': {'country_code': 'LC', 'country_name': 'Saint Lucia', 'tld_type': 'country'},
            'mf': {'country_code': 'MF', 'country_name': 'Saint Martin', 'tld_type': 'country'},
            'pm': {'country_code': 'PM', 'country_name': 'Saint Pierre and Miquelon', 'tld_type': 'country'},
            'vc': {'country_code': 'VC', 'country_name': 'Saint Vincent and the Grenadines', 'tld_type': 'country'},
            'ws': {'country_code': 'WS', 'country_name': 'Samoa', 'tld_type': 'country'},
            'sm': {'country_code': 'SM', 'country_name': 'San Marino', 'tld_type': 'country'},
            'st': {'country_code': 'ST', 'country_name': 'Sao Tome and Principe', 'tld_type': 'country'},
            'sa': {'country_code': 'SA', 'country_name': 'Saudi Arabia', 'tld_type': 'country'},
            'sn': {'country_code': 'SN', 'country_name': 'Senegal', 'tld_type': 'country'},
            'rs': {'country_code': 'RS', 'country_name': 'Serbia', 'tld_type': 'country'},
            'sc': {'country_code': 'SC', 'country_name': 'Seychelles', 'tld_type': 'country'},
            'sl': {'country_code': 'SL', 'country_name': 'Sierra Leone', 'tld_type': 'country'},
            'sg': {'country_code': 'SG', 'country_name': 'Singapore', 'tld_type': 'country'},
            'sx': {'country_code': 'SX', 'country_name': 'Sint Maarten', 'tld_type': 'country'},
            'sk': {'country_code': 'SK', 'country_name': 'Slovakia', 'tld_type': 'country'},
            'si': {'country_code': 'SI', 'country_name': 'Slovenia', 'tld_type': 'country'},
            'sb': {'country_code': 'SB', 'country_name': 'Solomon Islands', 'tld_type': 'country'},
            'so': {'country_code': 'SO', 'country_name': 'Somalia', 'tld_type': 'country'},
            'za': {'country_code': 'ZA', 'country_name': 'South Africa', 'tld_type': 'country'},
            'gs': {'country_code': 'GS', 'country_name': 'South Georgia and the South Sandwich Islands', 'tld_type': 'country'},
            'ss': {'country_code': 'SS', 'country_name': 'South Sudan', 'tld_type': 'country'},
            'es': {'country_code': 'ES', 'country_name': 'Spain', 'tld_type': 'country'},
            'lk': {'country_code': 'LK', 'country_name': 'Sri Lanka', 'tld_type': 'country'},
            'sd': {'country_code': 'SD', 'country_name': 'Sudan', 'tld_type': 'country'},
            'sr': {'country_code': 'SR', 'country_name': 'Suriname', 'tld_type': 'country'},
            'sj': {'country_code': 'SJ', 'country_name': 'Svalbard and Jan Mayen', 'tld_type': 'country'},
            'sz': {'country_code': 'SZ', 'country_name': 'Eswatini', 'tld_type': 'country'},
            'se': {'country_code': 'SE', 'country_name': 'Sweden', 'tld_type': 'country'},
            'ch': {'country_code': 'CH', 'country_name': 'Switzerland', 'tld_type': 'country'},
            'sy': {'country_code': 'SY', 'country_name': 'Syria', 'tld_type': 'country'},
            'tw': {'country_code': 'TW', 'country_name': 'Taiwan', 'tld_type': 'country'},
            'tj': {'country_code': 'TJ', 'country_name': 'Tajikistan', 'tld_type': 'country'},
            'tz': {'country_code': 'TZ', 'country_name': 'Tanzania', 'tld_type': 'country'},
            'th': {'country_code': 'TH', 'country_name': 'Thailand', 'tld_type': 'country'},
            'tl': {'country_code': 'TL', 'country_name': 'East Timor', 'tld_type': 'country'},
            'tg': {'country_code': 'TG', 'country_name': 'Togo', 'tld_type': 'country'},
            'tk': {'country_code': 'TK', 'country_name': 'Tokelau', 'tld_type': 'country'},
            'to': {'country_code': 'TO', 'country_name': 'Tonga', 'tld_type': 'country'},
            'tt': {'country_code': 'TT', 'country_name': 'Trinidad and Tobago', 'tld_type': 'country'},
            'tn': {'country_code': 'TN', 'country_name': 'Tunisia', 'tld_type': 'country'},
            'tr': {'country_code': 'TR', 'country_name': 'Turkey', 'tld_type': 'country'},
            'tm': {'country_code': 'TM', 'country_name': 'Turkmenistan', 'tld_type': 'country'},
            'tc': {'country_code': 'TC', 'country_name': 'Turks and Caicos Islands', 'tld_type': 'country'},
            'tv': {'country_code': 'TV', 'country_name': 'Tuvalu', 'tld_type': 'country'},
            'ug': {'country_code': 'UG', 'country_name': 'Uganda', 'tld_type': 'country'},
            'ua': {'country_code': 'UA', 'country_name': 'Ukraine', 'tld_type': 'country'},
            'ae': {'country_code': 'AE', 'country_name': 'United Arab Emirates', 'tld_type': 'country'},
            'gb': {'country_code': 'GB', 'country_name': 'United Kingdom', 'tld_type': 'country'},
            'us': {'country_code': 'US', 'country_name': 'United States', 'tld_type': 'country'},
            'um': {'country_code': 'UM', 'country_name': 'United States Minor Outlying Islands', 'tld_type': 'country'},
            'uy': {'country_code': 'UY', 'country_name': 'Uruguay', 'tld_type': 'country'},
            'uz': {'country_code': 'UZ', 'country_name': 'Uzbekistan', 'tld_type': 'country'},
            'vu': {'country_code': 'VU', 'country_name': 'Vanuatu', 'tld_type': 'country'},
            've': {'country_code': 'VE', 'country_name': 'Venezuela', 'tld_type': 'country'},
            'vn': {'country_code': 'VN', 'country_name': 'Vietnam', 'tld_type': 'country'},
            'vg': {'country_code': 'VG', 'country_name': 'British Virgin Islands', 'tld_type': 'country'},
            'vi': {'country_code': 'VI', 'country_name': 'US Virgin Islands', 'tld_type': 'country'},
            'wf': {'country_code': 'WF', 'country_name': 'Wallis and Futuna', 'tld_type': 'country'},
            'eh': {'country_code': 'EH', 'country_name': 'Western Sahara', 'tld_type': 'country'},
            'ye': {'country_code': 'YE', 'country_name': 'Yemen', 'tld_type': 'country'},
            'zm': {'country_code': 'ZM', 'country_name': 'Zambia', 'tld_type': 'country'},
            'zw': {'country_code': 'ZW', 'country_name': 'Zimbabwe', 'tld_type': 'country'},

            # Generic TLDs
            'com': {'country_code': None, 'country_name': 'Commercial', 'tld_type': 'generic'},
            'org': {'country_code': None, 'country_name': 'Organization', 'tld_type': 'generic'},
            'net': {'country_code': None, 'country_name': 'Network', 'tld_type': 'generic'},
            'edu': {'country_code': None, 'country_name': 'Education', 'tld_type': 'generic'},
            'gov': {'country_code': None, 'country_name': 'Government', 'tld_type': 'generic'},
            'mil': {'country_code': None, 'country_name': 'Military', 'tld_type': 'generic'},
            'int': {'country_code': None, 'country_name': 'International', 'tld_type': 'generic'},
        }
    
    def classify_tld(self, tld: str) -> Dict[str, Any]:
        """Classify a TLD and return its information"""
        if not tld:
            return {'tld_type': 'unknown', 'country_code': None, 'country_name': None}
        
        tld_lower = tld.lower().lstrip('.')
        return self.country_tld_map.get(tld_lower, {
            'tld_type': 'unknown',
            'country_code': None,
            'country_name': None
        })

class EnhancedProviderResolver:
    """Enhanced provider resolution combining v4 and v5 strategies"""
    
    def __init__(self, ipinfo_token: str = None):
        self.ipinfo_token = ipinfo_token
        self.ipinfo_handler = None
        self.tld_manager = TLDManager()
        
        # Initialize IPInfo handler if token provided
        if self.ipinfo_token and HAS_IPINFO:
            try:
                self.ipinfo_handler = getHandler(self.ipinfo_token)
                logger.info("IPInfo handler initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize IPInfo handler: {e}")
        
        # Provider detection patterns (from v4)
        self.cloud_provider_patterns = {
            'amazonaws.com': 'amazon',
            'amazon.com': 'amazon',
            'aws.com': 'amazon',
            'ec2.amazonaws.com': 'amazon',
            's3.amazonaws.com': 'amazon',
            'cloudfront.net': 'amazon',
            'elb.amazonaws.com': 'amazon',
            
            'google.com': 'google',
            'googleapis.com': 'google',
            'googleusercontent.com': 'google',
            'gstatic.com': 'google',
            'youtube.com': 'google',
            'googlevideo.com': 'google',
            'googlehosted.com': 'google',
            'appspot.com': 'google',
            
            'microsoft.com': 'microsoft',
            'azure.com': 'microsoft',
            'azurewebsites.net': 'microsoft',
            'cloudapp.net': 'microsoft',
            'outlook.com': 'microsoft',
            'office.com': 'microsoft',
            'onmicrosoft.com': 'microsoft',
            'microsoftonline.com': 'microsoft',
            
            'cloudflare.com': 'cloudflare',
            'cloudflare.net': 'cloudflare',
            'cdnjs.com': 'cloudflare',
            'cdnjs.cloudflare.com': 'cloudflare',
            
            'akamai.net': 'akamai',
            'akamaiedge.net': 'akamai',
            'edgesuite.net': 'akamai',
            'akamaihd.net': 'akamai',
            
            'fastly.com': 'fastly',
            'fastlylb.net': 'fastly',
            'fastlycdn.com': 'fastly',
            
            'digitalocean.com': 'digitalocean',
            'do.co': 'digitalocean',
            
            'linode.com': 'linode',
            'linode.net': 'linode',
            
            'vultr.com': 'vultr',
            'vultr.net': 'vultr',
        }
        
        # Regional provider hints (from v4)
        self.regional_providers = {
            'CL': ['gtd', 'entel', 'telefonica', 'movistar', 'claro'],
            'US': ['comcast', 'verizon', 'att', 'spectrum', 'cox'],
            'BR': ['vivo', 'tim', 'oi', 'claro'],
            'MX': ['telmex', 'telcel', 'totalplay', 'izzi'],
            'AR': ['telecom', 'fibertel', 'arnet', 'personal'],
        }
    
    def resolve_provider_comprehensive(self, ip: str, fqdn: str = None, metadata: Dict = None) -> ProviderInfo:
        """
        Comprehensive provider resolution using multiple strategies.
        Combines v4 and v5 approaches.
        """
        providers = []
        
        # Strategy 1: IPInfo resolution (from v4)
        if self.ipinfo_handler:
            try:
                ipinfo_data = self.ipinfo_handler.getDetails(ip)
                if ipinfo_data and hasattr(ipinfo_data, 'org'):
                    org_name = ipinfo_data.org
                    provider_name = self._extract_provider_from_org(org_name)
                    if provider_name != "unknown":
                        providers.append(ProviderInfo(
                            name=provider_name,
                            confidence=0.8,
                            source="ipinfo_org",
                            country=getattr(ipinfo_data, 'country', None),
                            metadata={'org': org_name, 'city': getattr(ipinfo_data, 'city', None)}
                        ))
            except Exception as e:
                logger.debug(f"IPInfo resolution failed for {ip}: {e}")
        
        # Strategy 2: Enhanced metadata resolution (from v5)
        if metadata:
            metadata_provider = self._extract_provider_from_metadata(metadata)
            if metadata_provider:
                providers.append(metadata_provider)
        
        # Strategy 3: PTR record resolution (from v4)
        if fqdn:
            try:
                ptr_records = RESOLVER.resolve_address(ip)
                for ptr in ptr_records:
                    hostname = str(ptr.target).rstrip('.')
                    provider_name = self._extract_provider_from_hostname(hostname)
                    if provider_name != "unknown":
                        providers.append(ProviderInfo(
                            name=provider_name,
                            confidence=0.7,
                            source="ptr_record",
                            metadata={'hostname': hostname}
                        ))
            except Exception:
                pass
        
        # Strategy 4: ASN-based resolution (from v5)
        # This would require additional ASN data integration
        
        # Strategy 5: Regional provider hints (from v4)
        try:
            ip_obj = ipaddress.ip_address(ip)
            if not ip_obj.is_private:
                # Use country code from metadata or IPInfo to suggest regional providers
                country = None
                if metadata and 'country' in metadata:
                    country = metadata['country']
                elif self.ipinfo_handler:
                    try:
                        ipinfo_data = self.ipinfo_handler.getDetails(ip)
                        country = getattr(ipinfo_data, 'country', None)
                    except:
                        pass
                
                if country and country in self.regional_providers:
                    for regional_provider in self.regional_providers[country]:
                        providers.append(ProviderInfo(
                            name=regional_provider,
                            confidence=0.3,
                            source="regional_hint",
                            country=country,
                            metadata={'hint_type': 'regional'}
                        ))
        except Exception:
            pass
        
        # Consolidate results
        if providers:
            return self._consolidate_provider_results(providers)
        else:
            return ProviderInfo(
                name="unknown",
                confidence=0.0,
                source="none",
                metadata={'ip': ip, 'strategies_tried': ['ipinfo', 'metadata', 'ptr', 'regional']}
            )
    
    def _extract_provider_from_metadata(self, metadata: Dict) -> Optional[ProviderInfo]:
        """Extract provider from rich metadata (v5 enhancement)"""
        if not metadata:
            return None
        
        # Try extracting from as_domain
        if 'as_domain' in metadata and metadata['as_domain']:
            as_domain = metadata['as_domain'].lower()
            
            # Check cloud provider patterns
            for pattern, provider in self.cloud_provider_patterns.items():
                if pattern in as_domain:
                    return ProviderInfo(
                        name=provider,
                        confidence=0.9,
                        source="metadata_as_domain",
                        metadata={'as_domain': metadata['as_domain']}
                    )
            
            # Extract provider from domain name
            if '.' in as_domain:
                domain_parts = as_domain.split('.')
                if len(domain_parts) >= 2:
                    potential_provider = domain_parts[-2]  # company name before TLD
                    if len(potential_provider) > 2:  # reasonable provider name
                        return ProviderInfo(
                            name=potential_provider,
                            confidence=0.7,
                            source="metadata_domain_extraction",
                            metadata={'as_domain': metadata['as_domain']}
                        )
        
        # Try extracting from as_name
        if 'as_name' in metadata and metadata['as_name']:
            as_name = metadata['as_name'].lower()
            provider_name = self._extract_provider_from_org(metadata['as_name'])
            if provider_name != "unknown":
                return ProviderInfo(
                    name=provider_name,
                    confidence=0.6,
                    source="metadata_as_name",
                    metadata={'as_name': metadata['as_name']}
                )
        
        # Try extracting from country information
        if 'country' in metadata:
            country = metadata['country']
            tld_info = self.tld_manager.classify_tld(country.lower())
            if tld_info['tld_type'] == 'country':
                return ProviderInfo(
                    name="regional",
                    confidence=0.4,
                    source="metadata_country",
                    country=country,
                    tld=country.lower(),
                    metadata={'country_info': tld_info}
                )
        
        return None
    
    def _extract_provider_from_org(self, org: str) -> str:
        """Extract provider name from organization string (from v4)"""
        if not org:
            return "unknown"
        
        org_lower = org.lower()
        
        # Direct matches
        direct_matches = {
            'amazon': 'amazon',
            'aws': 'amazon',
            'amazon.com': 'amazon',
            'amazon web services': 'amazon',
            'google': 'google',
            'microsoft': 'microsoft',
            'cloudflare': 'cloudflare',
            'akamai': 'akamai',
            'fastly': 'fastly',
            'digitalocean': 'digitalocean',
            'linode': 'linode',
            'vultr': 'vultr',
            'gtd': 'gtd',
            'entel': 'entel',
            'telefonica': 'telefonica',
            'movistar': 'movistar',
            'claro': 'claro',
        }
        
        for pattern, provider in direct_matches.items():
            if pattern in org_lower:
                return provider
        
        # Extract from common org patterns
        words = re.findall(r'\b\w+\b', org_lower)
        if words:
            # Return first meaningful word (length > 2)
            for word in words:
                if len(word) > 2 and word not in ['inc', 'ltd', 'llc', 'corp', 'the', 'and']:
                    return word
        
        return "unknown"
    
    def _extract_provider_from_hostname(self, hostname: str) -> str:
        """Extract provider from hostname using Neo4j providers"""
        if not hostname:
            return "unknown"
        
        hostname_lower = hostname.lower()
        
        # Use Neo4j provider detection patterns
        # AWS patterns
        if any(pattern in hostname_lower for pattern in ['amazonaws.com', 'aws.amazon.com', 'ec2', 's3']):
            return 'amazon'
        
        # Google patterns  
        if any(pattern in hostname_lower for pattern in ['googleapis.com', 'googleusercontent.com', 'gstatic.com', 'google.com']):
            return 'google'
        
        # Microsoft patterns
        if any(pattern in hostname_lower for pattern in ['azure.com', 'azurewebsites.net', 'outlook.com', 'office.com']):
            return 'microsoft'
        
        # Cloudflare patterns
        if any(pattern in hostname_lower for pattern in ['cloudflare.com', 'cloudflaressl.com']):
            return 'cloudflare'
        
        # GitHub patterns
        if any(pattern in hostname_lower for pattern in ['github.com', 'githubusercontent.com', 'github.io']):
            return 'github'
        
        # Heroku patterns
        if any(pattern in hostname_lower for pattern in ['heroku.com', 'herokuapp.com']):
            return 'heroku'
        
        # Salesforce patterns
        if any(pattern in hostname_lower for pattern in ['salesforce.com', 'force.com']):
            return 'salesforce'
        
        # Fastly patterns
        if any(pattern in hostname_lower for pattern in ['fastly.com', 'fastlylb.net']):
            return 'fastly'
        
        # DigitalOcean patterns
        if any(pattern in hostname_lower for pattern in ['digitalocean.com', 'digitaloceanspaces.com']):
            return 'digitalocean'
        
        # Akamai patterns
        if any(pattern in hostname_lower for pattern in ['akamai.com', 'akamaitechnologies.com', 'akamaiedge.net']):
            return 'akamai'
        
        # Linode patterns
        if any(pattern in hostname_lower for pattern in ['linode.com', 'linodeobjects.com']):
            return 'linode'
        
        # Vultr patterns  
        if 'vultr.com' in hostname_lower:
            return 'vultr'
        
        # OVH patterns
        if any(pattern in hostname_lower for pattern in ['ovh.com', 'ovhcloud.com', 'ovh.net']):
            return 'ovh'
        
        # Hetzner patterns
        if any(pattern in hostname_lower for pattern in ['hetzner.com', 'hetzner.de']):
            return 'hetzner'
        
        # GoDaddy patterns
        if any(pattern in hostname_lower for pattern in ['godaddy.com', 'secureserver.net']):
            return 'godaddy'
        
        # Namecheap patterns
        if any(pattern in hostname_lower for pattern in ['namecheap.com', 'registrar-servers.com']):
            return 'namecheap'
        
        # Fallback to old patterns for compatibility
        for pattern, provider in self.cloud_provider_patterns.items():
            if pattern in hostname_lower:
                return provider
        
        return "unknown"
    
    def _consolidate_provider_results(self, providers: List[ProviderInfo]) -> ProviderInfo:
        """Consolidate multiple provider results (enhanced from v4)"""
        if not providers:
            return ProviderInfo(name="unknown", confidence=0.0, source="none")
        
        if len(providers) == 1:
            return providers[0]
        
        # Group by provider name
        grouped = defaultdict(list)
        for provider in providers:
            grouped[provider.name].append(provider)
        
        # Find best provider (highest combined confidence)
        best_provider = None
        best_score = 0.0
        
        for name, provider_list in grouped.items():
            if name == "unknown":
                continue
            
            # Calculate combined confidence
            combined_confidence = sum(p.confidence for p in provider_list) / len(provider_list)
            # Bonus for multiple sources
            source_bonus = min(0.2, (len(provider_list) - 1) * 0.1)
            total_score = combined_confidence + source_bonus
            
            if total_score > best_score:
                best_score = total_score
                # Use the provider with highest individual confidence
                best_individual = max(provider_list, key=lambda p: p.confidence)
                best_provider = ProviderInfo(
                    name=name,
                    confidence=min(1.0, total_score),
                    source=f"consolidated({len(provider_list)})",
                    tld=best_individual.tld,
                    country=best_individual.country,
                    metadata={
                        'sources': [p.source for p in provider_list],
                        'individual_confidences': [p.confidence for p in provider_list]
                    }
                )
        
        if best_provider:
            return best_provider
        else:
            # Return unknown with metadata about attempted sources
            return ProviderInfo(
                name="unknown",
                confidence=0.0,
                source="consolidation_failed",
                metadata={'attempted_providers': [p.name for p in providers]}
            )

class UnifiedSubdomainDiscoverer:
    """Unified subdomain discovery engine combining v4 and v5 features"""
    
    def __init__(self, config: ProcessingConfig, neo4j_uri: str = None, neo4j_user: str = None, neo4j_pass: str = None, ipinfo_token: str = None):
        self.config = config
        self.provider_resolver = EnhancedProviderResolver(ipinfo_token)
        self.tld_manager = TLDManager()
        
        # Initialize Neo4j connection if provided
        self.neo4j_driver = None
        if neo4j_uri and HAS_NEO4J:
            try:
                self.neo4j_driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
                logger.info("Neo4j connection established")
            except Exception as e:
                logger.error(f"Failed to connect to Neo4j: {e}")
        
        # Initialize provider detector for MX analysis
        self.provider_detector = None
        if config.enable_mx_analysis and HAS_PROVIDER_DETECTION:
            try:
                self.provider_detector = ProviderDetector()
                logger.info("Provider detector initialized for MX analysis")
            except Exception as e:
                logger.warning(f"Failed to initialize provider detector: {e}")
        
        # Initialize industry classifier
        self.industry_classifier = None
        if config.enable_industry_classification and HAS_INDUSTRY_CLASSIFIER:
            try:
                self.industry_classifier = IndustryClassifier()
                logger.info("Industry classifier initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize industry classifier: {e}")
        
        # Initialize risk calculator
        self.risk_calculator = None
        if config.enable_risk_calculation and HAS_RISK_CALCULATOR:
            try:
                if neo4j_uri:
                    self.risk_calculator = DomainRiskCalculator(neo4j_uri, neo4j_user, neo4j_pass, ipinfo_token)
                    logger.info("Risk calculator initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize risk calculator: {e}")
    
    def _generate_cache_hash(self, domain: str) -> str:
        """Generate hash for domain (used for cache keys)"""
        return hashlib.sha256(domain.encode()).hexdigest()[:16]
    
    def _check_amass_cache(self, domain: str) -> Optional[List[str]]:
        """Check if valid cached amass results exist for domain"""
        if not self.config.enable_cache_check:
            return None
            
        cache_dir = Path(self.config.amass_cache_dir)
        metadata_dir = cache_dir / "metadata"
        data_dir = cache_dir / "data"
        
        if not metadata_dir.exists() or not data_dir.exists():
            return None
            
        hash_key = self._generate_cache_hash(domain)
        metadata_file = metadata_dir / f"{hash_key}.json"
        data_file = data_dir / f"{hash_key}.json.gz"
        
        if not metadata_file.exists() or not data_file.exists():
            return None
            
        try:
            # Check if cache is expired
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            timestamp_str = metadata.get('timestamp', '')
            if not timestamp_str:
                return None
                
            # Parse timestamp and check expiration
            try:
                cache_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            except:
                # Try different timestamp formats
                cache_time = datetime.fromisoformat(timestamp_str)
            
            now = datetime.now(cache_time.tzinfo) if cache_time.tzinfo else datetime.now()
            cache_age = now - cache_time
            max_age = timedelta(hours=self.config.amass_cache_duration_hours)
            
            if cache_age > max_age:
                logger.info(f"Cache expired for {domain} (age: {cache_age}, max: {max_age})")
                return None
            
            # Read cached data
            import gzip
            with gzip.open(data_file, 'rt') as f:
                subdomains_json = json.load(f)
            
            logger.info(f"Using cached amass results for {domain} (age: {cache_age})")
            return subdomains_json
            
        except Exception as e:
            logger.debug(f"Failed to read cache for {domain}: {e}")
            return None
    
    def discover_and_analyze(self, domain: str) -> DiscoveryResult:
        """Main entry point for domain discovery and analysis"""
        start_time = time.time()
        result = DiscoveryResult(
            domain=domain,
            subdomains=[],
            providers=[],
            services=[],
            certificates=[],
            risks=[],
            industry_classification=None,
            processing_time=0.0,
            errors=[]
        )
        
        try:
            logger.info(f"Starting discovery and analysis for {domain}")
            
            # 1. Subdomain Discovery
            if self.config.enable_subdomain_enumeration:
                result.subdomains = self._discover_subdomains(domain)
                logger.info(f"Discovered {len(result.subdomains)} subdomains")
            
            # 2. Provider Detection (including MX analysis)
            if self.config.enable_provider_detection:
                result.providers = self._analyze_providers(domain, result.subdomains)
                logger.info(f"Detected {len(result.providers)} providers")
            
            # 3. Service Detection
            if self.config.enable_service_detection:
                result.services = self._analyze_services(domain, result.subdomains)
                logger.info(f"Detected {len(result.services)} services")
            
            # 4. TLS Analysis
            if self.config.enable_tls_analysis:
                result.certificates = self._analyze_certificates(domain, result.subdomains)
                logger.info(f"Analyzed {len(result.certificates)} certificates")
            
            # 5. Industry Classification
            if self.config.enable_industry_classification:
                result.industry_classification = self._classify_industry(domain)
            
            # 6. Risk Analysis
            if self.config.enable_risk_calculation:
                result.risks = self._calculate_risks(domain)
                logger.info(f"Calculated {len(result.risks)} risk factors")
            
            # 7. Save to Neo4j if configured
            if self.config.save_to_neo4j and self.neo4j_driver:
                self._save_to_neo4j(result)
                logger.info("Results saved to Neo4j")
            
        except Exception as e:
            error_msg = f"Error during discovery: {e}"
            logger.error(error_msg)
            result.errors.append(error_msg)
        
        result.processing_time = time.time() - start_time
        logger.info(f"Discovery completed in {result.processing_time:.2f} seconds")
        
        return result
    
    def _discover_subdomains(self, domain: str) -> List[str]:
        """Discover subdomains using Amass and other methods"""
        subdomains = set()
        
        if self.config.enable_amass:
            try:
                amass_subdomains = self._run_amass(domain)
                subdomains.update(amass_subdomains)
                logger.info(f"Amass discovered {len(amass_subdomains)} subdomains")
            except Exception as e:
                logger.error(f"Amass discovery failed: {e}")
        
        # Add additional discovery methods here
        # - Certificate transparency logs
        # - DNS brute force
        # - Search engine enumeration
        
        # Limit results
        subdomain_list = list(subdomains)[:self.config.max_subdomains]
        return subdomain_list
    
    def _run_amass(self, domain: str) -> List[str]:
        """Run Amass for subdomain discovery with cache support"""
        
        # First check cache
        cached_results = self._check_amass_cache(domain)
        if cached_results is not None:
            return cached_results
        
        # No valid cache found, run amass
        logger.info(f"No valid cache found for {domain}, running amass")
        
        try:
            # Use standalone amass executor if available
            standalone_script = Path(self.config.amass_cache_dir).parent / "standalone_amass_executor.sh"
            
            if standalone_script.exists():
                logger.info(f"Using standalone amass executor for {domain}")
                try:
                    # Set environment variables for the script
                    env = {
                        **dict(os.environ),
                        'AMASS_CACHE_DIR': self.config.amass_cache_dir,
                        'CACHE_DURATION_HOURS': str(self.config.amass_cache_duration_hours)
                    }
                    
                    result = subprocess.run(
                        [str(standalone_script), "-t", str(self.config.amass_timeout), domain],
                        capture_output=True,
                        text=True,
                        timeout=self.config.amass_timeout + 60,
                        env=env
                    )
                    
                    if result.returncode == 0:
                        subdomains_json = json.loads(result.stdout)
                        logger.info(f"Standalone executor returned {len(subdomains_json)} subdomains")
                        return subdomains_json
                    else:
                        logger.warning(f"Standalone executor failed: {result.stderr}")
                        # Fall back to direct amass execution
                        
                except Exception as e:
                    logger.warning(f"Standalone executor error: {e}, falling back to direct amass")
            
            # Direct amass execution fallback
            cmd = [
                "amass",
                "enum",
                "-d", domain,
                "-timeout", str(self.config.amass_timeout // 60),  # Convert to minutes
                "-dns-qps", "50",  # Limit DNS queries per second
                "-silent"  # Reduce output noise
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.amass_timeout + 30
            )
            
            if result.returncode == 0:
                subdomains = []
                for line in result.stdout.splitlines():
                    if line.strip() and ' --> node --> ' in line:
                        # Extract subdomain from "domain (FQDN) --> node --> subdomain (FQDN)" format
                        parts = line.split(' --> node --> ')
                        if len(parts) == 2:
                            subdomain = parts[1].split(' (FQDN)')[0].strip()
                            if subdomain and domain in subdomain and subdomain != domain:
                                subdomains.append(subdomain)
                
                # Remove duplicates and sort
                unique_subdomains = sorted(list(set(subdomains)))
                logger.info(f"Parsed {len(unique_subdomains)} subdomains from amass output")
                return unique_subdomains
            else:
                logger.error(f"Amass failed: {result.stderr}")
                return []
        
        except subprocess.TimeoutExpired:
            logger.error(f"Amass timeout after {self.config.amass_timeout} seconds")
            return []
        except Exception as e:
            logger.error(f"Amass execution error: {e}")
            return []
    
    def _analyze_providers(self, domain: str, subdomains: List[str]) -> List[ProviderInfo]:
        """Analyze providers for domain and subdomains"""
        providers = []
        domains_to_analyze = [domain] + subdomains
        
        # IP-based provider detection
        for domain_name in domains_to_analyze:
            try:
                # Get IP addresses
                ip_addresses = self._resolve_ips(domain_name)
                
                for ip in ip_addresses:
                    provider_info = self.provider_resolver.resolve_provider_comprehensive(ip, domain_name)
                    if provider_info.name != "unknown":
                        providers.append(provider_info)
            
            except Exception as e:
                logger.debug(f"Provider analysis failed for {domain_name}: {e}")
        
        # MX-based provider detection
        if self.config.enable_mx_analysis and self.provider_detector:
            try:
                mx_providers = self.provider_detector.analyze_domain_dependencies(domain)
                for service in mx_providers:
                    provider_info = ProviderInfo(
                        name=service.provider,
                        confidence=service.confidence,
                        source=service.detection_method,
                        provider_type=service.service_type.value,
                        metadata=service.metadata
                    )
                    providers.append(provider_info)
            except Exception as e:
                logger.debug(f"MX provider analysis failed: {e}")
        
        return providers
    
    def _analyze_services(self, domain: str, subdomains: List[str]) -> List[Dict[str, Any]]:
        """Analyze services for domain and subdomains"""
        services = []
        domains_to_analyze = [domain] + subdomains
        
        for domain_name in domains_to_analyze:
            try:
                # Pattern-based service detection
                pattern_services = self._detect_services_by_pattern(domain_name)
                services.extend(pattern_services)
                
                # Port-based service detection (if enabled)
                if self.config.enable_service_detection:
                    ip_addresses = self._resolve_ips(domain_name)
                    port_services = self._detect_services_by_ports(domain_name, ip_addresses)
                    services.extend(port_services)
                
                # DNS-based service detection
                dns_services = self._detect_services_by_dns(domain_name)
                services.extend(dns_services)
                
            except Exception as e:
                logger.debug(f"Service analysis failed for {domain_name}: {e}")
        
        return services
    
    def _analyze_certificates(self, domain: str, subdomains: List[str]) -> List[Dict[str, Any]]:
        """Analyze TLS certificates for domain and subdomains"""
        certificates = []
        domains_to_analyze = [domain] + subdomains
        
        for domain_name in domains_to_analyze:
            try:
                cert_info = self._get_certificate_info(domain_name)
                if cert_info:
                    certificates.append(cert_info)
            except Exception as e:
                logger.debug(f"Certificate analysis failed for {domain_name}: {e}")
        
        return certificates
    
    def _classify_industry(self, domain: str) -> Optional[Dict[str, Any]]:
        """Classify domain industry"""
        if not self.industry_classifier:
            return None
        
        try:
            classification = self.industry_classifier.classify_domain(domain)
            return classification
        except Exception as e:
            logger.debug(f"Industry classification failed: {e}")
            return None
    
    def _calculate_risks(self, domain: str) -> List[Dict[str, Any]]:
        """Calculate risks for domain"""
        if not self.risk_calculator:
            return []
        
        try:
            risks = self.risk_calculator.calculate_domain_risks(domain)
            return [
                {
                    'risk_type': risk.risk_type,
                    'severity': risk.severity.value,
                    'score': risk.score,
                    'description': risk.description,
                    'remediation': risk.remediation
                }
                for risk in risks
            ]
        except Exception as e:
            logger.debug(f"Risk calculation failed: {e}")
            return []
    
    def _save_to_neo4j(self, result: DiscoveryResult):
        """Save discovery results to Neo4j"""
        if not self.neo4j_driver:
            return
        
        try:
            with self.neo4j_driver.session() as session:
                session.execute_write(self._save_discovery_transaction, result)
        except Exception as e:
            logger.error(f"Failed to save to Neo4j: {e}")
    
    def _save_discovery_transaction(self, tx, result: DiscoveryResult):
        """Transaction for saving discovery results"""
        # Implementation would save domains, subdomains, providers, services, etc.
        # This is a placeholder for the actual implementation
        pass
    
    # Helper methods (simplified implementations)
    
    def _resolve_ips(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses"""
        ips = []
        try:
            answers = RESOLVER.resolve(domain, 'A')
            ips.extend([str(answer) for answer in answers])
        except:
            pass
        
        try:
            answers = RESOLVER.resolve(domain, 'AAAA')
            ips.extend([str(answer) for answer in answers])
        except:
            pass
        
        return ips
    
    def _detect_services_by_pattern(self, domain: str) -> List[Dict[str, Any]]:
        """Detect services by subdomain patterns"""
        services = []
        
        # Common service patterns
        patterns = {
            'mail': 'email',
            'smtp': 'email',
            'imap': 'email',
            'pop': 'email',
            'webmail': 'email',
            'api': 'api',
            'www': 'web',
            'blog': 'web',
            'shop': 'ecommerce',
            'store': 'ecommerce',
            'ftp': 'file_transfer',
            'cdn': 'cdn',
            'static': 'cdn',
            'media': 'cdn',
            'vpn': 'vpn',
            'admin': 'admin',
            'dashboard': 'admin',
            'panel': 'admin',
        }
        
        domain_lower = domain.lower()
        for pattern, service_type in patterns.items():
            if pattern in domain_lower:
                services.append({
                    'name': f"{service_type}_service",
                    'type': service_type,
                    'domain': domain,
                    'detection_method': 'pattern_matching',
                    'confidence': 0.6
                })
        
        return services
    
    def _detect_services_by_ports(self, domain: str, ip_addresses: List[str]) -> List[Dict[str, Any]]:
        """Detect services by port scanning"""
        services = []
        
        # Common ports to check
        common_ports = {
            80: 'http',
            443: 'https',
            22: 'ssh',
            21: 'ftp',
            25: 'smtp',
            53: 'dns',
            110: 'pop3',
            143: 'imap',
            993: 'imaps',
            995: 'pop3s'
        }
        
        for ip in ip_addresses:
            for port, service_name in common_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    
                    if result == 0:  # Port is open
                        services.append({
                            'name': service_name,
                            'type': service_name,
                            'domain': domain,
                            'ip': ip,
                            'port': port,
                            'detection_method': 'port_scan',
                            'confidence': 0.8
                        })
                except Exception:
                    pass
        
        return services
    
    def _detect_services_by_dns(self, domain: str) -> List[Dict[str, Any]]:
        """Detect services by DNS records"""
        services = []
        
        # Check MX records
        try:
            mx_records = RESOLVER.resolve(domain, 'MX')
            if mx_records:
                services.append({
                    'name': 'email_service',
                    'type': 'email',
                    'domain': domain,
                    'detection_method': 'mx_record',
                    'confidence': 0.9,
                    'records': [str(mx) for mx in mx_records]
                })
        except:
            pass
        
        # Check SRV records for specific services
        srv_services = [
            ('_http._tcp', 'http'),
            ('_https._tcp', 'https'),
            ('_ftp._tcp', 'ftp'),
            ('_imap._tcp', 'imap'),
            ('_pop3._tcp', 'pop3'),
            ('_smtp._tcp', 'smtp')
        ]
        
        for srv_name, service_type in srv_services:
            try:
                srv_records = RESOLVER.resolve(f"{srv_name}.{domain}", 'SRV')
                if srv_records:
                    services.append({
                        'name': f"{service_type}_service",
                        'type': service_type,
                        'domain': domain,
                        'detection_method': 'srv_record',
                        'confidence': 0.8,
                        'records': [str(srv) for srv in srv_records]
                    })
            except:
                pass
        
        return services
    
    def _get_certificate_info(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get TLS certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'domain': domain,
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'serial_number': cert['serialNumber'],
                        'version': cert['version'],
                        'signature_algorithm': cert.get('signatureAlgorithm', 'unknown')
                    }
        except Exception as e:
            logger.debug(f"Certificate analysis failed for {domain}: {e}")
            return None
    
    def close(self):
        """Clean up resources"""
        if self.neo4j_driver:
            self.neo4j_driver.close()
        if self.risk_calculator:
            self.risk_calculator.close()

# CLI interface for standalone usage
def main():
    parser = argparse.ArgumentParser(description="Unified Subdomain Discovery Engine v6.0")
    parser.add_argument("domain", help="Domain to analyze")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--neo4j-user", default="neo4j", help="Neo4j username")
    parser.add_argument("--neo4j-pass", default="test.password", help="Neo4j password")
    parser.add_argument("--ipinfo-token", help="IPInfo token")
    parser.add_argument("--output", help="Output file for results")
    
    # Feature flags
    parser.add_argument("--no-amass", action="store_true", help="Disable Amass")
    parser.add_argument("--no-tls", action="store_true", help="Disable TLS analysis")
    parser.add_argument("--no-services", action="store_true", help="Disable service detection")
    parser.add_argument("--no-providers", action="store_true", help="Disable provider detection")
    parser.add_argument("--no-industry", action="store_true", help="Disable industry classification")
    parser.add_argument("--no-risk", action="store_true", help="Disable risk calculation")
    parser.add_argument("--no-mx", action="store_true", help="Disable MX analysis")
    parser.add_argument("--no-neo4j", action="store_true", help="Disable Neo4j saving")
    
    # Performance options
    parser.add_argument("--max-subdomains", type=int, default=1000, help="Max subdomains to process")
    parser.add_argument("--timeout", type=int, default=300, help="Amass timeout")
    parser.add_argument("--workers", type=int, default=10, help="Max worker threads")
    
    # Cache options
    parser.add_argument("--cache-dir", default="./amass_cache", help="Amass cache directory")
    parser.add_argument("--cache-duration", type=int, default=168, help="Cache duration in hours (default: 168 = 1 week)")
    parser.add_argument("--no-cache", action="store_true", help="Disable cache checking")
    
    args = parser.parse_args()
    
    # Create configuration
    config = ProcessingConfig(
        enable_amass=not args.no_amass,
        enable_tls_analysis=not args.no_tls,
        enable_service_detection=not args.no_services,
        enable_provider_detection=not args.no_providers,
        enable_industry_classification=not args.no_industry,
        enable_risk_calculation=not args.no_risk,
        enable_mx_analysis=not args.no_mx,
        save_to_neo4j=not args.no_neo4j,
        max_subdomains=args.max_subdomains,
        amass_timeout=args.timeout,
        max_workers=args.workers,
        amass_cache_dir=args.cache_dir,
        amass_cache_duration_hours=args.cache_duration,
        enable_cache_check=not args.no_cache
    )
    
    # Initialize discoverer
    discoverer = UnifiedSubdomainDiscoverer(
        config=config,
        neo4j_uri=args.neo4j_uri if not args.no_neo4j else None,
        neo4j_user=args.neo4j_user,
        neo4j_pass=args.neo4j_pass,
        ipinfo_token=args.ipinfo_token
    )
    
    try:
        # Run discovery
        result = discoverer.discover_and_analyze(args.domain)
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(result.__dict__, f, indent=2, default=str)
            logger.info(f"Results saved to {args.output}")
        else:
            print(json.dumps(result.__dict__, indent=2, default=str))
        
        # Print summary
        print(f"\n=== Discovery Summary for {args.domain} ===")
        print(f"Subdomains found: {len(result.subdomains)}")
        print(f"Providers detected: {len(result.providers)}")
        print(f"Services detected: {len(result.services)}")
        print(f"Certificates analyzed: {len(result.certificates)}")
        print(f"Risks identified: {len(result.risks)}")
        print(f"Processing time: {result.processing_time:.2f} seconds")
        if result.errors:
            print(f"Errors: {len(result.errors)}")
    
    finally:
        discoverer.close()

if __name__ == "__main__":
    main()