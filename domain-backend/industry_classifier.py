#!/usr/bin/env python3
"""
industry_classifier.py - Industry Classification Service

This module classifies domains into industry categories using multiple free sources:
1. Domain name pattern analysis 
2. Web content scraping and keyword analysis
3. WHOIS data analysis
4. DNS TXT record analysis
5. Certificate organization analysis

Uses completely free APIs and analysis methods.
"""

import re
import logging
import requests
import socket
import ssl
import dns.resolver
import time
import random
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from dataclasses import dataclass
from collections import Counter
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class IndustryClassification:
    """Industry classification result."""
    primary_industry: str
    confidence: float
    secondary_industries: List[str]
    source: str
    keywords_found: List[str]
    description: str

class IndustryClassifier:
    """Classify domains into industry categories using free methods."""
    
    def __init__(self):
        """Initialize the classifier."""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Industry keywords and patterns
        self.industry_keywords = {
            'financial_services': {
                'keywords': ['bank', 'banking', 'finance', 'financial', 'credit', 'loan', 'mortgage', 
                           'investment', 'trading', 'securities', 'capital', 'fund', 'insurance',
                           'wealth', 'asset', 'portfolio', 'fintech', 'payment', 'card', 'visa',
                           'mastercard', 'swift', 'banca', 'banco', 'credito', 'seguro'],
                'domains': ['visa.com', 'mastercard.com', 'jpmorgan.com', 'goldmansachs.com',
                           'bankofamerica.com', 'wells.com', 'citigroup.com'],
                'description': 'Banking, Finance, and Financial Services'
            },
            'technology': {
                'keywords': ['tech', 'software', 'cloud', 'data', 'digital', 'cyber', 'ai', 'ml',
                           'api', 'dev', 'code', 'programming', 'system', 'platform', 'saas',
                           'app', 'mobile', 'web', 'internet', 'online', 'startup', 'innovation'],
                'domains': ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com'],
                'description': 'Technology, Software, and Digital Services'
            },
            'healthcare': {
                'keywords': ['health', 'medical', 'hospital', 'clinic', 'doctor', 'medicine',
                           'pharmaceutical', 'pharma', 'drug', 'patient', 'care', 'wellness',
                           'therapy', 'treatment', 'diagnostic', 'surgery', 'nurse', 'medico',
                           'salud', 'clinica', 'farmacia'],
                'domains': ['mayo.edu', 'clevelandclinic.org', 'jhmi.edu'],
                'description': 'Healthcare, Medical, and Pharmaceutical'
            },
            'education': {
                'keywords': ['university', 'college', 'school', 'education', 'academic', 'student',
                           'learning', 'course', 'degree', 'research', 'faculty', 'campus',
                           'library', 'edu', 'universidad', 'colegio', 'escuela', 'educacion'],
                'domains': ['harvard.edu', 'mit.edu', 'stanford.edu', 'berkeley.edu'],
                'description': 'Education and Academic Institutions'
            },
            'government': {
                'keywords': ['government', 'gov', 'municipal', 'federal', 'state', 'public',
                           'ministry', 'department', 'agency', 'administration', 'official',
                           'municipal', 'congress', 'senate', 'tribunal', 'court', 'gob',
                           'gobierno', 'ministerio'],
                'domains': ['gov.cl', 'gob.cl', 'presidencia.cl', 'congreso.cl'],
                'description': 'Government and Public Sector'
            },
            'retail_ecommerce': {
                'keywords': ['shop', 'store', 'retail', 'ecommerce', 'marketplace', 'buy', 'sell',
                           'product', 'catalog', 'cart', 'checkout', 'payment', 'shipping',
                           'delivery', 'fashion', 'clothing', 'tienda', 'compra', 'venta'],
                'domains': ['amazon.com', 'ebay.com', 'walmart.com', 'target.com'],
                'description': 'Retail, E-commerce, and Online Shopping'
            },
            'media_entertainment': {
                'keywords': ['media', 'news', 'entertainment', 'tv', 'radio', 'music', 'video',
                           'streaming', 'content', 'publication', 'magazine', 'newspaper',
                           'broadcasting', 'film', 'movie', 'game', 'gaming', 'noticias',
                           'television', 'radio', 'musica'],
                'domains': ['cnn.com', 'bbc.com', 'netflix.com', 'spotify.com'],
                'description': 'Media, Entertainment, and Broadcasting'
            },
            'telecommunications': {
                'keywords': ['telecom', 'telecommunications', 'phone', 'mobile', 'cellular',
                           'internet', 'broadband', 'network', 'communication', 'wireless',
                           'fiber', 'cable', 'provider', 'isp', 'telefono', 'movil', 'celular'],
                'domains': ['verizon.com', 'att.com', 't-mobile.com', 'sprint.com'],
                'description': 'Telecommunications and Internet Services'
            },
            'transportation': {
                'keywords': ['transport', 'transportation', 'airline', 'airport', 'flight',
                           'shipping', 'logistics', 'delivery', 'cargo', 'freight', 'rail',
                           'bus', 'taxi', 'uber', 'lyft', 'transporte', 'aerolinea', 'vuelo'],
                'domains': ['fedex.com', 'ups.com', 'dhl.com', 'uber.com'],
                'description': 'Transportation and Logistics'
            },
            'manufacturing': {
                'keywords': ['manufacturing', 'factory', 'production', 'industrial', 'machinery',
                           'equipment', 'automotive', 'chemical', 'steel', 'metal', 'construction',
                           'building', 'materials', 'fabricacion', 'industria', 'fabrica'],
                'domains': ['ge.com', 'boeing.com', 'caterpillar.com', 'ford.com'],
                'description': 'Manufacturing and Industrial'
            },
            'energy_utilities': {
                'keywords': ['energy', 'power', 'electric', 'electricity', 'utility', 'gas',
                           'oil', 'petroleum', 'renewable', 'solar', 'wind', 'nuclear',
                           'coal', 'utilities', 'energia', 'electrica', 'gas', 'petroleo'],
                'domains': ['shell.com', 'exxonmobil.com', 'bp.com', 'chevron.com'],
                'description': 'Energy, Oil, Gas, and Utilities'
            },
            'real_estate': {
                'keywords': ['real estate', 'property', 'realty', 'homes', 'housing', 'rental',
                           'apartment', 'commercial', 'residential', 'land', 'development',
                           'construction', 'inmobiliaria', 'propiedad', 'casa', 'departamento'],
                'domains': ['zillow.com', 'realtor.com', 'remax.com'],
                'description': 'Real Estate and Property'
            },
            'professional_services': {
                'keywords': ['consulting', 'legal', 'law', 'accounting', 'audit', 'advisory',
                           'professional', 'services', 'firm', 'office', 'lawyer', 'attorney',
                           'consultant', 'consultoria', 'legal', 'abogado', 'contador'],
                'domains': ['mckinsey.com', 'deloitte.com', 'pwc.com', 'ey.com'],
                'description': 'Professional and Consulting Services'
            },
            'non_profit': {
                'keywords': ['nonprofit', 'non-profit', 'foundation', 'charity', 'organization',
                           'org', 'donation', 'volunteer', 'community', 'social', 'ngo',
                           'fundacion', 'caridad', 'organizacion', 'donacion'],
                'domains': ['redcross.org', 'unicef.org', 'who.int'],
                'description': 'Non-Profit and NGO'
            }
        }
        
        # Chilean specific patterns
        self.chile_patterns = {
            'financial_services': ['bci', 'santander', 'chile', 'estado', 'security', 'ripley', 'falabella'],
            'retail_ecommerce': ['falabella', 'ripley', 'paris', 'lider', 'jumbo', 'santa'],
            'telecommunications': ['movistar', 'entel', 'claro', 'wom', 'vtr'],
            'government': ['gob.cl', 'gov.cl', 'presidencia', 'congreso', 'tribunal', 'municipal'],
            'education': ['uc.cl', 'uchile.cl', 'usach.cl', 'uai.cl', 'udp.cl', 'puc.cl'],
            'media_entertainment': ['tvn.cl', 'canal13.cl', 'mega.cl', 'chv.cl', 'biobio.cl'],
            'energy_utilities': ['enel', 'colbun', 'engie', 'copec', 'shell'],
            'transportation': ['latam', 'sky', 'jetsmart', 'metro', 'transantiago']
        }

    def classify_domain(self, domain: str) -> IndustryClassification:
        """Classify a domain into an industry category."""
        logger.info(f"Classifying domain: {domain}")
        
        # Collect evidence from multiple sources
        evidence = {}
        
        # 1. Domain name analysis
        domain_evidence = self._analyze_domain_name(domain)
        if domain_evidence:
            evidence['domain_name'] = domain_evidence
        
        # 2. WHOIS analysis
        try:
            whois_evidence = self._analyze_whois(domain)
            if whois_evidence:
                evidence['whois'] = whois_evidence
        except Exception as e:
            logger.debug(f"WHOIS analysis failed: {e}")
        
        # 3. TLS certificate analysis
        try:
            cert_evidence = self._analyze_certificate(domain)
            if cert_evidence:
                evidence['certificate'] = cert_evidence
        except Exception as e:
            logger.debug(f"Certificate analysis failed: {e}")
        
        # 4. DNS TXT record analysis
        try:
            dns_evidence = self._analyze_dns_records(domain)
            if dns_evidence:
                evidence['dns'] = dns_evidence
        except Exception as e:
            logger.debug(f"DNS analysis failed: {e}")
        
        # 5. Web content analysis (with rate limiting)
        try:
            time.sleep(random.uniform(1, 3))  # Rate limiting
            content_evidence = self._analyze_web_content(domain)
            if content_evidence:
                evidence['web_content'] = content_evidence
        except Exception as e:
            logger.debug(f"Web content analysis failed: {e}")
        
        # Aggregate evidence and determine industry
        return self._aggregate_evidence(domain, evidence)
    
    def _analyze_domain_name(self, domain: str) -> Optional[Dict]:
        """Analyze domain name patterns."""
        domain_lower = domain.lower()
        matches = {}
        
        # Check against industry keywords
        for industry, data in self.industry_keywords.items():
            score = 0
            found_keywords = []
            
            for keyword in data['keywords']:
                if keyword in domain_lower:
                    score += 1
                    found_keywords.append(keyword)
            
            if score > 0:
                matches[industry] = {
                    'score': score,
                    'keywords': found_keywords,
                    'confidence': min(score * 0.2, 0.8)
                }
        
        # Check Chilean specific patterns
        if domain.endswith('.cl'):
            for industry, patterns in self.chile_patterns.items():
                for pattern in patterns:
                    if pattern in domain_lower:
                        if industry not in matches:
                            matches[industry] = {'score': 0, 'keywords': [], 'confidence': 0}
                        matches[industry]['score'] += 2
                        matches[industry]['keywords'].append(f"cl_pattern:{pattern}")
                        matches[industry]['confidence'] = min(matches[industry]['confidence'] + 0.3, 0.9)
        
        return matches if matches else None
    
    def _analyze_whois(self, domain: str) -> Optional[Dict]:
        """Analyze WHOIS data for industry clues."""
        try:
            import whois
            whois_data = whois.whois(domain)
            
            if not whois_data:
                return None
            
            # Extract organization and description
            org_fields = ['org', 'organization', 'registrant_org', 'registrant_organization']
            organization = None
            
            for field in org_fields:
                if hasattr(whois_data, field):
                    org_value = getattr(whois_data, field)
                    if org_value and isinstance(org_value, str):
                        organization = org_value.lower()
                        break
            
            if not organization:
                return None
            
            # Check organization name against industry keywords
            matches = {}
            for industry, data in self.industry_keywords.items():
                score = 0
                found_keywords = []
                
                for keyword in data['keywords']:
                    if keyword in organization:
                        score += 1
                        found_keywords.append(keyword)
                
                if score > 0:
                    matches[industry] = {
                        'score': score,
                        'keywords': found_keywords,
                        'confidence': min(score * 0.15, 0.6),
                        'organization': organization
                    }
            
            return matches if matches else None
            
        except ImportError:
            logger.debug("whois module not available")
            return None
        except Exception as e:
            logger.debug(f"WHOIS analysis error: {e}")
            return None
    
    def _analyze_certificate(self, domain: str) -> Optional[Dict]:
        """Analyze SSL certificate for organization info."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    if not cert:
                        return None
                    
                    # Extract organization from certificate
                    subject = cert.get('subject', [])
                    issuer = cert.get('issuer', [])
                    
                    org_info = []
                    for field_set in [subject, issuer]:
                        for field in field_set:
                            if field[0][0] == 'organizationName':
                                org_info.append(field[0][1].lower())
                    
                    if not org_info:
                        return None
                    
                    # Check organization against industry keywords
                    matches = {}
                    for org in org_info:
                        for industry, data in self.industry_keywords.items():
                            score = 0
                            found_keywords = []
                            
                            for keyword in data['keywords']:
                                if keyword in org:
                                    score += 1
                                    found_keywords.append(keyword)
                            
                            if score > 0:
                                if industry not in matches:
                                    matches[industry] = {'score': 0, 'keywords': [], 'confidence': 0}
                                matches[industry]['score'] += score
                                matches[industry]['keywords'].extend(found_keywords)
                                matches[industry]['confidence'] = min(matches[industry]['confidence'] + score * 0.1, 0.5)
                    
                    return matches if matches else None
                    
        except Exception as e:
            logger.debug(f"Certificate analysis error: {e}")
            return None
    
    def _analyze_dns_records(self, domain: str) -> Optional[Dict]:
        """Analyze DNS TXT records for industry indicators."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            
            txt_records = resolver.resolve(domain, 'TXT')
            txt_strings = [str(record) for record in txt_records]
            
            matches = {}
            for txt in txt_strings:
                txt_lower = txt.lower()
                
                # Look for service-specific TXT records
                if 'google-site-verification' in txt_lower:
                    self._add_evidence(matches, 'technology', ['google_services'], 0.1)
                elif 'facebook-domain-verification' in txt_lower:
                    self._add_evidence(matches, 'media_entertainment', ['facebook'], 0.1)
                elif 'v=spf1' in txt_lower:
                    if 'outlook' in txt_lower or 'office365' in txt_lower:
                        self._add_evidence(matches, 'technology', ['microsoft_services'], 0.1)
                    elif 'google' in txt_lower:
                        self._add_evidence(matches, 'technology', ['google_services'], 0.1)
                elif 'stripe' in txt_lower:
                    self._add_evidence(matches, 'financial_services', ['stripe_payments'], 0.2)
                elif 'paypal' in txt_lower:
                    self._add_evidence(matches, 'financial_services', ['paypal'], 0.2)
            
            return matches if matches else None
            
        except Exception as e:
            logger.debug(f"DNS analysis error: {e}")
            return None
    
    def _analyze_web_content(self, domain: str) -> Optional[Dict]:
        """Analyze web content for industry keywords."""
        try:
            url = f"https://{domain}"
            response = self.session.get(url, timeout=10, allow_redirects=True)
            
            if response.status_code != 200:
                # Try HTTP if HTTPS fails
                url = f"http://{domain}"
                response = self.session.get(url, timeout=10, allow_redirects=True)
                
                if response.status_code != 200:
                    return None
            
            content = response.text.lower()
            
            # Extract title and meta description
            title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
            title = title_match.group(1).strip() if title_match else ""
            
            desc_match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)["\']', content, re.IGNORECASE)
            description = desc_match.group(1).strip() if desc_match else ""
            
            # Combine title, description, and sample of content for analysis
            analysis_text = f"{title} {description} {content[:5000]}"
            
            matches = {}
            for industry, data in self.industry_keywords.items():
                score = 0
                found_keywords = []
                
                for keyword in data['keywords']:
                    count = analysis_text.count(keyword)
                    if count > 0:
                        score += count
                        found_keywords.append(f"{keyword}({count})")
                
                if score > 0:
                    matches[industry] = {
                        'score': score,
                        'keywords': found_keywords,
                        'confidence': min(score * 0.05, 0.7),
                        'title': title[:100],
                        'description': description[:200]
                    }
            
            return matches if matches else None
            
        except Exception as e:
            logger.debug(f"Web content analysis error: {e}")
            return None
    
    def _add_evidence(self, matches: Dict, industry: str, keywords: List[str], confidence: float):
        """Add evidence to matches dictionary."""
        if industry not in matches:
            matches[industry] = {'score': 0, 'keywords': [], 'confidence': 0}
        
        matches[industry]['score'] += 1
        matches[industry]['keywords'].extend(keywords)
        matches[industry]['confidence'] = min(matches[industry]['confidence'] + confidence, 0.8)
    
    def _aggregate_evidence(self, domain: str, evidence: Dict) -> IndustryClassification:
        """Aggregate evidence from all sources and determine final industry."""
        industry_scores = {}
        all_keywords = []
        sources_used = []
        
        # Aggregate scores from all sources
        for source, data in evidence.items():
            sources_used.append(source)
            if isinstance(data, dict):
                for industry, info in data.items():
                    if industry not in industry_scores:
                        industry_scores[industry] = {'total_score': 0, 'confidence': 0, 'keywords': []}
                    
                    industry_scores[industry]['total_score'] += info.get('score', 0)
                    industry_scores[industry]['confidence'] += info.get('confidence', 0)
                    industry_scores[industry]['keywords'].extend(info.get('keywords', []))
                    all_keywords.extend(info.get('keywords', []))
        
        if not industry_scores:
            # Default classification if no evidence found
            return IndustryClassification(
                primary_industry='unknown',
                confidence=0.0,
                secondary_industries=[],
                source='no_evidence',
                keywords_found=[],
                description='Industry could not be determined'
            )
        
        # Sort industries by combined score and confidence
        sorted_industries = sorted(
            industry_scores.items(),
            key=lambda x: (x[1]['total_score'] + x[1]['confidence'] * 10),
            reverse=True
        )
        
        primary_industry = sorted_industries[0][0]
        primary_confidence = min(sorted_industries[0][1]['confidence'], 1.0)
        
        # Get secondary industries (with significant scores)
        secondary_industries = []
        for industry, data in sorted_industries[1:4]:  # Top 3 secondary
            if data['total_score'] > 0 and data['confidence'] > 0.1:
                secondary_industries.append(industry)
        
        # Get description
        description = self.industry_keywords.get(primary_industry, {}).get('description', primary_industry.replace('_', ' ').title())
        
        return IndustryClassification(
            primary_industry=primary_industry,
            confidence=primary_confidence,
            secondary_industries=secondary_industries,
            source='+'.join(sources_used),
            keywords_found=list(set(all_keywords)),
            description=description
        )

def main():
    """Test the industry classifier."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Classify domain industry")
    parser.add_argument("domain", help="Domain to classify")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    classifier = IndustryClassifier()
    result = classifier.classify_domain(args.domain)
    
    print(f"\nIndustry Classification for {args.domain}:")
    print(f"Primary Industry: {result.primary_industry}")
    print(f"Description: {result.description}")
    print(f"Confidence: {result.confidence:.2f}")
    print(f"Secondary Industries: {', '.join(result.secondary_industries)}")
    print(f"Sources: {result.source}")
    print(f"Keywords Found: {', '.join(result.keywords_found[:10])}")

if __name__ == "__main__":
    main()