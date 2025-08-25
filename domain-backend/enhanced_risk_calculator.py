#!/usr/bin/env python3
"""
Enhanced Risk Calculator with 4 Components:
1. Base Risk (technologies, services, TLS) - 25%
2. Subdomain Risk (aggregation of subdomain risks) - 25%  
3. DNS/MX Risk (nameservers, SPF, DMARC, MX redundancy) - 25%
4. Provider Risk (cloud providers, hosting, unknown services) - 25%
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class EnhancedRiskCalculator:
    
    def __init__(self, neo4j_session):
        self.session = neo4j_session
        self.config = self._load_risk_configuration()
    
    def _load_risk_configuration(self) -> Dict:
        """Load risk configuration from Neo4j"""
        try:
            result = self.session.run("""
                MATCH (rc:RiskConfiguration {active: true})
                RETURN rc
                ORDER BY rc.created_at DESC
                LIMIT 1
            """)
            record = result.single()
            if record:
                config = dict(record['rc'])
                # Parse JSON fields
                if 'dns_security_weights_json' in config:
                    config['dns_security_weights'] = json.loads(config['dns_security_weights_json'])
                if 'provider_risk_factors_json' in config:
                    config['provider_risk_factors'] = json.loads(config['provider_risk_factors_json'])
                return config
            else:
                # Default configuration if none exists
                return self._get_default_config()
        except Exception as e:
            logger.error(f"Error loading risk configuration: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Get default risk configuration"""
        return {
            'base_risk_weight': 0.25,
            'subdomain_risk_weight': 0.25,
            'dns_mx_risk_weight': 0.25,
            'provider_risk_weight': 0.25,
            'max_risk_score': 100.0,
            'min_risk_score': 0.0,
            'subdomain_aggregation_method': 'weighted_average',
            'subdomain_critical_threshold': 80.0,
            'dns_nameserver_min_count': 2,
            'dns_nameserver_optimal_count': 4,
            'dns_security_weights': {
                'dnssec_enabled': 0.3,
                'spf_configured': 0.25,
                'dmarc_configured': 0.25,
                'mx_redundancy': 0.2
            },
            'provider_risk_factors': {
                'cloud_major': 0.1,
                'cloud_minor': 0.3,
                'hosting_shared': 0.5,
                'unknown_provider': 0.8
            }
        }
    
    async def calculate_enhanced_risk_score(self, target: str, is_base_domain: bool = True) -> Optional[Dict]:
        """Calculate enhanced risk score with 4 components"""
        try:
            # Component 1: Base Risk (technologies, services, TLS)
            base_risk_score = self._calculate_base_risk(target)
            
            # Component 2: Subdomain Risk (only for base domains)
            subdomain_risk_score = 0.0
            if is_base_domain:
                subdomain_risk_score = self._calculate_subdomain_aggregated_risk(target)
            
            # Component 3: DNS/MX Risk  
            dns_mx_risk_score = self._calculate_dns_mx_risk(target)
            
            # Component 4: Provider Risk
            provider_risk_score = self._calculate_provider_risk(target)
            
            # Combine components using configured weights
            final_score = (
                base_risk_score * self.config['base_risk_weight'] +
                subdomain_risk_score * self.config['subdomain_risk_weight'] +
                dns_mx_risk_score * self.config['dns_mx_risk_weight'] +
                provider_risk_score * self.config['provider_risk_weight']
            )
            
            # Cap at configured limits
            final_score = max(self.config['min_risk_score'], 
                             min(final_score, self.config['max_risk_score']))
            
            # Determine risk tier and grade (A=best, E=worst)
            risk_tier, risk_grade = self._determine_risk_grade(final_score)
            
            # Collect all risk factors
            risk_factors = []
            risk_factors.extend(self._get_base_risk_factors(target, base_risk_score))
            if is_base_domain:
                risk_factors.extend(self._get_subdomain_risk_factors(target, subdomain_risk_score))
            risk_factors.extend(self._get_dns_mx_risk_factors(target, dns_mx_risk_score))
            risk_factors.extend(self._get_provider_risk_factors(target, provider_risk_score))
            
            return {
                "final_score": final_score,
                "risk_tier": risk_tier,
                "risk_grade": risk_grade,
                "risk_factors": risk_factors,
                "score_breakdown": {
                    "base_score": base_risk_score,
                    "subdomain_score": subdomain_risk_score,
                    "dns_mx_score": dns_mx_risk_score,
                    "provider_score": provider_risk_score,
                    "weights": {
                        "base_score": self.config['base_risk_weight'],
                        "subdomain_score": self.config['subdomain_risk_weight'],
                        "dns_mx_score": self.config['dns_mx_risk_weight'],
                        "provider_score": self.config['provider_risk_weight']
                    }
                },
                "calculation_timestamp": datetime.now().isoformat(),
                "config_version": self.config.get('id', 'default')
            }
            
        except Exception as e:
            logger.error(f"Error calculating enhanced risk score for {target}: {e}")
            return None
    
    def _calculate_base_risk(self, target: str) -> float:
        """Calculate base risk from technologies, services, and TLS"""
        try:
            result = self.session.run("""
                MATCH (n {fqdn: $target})
                OPTIONAL MATCH (n)-[:RUNS_SERVICE]->(s:Service)
                OPTIONAL MATCH (n)-[:USES_TECHNOLOGY]->(t:Technology)
                RETURN n.fqdn as fqdn,
                       n.technologies as technologies,
                       n.tls_grade as tls_grade,
                       collect(DISTINCT s.service_name) as services,
                       collect(DISTINCT {name: t.name, category: t.category}) as tech_nodes
            """, target=target)
            
            record = result.single()
            if not record:
                return 15.0  # Default risk for unknown domains
            
            # Start with base risk
            risk_score = 10.0  # Base risk for any publicly accessible domain
            
            # Service exposure risk
            services = record.get("services", [])
            high_risk_services = ['ftp', 'telnet', 'mysql', 'rdp', 'vnc', 'postgresql']
            medium_risk_services = ['ssh', 'http-alt', 'https-alt']
            
            for service in services:
                if service in high_risk_services:
                    risk_score += 15.0
                elif service in medium_risk_services:
                    risk_score += 5.0
            
            # Technology risk
            technologies_json = record.get("technologies")
            technologies = []
            if technologies_json:
                try:
                    technologies = json.loads(technologies_json)
                except:
                    technologies = []
            
            if technologies:
                tech_complexity = len(technologies)
                if tech_complexity > 10:
                    risk_score += 8.0
                elif tech_complexity > 5:
                    risk_score += 4.0
                else:
                    risk_score += 2.0
            else:
                risk_score += 5.0
            
            for tech in technologies:
                tech_name = tech.get("name", "").lower()
                if "wordpress" in tech_name:
                    risk_score += 8.0
                elif "apache" in tech_name:
                    risk_score += 3.0
                elif "nginx" in tech_name:
                    risk_score += 2.0
                elif "php" in tech_name:
                    risk_score += 5.0
                elif "mysql" in tech_name or "database" in tech_name:
                    risk_score += 4.0
            
            # TLS configuration risk
            tls_grade = record.get("tls_grade")
            if tls_grade in ["C", "D", "F"]:
                risk_score += 15.0
            elif tls_grade == "B":
                risk_score += 5.0
            elif not tls_grade:
                risk_score += 10.0
            else:  # A or A+
                risk_score = max(risk_score - 2.0, 5.0)
            
            return min(risk_score, 100.0)
            
        except Exception as e:
            logger.error(f"Error calculating base risk for {target}: {e}")
            return 20.0  # Safe default
    
    def _calculate_subdomain_aggregated_risk(self, base_domain: str) -> float:
        """Calculate aggregated risk from subdomains"""
        try:
            result = self.session.run("""
                MATCH (bd:Domain {fqdn: $base_domain})<-[:BELONGS_TO]-(s:Subdomain)
                WHERE s.risk_score IS NOT NULL
                RETURN collect({fqdn: s.fqdn, risk_score: s.risk_score}) as subdomains
            """, base_domain=base_domain)
            
            record = result.single()
            if not record or not record['subdomains']:
                return 0.0  # No subdomains or no risk data
            
            subdomains = record['subdomains']
            risk_scores = [s['risk_score'] for s in subdomains]
            
            method = self.config.get('subdomain_aggregation_method', 'weighted_average')
            
            if method == 'max':
                return max(risk_scores)
            elif method == 'average':
                return sum(risk_scores) / len(risk_scores)
            elif method == 'weighted_average':
                # Weight higher scores more heavily
                critical_threshold = self.config.get('subdomain_critical_threshold', 80.0)
                weighted_sum = 0.0
                total_weight = 0.0
                
                for score in risk_scores:
                    weight = 2.0 if score >= critical_threshold else 1.0
                    weighted_sum += score * weight
                    total_weight += weight
                
                return weighted_sum / total_weight if total_weight > 0 else 0.0
            else:
                return sum(risk_scores) / len(risk_scores)
                
        except Exception as e:
            logger.error(f"Error calculating subdomain aggregated risk for {base_domain}: {e}")
            return 0.0
    
    def _calculate_dns_mx_risk(self, target: str) -> float:
        """Calculate DNS and MX configuration risk"""
        try:
            result = self.session.run("""
                MATCH (n {fqdn: $target})
                RETURN n.dns_info as dns_info
            """, target=target)
            
            record = result.single()
            if not record or not record['dns_info']:
                return 50.0  # High risk for missing DNS info
            
            dns_info = json.loads(record['dns_info']) if isinstance(record['dns_info'], str) else record['dns_info']
            
            risk_score = 0.0
            weights = self.config.get('dns_security_weights', {
                'dnssec_enabled': 0.3,
                'spf_configured': 0.25,
                'dmarc_configured': 0.25,
                'mx_redundancy': 0.2
            })
            
            # DNSSEC evaluation
            dnssec_enabled = dns_info.get('dns_sec_enabled', False)
            if not dnssec_enabled:
                risk_score += 40.0 * weights.get('dnssec_enabled', 0.3)
            
            # SPF evaluation
            has_spf = bool(dns_info.get('spf_record'))
            if not has_spf:
                risk_score += 50.0 * weights.get('spf_configured', 0.25)
            
            # DMARC evaluation
            has_dmarc = bool(dns_info.get('dmarc_record'))
            if not has_dmarc:
                risk_score += 50.0 * weights.get('dmarc_configured', 0.25)
            
            # MX redundancy evaluation
            mx_records = dns_info.get('mx_records', [])
            if isinstance(mx_records, str):
                mx_records = json.loads(mx_records)
            
            mx_count = len(mx_records) if mx_records else 0
            if mx_count == 0:
                risk_score += 60.0 * weights.get('mx_redundancy', 0.2)
            elif mx_count == 1:
                risk_score += 30.0 * weights.get('mx_redundancy', 0.2)
            # mx_count >= 2 is good (no additional risk)
            
            # Nameserver redundancy evaluation
            dns_records = dns_info.get('dns_records')
            if dns_records:
                if isinstance(dns_records, str):
                    dns_records = json.loads(dns_records)
                ns_records = dns_records.get('NS', [])
                ns_count = len(ns_records)
                
                min_count = self.config.get('dns_nameserver_min_count', 2)
                optimal_count = self.config.get('dns_nameserver_optimal_count', 4)
                
                if ns_count < min_count:
                    risk_score += 40.0  # High risk for insufficient nameservers
                elif ns_count < optimal_count:
                    risk_score += 15.0  # Medium risk
                # ns_count >= optimal is excellent (no additional risk)
            else:
                risk_score += 30.0  # Risk for missing NS records
            
            return min(risk_score, 100.0)
            
        except Exception as e:
            logger.error(f"Error calculating DNS/MX risk for {target}: {e}")
            return 40.0  # Medium default risk
    
    def _calculate_provider_risk(self, target: str) -> float:
        """Calculate provider-based risk"""
        try:
            result = self.session.run("""
                MATCH (n {fqdn: $target})-[:USES_PROVIDER]->(p:Provider)
                RETURN collect({name: p.name, type: p.type, confidence: p.confidence}) as providers
            """, target=target)
            
            record = result.single()
            if not record or not record['providers']:
                return 60.0  # High risk for unknown providers
            
            providers = record['providers']
            risk_factors = self.config.get('provider_risk_factors', {
                'cloud_major': 0.1,
                'cloud_minor': 0.3,
                'hosting_shared': 0.5,
                'unknown_provider': 0.8
            })
            
            provider_risks = []
            for provider in providers:
                provider_name = provider['name'].lower()
                provider_type = provider.get('type', 'unknown')
                
                # Classify provider risk
                if any(major in provider_name for major in ['aws', 'amazon', 'azure', 'microsoft', 'google', 'gcp']):
                    provider_risk = risk_factors.get('cloud_major', 0.1)
                elif provider_type in ['cdn', 'cloud_provider']:
                    provider_risk = risk_factors.get('cloud_minor', 0.3)
                elif 'hosting' in provider_type:
                    provider_risk = risk_factors.get('hosting_shared', 0.5)
                else:
                    provider_risk = risk_factors.get('unknown_provider', 0.8)
                
                provider_risks.append(provider_risk)
            
            # Use average provider risk, scaled to 0-100
            avg_provider_risk = sum(provider_risks) / len(provider_risks)
            return avg_provider_risk * 100.0
            
        except Exception as e:
            logger.error(f"Error calculating provider risk for {target}: {e}")
            return 50.0  # Medium default risk
    
    def _determine_risk_grade(self, score: float) -> tuple[str, str]:
        """Determine risk tier and grade from score (A=best, E=worst)"""
        if score <= 20:
            return "A", "A"  # Excellent - Low risk
        elif score <= 40:
            return "B", "B"  # Good - Low-Medium risk
        elif score <= 60:
            return "C", "C"  # Fair - Medium risk
        elif score <= 80:
            return "D", "D"  # Poor - High risk
        else:
            return "E", "E"  # Critical - Very High risk
    
    def _get_base_risk_factors(self, target: str, score: float) -> List[str]:
        """Get base risk factors for reporting"""
        factors = []
        if score > 40:
            factors.append(f"Base infrastructure risk: {score:.1f}/100")
        if score > 60:
            factors.append("High complexity technology stack detected")
        return factors
    
    def _get_subdomain_risk_factors(self, target: str, score: float) -> List[str]:
        """Get subdomain risk factors"""
        factors = []
        if score > 50:
            factors.append(f"Subdomain risk aggregation: {score:.1f}/100")
        if score > 70:
            factors.append("Critical subdomain risks detected")
        return factors
    
    def _get_dns_mx_risk_factors(self, target: str, score: float) -> List[str]:
        """Get DNS/MX risk factors"""
        factors = []
        if score > 30:
            factors.append(f"DNS/MX configuration risk: {score:.1f}/100")
        if score > 50:
            factors.append("DNS security configuration issues detected")
        return factors
    
    def _get_provider_risk_factors(self, target: str, score: float) -> List[str]:
        """Get provider risk factors"""
        factors = []
        if score > 40:
            factors.append(f"Provider infrastructure risk: {score:.1f}/100")
        if score > 60:
            factors.append("Higher risk hosting/cloud providers detected")
        return factors