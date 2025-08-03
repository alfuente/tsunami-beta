#!/usr/bin/env python3
"""
risk_score_updater.py - Script para actualizar scores de riesgo según las definiciones de Risk.md

Este script implementa el algoritmo exacto definido en docs/Risk.md:
1. Base Tech Score (40%) - DNS, TLS, CVEs, Redundancia
2. Third-Party Score (25%) - Dependencias con weights y propagación
3. Incident Impact (30%) - Incidentes con decaimiento temporal
4. Context Boost (5%) - Certificaciones y controles compensatorios

Características:
- Logging detallado de cada criterio y cálculo
- Implementación exacta de las fórmulas de Risk.md
- Procesamiento de un dominio base inicialmente
- Validación de consistencia con risk-graph-service
"""

import argparse
import json
import logging
import math
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

# Neo4j imports
try:
    from neo4j import GraphDatabase, Driver
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'risk_update_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class RiskScoreComponents:
    """Componentes del risk score calculado"""
    base_tech_score: float
    third_party_score: float
    incident_impact_score: float
    context_boost_score: float
    final_score: float
    tier: str
    
    # Detalles de cada componente
    base_tech_details: Dict[str, Any]
    third_party_details: Dict[str, Any]
    incident_details: Dict[str, Any]
    context_details: Dict[str, Any]

class RiskScoreUpdater:
    """Actualizador de scores de riesgo según Risk.md"""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_pass: str):
        if not HAS_NEO4J:
            raise ImportError("Neo4j driver is required. Install with: pip install neo4j")
        
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
        
        # Constants from Risk.md
        self.WEIGHTS = {
            'base_tech': 0.40,
            'third_party': 0.25,
            'incident_impact': 0.30,
            'context_boost': 0.05
        }
        
        # Base Tech Score constants
        self.DNSSEC_BONUS = 20
        self.SINGLE_NS_PENALTY = -15
        self.TLS_GRADES = {
            'A+': 0, 'A': 0,
            'B': -5,
            'C': -15,
            'D': -30, 'E': -30, 'F': -30
        }
        self.CVE_MULTIPLIERS = {'critical': 5, 'high': 3}
        self.CVE_MAX_PENALTY = -25
        self.REDUNDANCY_BONUS = 10
        
        # Third-Party Score constants
        self.EXPOSURE_WEIGHTS = {
            'Critical': 1.0,
            'Important': 0.6,
            'Nice-to-have': 0.3
        }
        self.MAX_DEPTH = 2
        self.DEPTH_ATTENUATION = 0.8
        
        # Incident Impact constants
        self.SEVERITY_SCORES = {
            'Critical': 100,
            'High': 70,
            'Medium': 40,
            'Low': 10
        }
        self.LAMBDA_DECAY = 0.015  # λ for temporal decay
        self.HALF_LIFE_DAYS = 46
        self.PROPAGATION_FACTORS = {
            'Provider': 0.5,
            'Service': 0.4,
            'Domain': 0.3
        }
        self.REDUNDANCY_DISCOUNT = 0.6
        
        # Context Boost constants
        self.CERTIFICATION_BOOSTS = {
            'ISO_27001': 3,
            'SOC2_TYPE_II': 3,
            'PCI_DSS': 2,
            'HIPAA': 2
        }
        self.CONTINUITY_PLAN_BOOST = 2
        self.BUG_BOUNTY_BOOST = 1
        
        # Risk tiers
        self.RISK_TIERS = [
            (80, 'Critical'),
            (60, 'High'),
            (40, 'Medium'),
            (20, 'Low'),
            (0, 'Minimal')
        ]
    
    def get_risk_tier(self, score: float) -> str:
        """Obtiene el tier de riesgo según el score"""
        for threshold, tier in self.RISK_TIERS:
            if score >= threshold:
                return tier
        return 'Minimal'
    
    def calculate_base_tech_score(self, domain_fqdn: str) -> Tuple[float, Dict[str, Any]]:
        """
        Calcula Base Tech Score según Risk.md:
        - DNS: +20 pts DNSSEC; -15 pts single NS/ASN
        - TLS: Grade SSL-Labs penalties
        - CVEs: (critical×5 + high×3) max -25
        - Redundancy: +10 pts Multi-AZ/Region
        """
        logger.info(f"🔍 Calculando Base Tech Score para {domain_fqdn}")
        
        with self.driver.session() as session:
            # Get domain data
            result = session.run("""
                MATCH (d:Domain {fqdn: $fqdn})
                OPTIONAL MATCH (d)-[:SECURED_BY]->(c:Certificate)
                OPTIONAL MATCH (d)-[:RESOLVES_TO]->(ip:IPAddress)-[:BELONGS_TO]->(asn:ASN)
                WITH d, c, collect(DISTINCT {asn: asn.asn, country: asn.country, geo: asn.geo_location}) as name_servers
                RETURN 
                    d.dns_sec_enabled as dns_sec_enabled,
                    d.multi_az as multi_az,
                    d.multi_region as multi_region,
                    c.tls_grade as tls_grade,
                    d.critical_cves as critical_cves,
                    d.high_cves as high_cves,
                    name_servers
            """, fqdn=domain_fqdn)
            
            record = result.single()
            if not record:
                logger.warning(f"⚠️  Dominio {domain_fqdn} no encontrado")
                return 0.0, {"error": "Domain not found"}
            
            # Initialize with perfect score
            score = 100.0
            details = {}
            
            # 1. DNS Score
            dns_score = 0
            dnssec_enabled = record.get('dns_sec_enabled', False)
            if dnssec_enabled:
                dns_score += self.DNSSEC_BONUS
                logger.info(f"   ✓ DNSSEC habilitado: +{self.DNSSEC_BONUS} pts")
            else:
                logger.info(f"   ⚠️  DNSSEC deshabilitado: 0 pts")
            
            # Check name server diversity
            name_servers = record.get('name_servers', [])
            single_ns_penalty = self._check_single_ns_or_geo(name_servers)
            if single_ns_penalty:
                dns_score += self.SINGLE_NS_PENALTY
                logger.info(f"   ⚠️  NS en mismo ASN/geo: {self.SINGLE_NS_PENALTY} pts")
            else:
                logger.info(f"   ✓ NS distribuidos: 0 pts penalty")
            
            dns_final = max(-35, min(35, dns_score))
            details['dns'] = {
                'dnssec_enabled': dnssec_enabled,
                'single_ns_penalty': single_ns_penalty,
                'raw_score': dns_score,
                'final_score': dns_final
            }
            score += dns_final
            logger.info(f"   📊 DNS Score: {dns_final} pts")
            
            # 2. TLS Score
            tls_grade = record.get('tls_grade', '').upper()
            tls_penalty = self.TLS_GRADES.get(tls_grade, 0)
            details['tls'] = {
                'grade': tls_grade,
                'penalty': tls_penalty
            }
            score += tls_penalty
            logger.info(f"   📊 TLS Grade {tls_grade}: {tls_penalty} pts")
            
            # 3. CVE Score  
            critical_cves = record.get('critical_cves', 0) or 0
            high_cves = record.get('high_cves', 0) or 0
            cve_penalty = -(critical_cves * self.CVE_MULTIPLIERS['critical'] + 
                           high_cves * self.CVE_MULTIPLIERS['high'])
            cve_final = max(self.CVE_MAX_PENALTY, cve_penalty)
            details['cves'] = {
                'critical_count': critical_cves,
                'high_count': high_cves,
                'raw_penalty': cve_penalty,
                'final_penalty': cve_final
            }
            score += cve_final
            logger.info(f"   📊 CVEs (C:{critical_cves}, H:{high_cves}): {cve_final} pts")
            
            # 4. Redundancy Score
            multi_az = record.get('multi_az', False)
            multi_region = record.get('multi_region', False)
            redundancy_bonus = 0
            if multi_region or multi_az:
                redundancy_bonus = self.REDUNDANCY_BONUS
                logger.info(f"   ✓ Redundancia (AZ:{multi_az}, Region:{multi_region}): +{redundancy_bonus} pts")
            else:
                logger.info(f"   ⚠️  Sin redundancia: 0 pts")
            
            details['redundancy'] = {
                'multi_az': multi_az,
                'multi_region': multi_region,
                'bonus': redundancy_bonus
            }
            score += redundancy_bonus
            
            # Final base tech score (0-100)
            final_score = max(0, min(100, score))
            details['final_score'] = final_score
            
            logger.info(f"   🎯 Base Tech Score final: {final_score:.2f}/100")
            return final_score, details
    
    def _check_single_ns_or_geo(self, name_servers: List[Dict]) -> bool:
        """Verifica si los name servers están en el mismo ASN o geolocalización"""
        if len(name_servers) <= 1:
            return True
        
        first_asn = None
        first_geo = None
        
        for ns in name_servers:
            asn = ns.get('asn')
            geo = ns.get('geo') or ns.get('country')
            
            if first_asn is None:
                first_asn = asn
                first_geo = geo
            else:
                if asn != first_asn or geo != first_geo:
                    return False
        
        return True
    
    def calculate_third_party_score(self, domain_fqdn: str) -> Tuple[float, Dict[str, Any]]:
        """
        Calcula Third-Party Score según Risk.md:
        - Suma ponderada de risk_scores de dependencias
        - Weights: Critical=1.0, Important=0.6, Nice-to-have=0.3
        - Max depth=2, attenuation=0.8^hops
        """
        logger.info(f"🔗 Calculando Third-Party Score para {domain_fqdn}")
        
        visited = set()
        score, details = self._calculate_third_party_recursive(domain_fqdn, 0, visited)
        
        logger.info(f"   🎯 Third-Party Score final: {score:.2f}/100")
        return score, details
    
    def _calculate_third_party_recursive(self, node_id: str, depth: int, visited: set) -> Tuple[float, Dict[str, Any]]:
        """Cálculo recursivo de third-party score"""
        if depth >= self.MAX_DEPTH or node_id in visited:
            return 0.0, {}
        
        visited.add(node_id)
        
        with self.driver.session() as session:
            # Get dependencies
            result = session.run("""
                MATCH (d:Domain {fqdn: $fqdn})-[r:DEPENDS_ON]->(dep)
                WHERE dep:Service OR dep:Provider
                RETURN 
                    CASE 
                        WHEN dep:Service THEN dep.id
                        WHEN dep:Provider THEN dep.id
                        ELSE dep.name
                    END as dep_id,
                    labels(dep)[0] as dep_type,
                    coalesce(r.dependency_type, 'Nice-to-have') as dependency_type,
                    coalesce(dep.risk_score, 0.0) as dep_risk_score,
                    dep.name as dep_name
            """, fqdn=node_id)
            
            dependencies = []
            total_weighted_score = 0.0
            total_weight = 0.0
            
            for record in result:
                dep_id = record['dep_id']
                dep_type = record['dep_type']
                dependency_type = record['dependency_type']
                dep_risk_score = record['dep_risk_score']
                dep_name = record['dep_name']
                
                # Calculate weights and attenuation
                exposure_weight = self.EXPOSURE_WEIGHTS.get(dependency_type, 0.3)
                attenuation_factor = math.pow(self.DEPTH_ATTENUATION, depth)
                effective_weight = exposure_weight * attenuation_factor
                
                # Recursive calculation for deeper dependencies
                recursive_score, _ = self._calculate_third_party_recursive(dep_id, depth + 1, visited.copy())
                combined_score = max(dep_risk_score, recursive_score)
                
                weighted_contribution = combined_score * effective_weight
                total_weighted_score += weighted_contribution
                total_weight += effective_weight
                
                dep_info = {
                    'id': dep_id,
                    'name': dep_name,
                    'type': dep_type,
                    'dependency_type': dependency_type,
                    'risk_score': dep_risk_score,
                    'recursive_score': recursive_score,
                    'combined_score': combined_score,
                    'exposure_weight': exposure_weight,
                    'attenuation_factor': attenuation_factor,
                    'effective_weight': effective_weight,
                    'weighted_contribution': weighted_contribution
                }
                dependencies.append(dep_info)
                
                logger.info(f"   📎 {dep_name} ({dependency_type}): risk={dep_risk_score:.1f}, "
                          f"weight={effective_weight:.3f}, contribution={weighted_contribution:.2f}")
            
            visited.remove(node_id)
            
            final_score = total_weighted_score / total_weight if total_weight > 0 else 0.0
            
            details = {
                'depth': depth,
                'dependencies': dependencies,
                'total_weighted_score': total_weighted_score,
                'total_weight': total_weight,
                'final_score': final_score
            }
            
            return final_score, details
    
    def calculate_incident_impact_score(self, domain_fqdn: str) -> Tuple[float, Dict[str, Any]]:
        """
        Calcula Incident Impact Score según Risk.md:
        - Severity base: Critical=100, High=70, Medium=40, Low=10
        - Decaimiento temporal: e^(-λ×days), λ=0.015
        - Propagación: Provider×0.5, Service×0.4
        - Descuento redundancia: ×0.6
        """
        logger.info(f"🚨 Calculando Incident Impact Score para {domain_fqdn}")
        
        direct_impact, direct_details = self._calculate_direct_incident_impact(domain_fqdn)
        indirect_impact, indirect_details = self._calculate_indirect_incident_impact(domain_fqdn)
        
        total_impact = min(100.0, direct_impact + indirect_impact)
        
        details = {
            'direct_impact': direct_impact,
            'direct_details': direct_details,
            'indirect_impact': indirect_impact,
            'indirect_details': indirect_details,
            'total_impact': total_impact
        }
        
        logger.info(f"   🎯 Incident Impact final: {total_impact:.2f}/100 "
                   f"(Directo: {direct_impact:.2f}, Indirecto: {indirect_impact:.2f})")
        
        return total_impact, details
    
    def _calculate_direct_incident_impact(self, domain_fqdn: str) -> Tuple[float, Dict[str, Any]]:
        """Calcula impacto directo de incidentes"""
        with self.driver.session() as session:
            result = session.run("""
                MATCH (d:Domain {fqdn: $fqdn})<-[:AFFECTS]-(i:Incident)
                OPTIONAL MATCH (d)-[r:DEPENDS_ON]-()
                RETURN 
                    i.severity as severity,
                    i.detected as detected,
                    i.resolved as resolved,
                    i.title as title,
                    i.id as incident_id,
                    coalesce(r.failover_exists, false) as failover_exists
                ORDER BY i.detected DESC
            """, fqdn=domain_fqdn)
            
            incidents = []
            total_impact = 0.0
            
            for record in result:
                severity = record['severity']
                detected = record['detected']
                resolved = record['resolved']
                title = record['title']
                incident_id = record['incident_id']
                failover_exists = record['failover_exists']
                
                # Calculate incident score with temporal decay
                incident_score = self._calculate_incident_score(severity, detected, resolved)
                
                # Apply redundancy discount
                if failover_exists:
                    incident_score *= self.REDUNDANCY_DISCOUNT
                    logger.info(f"   🔄 Failover exists, aplicando descuento ×{self.REDUNDANCY_DISCOUNT}")
                
                total_impact += incident_score
                
                incident_info = {
                    'id': incident_id,
                    'title': title,
                    'severity': severity,
                    'detected': detected.isoformat() if detected else None,
                    'resolved': resolved.isoformat() if resolved else None,
                    'failover_exists': failover_exists,
                    'base_score': self.SEVERITY_SCORES.get(severity, 10),
                    'final_score': incident_score
                }
                incidents.append(incident_info)
                
                days_since = self._get_days_since_detection(detected, resolved)
                logger.info(f"   🚨 Incidente {incident_id} ({severity}): "
                          f"score={incident_score:.2f}, días={days_since}")
            
            return total_impact, {'incidents': incidents, 'total_impact': total_impact}
    
    def _calculate_indirect_incident_impact(self, domain_fqdn: str) -> Tuple[float, Dict[str, Any]]:
        """Calcula impacto indirecto de incidentes via dependencias"""
        with self.driver.session() as session:
            result = session.run("""
                MATCH (d:Domain {fqdn: $fqdn})-[r:DEPENDS_ON]->(dep)
                MATCH (dep)<-[:AFFECTS]-(i:Incident)
                RETURN 
                    i.severity as severity,
                    i.detected as detected,
                    i.resolved as resolved,
                    i.title as title,
                    i.id as incident_id,
                    labels(dep)[0] as affected_type,
                    dep.name as affected_name,
                    coalesce(r.dependency_type, 'Nice-to-have') as dependency_type,
                    coalesce(r.failover_exists, false) as failover_exists
                ORDER BY i.detected DESC
            """, fqdn=domain_fqdn)
            
            incidents = []
            total_impact = 0.0
            
            for record in result:
                severity = record['severity']
                detected = record['detected']
                resolved = record['resolved']
                title = record['title']
                incident_id = record['incident_id']
                affected_type = record['affected_type']
                affected_name = record['affected_name']
                dependency_type = record['dependency_type']
                failover_exists = record['failover_exists']
                
                # Calculate base incident score
                incident_score = self._calculate_incident_score(severity, detected, resolved)
                
                # Apply propagation factor
                propagation_factor = self.PROPAGATION_FACTORS.get(affected_type, 0.3)
                incident_score *= propagation_factor
                
                # Apply exposure weight
                exposure_weight = self.EXPOSURE_WEIGHTS.get(dependency_type, 0.3)
                incident_score *= exposure_weight
                
                # Apply redundancy discount
                if failover_exists:
                    incident_score *= self.REDUNDANCY_DISCOUNT
                
                total_impact += incident_score
                
                incident_info = {
                    'id': incident_id,
                    'title': title,
                    'severity': severity,
                    'detected': detected.isoformat() if detected else None,
                    'resolved': resolved.isoformat() if resolved else None,
                    'affected_type': affected_type,
                    'affected_name': affected_name,
                    'dependency_type': dependency_type,
                    'failover_exists': failover_exists,
                    'base_score': self.SEVERITY_SCORES.get(severity, 10),
                    'propagation_factor': propagation_factor,
                    'exposure_weight': exposure_weight,
                    'final_score': incident_score
                }
                incidents.append(incident_info)
                
                days_since = self._get_days_since_detection(detected, resolved)
                logger.info(f"   🔗 Incidente indirecto {incident_id} via {affected_name} ({affected_type}): "
                          f"score={incident_score:.2f}, días={days_since}, factor={propagation_factor}")
            
            return total_impact, {'incidents': incidents, 'total_impact': total_impact}
    
    def _calculate_incident_score(self, severity: str, detected: datetime, resolved: Optional[datetime]) -> float:
        """Calcula score de incidente con decaimiento temporal"""
        base_score = self.SEVERITY_SCORES.get(severity, 10)
        
        end_time = resolved if resolved else datetime.now()
        days_since_detection = (end_time - detected).days
        
        # Temporal decay: e^(-λ×days)
        time_decay = math.exp(-self.LAMBDA_DECAY * days_since_detection)
        
        return base_score * time_decay
    
    def _get_days_since_detection(self, detected: datetime, resolved: Optional[datetime]) -> int:
        """Obtiene días desde detección del incidente"""
        end_time = resolved if resolved else datetime.now()
        return (end_time - detected).days
    
    def calculate_context_boost_score(self, domain_fqdn: str) -> Tuple[float, Dict[str, Any]]:
        """
        Calcula Context Boost Score según Risk.md:
        - ISO 27001/SOC2 Type II: -3 pts
        - Plan continuidad <12 meses: -2 pts  
        - Bug-bounty activo: -1 pt
        """
        logger.info(f"🛡️  Calculando Context Boost Score para {domain_fqdn}")
        
        with self.driver.session() as session:
            # Get organization data (domains belong to organizations)
            result = session.run("""
                MATCH (d:Domain {fqdn: $fqdn})<-[:OWNS]-(o:Organization)
                OPTIONAL MATCH (o)-[:HAS_CERTIFICATION]->(c:Certification)
                WHERE c.valid_until IS NULL OR c.valid_until > datetime()
                RETURN 
                    o.id as org_id,
                    o.name as org_name,
                    o.continuity_plan_last_tested as continuity_plan_last_tested,
                    o.bug_bounty_active as bug_bounty_active,
                    o.bug_bounty_last_update as bug_bounty_last_update,
                    collect(DISTINCT c.type) as certifications
            """, fqdn=domain_fqdn)
            
            record = result.single()
            if not record:
                logger.info(f"   ⚠️  No se encontró organización para {domain_fqdn}")
                return 0.0, {"error": "No organization found"}
            
            org_name = record['org_name']
            certifications = record['certifications'] or []
            continuity_plan_last_tested = record['continuity_plan_last_tested']
            bug_bounty_active = record['bug_bounty_active']
            bug_bounty_last_update = record['bug_bounty_last_update']
            
            total_boost = 0.0
            details = {'organization': org_name}
            
            # 1. Certification boosts
            cert_boost = 0
            valid_certs = []
            for cert in certifications:
                if cert in self.CERTIFICATION_BOOSTS:
                    boost = self.CERTIFICATION_BOOSTS[cert]
                    cert_boost += boost
                    valid_certs.append(cert)
                    logger.info(f"   ✓ Certificación {cert}: +{boost} pts")
            
            details['certifications'] = {
                'valid_certifications': valid_certs,
                'total_boost': cert_boost
            }
            total_boost += cert_boost
            
            # 2. Continuity plan boost
            continuity_boost = 0
            if continuity_plan_last_tested:
                try:
                    if isinstance(continuity_plan_last_tested, str):
                        test_date = datetime.fromisoformat(continuity_plan_last_tested.replace('Z', '+00:00'))
                    else:
                        test_date = continuity_plan_last_tested
                    
                    months_since_test = (datetime.now() - test_date).days / 30.44  # Average days per month
                    
                    if months_since_test <= 12:
                        continuity_boost = self.CONTINUITY_PLAN_BOOST
                        logger.info(f"   ✓ Plan continuidad probado hace {months_since_test:.1f} meses: +{continuity_boost} pts")
                    else:
                        logger.info(f"   ⚠️  Plan continuidad desactualizado ({months_since_test:.1f} meses): 0 pts")
                except Exception as e:
                    logger.warning(f"   ⚠️  Error procesando fecha plan continuidad: {e}")
            else:
                logger.info(f"   ⚠️  Sin plan de continuidad: 0 pts")
            
            details['continuity_plan'] = {
                'last_tested': continuity_plan_last_tested,
                'boost': continuity_boost
            }
            total_boost += continuity_boost
            
            # 3. Bug bounty boost
            bounty_boost = 0
            if bug_bounty_active and bug_bounty_last_update:
                try:
                    if isinstance(bug_bounty_last_update, str):
                        update_date = datetime.fromisoformat(bug_bounty_last_update.replace('Z', '+00:00'))
                    else:
                        update_date = bug_bounty_last_update
                    
                    months_since_update = (datetime.now() - update_date).days / 30.44
                    
                    if months_since_update <= 6:
                        bounty_boost = self.BUG_BOUNTY_BOOST
                        logger.info(f"   ✓ Bug bounty activo (actualizado hace {months_since_update:.1f} meses): +{bounty_boost} pts")
                    else:
                        logger.info(f"   ⚠️  Bug bounty desactualizado: 0 pts")
                except Exception as e:
                    logger.warning(f"   ⚠️  Error procesando fecha bug bounty: {e}")
            elif bug_bounty_active:
                logger.info(f"   ⚠️  Bug bounty activo pero sin fecha actualización: 0 pts")
            else:
                logger.info(f"   ⚠️  Sin bug bounty: 0 pts")
            
            details['bug_bounty'] = {
                'active': bug_bounty_active,
                'last_update': bug_bounty_last_update,
                'boost': bounty_boost
            }
            total_boost += bounty_boost
            
            # Limit total boost to 5% (as per Risk.md)
            final_boost = min(5.0, total_boost)
            details['total_boost'] = final_boost
            
            logger.info(f"   🎯 Context Boost final: {final_boost:.2f}/5.0")
            return final_boost, details
    
    def calculate_complete_risk_score(self, domain_fqdn: str) -> RiskScoreComponents:
        """Calcula el risk score completo según Risk.md"""
        logger.info(f"\n🎯 CALCULANDO RISK SCORE COMPLETO PARA: {domain_fqdn}")
        logger.info("=" * 80)
        
        start_time = time.time()
        
        # Calculate each component
        base_tech_score, base_tech_details = self.calculate_base_tech_score(domain_fqdn)
        third_party_score, third_party_details = self.calculate_third_party_score(domain_fqdn)
        incident_impact_score, incident_details = self.calculate_incident_impact_score(domain_fqdn)
        context_boost_score, context_details = self.calculate_context_boost_score(domain_fqdn)
        
        # Apply weights from Risk.md: 40% + 25% + 30% - 5%
        final_score = (
            base_tech_score * self.WEIGHTS['base_tech'] +
            third_party_score * self.WEIGHTS['third_party'] +
            incident_impact_score * self.WEIGHTS['incident_impact'] -
            context_boost_score * self.WEIGHTS['context_boost']
        )
        
        # Normalize to 0-100
        final_score = max(0, min(100, final_score))
        
        # Get risk tier
        tier = self.get_risk_tier(final_score)
        
        elapsed_time = time.time() - start_time
        
        # Log final calculation
        logger.info(f"\n📊 RESUMEN DE CÁLCULO FINAL:")
        logger.info(f"   Base Tech Score:     {base_tech_score:6.2f} × {self.WEIGHTS['base_tech']:4.2f} = {base_tech_score * self.WEIGHTS['base_tech']:6.2f}")
        logger.info(f"   Third-Party Score:   {third_party_score:6.2f} × {self.WEIGHTS['third_party']:4.2f} = {third_party_score * self.WEIGHTS['third_party']:6.2f}")
        logger.info(f"   Incident Impact:     {incident_impact_score:6.2f} × {self.WEIGHTS['incident_impact']:4.2f} = {incident_impact_score * self.WEIGHTS['incident_impact']:6.2f}")
        logger.info(f"   Context Boost:       {context_boost_score:6.2f} × {self.WEIGHTS['context_boost']:4.2f} = {-context_boost_score * self.WEIGHTS['context_boost']:6.2f}")
        logger.info(f"   " + "-" * 50)
        logger.info(f"   SCORE FINAL:         {final_score:6.2f}/100 ({tier})")
        logger.info(f"   Tiempo de cálculo:   {elapsed_time:.2f} segundos")
        logger.info("=" * 80)
        
        return RiskScoreComponents(
            base_tech_score=base_tech_score,
            third_party_score=third_party_score,
            incident_impact_score=incident_impact_score,
            context_boost_score=context_boost_score,
            final_score=final_score,
            tier=tier,
            base_tech_details=base_tech_details,
            third_party_details=third_party_details,
            incident_details=incident_details,
            context_details=context_details
        )
    
    def update_domain_risk_score(self, domain_fqdn: str) -> bool:
        """Actualiza el risk score de un dominio en Neo4j"""
        try:
            # Calculate risk score
            risk_components = self.calculate_complete_risk_score(domain_fqdn)
            
            # Update in Neo4j
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (d:Domain {fqdn: $fqdn})
                    SET d.risk_score = $risk_score,
                        d.risk_tier = $risk_tier,
                        d.base_tech_score = $base_tech_score,
                        d.third_party_score = $third_party_score,
                        d.incident_impact_score = $incident_impact_score,
                        d.context_boost_score = $context_boost_score,
                        d.risk_calculated_at = datetime(),
                        d.risk_calculation_version = 'Risk.md-v1.0'
                    RETURN d.fqdn as updated_domain
                """, 
                fqdn=domain_fqdn,
                risk_score=risk_components.final_score,
                risk_tier=risk_components.tier,
                base_tech_score=risk_components.base_tech_score,
                third_party_score=risk_components.third_party_score,
                incident_impact_score=risk_components.incident_impact_score,
                context_boost_score=risk_components.context_boost_score
                )
                
                updated = result.single()
                if updated:
                    logger.info(f"✅ Risk score actualizado en Neo4j para {domain_fqdn}")
                    
                    # Save detailed calculation log
                    log_data = {
                        'domain': domain_fqdn,
                        'timestamp': datetime.now().isoformat(),
                        'final_score': risk_components.final_score,
                        'tier': risk_components.tier,
                        'components': {
                            'base_tech': {
                                'score': risk_components.base_tech_score,
                                'weight': self.WEIGHTS['base_tech'],
                                'weighted_contribution': risk_components.base_tech_score * self.WEIGHTS['base_tech'],
                                'details': risk_components.base_tech_details
                            },
                            'third_party': {
                                'score': risk_components.third_party_score,
                                'weight': self.WEIGHTS['third_party'],
                                'weighted_contribution': risk_components.third_party_score * self.WEIGHTS['third_party'],
                                'details': risk_components.third_party_details
                            },
                            'incident_impact': {
                                'score': risk_components.incident_impact_score,
                                'weight': self.WEIGHTS['incident_impact'],
                                'weighted_contribution': risk_components.incident_impact_score * self.WEIGHTS['incident_impact'],
                                'details': risk_components.incident_details
                            },
                            'context_boost': {
                                'score': risk_components.context_boost_score,
                                'weight': self.WEIGHTS['context_boost'],
                                'weighted_contribution': -risk_components.context_boost_score * self.WEIGHTS['context_boost'],
                                'details': risk_components.context_details
                            }
                        }
                    }
                    
                    # Save to detailed log file
                    log_filename = f"risk_calculation_{domain_fqdn}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    with open(log_filename, 'w', encoding='utf-8') as f:
                        json.dump(log_data, f, indent=2, ensure_ascii=False, default=str)
                    
                    logger.info(f"📄 Log detallado guardado en: {log_filename}")
                    return True
                else:
                    logger.error(f"❌ No se pudo actualizar el dominio {domain_fqdn}")
                    return False
                    
        except Exception as e:
            logger.error(f"❌ Error actualizando risk score para {domain_fqdn}: {e}")
            return False
    
    def close(self):
        """Cierra la conexión a Neo4j"""
        if self.driver:
            self.driver.close()

def main():
    """Función principal"""
    parser = argparse.ArgumentParser(
        description="Actualizar risk scores según definiciones de Risk.md"
    )
    parser.add_argument("--domain", required=True, help="Dominio base a procesar")
    parser.add_argument("--bolt", default="bolt://localhost:7687", help="Neo4j bolt URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", default="test.password", help="Neo4j password")
    parser.add_argument("--dry-run", action="store_true", help="Solo calcular, no actualizar en DB")
    
    args = parser.parse_args()
    
    logger.info(f"🚀 Iniciando actualización de risk score para: {args.domain}")
    logger.info(f"   Neo4j URI: {args.bolt}")
    logger.info(f"   Dry run: {args.dry_run}")
    
    updater = None
    try:
        # Initialize updater
        updater = RiskScoreUpdater(args.bolt, args.user, args.password)
        
        if args.dry_run:
            # Just calculate, don't update
            logger.info("🔍 MODO DRY-RUN: Solo calculando, sin actualizar DB")
            risk_components = updater.calculate_complete_risk_score(args.domain)
            logger.info(f"✅ Cálculo completado. Score final: {risk_components.final_score:.2f} ({risk_components.tier})")
        else:
            # Calculate and update
            success = updater.update_domain_risk_score(args.domain)
            if success:
                logger.info(f"✅ Risk score actualizado exitosamente para {args.domain}")
            else:
                logger.error(f"❌ Error actualizando risk score para {args.domain}")
                return 1
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("⏹️  Proceso interrumpido por el usuario")
        return 1
    except Exception as e:
        logger.error(f"❌ Error fatal: {e}")
        return 1
    finally:
        if updater:
            updater.close()

if __name__ == "__main__":
    exit(main())