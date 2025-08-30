#!/usr/bin/env python3
"""
data_completeness_analyzer.py - Tsunami Beta Data Completeness Analyzer

Analyzes data completeness in the graph and generates specific tasks for data completion.
Creates actionable recommendations based on missing data patterns.

This script works in conjunction with graph_validator.py to provide detailed analysis
of what data is missing and how to collect it.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
import sys
import os

try:
    from neo4j import GraphDatabase
    import neo4j
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False
    print("Warning: Neo4j driver not available")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TaskPriority(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class DataType(Enum):
    SUBDOMAIN = "subdomain"
    DNS = "dns"
    CERTIFICATE = "certificate"
    TECHNOLOGY = "technology"
    SERVICE = "service"
    PROVIDER = "provider"
    RISK = "risk"
    VULNERABILITY = "vulnerability"

@dataclass
class DataGap:
    data_type: DataType
    priority: TaskPriority
    domain: str
    description: str
    affected_count: int
    completion_command: str
    estimated_time_minutes: int
    dependencies: List[str] = None

@dataclass
class CompletenessReport:
    timestamp: datetime
    total_domains: int
    total_gaps: int
    critical_gaps: int
    high_priority_gaps: int
    gaps_by_type: Dict[str, int]
    data_gaps: List[DataGap]
    completion_estimate_hours: float
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp.isoformat(),
            'total_domains': self.total_domains,
            'total_gaps': self.total_gaps,
            'critical_gaps': self.critical_gaps,
            'high_priority_gaps': self.high_priority_gaps,
            'gaps_by_type': self.gaps_by_type,
            'completion_estimate_hours': self.completion_estimate_hours,
            'data_gaps': [self._gap_to_dict(gap) for gap in self.data_gaps]
        }
    
    def _gap_to_dict(self, gap):
        return {
            'data_type': gap.data_type.value,
            'priority': gap.priority.value,
            'domain': gap.domain,
            'description': gap.description,
            'affected_count': gap.affected_count,
            'completion_command': gap.completion_command,
            'estimated_time_minutes': gap.estimated_time_minutes,
            'dependencies': gap.dependencies or []
        }

class DataCompletenessAnalyzer:
    """Analyzes data completeness and generates completion tasks"""
    
    def __init__(self, neo4j_uri="bolt://localhost:7687", neo4j_user="neo4j", neo4j_password="neo4j"):
        if not HAS_NEO4J:
            raise ImportError("Neo4j driver is required")
        
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.data_gaps: List[DataGap] = []
        self.domain_backend_api = "http://localhost:8001"  # Default domain-backend API
        
    def close(self):
        """Close the Neo4j driver connection"""
        if self.driver:
            self.driver.close()

    def analyze_subdomain_gaps(self) -> None:
        """Analyze missing subdomain data"""
        with self.driver.session() as session:
            # Find base domains without subdomain discovery
            query = """
            MATCH (d:Domain)
            WHERE d.fqdn IS NOT NULL 
            AND NOT d.fqdn CONTAINS '.'
            AND NOT EXISTS {
                MATCH (sub:Domain) 
                WHERE sub.fqdn CONTAINS d.fqdn 
                AND sub.fqdn <> d.fqdn
            }
            RETURN d.fqdn as domain, count(*) as count
            ORDER BY d.fqdn
            """
            result = session.run(query)
            
            for record in result:
                domain = record["domain"]
                self.data_gaps.append(DataGap(
                    data_type=DataType.SUBDOMAIN,
                    priority=TaskPriority.HIGH,
                    domain=domain,
                    description=f"No subdomains discovered for {domain}",
                    affected_count=1,
                    completion_command=f"curl -X 'POST' '{self.domain_backend_api}/api/v1/discover/amass/{domain}' -H 'accept: application/json' -d ''",
                    estimated_time_minutes=30,
                    dependencies=["amass", "domain-backend"]
                ))

    def analyze_dns_gaps(self) -> None:
        """Analyze missing DNS resolution data for subdomains only"""
        with self.driver.session() as session:
            query = """
            MATCH (s:Subdomain)
            WHERE s.fqdn IS NOT NULL
            AND (s.fqdn CONTAINS 'www.' OR s.fqdn CONTAINS 'portal.' OR s.fqdn CONTAINS 'api.' OR s.fqdn CONTAINS 'app.' OR s.fqdn CONTAINS 'mail.')
            AND (s.dns_analyzed_at IS NULL OR s.dns_records IS NULL)
            RETURN s.fqdn as subdomain
            ORDER BY s.fqdn
            LIMIT 10
            """
            result = session.run(query)
            
            for record in result:
                subdomain = record["subdomain"]
                self.data_gaps.append(DataGap(
                    data_type=DataType.DNS,
                    priority=TaskPriority.CRITICAL,
                    domain=subdomain,
                    description=f"Missing DNS analysis for subdomain {subdomain}",
                    affected_count=1,
                    completion_command=f"curl -X 'POST' '{self.domain_backend_api}/api/v1/discover/dns/{subdomain.split('.', 1)[1] if '.' in subdomain else subdomain}?subdomain={subdomain}' -H 'accept: application/json' -d ''",
                    estimated_time_minutes=2,
                    dependencies=["domain-backend"]
                ))

    def analyze_certificate_gaps(self) -> None:
        """Analyze missing certificate data for web-facing subdomains only"""
        with self.driver.session() as session:
            query = """
            MATCH (s:Subdomain)
            WHERE s.fqdn IS NOT NULL
            AND (s.fqdn CONTAINS 'www.' OR s.fqdn CONTAINS 'portal.' OR s.fqdn CONTAINS 'api.' OR s.fqdn CONTAINS 'app.' OR s.fqdn CONTAINS 'secure.')
            AND (s.tls_analyzed_at IS NULL OR s.certificate_info IS NULL OR s.hasSSL IS NULL)
            RETURN s.fqdn as subdomain
            ORDER BY s.fqdn
            LIMIT 10
            """
            result = session.run(query)
            
            for record in result:
                subdomain = record["subdomain"]
                self.data_gaps.append(DataGap(
                    data_type=DataType.CERTIFICATE,
                    priority=TaskPriority.HIGH,
                    domain=subdomain,
                    description=f"Missing SSL/TLS certificate analysis for subdomain {subdomain}",
                    affected_count=1,
                    completion_command=f"curl -X 'POST' '{self.domain_backend_api}/api/v1/discover/tls/{subdomain.split('.', 1)[1] if '.' in subdomain else subdomain}?subdomain={subdomain}' -H 'accept: application/json' -d ''",
                    estimated_time_minutes=3,
                    dependencies=["domain-backend"]
                ))

    def analyze_technology_gaps(self) -> None:
        """Analyze missing web technology data for web-facing subdomains only"""
        with self.driver.session() as session:
            query = """
            MATCH (s:Subdomain)
            WHERE s.fqdn IS NOT NULL
            AND (s.fqdn CONTAINS 'www.' OR s.fqdn CONTAINS 'portal.' OR s.fqdn CONTAINS 'app.' OR s.fqdn STARTS WITH 'web.' OR s.fqdn CONTAINS 'intranet.')
            AND (s.tech_analyzed_at IS NULL OR s.technologies IS NULL OR s.technologiesAnalyzed IS NULL)
            RETURN s.fqdn as subdomain
            ORDER BY s.fqdn
            LIMIT 10
            """
            result = session.run(query)
            
            for record in result:
                subdomain = record["subdomain"]
                self.data_gaps.append(DataGap(
                    data_type=DataType.TECHNOLOGY,
                    priority=TaskPriority.MEDIUM,
                    domain=subdomain,
                    description=f"Missing web technology analysis for subdomain {subdomain}",
                    affected_count=1,
                    completion_command=f"curl -X 'POST' '{self.domain_backend_api}/api/v1/discover/tech/{subdomain.split('.', 1)[1] if '.' in subdomain else subdomain}?subdomain={subdomain}' -H 'accept: application/json' -d ''",
                    estimated_time_minutes=5,
                    dependencies=["domain-backend", "wappalyzer"]
                ))

    def analyze_service_gaps(self) -> None:
        """Analyze missing service discovery data for service-oriented subdomains only"""
        with self.driver.session() as session:
            query = """
            MATCH (s:Subdomain)
            WHERE s.fqdn IS NOT NULL
            AND (s.fqdn CONTAINS 'api.' OR s.fqdn CONTAINS 'service.' OR s.fqdn CONTAINS 'ws.' OR s.fqdn CONTAINS 'rest.' OR s.fqdn CONTAINS 'soap.')
            AND (s.services_count IS NULL OR s.services_count = 0)
            AND NOT EXISTS {(s)-[:DEPENDS_ON]->(:Service)}
            RETURN s.fqdn as subdomain
            ORDER BY s.fqdn
            LIMIT 10
            """
            result = session.run(query)
            
            for record in result:
                subdomain = record["subdomain"]
                self.data_gaps.append(DataGap(
                    data_type=DataType.SERVICE,
                    priority=TaskPriority.MEDIUM,
                    domain=subdomain,
                    description=f"Missing service discovery for API/service subdomain {subdomain}",
                    affected_count=1,
                    completion_command=f"curl -X 'POST' '{self.domain_backend_api}/api/v1/discover/services/{subdomain.split('.', 1)[1] if '.' in subdomain else subdomain}?subdomain={subdomain}' -H 'accept: application/json' -d ''",
                    estimated_time_minutes=4,
                    dependencies=["domain-backend"]
                ))

    def analyze_risk_gaps(self) -> None:
        """Analyze missing risk score data"""
        with self.driver.session() as session:
            # Domains without risk scores
            domain_query = """
            MATCH (d:Domain)
            WHERE d.risk_score IS NULL
            RETURN count(d) as missing_count
            """
            result = session.run(domain_query)
            missing_domains = result.single()["missing_count"]
            
            if missing_domains > 0:
                # Get a sample of domains without risk scores
                domains_query = """
                MATCH (d:Domain)
                WHERE d.risk_score IS NULL AND d.fqdn IS NOT NULL
                RETURN d.fqdn as domain
                LIMIT 5
                """
                domains_result = session.run(domains_query)
                
                for record in domains_result:
                    domain = record["domain"]
                    self.data_gaps.append(DataGap(
                        data_type=DataType.RISK,
                        priority=TaskPriority.HIGH,
                        domain=domain,
                        description=f"Missing risk score for {domain}",
                        affected_count=1,
                        completion_command=f"curl -X 'POST' '{self.domain_backend_api}/api/v1/calculate/risk/{domain}' -H 'accept: application/json' -d ''",
                        estimated_time_minutes=2,
                        dependencies=["domain-backend", "risk-calculator"]
                    ))
            
            # Services without risk scores
            service_query = """
            MATCH (s:Service)
            WHERE s.risk_score IS NULL
            RETURN count(s) as missing_count
            """
            result = session.run(service_query)
            missing_services = result.single()["missing_count"]
            
            if missing_services > 0:
                # Note: API doesn't have service-specific risk calculation endpoint
                # Services get risk scores through domain risk calculation
                self.data_gaps.append(DataGap(
                    data_type=DataType.RISK,
                    priority=TaskPriority.MEDIUM,
                    domain="services",
                    description=f"Missing risk scores for {missing_services} services - calculate via domain analysis",
                    affected_count=missing_services,
                    completion_command=f"echo 'Services get risk scores through domain analysis - run domain risk calculations first'",
                    estimated_time_minutes=missing_services * 1,
                    dependencies=["domain-backend", "risk-calculator"]
                ))

    def analyze_provider_gaps(self) -> None:
        """Analyze missing provider data"""
        with self.driver.session() as session:
            # Services without providers
            query = """
            MATCH (s:Service)
            WHERE NOT EXISTS {(s)<-[:PROVIDES]-(:Provider)}
            RETURN s.name as service_name, s.provider_name as provider_name
            ORDER BY s.name
            LIMIT 20
            """
            result = session.run(query)
            
            orphaned_services = []
            for record in result:
                orphaned_services.append({
                    "service": record["service_name"],
                    "provider": record["provider_name"]
                })
            
            if orphaned_services:
                self.data_gaps.append(DataGap(
                    data_type=DataType.PROVIDER,
                    priority=TaskPriority.MEDIUM,
                    domain="services",
                    description=f"Missing provider relationships for {len(orphaned_services)} services",
                    affected_count=len(orphaned_services),
                    completion_command=f"echo 'Provider linking is not available via API - requires manual database operations'",
                    estimated_time_minutes=len(orphaned_services) * 3,
                    dependencies=["domain-backend", "provider-database"]
                ))

    def analyze_vulnerability_gaps(self) -> None:
        """Analyze missing vulnerability data"""
        with self.driver.session() as session:
            # Technologies without vulnerability information
            query = """
            MATCH (t:Technology)
            WHERE NOT EXISTS {(t)-[:HAS_VULNERABILITY]->(:Vulnerability)}
            RETURN count(t) as missing_count
            """
            result = session.run(query)
            missing_vulns = result.single()["missing_count"]
            
            if missing_vulns > 0:
                self.data_gaps.append(DataGap(
                    data_type=DataType.VULNERABILITY,
                    priority=TaskPriority.LOW,
                    domain="technologies",
                    description=f"Missing vulnerability data for {missing_vulns} technologies",
                    affected_count=missing_vulns,
                    completion_command=f"echo 'Vulnerability scanning is not available via API - requires external tools'",
                    estimated_time_minutes=missing_vulns * 2,
                    dependencies=["domain-backend", "nvd-api", "cve-database"]
                ))

    def get_domain_count(self) -> int:
        """Get total number of domains in the graph"""
        with self.driver.session() as session:
            result = session.run("MATCH (d:Domain) RETURN count(d) as count")
            return result.single()["count"]

    def generate_completion_script(self, output_dir: str) -> str:
        """Generate a bash script to execute all completion tasks"""
        script_path = os.path.join(output_dir, "complete_missing_data.sh")
        
        script_content = """#!/bin/bash
# Tsunami Beta - Data Completion Script
# Generated by data_completeness_analyzer.py

set -e

DOMAIN_BACKEND_API="${DOMAIN_BACKEND_API:-http://localhost:8001}"
LOG_FILE="data_completion_$(date +%Y%m%d_%H%M%S).log"

echo "Starting data completion process..." | tee -a "$LOG_FILE"
echo "Domain Backend API: $DOMAIN_BACKEND_API" | tee -a "$LOG_FILE"
echo "Log file: $LOG_FILE" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Function to execute API call with retry
execute_with_retry() {
    local command="$1"
    local description="$2"
    local max_retries=3
    local retry=0
    
    echo "[$description] Starting..." | tee -a "$LOG_FILE"
    
    while [ $retry -lt $max_retries ]; do
        if eval "$command"; then
            echo "[$description] Completed successfully" | tee -a "$LOG_FILE"
            return 0
        else
            retry=$((retry + 1))
            echo "[$description] Failed (attempt $retry/$max_retries)" | tee -a "$LOG_FILE"
            if [ $retry -lt $max_retries ]; then
                echo "[$description] Retrying in 5 seconds..." | tee -a "$LOG_FILE"
                sleep 5
            fi
        fi
    done
    
    echo "[$description] Failed after $max_retries attempts" | tee -a "$LOG_FILE"
    return 1
}

# Check domain-backend health
echo "Checking domain-backend health..." | tee -a "$LOG_FILE"
if ! curl -f "$DOMAIN_BACKEND_API/health" > /dev/null 2>&1; then
    echo "ERROR: Domain backend is not available at $DOMAIN_BACKEND_API" | tee -a "$LOG_FILE"
    exit 1
fi
echo "Domain backend is healthy" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

"""
        
        # Group tasks by priority
        critical_tasks = [gap for gap in self.data_gaps if gap.priority == TaskPriority.CRITICAL]
        high_tasks = [gap for gap in self.data_gaps if gap.priority == TaskPriority.HIGH]
        medium_tasks = [gap for gap in self.data_gaps if gap.priority == TaskPriority.MEDIUM]
        low_tasks = [gap for gap in self.data_gaps if gap.priority == TaskPriority.LOW]
        
        # Add tasks to script
        for priority_name, tasks in [("CRITICAL", critical_tasks), ("HIGH", high_tasks), 
                                   ("MEDIUM", medium_tasks), ("LOW", low_tasks)]:
            if not tasks:
                continue
                
            script_content += f"""
# {priority_name} PRIORITY TASKS
echo "=== Processing {priority_name} priority tasks ===" | tee -a "$LOG_FILE"
"""
            
            for i, gap in enumerate(tasks):
                task_id = f"{priority_name.lower()}_{i+1}"
                script_content += f"""
# Task: {gap.description}
execute_with_retry "{gap.completion_command}" "{gap.description}"
sleep 2

"""
        
        script_content += """
echo "" | tee -a "$LOG_FILE"
echo "Data completion process finished" | tee -a "$LOG_FILE"
echo "Check the log file for details: $LOG_FILE" | tee -a "$LOG_FILE"
"""
        
        # Write script file
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        # Make script executable
        os.chmod(script_path, 0o755)
        
        return script_path

    def get_completeness_statistics(self) -> Dict[str, Any]:
        """Get detailed completeness statistics"""
        stats = {}
        
        with self.driver.session() as session:
            try:
                # Domain completeness statistics
                domain_stats = {}
                
                # Total domains
                total_domains_result = session.run("MATCH (d:Domain) RETURN count(d) as total")
                total_domains_record = total_domains_result.single()
                total_domains = total_domains_record["total"] if total_domains_record else 0
                domain_stats['total'] = total_domains
                
                if total_domains > 0:
                    # Domains with subdomains
                    subdomains_query = """
                    MATCH (d:Domain)
                    WHERE NOT d.fqdn CONTAINS '.' OR d.fqdn =~ '[^.]+\\.cl'
                    OPTIONAL MATCH (sub:Domain) 
                    WHERE sub.fqdn CONTAINS d.fqdn AND sub.fqdn <> d.fqdn
                    WITH d, count(sub) as sub_count
                    RETURN count(CASE WHEN sub_count > 0 THEN 1 END) as with_subs,
                           count(d) as base_domains
                    """
                    result = session.run(subdomains_query)
                    record = result.single()
                    if record:
                        domain_stats['base_domains'] = record['base_domains']
                        domain_stats['base_with_subdomains'] = record['with_subs']
                        domain_stats['subdomain_coverage'] = round((record['with_subs'] / record['base_domains']) * 100, 1) if record['base_domains'] > 0 else 0
                    
                    # Domains with DNS data
                    dns_query = """
                    MATCH (d:Domain)
                    WITH count(d) as total,
                         count(CASE WHEN EXISTS {(d)-[:RESOLVES_TO]->(:DNSServer)} THEN 1 END) as with_dns
                    RETURN total, with_dns, (with_dns * 100.0 / total) as coverage_pct
                    """
                    result = session.run(dns_query)
                    record = result.single()
                    if record:
                        domain_stats['dns_coverage'] = {
                            'total': record['total'],
                            'with_dns': record['with_dns'],
                            'coverage_percent': round(record['coverage_pct'], 1)
                        }
                    
                    # Domains with certificates
                    cert_query = """
                    MATCH (d:Domain)
                    WITH count(d) as total,
                         count(CASE WHEN EXISTS {(d)-[:SECURED_BY]->(:Certificate)} THEN 1 END) as with_certs
                    RETURN total, with_certs, (with_certs * 100.0 / total) as coverage_pct
                    """
                    result = session.run(cert_query)
                    record = result.single()
                    if record:
                        domain_stats['certificate_coverage'] = {
                            'total': record['total'],
                            'with_certificates': record['with_certs'],
                            'coverage_percent': round(record['coverage_pct'], 1)
                        }
                    
                    # Domains with technology data
                    tech_query = """
                    MATCH (d:Domain)
                    WITH count(d) as total,
                         count(CASE WHEN EXISTS {(d)-[:USES_TECH]->(:Technology)} THEN 1 END) as with_tech
                    RETURN total, with_tech, (with_tech * 100.0 / total) as coverage_pct
                    """
                    result = session.run(tech_query)
                    record = result.single()
                    if record:
                        domain_stats['technology_coverage'] = {
                            'total': record['total'],
                            'with_technology': record['with_tech'],
                            'coverage_percent': round(record['coverage_pct'], 1)
                        }
                
                # Service and Provider statistics
                service_stats = {}
                
                # Services without providers
                service_provider_query = """
                MATCH (s:Service)
                WITH count(s) as total,
                     count(CASE WHEN EXISTS {(s)<-[:PROVIDES]-(:Provider)} THEN 1 END) as with_provider
                RETURN total, with_provider, (with_provider * 100.0 / total) as coverage_pct
                """
                result = session.run(service_provider_query)
                record = result.single()
                if record:
                    service_stats['provider_linkage'] = {
                        'total_services': record['total'],
                        'with_provider': record['with_provider'],
                        'coverage_percent': round(record['coverage_pct'], 1)
                    }
                
                # Top missing data types
                missing_data_priority = []
                if domain_stats.get('dns_coverage', {}).get('coverage_percent', 0) < 100:
                    missing_data_priority.append({
                        'type': 'DNS Resolution',
                        'missing_count': domain_stats['dns_coverage']['total'] - domain_stats['dns_coverage']['with_dns'],
                        'coverage_percent': domain_stats['dns_coverage']['coverage_percent']
                    })
                
                if domain_stats.get('certificate_coverage', {}).get('coverage_percent', 0) < 100:
                    missing_data_priority.append({
                        'type': 'SSL Certificates', 
                        'missing_count': domain_stats['certificate_coverage']['total'] - domain_stats['certificate_coverage']['with_certificates'],
                        'coverage_percent': domain_stats['certificate_coverage']['coverage_percent']
                    })
                
                if service_stats.get('provider_linkage', {}).get('coverage_percent', 0) < 100:
                    missing_data_priority.append({
                        'type': 'Service-Provider Links',
                        'missing_count': service_stats['provider_linkage']['total_services'] - service_stats['provider_linkage']['with_provider'],
                        'coverage_percent': service_stats['provider_linkage']['coverage_percent']
                    })
                
                # Sort by missing count descending
                missing_data_priority.sort(key=lambda x: x['missing_count'], reverse=True)
                
                stats = {
                    'domain_statistics': domain_stats,
                    'service_statistics': service_stats,
                    'top_missing_data': missing_data_priority
                }
                
            except Exception as e:
                logger.error(f"Error getting completeness statistics: {e}")
                stats = {'error': str(e)}
        
        return stats

    def run_analysis(self) -> CompletenessReport:
        """Run complete data completeness analysis"""
        logger.info("Starting data completeness analysis...")
        self.data_gaps.clear()
        
        # Get statistics first
        stats = self.get_completeness_statistics()
        
        logger.info("=" * 60)
        logger.info("DATA COMPLETENESS STATISTICS")
        logger.info("=" * 60)
        
        # Domain statistics
        domain_stats = stats.get('domain_statistics', {})
        logger.info(f"📊 Total Domains: {domain_stats.get('total', 0):,}")
        
        if 'base_domains' in domain_stats:
            logger.info(f"🏠 Base Domains: {domain_stats['base_domains']:,}")
            logger.info(f"🌳 With Subdomains: {domain_stats['base_with_subdomains']:,} ({domain_stats['subdomain_coverage']}%)")
        
        # Coverage statistics
        logger.info("\n📋 DATA COVERAGE:")
        
        if 'dns_coverage' in domain_stats:
            dns_cov = domain_stats['dns_coverage']
            status = "✅" if dns_cov['coverage_percent'] > 80 else "⚠️" if dns_cov['coverage_percent'] > 50 else "❌"
            logger.info(f"  {status} DNS Resolution: {dns_cov['with_dns']}/{dns_cov['total']} ({dns_cov['coverage_percent']}%)")
        
        if 'certificate_coverage' in domain_stats:
            cert_cov = domain_stats['certificate_coverage']
            status = "✅" if cert_cov['coverage_percent'] > 80 else "⚠️" if cert_cov['coverage_percent'] > 50 else "❌"
            logger.info(f"  {status} SSL Certificates: {cert_cov['with_certificates']}/{cert_cov['total']} ({cert_cov['coverage_percent']}%)")
        
        if 'technology_coverage' in domain_stats:
            tech_cov = domain_stats['technology_coverage']
            status = "✅" if tech_cov['coverage_percent'] > 80 else "⚠️" if tech_cov['coverage_percent'] > 50 else "❌"
            logger.info(f"  {status} Technology Detection: {tech_cov['with_technology']}/{tech_cov['total']} ({tech_cov['coverage_percent']}%)")
        
        # Service statistics
        service_stats = stats.get('service_statistics', {})
        if 'provider_linkage' in service_stats:
            provider_link = service_stats['provider_linkage']
            status = "✅" if provider_link['coverage_percent'] > 80 else "⚠️" if provider_link['coverage_percent'] > 50 else "❌"
            logger.info(f"  {status} Service-Provider Links: {provider_link['with_provider']}/{provider_link['total_services']} ({provider_link['coverage_percent']}%)")
        
        # Top missing data
        top_missing = stats.get('top_missing_data', [])
        if top_missing:
            logger.info("\n🚨 TOP MISSING DATA TYPES:")
            for i, missing in enumerate(top_missing[:5], 1):
                logger.info(f"  {i}. {missing['type']}: {missing['missing_count']:,} missing ({100-missing['coverage_percent']:.1f}% incomplete)")
        
        logger.info("=" * 60)
        logger.info("GAP ANALYSIS")
        logger.info("=" * 60)
        
        try:
            # Run all gap analyses
            self.analyze_subdomain_gaps()
            self.analyze_dns_gaps()
            self.analyze_certificate_gaps()
            self.analyze_technology_gaps()
            self.analyze_service_gaps()
            self.analyze_risk_gaps()
            self.analyze_provider_gaps()
            self.analyze_vulnerability_gaps()
            
            # Calculate statistics
            total_domains = self.get_domain_count()
            critical_gaps = sum(1 for gap in self.data_gaps if gap.priority == TaskPriority.CRITICAL)
            high_gaps = sum(1 for gap in self.data_gaps if gap.priority == TaskPriority.HIGH)
            medium_gaps = sum(1 for gap in self.data_gaps if gap.priority == TaskPriority.MEDIUM)
            low_gaps = sum(1 for gap in self.data_gaps if gap.priority == TaskPriority.LOW)
            
            gaps_by_type = {}
            total_time = 0
            for gap in self.data_gaps:
                gaps_by_type[gap.data_type.value] = gaps_by_type.get(gap.data_type.value, 0) + 1
                total_time += gap.estimated_time_minutes
            
            report = CompletenessReport(
                timestamp=datetime.now(),
                total_domains=total_domains,
                total_gaps=len(self.data_gaps),
                critical_gaps=critical_gaps,
                high_priority_gaps=high_gaps,
                gaps_by_type=gaps_by_type,
                completion_estimate_hours=total_time / 60.0,
                data_gaps=self.data_gaps.copy()
            )
            
            # Add statistics to report
            report.completeness_statistics = stats
            
            logger.info("=" * 60)
            logger.info("ANALYSIS SUMMARY")
            logger.info("=" * 60)
            logger.info(f"🔍 Total Gaps Found: {len(self.data_gaps)}")
            logger.info(f"🔴 Critical: {critical_gaps}")
            logger.info(f"🟠 High: {high_gaps}")
            logger.info(f"🟡 Medium: {medium_gaps}")
            logger.info(f"🟢 Low: {low_gaps}")
            logger.info(f"⏱️  Estimated Completion Time: {total_time/60:.1f} hours")
            
            # Completion priority
            if critical_gaps > 0:
                logger.info("🚨 RECOMMENDATION: Address critical gaps immediately")
            elif high_gaps > 0:
                logger.info("⚠️ RECOMMENDATION: Address high priority gaps soon")
            else:
                logger.info("✅ RECOMMENDATION: Current data quality is acceptable")
            
            return report
            
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            raise

def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze Tsunami Beta data completeness')
    parser.add_argument('--neo4j-uri', default='bolt://localhost:7687', help='Neo4j URI')
    parser.add_argument('--neo4j-user', default='neo4j', help='Neo4j username')
    parser.add_argument('--neo4j-password', default='neo4j', help='Neo4j password')
    parser.add_argument('--domain-backend', default='http://localhost:8001', help='Domain backend API URL')
    parser.add_argument('--output', '-o', help='Output file for completeness report (JSON)')
    parser.add_argument('--generate-script', '-s', help='Generate completion script in directory')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        analyzer = DataCompletenessAnalyzer(args.neo4j_uri, args.neo4j_user, args.neo4j_password)
        analyzer.domain_backend_api = args.domain_backend
        
        report = analyzer.run_analysis()
        
        # Generate completion script if requested
        if args.generate_script:
            script_path = analyzer.generate_completion_script(args.generate_script)
            print(f"Completion script generated: {script_path}")
        
        analyzer.close()
        
        # Output report
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report.to_dict(), f, indent=2)
            print(f"Completeness report saved to {args.output}")
        else:
            print(json.dumps(report.to_dict(), indent=2))
        
        return 0
        
    except Exception as e:
        logger.error(f"Failed to run analysis: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())