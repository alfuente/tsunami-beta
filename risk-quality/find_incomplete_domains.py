#!/usr/bin/env python3
"""
find_incomplete_domains.py - Find domains without subdomains or providers

Analyzes the Neo4j graph to identify base domains that lack:
1. Subdomain discovery (no HAS_SUBDOMAIN relationships)
2. Provider relationships (no USES_PROVIDER relationships)

Generates a comprehensive script with domain-backend API calls to complete missing data.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass
import sys
import os
import argparse

try:
    from neo4j import GraphDatabase
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False
    print("Error: Neo4j driver not available. Run: pip install neo4j")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class IncompleteDomain:
    domain: str
    missing_subdomains: bool
    missing_providers: bool
    subdomain_count: int
    provider_count: int
    has_dns: bool
    has_tls: bool
    has_tech: bool
    has_services: bool
    organization: Optional[str] = None
    sector: Optional[str] = None

@dataclass
class CompletionScript:
    domain: str
    api_calls: List[str]
    estimated_time_minutes: int
    priority: str

class IncompleteDomainAnalyzer:
    """Analyzes domains for missing subdomain and provider data"""
    
    def __init__(self, neo4j_uri="bolt://localhost:7687", 
                 neo4j_user="neo4j", neo4j_password="neo4j"):
        if not HAS_NEO4J:
            raise ImportError("Neo4j driver is required")
        
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.domain_backend_api = "http://localhost:8001"

    def close(self):
        if hasattr(self, 'driver'):
            self.driver.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def run_query(self, query: str, parameters: Dict = None) -> List[Dict]:
        """Execute a Neo4j query and return results"""
        try:
            with self.driver.session() as session:
                result = session.run(query, parameters or {})
                return list(result)
        except Exception as e:
            logger.error(f"Query failed: {e}")
            return []

    def find_incomplete_domains(self) -> List[IncompleteDomain]:
        """Find domains that are missing subdomain or provider data"""
        logger.info("Analyzing domains for missing data...")
        
        # Query to find domains and their relationships
        query = """
        MATCH (d:Domain)
        OPTIONAL MATCH (o:Organization)-[:OWNS]->(d)
        OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(sub:Subdomain)
        OPTIONAL MATCH (d)-[:USES_PROVIDER]->(prov:Provider)
        
        WITH d, o,
             count(DISTINCT sub) as subdomain_count,
             count(DISTINCT prov) as provider_count,
             d.has_dns IS NOT NULL as has_dns,
             d.has_tls IS NOT NULL OR d.tls_analyzed_at IS NOT NULL as has_tls,
             d.technologies IS NOT NULL OR d.tech_analyzed_at IS NOT NULL as has_tech,
             d.services_count IS NOT NULL OR d.services_analyzed_at IS NOT NULL as has_services
        
        WHERE subdomain_count = 0 OR provider_count = 0
        
        RETURN d.domain as domain,
               d.fqdn as fqdn,
               o.name as organization,
               o.sector as sector,
               subdomain_count,
               provider_count,
               has_dns,
               has_tls,
               has_tech,
               has_services,
               d.discovered_at as discovered_at,
               d.updated_at as updated_at
        
        ORDER BY subdomain_count ASC, provider_count ASC, d.domain
        """
        
        results = self.run_query(query)
        incomplete_domains = []
        
        for record in results:
            domain_name = record.get('domain') or record.get('fqdn', '')
            if not domain_name:
                continue
            
            subdomain_count = record.get('subdomain_count', 0)
            provider_count = record.get('provider_count', 0)
            
            # Determine what's missing
            missing_subdomains = subdomain_count == 0
            missing_providers = provider_count == 0
            
            incomplete_domain = IncompleteDomain(
                domain=domain_name,
                missing_subdomains=missing_subdomains,
                missing_providers=missing_providers,
                subdomain_count=subdomain_count,
                provider_count=provider_count,
                has_dns=record.get('has_dns', False),
                has_tls=record.get('has_tls', False),
                has_tech=record.get('has_tech', False),
                has_services=record.get('has_services', False),
                organization=record.get('organization'),
                sector=record.get('sector')
            )
            
            incomplete_domains.append(incomplete_domain)
        
        logger.info(f"Found {len(incomplete_domains)} incomplete domains")
        return incomplete_domains

    def analyze_missing_data_patterns(self, domains: List[IncompleteDomain]) -> Dict[str, Any]:
        """Analyze patterns in missing data"""
        total_domains = len(domains)
        
        missing_subdomains_count = sum(1 for d in domains if d.missing_subdomains)
        missing_providers_count = sum(1 for d in domains if d.missing_providers)
        missing_both_count = sum(1 for d in domains if d.missing_subdomains and d.missing_providers)
        
        # Analysis by sector
        sector_analysis = {}
        for domain in domains:
            sector = domain.sector or 'unknown'
            if sector not in sector_analysis:
                sector_analysis[sector] = {
                    'total': 0,
                    'missing_subdomains': 0,
                    'missing_providers': 0,
                    'missing_both': 0
                }
            
            sector_analysis[sector]['total'] += 1
            if domain.missing_subdomains:
                sector_analysis[sector]['missing_subdomains'] += 1
            if domain.missing_providers:
                sector_analysis[sector]['missing_providers'] += 1
            if domain.missing_subdomains and domain.missing_providers:
                sector_analysis[sector]['missing_both'] += 1
        
        # Analysis by other missing data
        missing_dns = sum(1 for d in domains if not d.has_dns)
        missing_tls = sum(1 for d in domains if not d.has_tls)
        missing_tech = sum(1 for d in domains if not d.has_tech)
        missing_services = sum(1 for d in domains if not d.has_services)
        
        return {
            'total_incomplete_domains': total_domains,
            'missing_subdomains_count': missing_subdomains_count,
            'missing_providers_count': missing_providers_count,
            'missing_both_count': missing_both_count,
            'missing_dns': missing_dns,
            'missing_tls': missing_tls,
            'missing_tech': missing_tech,
            'missing_services': missing_services,
            'sector_analysis': sector_analysis,
            'completion_priorities': self._calculate_completion_priorities(domains)
        }

    def _calculate_completion_priorities(self, domains: List[IncompleteDomain]) -> Dict[str, List[str]]:
        """Calculate completion priorities for domains"""
        priorities = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for domain in domains:
            # Critical: Missing both subdomains and providers
            if domain.missing_subdomains and domain.missing_providers:
                priorities['critical'].append(domain.domain)
            # High: Missing subdomains (usually more important)
            elif domain.missing_subdomains:
                priorities['high'].append(domain.domain)
            # Medium: Missing providers only
            elif domain.missing_providers:
                priorities['medium'].append(domain.domain)
            else:
                priorities['low'].append(domain.domain)
        
        return priorities

    def generate_completion_scripts(self, domains: List[IncompleteDomain]) -> List[CompletionScript]:
        """Generate API call scripts to complete missing data"""
        logger.info("Generating completion scripts...")
        
        scripts = []
        
        for domain in domains:
            api_calls = []
            estimated_time = 0
            
            # Determine priority
            if domain.missing_subdomains and domain.missing_providers:
                priority = "critical"
            elif domain.missing_subdomains:
                priority = "high"
            elif domain.missing_providers:
                priority = "medium"
            else:
                priority = "low"
            
            # 1. Subdomain discovery (if missing)
            if domain.missing_subdomains:
                api_calls.append(
                    f"curl -X 'POST' '{self.domain_backend_api}/api/v1/discover/amass/{domain.domain}' "
                    f"-H 'accept: application/json' -d ''"
                )
                estimated_time += 30  # Amass takes longer
            
            # 2. DNS analysis (if missing and we have subdomains or will discover them)
            if not domain.has_dns:
                api_calls.append(
                    f"curl -X 'POST' '{self.domain_backend_api}/api/v1/discover/dns/{domain.domain}' "
                    f"-H 'accept: application/json' -d ''"
                )
                estimated_time += 2
            
            # 3. TLS analysis (if missing)
            if not domain.has_tls:
                api_calls.append(
                    f"curl -X 'POST' '{self.domain_backend_api}/api/v1/discover/tls/{domain.domain}' "
                    f"-H 'accept: application/json' -d ''"
                )
                estimated_time += 3
            
            # 4. Technology analysis (if missing)
            if not domain.has_tech:
                api_calls.append(
                    f"curl -X 'POST' '{self.domain_backend_api}/api/v1/discover/tech/{domain.domain}' "
                    f"-H 'accept: application/json' -d ''"
                )
                estimated_time += 5
            
            # 5. Service discovery (if missing)
            if not domain.has_services:
                api_calls.append(
                    f"curl -X 'POST' '{self.domain_backend_api}/api/v1/discover/services/{domain.domain}' "
                    f"-H 'accept: application/json' -d ''"
                )
                estimated_time += 4
            
            # 6. Web scraping for additional relationships
            api_calls.append(
                f"curl -X 'POST' '{self.domain_backend_api}/api/v1/discover/web-scraping/{domain.domain}' "
                f"-H 'accept: application/json' -d ''"
            )
            estimated_time += 8
            
            # 7. Risk calculation (after data collection)
            api_calls.append(
                f"curl -X 'POST' '{self.domain_backend_api}/api/v1/calculate/risk/{domain.domain}' "
                f"-H 'accept: application/json' -d ''"
            )
            estimated_time += 2
            
            if api_calls:
                script = CompletionScript(
                    domain=domain.domain,
                    api_calls=api_calls,
                    estimated_time_minutes=estimated_time,
                    priority=priority
                )
                scripts.append(script)
        
        return scripts

    def export_analysis_report(self, domains: List[IncompleteDomain], 
                             analysis: Dict[str, Any], output_file: str) -> None:
        """Export comprehensive analysis report"""
        logger.info(f"Exporting analysis report to {output_file}")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'analysis_summary': analysis,
            'incomplete_domains': [
                {
                    'domain': d.domain,
                    'missing_subdomains': d.missing_subdomains,
                    'missing_providers': d.missing_providers,
                    'subdomain_count': d.subdomain_count,
                    'provider_count': d.provider_count,
                    'has_dns': d.has_dns,
                    'has_tls': d.has_tls,
                    'has_tech': d.has_tech,
                    'has_services': d.has_services,
                    'organization': d.organization,
                    'sector': d.sector
                }
                for d in domains
            ]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Analysis report saved to {output_file}")

    def export_completion_scripts(self, scripts: List[CompletionScript], 
                                 output_dir: str = ".") -> Dict[str, str]:
        """Export completion scripts organized by priority"""
        logger.info(f"Exporting completion scripts to {output_dir}")
        
        # Group scripts by priority
        scripts_by_priority = {}
        for script in scripts:
            priority = script.priority
            if priority not in scripts_by_priority:
                scripts_by_priority[priority] = []
            scripts_by_priority[priority].append(script)
        
        output_files = {}
        
        for priority, priority_scripts in scripts_by_priority.items():
            script_file = os.path.join(output_dir, f"complete_domains_{priority}.sh")
            
            with open(script_file, 'w', encoding='utf-8') as f:
                f.write("#!/bin/bash\n")
                f.write(f"# Domain completion script - {priority.upper()} priority\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n")
                f.write(f"# Total domains: {len(priority_scripts)}\n")
                f.write(f"# Estimated time: {sum(s.estimated_time_minutes for s in priority_scripts)} minutes\n\n")
                
                f.write("set -e  # Exit on error\n")
                f.write("set -u  # Exit on undefined variable\n\n")
                
                f.write("# Configuration\n")
                f.write(f"API_BASE=\"{self.domain_backend_api}\"\n")
                f.write("DELAY_BETWEEN_CALLS=2  # seconds\n")
                f.write("MAX_RETRIES=3\n")
                f.write("TIMEOUT=30  # seconds\n\n")
                
                f.write("# Logging function\n")
                f.write("log() {\n")
                f.write("    echo \"[$(date '+%Y-%m-%d %H:%M:%S')] $1\"\n")
                f.write("}\n\n")
                
                f.write("# Retry function\n")
                f.write("retry_curl() {\n")
                f.write("    local url=\"$1\"\n")
                f.write("    local retries=0\n")
                f.write("    \n")
                f.write("    while [ $retries -lt $MAX_RETRIES ]; do\n")
                f.write("        log \"Attempting: $url (attempt $((retries+1))/$MAX_RETRIES)\"\n")
                f.write("        \n")
                f.write("        if curl -s -X POST --max-time $TIMEOUT -H 'accept: application/json' -d '' \"$url\"; then\n")
                f.write("            log \"Success: $url\"\n")
                f.write("            sleep 1  # Brief pause after successful call\n")
                f.write("            return 0\n")
                f.write("        else\n")
                f.write("            log \"Failed: $url (attempt $((retries+1)))\"\n")
                f.write("            retries=$((retries+1))\n")
                f.write("            sleep $((DELAY_BETWEEN_CALLS * retries))  # Exponential backoff\n")
                f.write("        fi\n")
                f.write("    done\n")
                f.write("    \n")
                f.write("    log \"ERROR: Failed all attempts for: $url\"\n")
                f.write("    return 1\n")
                f.write("}\n\n")
                
                f.write(f"log \"Starting {priority.upper()} priority domain completion\"\n")
                f.write(f"log \"Processing {len(priority_scripts)} domains\"\n\n")
                
                for i, script in enumerate(priority_scripts, 1):
                    f.write(f"# Domain {i}/{len(priority_scripts)}: {script.domain}\n")
                    f.write(f"log \"Processing domain {i}/{len(priority_scripts)}: {script.domain}\"\n")
                    f.write(f"log \"Estimated time: {script.estimated_time_minutes} minutes\"\n\n")
                    
                    for j, api_call in enumerate(script.api_calls, 1):
                        # Extract URL from curl command - the URL is in the second set of quotes (index 3)
                        url_parts = api_call.split("'")
                        if len(url_parts) >= 4:
                            url_part = url_parts[3]  # URL is the 4th element (index 3) 
                            try:
                                analysis_type = url_part.split('/')[-2] if len(url_part.split('/')) > 2 else 'analysis'
                            except:
                                analysis_type = 'analysis'
                        else:
                            # Fallback: try to extract URL from the command
                            url_start = api_call.find("http")
                            if url_start != -1:
                                url_end = api_call.find("'", url_start)
                                if url_end == -1:
                                    url_end = api_call.find(" ", url_start)
                                if url_end == -1:
                                    url_end = len(api_call)
                                url_part = api_call[url_start:url_end]
                                analysis_type = 'analysis'
                            else:
                                url_part = api_call
                                analysis_type = 'analysis'
                        
                        f.write(f"# Step {j}: {analysis_type} analysis\n")
                        f.write(f"retry_curl \"{url_part}\"\n")
                        f.write("sleep $DELAY_BETWEEN_CALLS\n\n")
                    
                    f.write(f"log \"Completed domain: {script.domain}\"\n")
                    f.write("echo \"---\"\n\n")
                
                f.write(f"log \"Completed {priority.upper()} priority domain completion\"\n")
            
            # Make script executable
            os.chmod(script_file, 0o755)
            output_files[priority] = script_file
            logger.info(f"Created {priority} priority script: {script_file}")
        
        return output_files

def main():
    parser = argparse.ArgumentParser(description="Find domains without subdomains or providers")
    parser.add_argument('--neo4j-uri', default='bolt://localhost:7687',
                       help='Neo4j URI (default: bolt://localhost:7687)')
    parser.add_argument('--neo4j-user', default='neo4j',
                       help='Neo4j username (default: neo4j)')
    parser.add_argument('--neo4j-password', default='neo4j',
                       help='Neo4j password (default: neo4j)')
    parser.add_argument('--domain-backend-api', default='http://localhost:8001',
                       help='Domain backend API URL (default: http://localhost:8001)')
    parser.add_argument('--output-dir', '-d', default='.',
                       help='Output directory for scripts (default: current directory)')
    parser.add_argument('--report-file', '-r', default='incomplete_domains_report.json',
                       help='Output file for analysis report')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        with IncompleteDomainAnalyzer(
            neo4j_uri=args.neo4j_uri,
            neo4j_user=args.neo4j_user,
            neo4j_password=args.neo4j_password
        ) as analyzer:
            
            # Set domain backend API URL
            analyzer.domain_backend_api = args.domain_backend_api
            
            # Find incomplete domains
            incomplete_domains = analyzer.find_incomplete_domains()
            
            if not incomplete_domains:
                logger.info("No incomplete domains found! All domains have subdomains and providers.")
                return
            
            # Analyze patterns
            analysis = analyzer.analyze_missing_data_patterns(incomplete_domains)
            
            # Generate completion scripts
            completion_scripts = analyzer.generate_completion_scripts(incomplete_domains)
            
            # Export analysis report
            analyzer.export_analysis_report(incomplete_domains, analysis, args.report_file)
            
            # Export completion scripts
            script_files = analyzer.export_completion_scripts(completion_scripts, args.output_dir)
            
            # Print summary
            print(f"\n{'='*80}")
            print("INCOMPLETE DOMAINS ANALYSIS SUMMARY")
            print(f"{'='*80}")
            print(f"Total incomplete domains: {analysis['total_incomplete_domains']}")
            print(f"Missing subdomains: {analysis['missing_subdomains_count']}")
            print(f"Missing providers: {analysis['missing_providers_count']}")
            print(f"Missing both: {analysis['missing_both_count']}")
            
            print(f"\nOther missing data:")
            print(f"Missing DNS: {analysis['missing_dns']}")
            print(f"Missing TLS: {analysis['missing_tls']}")
            print(f"Missing Tech: {analysis['missing_tech']}")
            print(f"Missing Services: {analysis['missing_services']}")
            
            print(f"\nCompletion priorities:")
            priorities = analysis['completion_priorities']
            for priority, domains in priorities.items():
                if domains:
                    print(f"  {priority.upper()}: {len(domains)} domains")
            
            print(f"\nGenerated files:")
            print(f"  Analysis report: {args.report_file}")
            for priority, script_file in script_files.items():
                print(f"  {priority.upper()} script: {script_file}")
            
            print(f"\nTo execute completion scripts:")
            for priority in ['critical', 'high', 'medium', 'low']:
                if priority in script_files:
                    print(f"  ./{os.path.basename(script_files[priority])}")
            
            print(f"{'='*80}")
    
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()