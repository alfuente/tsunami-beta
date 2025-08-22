#!/usr/bin/env python3
"""
Script maestro para la gestión completa del ciclo de dominios

Este script facilita el proceso completo de:
1. Extraer dominios base del grafo actual
2. Respaldar y limpiar la base de datos
3. Recargar dominios usando domain-backend para análisis fresco

Uso:
    python domain_management.py extract          # Solo extraer dominios
    python domain_management.py backup           # Solo respaldar
    python domain_management.py full-cycle      # Proceso completo
    python domain_management.py reload          # Solo recargar desde archivo
"""

import sys
import os
import subprocess
import json
import argparse
import logging
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DomainManagementOrchestrator:
    def __init__(self, scripts_dir=None):
        """Initialize the orchestrator"""
        self.scripts_dir = scripts_dir or os.path.dirname(os.path.abspath(__file__))
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.working_dir = f"domain_cycle_{self.timestamp}"
        
        # Script paths
        self.extract_script = os.path.join(self.scripts_dir, "extract_base_domains.py")
        self.backup_script = os.path.join(self.scripts_dir, "backup_and_clean_graph.py")
        self.reload_script = os.path.join(self.scripts_dir, "reload_domains_via_api.py")
        
        # Verify scripts exist
        for script in [self.extract_script, self.backup_script, self.reload_script]:
            if not os.path.exists(script):
                raise FileNotFoundError(f"Required script not found: {script}")
    
    def create_working_directory(self):
        """Create working directory for this cycle"""
        os.makedirs(self.working_dir, exist_ok=True)
        logger.info(f"Working directory: {self.working_dir}")
        return self.working_dir
    
    def run_script(self, script_path, args=None, capture_output=True):
        """Run a script with arguments"""
        cmd = ["python", script_path]
        if args:
            cmd.extend(args)
        
        logger.info(f"Running: {' '.join(cmd)}")
        
        try:
            if capture_output:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                return result.stdout, result.stderr
            else:
                result = subprocess.run(cmd, check=True)
                return None, None
        except subprocess.CalledProcessError as e:
            logger.error(f"Script failed: {e}")
            if capture_output:
                logger.error(f"stdout: {e.stdout}")
                logger.error(f"stderr: {e.stderr}")
            raise
    
    def extract_domains(self):
        """Extract domains from the current graph"""
        logger.info("🔍 Step 1: Extracting domains from Neo4j graph...")
        
        extraction_dir = os.path.join(self.working_dir, "extraction")
        
        try:
            stdout, stderr = self.run_script(self.extract_script, capture_output=False)
            
            # Find the generated extraction directory
            extraction_dirs = [d for d in os.listdir('.') if d.startswith('domain_extraction_')]
            if extraction_dirs:
                latest_extraction = max(extraction_dirs)
                # Move to our working directory
                if os.path.exists(latest_extraction):
                    import shutil
                    shutil.move(latest_extraction, extraction_dir)
                    logger.info(f"✅ Extraction completed: {extraction_dir}")
                    
                    # Return path to the domains list file
                    domains_file = os.path.join(extraction_dir, "base_domains_list.json")
                    if os.path.exists(domains_file):
                        return domains_file
            
            raise FileNotFoundError("Extraction output not found")
            
        except Exception as e:
            logger.error(f"❌ Domain extraction failed: {e}")
            raise
    
    def backup_and_clean(self, confirm=False):
        """Backup the graph and optionally clean it"""
        logger.info("💾 Step 2: Backing up and cleaning Neo4j graph...")
        
        backup_dir = os.path.join(self.working_dir, "backup")
        
        args = ["--output-dir", backup_dir]
        if confirm:
            args.extend(["--clean", "--confirm"])
        
        try:
            stdout, stderr = self.run_script(self.backup_script, args, capture_output=False)
            logger.info(f"✅ Backup completed: {backup_dir}")
            return backup_dir
            
        except Exception as e:
            logger.error(f"❌ Backup failed: {e}")
            raise
    
    def reload_domains(self, domains_file, api_url="http://localhost:8000", analysis_type="complete", 
                      max_concurrent=3, delay=5, limit=None):
        """Reload domains using the API"""
        logger.info("🚀 Step 3: Reloading domains via domain-backend API...")
        
        reload_dir = os.path.join(self.working_dir, "reload")
        os.makedirs(reload_dir, exist_ok=True)
        
        args = [
            domains_file,
            "--api-url", api_url,
            "--analysis-type", analysis_type,
            "--max-concurrent", str(max_concurrent),
            "--delay", str(delay),
            "--output-dir", reload_dir
        ]
        
        if limit:
            args.extend(["--limit", str(limit)])
        
        try:
            stdout, stderr = self.run_script(self.reload_script, args, capture_output=False)
            logger.info(f"✅ Reload completed: {reload_dir}")
            return reload_dir
            
        except Exception as e:
            logger.error(f"❌ Reload failed: {e}")
            raise
    
    def generate_report(self, extraction_dir=None, backup_dir=None, reload_dir=None):
        """Generate a comprehensive report of the cycle"""
        report = {
            "cycle_info": {
                "timestamp": self.timestamp,
                "working_directory": self.working_dir,
                "completed_steps": []
            }
        }
        
        if extraction_dir:
            report["cycle_info"]["completed_steps"].append("extraction")
            # Load extraction summary
            complete_export = os.path.join(extraction_dir, "complete_domain_export.json")
            if os.path.exists(complete_export):
                with open(complete_export, 'r') as f:
                    extraction_data = json.load(f)
                    report["extraction"] = extraction_data.get("extraction_info", {})
                    report["extraction"]["statistics"] = extraction_data.get("statistics", {})
        
        if backup_dir:
            report["cycle_info"]["completed_steps"].append("backup")
            # Load backup metadata
            backup_metadata = os.path.join(backup_dir, "backup_metadata.json")
            if os.path.exists(backup_metadata):
                with open(backup_metadata, 'r') as f:
                    backup_data = json.load(f)
                    report["backup"] = backup_data
        
        if reload_dir:
            report["cycle_info"]["completed_steps"].append("reload")
            # Find reload results file
            reload_files = [f for f in os.listdir(reload_dir) if f.startswith('reload_results_')]
            if reload_files:
                reload_file = os.path.join(reload_dir, reload_files[-1])  # Latest
                with open(reload_file, 'r') as f:
                    reload_data = json.load(f)
                    report["reload"] = reload_data.get("summary", {})
        
        # Save report
        report_file = os.path.join(self.working_dir, "cycle_report.json")
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        
        logger.info(f"📊 Cycle report saved: {report_file}")
        return report_file, report
    
    def full_cycle(self, api_url="http://localhost:8000", analysis_type="complete", 
                   max_concurrent=3, delay=5, limit=None, confirm_clean=False):
        """Execute the complete domain management cycle"""
        logger.info("🔄 Starting full domain management cycle...")
        
        self.create_working_directory()
        
        extraction_dir = None
        backup_dir = None
        reload_dir = None
        
        try:
            # Step 1: Extract domains
            domains_file = self.extract_domains()
            extraction_dir = os.path.dirname(domains_file)
            
            # Count domains
            with open(domains_file, 'r') as f:
                domains = json.load(f)
                domain_count = len(domains)
            
            logger.info(f"📊 Found {domain_count} domains to process")
            
            if limit and limit < domain_count:
                logger.info(f"⚠️  Limited to first {limit} domains for testing")
            
            # Step 2: Backup and clean
            backup_dir = self.backup_and_clean(confirm=confirm_clean)
            
            # Step 3: Reload domains
            reload_dir = self.reload_domains(
                domains_file, api_url, analysis_type, 
                max_concurrent, delay, limit
            )
            
            # Generate report
            report_file, report = self.generate_report(extraction_dir, backup_dir, reload_dir)
            
            # Print summary
            self.print_cycle_summary(report)
            
            return report_file
            
        except Exception as e:
            logger.error(f"❌ Full cycle failed: {e}")
            
            # Generate partial report
            if extraction_dir or backup_dir or reload_dir:
                report_file, report = self.generate_report(extraction_dir, backup_dir, reload_dir)
                logger.info(f"📊 Partial report saved: {report_file}")
            
            raise
    
    def print_cycle_summary(self, report):
        """Print a nice summary of the cycle"""
        print("\\n" + "="*70)
        print("DOMAIN MANAGEMENT CYCLE SUMMARY")
        print("="*70)
        print(f"📁 Working Directory: {self.working_dir}")
        print(f"⏰ Timestamp: {self.timestamp}")
        print(f"📋 Completed Steps: {', '.join(report['cycle_info']['completed_steps'])}")
        
        if 'extraction' in report:
            ext = report['extraction']
            print(f"\\n🔍 EXTRACTION:")
            print(f"   • Base domains: {ext.get('total_base_domains', 'N/A')}")
            print(f"   • Providers: {ext.get('total_providers', 'N/A')}")
            print(f"   • Services: {ext.get('total_services', 'N/A')}")
        
        if 'backup' in report:
            backup = report['backup']
            print(f"\\n💾 BACKUP:")
            print(f"   • Total nodes: {backup.get('statistics', {}).get('total_nodes', 'N/A')}")
            print(f"   • Total relationships: {backup.get('statistics', {}).get('total_relationships', 'N/A')}")
            print(f"   • Backup time: {backup.get('backup_timestamp', 'N/A')}")
        
        if 'reload' in report:
            reload = report['reload']
            print(f"\\n🚀 RELOAD:")
            print(f"   • Total domains: {reload.get('total_domains', 'N/A')}")
            print(f"   • Successful: {reload.get('successful', 'N/A')}")
            print(f"   • Failed: {reload.get('failed', 'N/A')}")
            print(f"   • Success rate: {reload.get('success_rate', 0):.1f}%")
            print(f"   • Total time: {reload.get('total_time_minutes', 0):.1f} minutes")
        
        print("\\n✅ Cycle completed successfully!")

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Domain Management Orchestrator')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Extract command
    extract_parser = subparsers.add_parser('extract', help='Extract domains from graph')
    
    # Backup command
    backup_parser = subparsers.add_parser('backup', help='Backup and optionally clean graph')
    backup_parser.add_argument('--clean', action='store_true', help='Clean database after backup')
    backup_parser.add_argument('--confirm', action='store_true', help='Confirm destructive operations')
    
    # Reload command
    reload_parser = subparsers.add_parser('reload', help='Reload domains from file')
    reload_parser.add_argument('domains_file', help='File containing domains to reload')
    reload_parser.add_argument('--api-url', default='http://localhost:8000', help='API URL')
    reload_parser.add_argument('--analysis-type', default='complete', help='Analysis type')
    reload_parser.add_argument('--max-concurrent', type=int, default=3, help='Max concurrent requests')
    reload_parser.add_argument('--delay', type=int, default=5, help='Delay between requests')
    reload_parser.add_argument('--limit', type=int, help='Limit domains for testing')
    
    # Full cycle command
    cycle_parser = subparsers.add_parser('full-cycle', help='Execute complete cycle')
    cycle_parser.add_argument('--api-url', default='http://localhost:8000', help='API URL')
    cycle_parser.add_argument('--analysis-type', default='complete', help='Analysis type')
    cycle_parser.add_argument('--max-concurrent', type=int, default=3, help='Max concurrent requests')
    cycle_parser.add_argument('--delay', type=int, default=5, help='Delay between requests')
    cycle_parser.add_argument('--limit', type=int, help='Limit domains for testing')
    cycle_parser.add_argument('--confirm-clean', action='store_true', help='Confirm database cleaning')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Initialize orchestrator
    try:
        orchestrator = DomainManagementOrchestrator()
    except FileNotFoundError as e:
        logger.error(f"Setup error: {e}")
        sys.exit(1)
    
    try:
        if args.command == 'extract':
            orchestrator.create_working_directory()
            domains_file = orchestrator.extract_domains()
            print(f"✅ Domains extracted to: {domains_file}")
            
        elif args.command == 'backup':
            orchestrator.create_working_directory()
            backup_dir = orchestrator.backup_and_clean(confirm=args.confirm and args.clean)
            print(f"✅ Backup completed: {backup_dir}")
            
        elif args.command == 'reload':
            if not os.path.exists(args.domains_file):
                logger.error(f"Domains file not found: {args.domains_file}")
                sys.exit(1)
            
            orchestrator.create_working_directory()
            reload_dir = orchestrator.reload_domains(
                args.domains_file, args.api_url, args.analysis_type,
                args.max_concurrent, args.delay, args.limit
            )
            print(f"✅ Reload completed: {reload_dir}")
            
        elif args.command == 'full-cycle':
            report_file = orchestrator.full_cycle(
                args.api_url, args.analysis_type, args.max_concurrent,
                args.delay, args.limit, args.confirm_clean
            )
            print(f"✅ Full cycle completed: {report_file}")
    
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Operation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()