#!/usr/bin/env python3
"""
Batch Domain Processor - Executes subdomain_relationship_discovery_v4.py for each domain individually
"""

import subprocess
import sys
import time
import argparse
import os
from datetime import datetime

def run_domain_analysis(domain, password, **kwargs):
    """Run analysis for a single domain"""
    
    # Create temporary file with single domain
    temp_file = f"temp_domain_{int(time.time())}.txt"
    try:
        with open(temp_file, 'w') as f:
            f.write(domain + '\n')
        
        # Build command
        cmd = [
            'python3', 'subdomain_relationship_discovery_v4.py',
            '--domains', temp_file,
            '--password', password
        ]
        
        # Add ipinfo token if provided
        if kwargs.get('ipinfo_token'):
            cmd.extend(['--ipinfo-token', kwargs['ipinfo_token']])
        
        # Add optional parameters
        if kwargs.get('tls_timeout'):
            cmd.extend(['--tls-timeout', str(kwargs['tls_timeout'])])
        if kwargs.get('tls_retries'):
            cmd.extend(['--tls-retries', str(kwargs['tls_retries'])])
        if kwargs.get('discovery_depth'):
            cmd.extend(['--discovery-depth', str(kwargs['discovery_depth'])])
        if kwargs.get('amass_timeout'):
            cmd.extend(['--amass-timeout', str(kwargs['amass_timeout'])])
        if kwargs.get('discovery_workers'):
            cmd.extend(['--discovery-workers', str(kwargs['discovery_workers'])])
        if kwargs.get('processing_workers'):
            cmd.extend(['--processing-workers', str(kwargs['processing_workers'])])
        if kwargs.get('batch_size'):
            cmd.extend(['--batch-size', str(kwargs['batch_size'])])
        
        # Feature flags
        if kwargs.get('enable_tls', True):
            cmd.append('--enable-tls')
        if kwargs.get('enable_services', True):
            cmd.append('--enable-services')
        if kwargs.get('enable_providers', True):
            cmd.append('--enable-providers')
        if kwargs.get('enable_industry', True):
            cmd.append('--enable-industry')
        
        # Phase control
        if kwargs.get('phase1_only'):
            cmd.append('--phase1-only')
        elif kwargs.get('phase2_only'):
            cmd.append('--phase2-only')
        
        print(f"🚀 Processing domain: {domain}")
        print(f"📝 Command: {' '.join(cmd)}")
        
        start_time = time.time()
        
        # Execute command
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=kwargs.get('timeout', 3600))
        
        duration = time.time() - start_time
        
        if result.returncode == 0:
            print(f"✅ {domain} completed successfully in {duration:.1f}s")
            return True, duration, result.stdout, result.stderr
        else:
            print(f"❌ {domain} failed with exit code {result.returncode}")
            print(f"Error: {result.stderr}")
            return False, duration, result.stdout, result.stderr
            
    except subprocess.TimeoutExpired:
        print(f"⏰ {domain} timed out after {kwargs.get('timeout', 3600)}s")
        return False, kwargs.get('timeout', 3600), "", "Timeout"
    except Exception as e:
        print(f"💥 {domain} failed with exception: {e}")
        return False, 0, "", str(e)
    finally:
        # Clean up temporary file
        if os.path.exists(temp_file):
            os.remove(temp_file)

def main():
    parser = argparse.ArgumentParser(description='Batch process domains individually')
    
    # Required parameters
    parser.add_argument('--domains', required=True, help='File with list of domains')
    parser.add_argument('--password', required=True, help='Neo4j password')
    parser.add_argument('--ipinfo-token', help='IPInfo token for geolocation data')
    
    # Processing parameters
    parser.add_argument('--tls-timeout', type=int, default=60, help='TLS timeout (default: 60s)')
    parser.add_argument('--tls-retries', type=int, default=3, help='TLS retries (default: 3)')
    parser.add_argument('--discovery-depth', type=int, default=2, help='Discovery depth (default: 2)')
    parser.add_argument('--amass-timeout', type=int, default=120, help='Amass timeout (default: 120s)')
    parser.add_argument('--discovery-workers', type=int, default=1, help='Discovery workers (default: 1)')
    parser.add_argument('--processing-workers', type=int, default=1, help='Processing workers (default: 1)')
    parser.add_argument('--batch-size', type=int, default=20, help='Batch size (default: 20)')
    parser.add_argument('--timeout', type=int, default=3600, help='Per-domain timeout (default: 3600s)')
    
    # Feature flags
    parser.add_argument('--disable-tls', action='store_true', help='Disable TLS analysis')
    parser.add_argument('--disable-services', action='store_true', help='Disable service detection')
    parser.add_argument('--disable-providers', action='store_true', help='Disable provider detection')
    parser.add_argument('--disable-industry', action='store_true', help='Disable industry classification')
    
    # Phase control
    parser.add_argument('--phase1-only', action='store_true', help='Run only discovery phase')
    parser.add_argument('--phase2-only', action='store_true', help='Run only processing phase')
    
    # Execution control
    parser.add_argument('--continue-on-error', action='store_true', help='Continue processing other domains if one fails')
    parser.add_argument('--delay', type=int, default=5, help='Delay between domains in seconds (default: 5)')
    parser.add_argument('--start-from', type=int, default=0, help='Start from domain N (0-indexed)')
    parser.add_argument('--max-domains', type=int, help='Process maximum N domains')
    
    args = parser.parse_args()
    
    # Read domains
    try:
        with open(args.domains, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"❌ Domain file not found: {args.domains}")
        sys.exit(1)
    
    if not domains:
        print(f"❌ No domains found in file: {args.domains}")
        sys.exit(1)
    
    # Apply start_from and max_domains filters
    if args.start_from > 0:
        domains = domains[args.start_from:]
        print(f"📍 Starting from domain #{args.start_from}")
    
    if args.max_domains:
        domains = domains[:args.max_domains]
        print(f"📊 Processing maximum {args.max_domains} domains")
    
    print(f"\n🎯 BATCH PROCESSING: {len(domains)} domains")
    print(f"⏱️ Per-domain timeout: {args.timeout}s")
    print(f"⏳ Delay between domains: {args.delay}s")
    print("=" * 60)
    
    # Prepare kwargs for domain processing
    kwargs = {
        'ipinfo_token': args.ipinfo_token,
        'tls_timeout': args.tls_timeout,
        'tls_retries': args.tls_retries,
        'discovery_depth': args.discovery_depth,
        'amass_timeout': args.amass_timeout,
        'discovery_workers': args.discovery_workers,
        'processing_workers': args.processing_workers,
        'batch_size': args.batch_size,
        'timeout': args.timeout,
        'enable_tls': not args.disable_tls,
        'enable_services': not args.disable_services,
        'enable_providers': not args.disable_providers,
        'enable_industry': not args.disable_industry,
        'phase1_only': args.phase1_only,
        'phase2_only': args.phase2_only
    }
    
    # Process domains
    start_time = datetime.now()
    successful = 0
    failed = 0
    total_processing_time = 0
    
    for i, domain in enumerate(domains):
        print(f"\n📍 [{i+1}/{len(domains)}] Processing: {domain}")
        print("-" * 40)
        
        success, duration, stdout, stderr = run_domain_analysis(domain, args.password, **kwargs)
        
        total_processing_time += duration
        
        if success:
            successful += 1
        else:
            failed += 1
            if not args.continue_on_error:
                print(f"\n💥 Stopping execution due to failure on {domain}")
                break
        
        # Delay between domains (except for the last one)
        if i < len(domains) - 1 and args.delay > 0:
            print(f"⏳ Waiting {args.delay}s before next domain...")
            time.sleep(args.delay)
    
    # Final statistics
    end_time = datetime.now()
    total_elapsed = (end_time - start_time).total_seconds()
    
    print(f"\n📊 BATCH PROCESSING COMPLETE")
    print("=" * 60)
    print(f"✅ Successful: {successful}")
    print(f"❌ Failed: {failed}")
    print(f"📈 Success rate: {successful}/{successful + failed} ({100 * successful / (successful + failed) if (successful + failed) > 0 else 0:.1f}%)")
    print(f"⏱️ Total time: {total_elapsed:.1f}s ({total_elapsed/60:.1f} min)")
    print(f"⚡ Avg per domain: {total_processing_time/len(domains):.1f}s")
    print(f"🕐 Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🏁 Finished: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Exit with appropriate code
    sys.exit(0 if failed == 0 else 1)

if __name__ == "__main__":
    main()