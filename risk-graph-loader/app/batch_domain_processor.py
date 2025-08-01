#!/usr/bin/env python3
"""
Batch Domain Processor - Executes subdomain_relationship_discovery_v4.py for each domain individually
"""

import subprocess
import sys
import time
import argparse
import os
import logging
from datetime import datetime

def setup_debug_logging(log_file):
    """Setup debug logging configuration"""
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    
    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s'
    )
    
    # File handler for debug log
    file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)
    logger.addHandler(file_handler)
    
    # Console handler for info and above
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(detailed_formatter)
    logger.addHandler(console_handler)
    
    return logger

def run_domain_analysis(domain, password, logger=None, **kwargs):
    """Run analysis for a single domain with comprehensive logging"""
    
    if logger:
        logger.info(f"Starting domain analysis for: {domain}")
        logger.debug(f"Analysis parameters: {kwargs}")
    
    # Create temporary file with single domain
    temp_file = f"temp_domain_{int(time.time())}.txt"
    try:
        if logger:
            logger.debug(f"Creating temporary domain file: {temp_file}")
        with open(temp_file, 'w') as f:
            f.write(domain + '\n')
        if logger:
            logger.debug(f"Temporary file created successfully")
        
        # Build command
        cmd = [
            'python3', 'subdomain_relationship_discovery_v4.py',
            '--domains', temp_file,
            '--password', password
        ]
        
        if logger:
            logger.debug(f"Base command: {' '.join(cmd[:4])}...")
        
        # Add ipinfo token if provided
        if kwargs.get('ipinfo_token'):
            cmd.extend(['--ipinfo-token', kwargs['ipinfo_token']])
            if logger:
                logger.debug(f"Added IPInfo token parameter")
        
        # Add optional parameters
        if kwargs.get('tls_timeout'):
            cmd.extend(['--tls-timeout', str(kwargs['tls_timeout'])])
            if logger: logger.debug(f"TLS timeout: {kwargs['tls_timeout']}s")
        if kwargs.get('tls_retries'):
            cmd.extend(['--tls-retries', str(kwargs['tls_retries'])])
            if logger: logger.debug(f"TLS retries: {kwargs['tls_retries']}")
        if kwargs.get('discovery_depth'):
            cmd.extend(['--discovery-depth', str(kwargs['discovery_depth'])])
            if logger: logger.debug(f"Discovery depth: {kwargs['discovery_depth']}")
        if kwargs.get('amass_timeout'):
            cmd.extend(['--amass-timeout', str(kwargs['amass_timeout'])])
            if logger: logger.debug(f"Amass timeout: {kwargs['amass_timeout']}s")
        if kwargs.get('discovery_workers'):
            cmd.extend(['--discovery-workers', str(kwargs['discovery_workers'])])
            if logger: logger.debug(f"Discovery workers: {kwargs['discovery_workers']}")
        if kwargs.get('processing_workers'):
            cmd.extend(['--processing-workers', str(kwargs['processing_workers'])])
            if logger: logger.debug(f"Processing workers: {kwargs['processing_workers']}")
        if kwargs.get('batch_size'):
            cmd.extend(['--batch-size', str(kwargs['batch_size'])])
            if logger: logger.debug(f"Batch size: {kwargs['batch_size']}")
        
        # Feature flags
        if kwargs.get('enable_tls', False):
            cmd.append('--enable-tls')
            if logger: logger.debug("TLS analysis enabled")
        elif logger:
            logger.debug("TLS analysis disabled (use --enable-tls to activate)")
        if kwargs.get('enable_services', True):
            cmd.append('--enable-services')
            if logger: logger.debug("Service detection enabled")
        if kwargs.get('enable_providers', True):
            cmd.append('--enable-providers')
            if logger: logger.debug("Provider detection enabled")
        if kwargs.get('enable_industry', True):
            cmd.append('--enable-industry')
            if logger: logger.debug("Industry classification enabled")
        if kwargs.get('enable_risks', True):
            cmd.append('--enable-risks')
            if logger: logger.debug("Risk calculation enabled")
        elif logger:
            logger.debug("Risk calculation disabled")
        
        # Phase control
        if kwargs.get('phase1_only'):
            cmd.append('--phase1-only')
            if logger: logger.debug("Running Phase 1 only (discovery)")
        elif kwargs.get('phase2_only'):
            cmd.append('--phase2-only')
            if logger: logger.debug("Running Phase 2 only (processing)")
        
        # Related domains control
        if kwargs.get('no_related_domains'):
            cmd.append('--no-related-domains')
            if logger: logger.debug("Related domains storage disabled")
        
        print(f"🚀 Processing domain: {domain}")
        print(f"📝 Command: {' '.join(cmd)}")
        
        if logger:
            logger.info(f"🚀 Starting processing for domain: {domain}")
            logger.info(f"📝 Full command: {' '.join(cmd)}")
            logger.debug(f"Timeout configured: {kwargs.get('timeout', 3600)}s")
        
        start_time = time.time()
        
        if logger:
            logger.debug(f"⏱️ Domain processing started at: {datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Execute command with comprehensive logging
        try:
            if logger:
                logger.debug(f"🔧 Executing subprocess with capture_output=True, text=True")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=kwargs.get('timeout', 3600))
        except subprocess.TimeoutExpired as e:
            duration = time.time() - start_time
            if logger:
                logger.error(f"⏰ Domain {domain} timed out after {duration:.2f}s")
                logger.debug(f"Timeout exception details: {e}")
            raise e
        except Exception as e:
            duration = time.time() - start_time
            if logger:
                logger.error(f"💥 Subprocess execution failed for {domain} after {duration:.2f}s: {e}")
            raise e
        
        duration = time.time() - start_time
        end_time = time.time()
        
        if logger:
            logger.debug(f"⏱️ Domain processing ended at: {datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S')}")
            logger.info(f"📊 Domain {domain} processing time: {duration:.2f}s")
            logger.debug(f"📤 Return code: {result.returncode}")
            logger.debug(f"📏 STDOUT length: {len(result.stdout)} characters")
            logger.debug(f"📏 STDERR length: {len(result.stderr)} characters")
        
        if result.returncode == 0:
            print(f"✅ {domain} completed successfully in {duration:.1f}s")
            if logger:
                logger.info(f"✅ {domain} completed successfully in {duration:.2f}s")
                logger.debug(f"📤 STDOUT for {domain}:\n{result.stdout[:2000]}{'...' if len(result.stdout) > 2000 else ''}")
                if result.stderr:
                    logger.debug(f"📤 STDERR for {domain}:\n{result.stderr[:1000]}{'...' if len(result.stderr) > 1000 else ''}")
            return True, duration, result.stdout, result.stderr
        else:
            print(f"❌ {domain} failed with exit code {result.returncode}")
            print(f"Error: {result.stderr}")
            if logger:
                logger.error(f"❌ {domain} failed with exit code {result.returncode} after {duration:.2f}s")
                logger.error(f"📤 STDERR for {domain}:\n{result.stderr}")
                if result.stdout:
                    logger.debug(f"📤 STDOUT for failed {domain}:\n{result.stdout[:1000]}{'...' if len(result.stdout) > 1000 else ''}")
            return False, duration, result.stdout, result.stderr
            
    except subprocess.TimeoutExpired:
        timeout_duration = kwargs.get('timeout', 3600)
        print(f"⏰ {domain} timed out after {timeout_duration}s")
        if logger:
            logger.error(f"⏰ {domain} timed out after {timeout_duration}s")
        return False, timeout_duration, "", "Timeout"
    except Exception as e:
        duration = time.time() - start_time if 'start_time' in locals() else 0
        print(f"💥 {domain} failed with exception: {e}")
        if logger:
            logger.error(f"💥 {domain} failed with exception after {duration:.2f}s: {e}")
            logger.debug(f"Exception details: {type(e).__name__}: {e}")
        return False, duration, "", str(e)
    finally:
        # Clean up temporary file
        if os.path.exists(temp_file):
            if logger:
                logger.debug(f"🧹 Cleaning up temporary file: {temp_file}")
            os.remove(temp_file)
        elif logger:
            logger.debug(f"🧹 Temporary file {temp_file} not found (already cleaned or never created)")

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
    parser.add_argument('--enable-tls', action='store_true', help='Enable TLS analysis (disabled by default)')
    parser.add_argument('--disable-services', action='store_true', help='Disable service detection')
    parser.add_argument('--disable-providers', action='store_true', help='Disable provider detection')
    parser.add_argument('--disable-industry', action='store_true', help='Disable industry classification')
    parser.add_argument('--disable-risks', action='store_true', help='Disable risk calculation and analysis')
    
    # Phase control
    parser.add_argument('--phase1-only', action='store_true', help='Run only discovery phase')
    parser.add_argument('--phase2-only', action='store_true', help='Run only processing phase')
    parser.add_argument('--no-related-domains', action='store_true', help='Disable storage of DISCOVERED_RELATED domains')
    
    # Execution control
    parser.add_argument('--continue-on-error', action='store_true', help='Continue processing other domains if one fails')
    parser.add_argument('--delay', type=int, default=5, help='Delay between domains in seconds (default: 5)')
    parser.add_argument('--start-from', type=int, default=0, help='Start from domain N (0-indexed)')
    parser.add_argument('--max-domains', type=int, help='Process maximum N domains')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode with comprehensive logging')
    
    args = parser.parse_args()
    
    # Setup debug logging if enabled
    logger = None
    if args.debug:
        log_filename = f"batch_domain_processor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        logger = setup_debug_logging(log_filename)
        logger.info(f"🐛 DEBUG MODE ENABLED - Logging to: {log_filename}")
        logger.info(f"📋 Arguments: {vars(args)}")
        print(f"🐛 DEBUG MODE ENABLED - Detailed logging to: {log_filename}")
    
    # Read domains
    try:
        if logger:
            logger.debug(f"📂 Reading domains from file: {args.domains}")
        with open(args.domains, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        if logger:
            logger.info(f"📂 Successfully read {len(domains)} domains from file")
            logger.debug(f"📋 Domains list: {domains[:10]}{'...' if len(domains) > 10 else ''}")
    except FileNotFoundError:
        error_msg = f"❌ Domain file not found: {args.domains}"
        print(error_msg)
        if logger:
            logger.error(error_msg)
        sys.exit(1)
    
    if not domains:
        error_msg = f"❌ No domains found in file: {args.domains}"
        print(error_msg)
        if logger:
            logger.error(error_msg)
        sys.exit(1)
    
    # Apply start_from and max_domains filters
    if args.start_from > 0:
        domains = domains[args.start_from:]
        msg = f"📍 Starting from domain #{args.start_from}"
        print(msg)
        if logger:
            logger.info(msg)
    
    if args.max_domains:
        domains = domains[:args.max_domains]
        msg = f"📊 Processing maximum {args.max_domains} domains"
        print(msg)
        if logger:
            logger.info(msg)
    
    print(f"\n🎯 BATCH PROCESSING: {len(domains)} domains")
    print(f"⏱️ Per-domain timeout: {args.timeout}s")
    print(f"⏳ Delay between domains: {args.delay}s")
    print("=" * 60)
    
    if logger:
        logger.info(f"🎯 BATCH PROCESSING STARTED: {len(domains)} domains")
        logger.info(f"⏱️ Per-domain timeout: {args.timeout}s")
        logger.info(f"⏳ Delay between domains: {args.delay}s")
        logger.info(f"🐛 Debug mode: {args.debug}")
    
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
        'enable_tls': args.enable_tls,
        'enable_services': not args.disable_services,
        'enable_providers': not args.disable_providers,
        'enable_industry': not args.disable_industry,
        'enable_risks': not args.disable_risks,
        'phase1_only': args.phase1_only,
        'phase2_only': args.phase2_only,
        'no_related_domains': args.no_related_domains
    }
    
    # Process domains
    start_time = datetime.now()
    successful = 0
    failed = 0
    total_processing_time = 0
    
    for i, domain in enumerate(domains):
        print(f"\n📍 [{i+1}/{len(domains)}] Processing: {domain}")
        print("-" * 40)
        
        success, duration, stdout, stderr = run_domain_analysis(domain, args.password, logger=logger, **kwargs)
        
        total_processing_time += duration
        
        if success:
            successful += 1
            if logger:
                logger.info(f"✅ Domain {domain} completed successfully ({successful}/{successful + failed})")
        else:
            failed += 1
            if logger:
                logger.error(f"❌ Domain {domain} failed ({failed} total failures)")
            if not args.continue_on_error:
                stop_msg = f"\n💥 Stopping execution due to failure on {domain}"
                print(stop_msg)
                if logger:
                    logger.error(stop_msg)
                break
        
        # Delay between domains (except for the last one)
        if i < len(domains) - 1 and args.delay > 0:
            delay_msg = f"⏳ Waiting {args.delay}s before next domain..."
            print(delay_msg)
            if logger:
                logger.debug(delay_msg)
            time.sleep(args.delay)
    
    # Final statistics
    end_time = datetime.now()
    total_elapsed = (end_time - start_time).total_seconds()
    avg_per_domain = total_processing_time / len(domains) if len(domains) > 0 else 0
    success_rate = 100 * successful / (successful + failed) if (successful + failed) > 0 else 0
    
    print(f"\n📊 BATCH PROCESSING COMPLETE")
    print("=" * 60)
    print(f"✅ Successful: {successful}")
    print(f"❌ Failed: {failed}")
    print(f"📈 Success rate: {successful}/{successful + failed} ({success_rate:.1f}%)")
    print(f"⏱️ Total time: {total_elapsed:.1f}s ({total_elapsed/60:.1f} min)")
    print(f"⚡ Avg per domain: {avg_per_domain:.1f}s")
    print(f"🕐 Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🏁 Finished: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    if logger:
        logger.info(f"📊 BATCH PROCESSING COMPLETE")
        logger.info(f"✅ Successful domains: {successful}")
        logger.info(f"❌ Failed domains: {failed}")
        logger.info(f"📈 Success rate: {success_rate:.1f}%")
        logger.info(f"⏱️ Total elapsed time: {total_elapsed:.2f}s ({total_elapsed/60:.2f} minutes)")
        logger.info(f"⚡ Average processing time per domain: {avg_per_domain:.2f}s")
        logger.info(f"🕐 Started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"🏁 Finished at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"📝 Debug log completed - check log file for detailed analysis")
    
    # Exit with appropriate code
    sys.exit(0 if failed == 0 else 1)

if __name__ == "__main__":
    main()