#!/usr/bin/env python3
"""
Load Domains via API Script (Risk Quality Module)

This script reads domains from a txt file (one domain per line) and
loads them into the graph using the domain-backend API endpoints.

The script can perform different types of discovery operations:
- amass: Full subdomain and provider discovery
- combined: Complete analysis including DNS, TLS, MX, etc.
- dns: DNS analysis only
- mx: MX record analysis only
- tls: TLS analysis only

Usage:
    python3 load_domains_via_api.py --input incomplete_domains.txt [--operation combined] [--api-url http://localhost:8000] [--concurrent 3] [--delay 3]
"""

import argparse
import requests
import time
import logging
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
from typing import List, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DomainAPILoader:
    def __init__(self, api_url: str = "http://localhost:8000", concurrent: int = 3, delay: float = 3.0):
        self.api_url = api_url.rstrip('/')
        self.concurrent = concurrent
        self.delay = delay
        self.session = None
        
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=self.concurrent)
        self.session = aiohttp.ClientSession(connector=connector)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def read_domains_from_txt(self, input_file: str) -> List[str]:
        """Read domains from txt file, one per line"""
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                domains = [line.strip() for line in f if line.strip()]
            
            logger.info(f"Read {len(domains)} domains from {input_file}")
            return domains
            
        except FileNotFoundError:
            logger.error(f"Input file {input_file} not found")
            return []
        except Exception as e:
            logger.error(f"Error reading domains from {input_file}: {e}")
            return []
    
    async def discover_domain(self, domain: str, operation: str = "combined") -> dict:
        """Trigger domain discovery via API"""
        endpoint_map = {
            "amass": f"/api/v1/discover/amass/{domain}",
            "combined": f"/api/v1/discover/combined/{domain}",
            "combined-recursive": f"/api/v1/discover/combined-recursive/{domain}",
            "dns": f"/api/v1/discover/dns/{domain}",
            "mx": f"/api/v1/discover/mx/{domain}",
            "tls": f"/api/v1/discover/tls/{domain}",
            "tls-detailed": f"/api/v1/discover/tls-detailed/{domain}",
            "tech": f"/api/v1/discover/tech/{domain}",
            "services": f"/api/v1/discover/services/{domain}",
            "web-scraping": f"/api/v1/discover/web-scraping/{domain}",
            "risk": f"/api/v1/calculate/risk/{domain}",
            "risk-tree": f"/api/v1/calculate/risk-tree/{domain}"
        }
        
        if operation not in endpoint_map:
            return {"domain": domain, "status": "error", "error": f"Unknown operation: {operation}"}
        
        url = f"{self.api_url}{endpoint_map[operation]}"
        
        try:
            async with self.session.post(url, timeout=600) as response:  # Increased timeout for combined operations
                if response.status == 200:
                    result = await response.json()
                    logger.info(f"✅ {domain}: {operation} operation successful")
                    return {"domain": domain, "status": "success", "operation": operation, "result": result}
                else:
                    error_text = await response.text()
                    logger.warning(f"⚠️ {domain}: {operation} operation failed with status {response.status}")
                    return {"domain": domain, "status": "error", "operation": operation, "error": error_text}
                    
        except asyncio.TimeoutError:
            logger.error(f"❌ {domain}: {operation} operation timed out")
            return {"domain": domain, "status": "timeout", "operation": operation}
        except Exception as e:
            logger.error(f"❌ {domain}: {operation} operation failed: {e}")
            return {"domain": domain, "status": "error", "operation": operation, "error": str(e)}
    
    async def process_domains(self, domains: List[str], operation: str = "combined") -> List[dict]:
        """Process multiple domains with concurrency control"""
        results = []
        semaphore = asyncio.Semaphore(self.concurrent)
        
        async def process_single_domain(domain):
            async with semaphore:
                result = await self.discover_domain(domain, operation)
                if self.delay > 0:
                    await asyncio.sleep(self.delay)
                return result
        
        logger.info(f"Starting {operation} operation for {len(domains)} domains with {self.concurrent} concurrent requests")
        
        tasks = [process_single_domain(domain) for domain in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle exceptions in results
        clean_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                clean_results.append({
                    "domain": domains[i],
                    "status": "exception", 
                    "operation": operation,
                    "error": str(result)
                })
            else:
                clean_results.append(result)
        
        return clean_results
    
    def save_results(self, results: List[dict], output_file: str):
        """Save results to JSON file"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False, default=str)
            logger.info(f"Results saved to {output_file}")
        except Exception as e:
            logger.error(f"Error saving results: {e}")
    
    def print_summary(self, results: List[dict], operation: str):
        """Print summary of results"""
        total = len(results)
        success = len([r for r in results if r.get("status") == "success"])
        errors = len([r for r in results if r.get("status") == "error"])
        timeouts = len([r for r in results if r.get("status") == "timeout"])
        exceptions = len([r for r in results if r.get("status") == "exception"])
        
        print("\n" + "="*70)
        print("DOMAIN PROCESSING SUMMARY")
        print("="*70)
        print(f"🎯 Operation: {operation}")
        print(f"📊 Total domains processed: {total}")
        print(f"✅ Successful: {success}")
        print(f"❌ Errors: {errors}")
        print(f"⏱️ Timeouts: {timeouts}")
        print(f"💥 Exceptions: {exceptions}")
        
        if total > 0:
            success_rate = success/total*100
            print(f"📈 Success rate: {success_rate:.1f}%")
            
            if success > 0:
                print(f"\n🎉 Successfully processed domains:")
                for result in results[:10]:  # Show first 10 successful
                    if result.get("status") == "success":
                        print(f"   ✅ {result['domain']}")
                if success > 10:
                    print(f"   ... and {success - 10} more")
        
        if errors > 0:
            print(f"\n❌ Domains with errors:")
            for result in results[:5]:  # Show first 5 errors
                if result.get("status") == "error":
                    error = result.get("error", "Unknown error")
                    print(f"   • {result['domain']}: {error[:100]}...")
            if errors > 5:
                print(f"   ... and {errors - 5} more errors")
        
        if timeouts > 0:
            print(f"\n⏱️ Domains with timeouts:")
            for result in results[:5]:  # Show first 5 timeouts
                if result.get("status") == "timeout":
                    print(f"   • {result['domain']}")
            if timeouts > 5:
                print(f"   ... and {timeouts - 5} more timeouts")
    
    def generate_retry_list(self, results: List[dict], output_file: str):
        """Generate a txt file with failed domains for retry"""
        failed_domains = []
        for result in results:
            if result.get("status") in ["error", "timeout", "exception"]:
                failed_domains.append(result["domain"])
        
        if failed_domains:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    for domain in failed_domains:
                        f.write(f"{domain}\n")
                logger.info(f"Failed domains saved to {output_file} for retry")
                print(f"📄 Failed domains saved to: {output_file}")
                return len(failed_domains)
            except Exception as e:
                logger.error(f"Error saving failed domains: {e}")
        
        return 0

async def main():
    parser = argparse.ArgumentParser(description='Load incomplete domains via domain-backend API')
    parser.add_argument('--input', '-i', default='incomplete_domains.txt',
                        help='Input TXT file with domains (default: incomplete_domains.txt)')
    parser.add_argument('--operation', '-op', default='combined',
                        choices=['amass', 'combined', 'combined-recursive', 'dns', 'mx', 'tls', 
                                'tls-detailed', 'tech', 'services', 'web-scraping', 'risk', 'risk-tree'],
                        help='Type of discovery operation (default: combined)')
    parser.add_argument('--api-url', '-u', default='http://localhost:8000',
                        help='Domain backend API URL (default: http://localhost:8000)')
    parser.add_argument('--concurrent', '-c', type=int, default=3,
                        help='Number of concurrent requests (default: 3 - conservative for incomplete domains)')
    parser.add_argument('--delay', '-d', type=float, default=3.0,
                        help='Delay between requests in seconds (default: 3.0 - conservative)')
    parser.add_argument('--output', '-o', 
                        help='Output JSON file for results (default: auto-generated)')
    parser.add_argument('--limit', '-l', type=int,
                        help='Limit number of domains to process (for testing)')
    parser.add_argument('--retry-failed', action='store_true',
                        help='Generate retry file for failed domains')
    
    args = parser.parse_args()
    
    # Check if input file exists
    if not Path(args.input).exists():
        print(f"❌ Input file {args.input} not found")
        print(f"💡 Tip: Run 'python3 export_incomplete_domains_txt.py' first to generate the file")
        return
    
    # Auto-generate output filename if not provided
    if not args.output:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        args.output = f"domain_loading_results_{args.operation}_{timestamp}.json"
    
    async with DomainAPILoader(args.api_url, args.concurrent, args.delay) as loader:
        # Read domains from file
        domains = loader.read_domains_from_txt(args.input)
        
        if not domains:
            print("❌ No domains found in input file")
            return
        
        # Apply limit if specified
        if args.limit:
            domains = domains[:args.limit]
            print(f"🔢 Limited processing to first {args.limit} domains")
        
        print(f"🚀 Starting {args.operation} operation for {len(domains)} incomplete domains")
        print(f"🌐 API URL: {args.api_url}")
        print(f"⚡ Concurrent requests: {args.concurrent}")
        print(f"⏱️ Delay between requests: {args.delay}s")
        print(f"💡 Processing domains without subdomains or providers")
        
        # Process domains
        start_time = time.time()
        results = await loader.process_domains(domains, args.operation)
        end_time = time.time()
        
        # Save results
        loader.save_results(results, args.output)
        
        # Generate retry list if requested
        if args.retry_failed:
            retry_file = f"retry_{args.operation}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
            failed_count = loader.generate_retry_list(results, retry_file)
        
        # Print summary
        loader.print_summary(results, args.operation)
        
        print(f"\n⏱️ Total time: {end_time - start_time:.1f} seconds")
        print(f"📄 Results saved to: {args.output}")
        
        if args.retry_failed and failed_count > 0:
            print(f"🔄 {failed_count} failed domains ready for retry")

if __name__ == "__main__":
    asyncio.run(main())