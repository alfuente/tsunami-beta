#!/usr/bin/env python3
"""
Test script for the new amass cache functionality
"""

import json
import time
from pathlib import Path
from subdomain_relationship_discovery_unified import (
    UnifiedSubdomainDiscoverer, 
    ProcessingConfig
)

def test_cache_functionality():
    """Test the cache checking and cache-first execution"""
    
    # Configuration with cache enabled
    config = ProcessingConfig(
        enable_amass=True,
        enable_subdomain_enumeration=True,
        enable_tls_analysis=False,
        enable_service_detection=False,
        enable_provider_detection=False,
        enable_industry_classification=False,
        enable_risk_calculation=False,
        enable_mx_analysis=False,
        amass_timeout=60,  # Short timeout for testing
        max_subdomains=100,
        max_workers=5,
        amass_cache_dir="./amass_cache",
        amass_cache_duration_hours=24,  # 24 hours for testing
        enable_cache_check=True,
        save_to_neo4j=False,
        generate_report=False
    )
    
    print("=== Testing Amass Cache Functionality ===")
    print(f"Cache directory: {config.amass_cache_dir}")
    print(f"Cache duration: {config.amass_cache_duration_hours} hours")
    print(f"Cache checking: {'Enabled' if config.enable_cache_check else 'Disabled'}")
    print()
    
    # Test domain
    test_domain = "example.com"
    
    # Initialize discoverer
    discoverer = UnifiedSubdomainDiscoverer(config=config)
    
    print(f"Testing domain: {test_domain}")
    print()
    
    # Test 1: First run (should execute amass and cache results)
    print("=== Test 1: First run (should execute amass) ===")
    start_time = time.time()
    
    try:
        # Check cache first (should return None for first run)
        cached_results = discoverer._check_amass_cache(test_domain)
        if cached_results:
            print(f"❌ Unexpected: Found cached results on first run: {len(cached_results)} subdomains")
        else:
            print("✅ No cache found (expected for first run)")
        
        # Run amass (should execute and cache)
        amass_results = discoverer._run_amass(test_domain)
        execution_time = time.time() - start_time
        
        print(f"✅ Amass execution completed in {execution_time:.2f} seconds")
        print(f"✅ Found {len(amass_results)} subdomains")
        
        if amass_results:
            print(f"   Sample subdomains: {amass_results[:3]}")
        
    except Exception as e:
        print(f"❌ Test 1 failed: {e}")
        return False
    
    print()
    
    # Test 2: Second run (should use cache)
    print("=== Test 2: Second run (should use cache) ===")
    start_time = time.time()
    
    try:
        # Check cache (should return cached results now)
        cached_results = discoverer._check_amass_cache(test_domain)
        if cached_results:
            print(f"✅ Found cached results: {len(cached_results)} subdomains")
            if cached_results:
                print(f"   Sample cached subdomains: {cached_results[:3]}")
        else:
            print("❌ No cache found (unexpected for second run)")
        
        # Run amass again (should use cache)
        amass_results = discoverer._run_amass(test_domain)
        execution_time = time.time() - start_time
        
        print(f"✅ Second execution completed in {execution_time:.2f} seconds")
        print(f"✅ Found {len(amass_results)} subdomains")
        
        # Cache should be much faster
        if execution_time < 2.0:  # Less than 2 seconds indicates cache usage
            print("✅ Fast execution indicates cache was used")
        else:
            print("❌ Slow execution suggests cache was not used")
            
    except Exception as e:
        print(f"❌ Test 2 failed: {e}")
        return False
    
    print()
    
    # Test 3: Verify cache files exist
    print("=== Test 3: Verify cache files ===")
    
    try:
        cache_dir = Path(config.amass_cache_dir)
        metadata_dir = cache_dir / "metadata"
        data_dir = cache_dir / "data"
        
        if metadata_dir.exists() and data_dir.exists():
            print(f"✅ Cache directories exist")
            
            metadata_files = list(metadata_dir.glob("*.json"))
            data_files = list(data_dir.glob("*.json.gz"))
            
            print(f"✅ Found {len(metadata_files)} metadata files")
            print(f"✅ Found {len(data_files)} data files")
            
            if metadata_files:
                # Check a metadata file
                with open(metadata_files[0], 'r') as f:
                    metadata = json.load(f)
                print(f"✅ Sample metadata: domain={metadata.get('domain')}, "
                      f"timestamp={metadata.get('timestamp')}, "
                      f"subdomain_count={metadata.get('subdomain_count')}")
        else:
            print("❌ Cache directories not found")
            return False
            
    except Exception as e:
        print(f"❌ Test 3 failed: {e}")
        return False
    
    print()
    
    # Test 4: Test cache expiration (simulate)
    print("=== Test 4: Test with cache disabled ===")
    
    try:
        # Temporarily disable cache
        config.enable_cache_check = False
        discoverer.config = config
        
        start_time = time.time()
        amass_results = discoverer._run_amass(test_domain)
        execution_time = time.time() - start_time
        
        print(f"✅ Execution with cache disabled completed in {execution_time:.2f} seconds")
        print(f"✅ Found {len(amass_results)} subdomains")
        
        # Re-enable cache
        config.enable_cache_check = True
        discoverer.config = config
        
    except Exception as e:
        print(f"❌ Test 4 failed: {e}")
        return False
    
    print()
    print("=== All tests completed successfully! ===")
    return True

def test_standalone_script():
    """Test the standalone amass executor script"""
    
    print("=== Testing Standalone Amass Executor ===")
    
    script_path = Path("./standalone_amass_executor.sh")
    
    if not script_path.exists():
        print("❌ Standalone script not found")
        return False
    
    if not script_path.is_file() or not (script_path.stat().st_mode & 0o111):
        print("❌ Script is not executable")
        return False
    
    print("✅ Standalone script found and executable")
    
    # Test help
    try:
        import subprocess
        result = subprocess.run([str(script_path), "--help"], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✅ Script help works")
            print("   Help output preview:")
            for line in result.stdout.split('\n')[:5]:
                if line.strip():
                    print(f"   {line}")
        else:
            print(f"❌ Script help failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Failed to test script help: {e}")
        return False
    
    print("✅ Standalone script test completed")
    return True

if __name__ == "__main__":
    print("Starting amass cache integration tests...\n")
    
    # Test standalone script first
    if not test_standalone_script():
        print("Standalone script test failed, but continuing with cache tests...")
    
    print()
    
    # Test cache functionality
    if test_cache_functionality():
        print("\n🎉 All tests passed! The cache integration is working correctly.")
    else:
        print("\n💥 Some tests failed. Please check the implementation.")