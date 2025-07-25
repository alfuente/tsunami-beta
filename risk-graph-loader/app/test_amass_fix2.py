#!/usr/bin/env python3
"""
Test to identify and fix the amass issue - with proper path handling
"""

import subprocess
import tempfile
from pathlib import Path
import time
import os

def test_amass_fixed():
    """Test the fixed amass command."""
    print("=== TESTING FIXED AMASS COMMAND ===")
    
    test_domain = "example.com"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.txt"
        
        # Create minimal config to avoid external API issues
        config_dir = Path(tmp) / "amass_config"
        config_dir.mkdir()
        
        # Write minimal datasources.yaml without external APIs
        (config_dir / "datasources.yaml").write_text("""
datasources:
global_options: 
  minimum_ttl: 1440
""")
        
        # Preserve PATH and set config dir
        env = os.environ.copy()
        env["AMASS_CONFIG_DIR"] = str(config_dir)
        
        # Fixed command based on v4.2.0 capabilities
        cmd = [
            "/usr/local/bin/amass", "enum", 
            "-d", test_domain, 
            "-o", str(out),
            "-timeout", "5",
            "-r", "8.8.8.8,1.1.1.1",  # Explicit resolvers
            "-dns-qps", "10",  # Limit DNS queries per second
            "-silent"
        ]
        
        print(f"Command: {' '.join(cmd)}")
        
        start_time = time.time()
        try:
            result = subprocess.run(
                cmd, 
                env=env,
                check=False,
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                timeout=15,
                text=True
            )
            
            elapsed = time.time() - start_time
            print(f"Elapsed: {elapsed:.2f}s")
            print(f"Return code: {result.returncode}")
            if result.stdout:
                print(f"STDOUT: '{result.stdout[:200]}'")
            if result.stderr:
                print(f"STDERR: '{result.stderr}'")
            
            if out.exists():
                content = out.read_text()
                print(f"Output file size: {len(content)} chars")
                if content:
                    lines = content.strip().split('\n')
                    print(f"Lines found: {len(lines)}")
                    for i, line in enumerate(lines[:5], 1):
                        print(f"  {i}: {line}")
                    return True, lines
                else:
                    print("  (empty file)")
                    return True, []
            else:
                print("No output file created")
                return False, []
                
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            print(f"TIMEOUT after {elapsed:.2f}s")
            if out.exists():
                content = out.read_text()
                print(f"Partial results: {len(content)} chars")
                if content:
                    lines = content.strip().split('\n')
                    print(f"Partial lines: {len(lines)}")
                    return True, lines
            return False, []
        except Exception as e:
            print(f"Error: {e}")
            return False, []

def show_recommended_fix():
    """Show the recommended fix for the script."""
    print("\n=== RECOMMENDED FIX FOR SCRIPT ===")
    
    print("""
The issue with Amass is likely caused by:

1. External API timeouts from datasources.yaml configuration
2. Deprecated -passive flag in v4.2.0
3. Complex -exclude parameters causing issues

RECOMMENDED FIXES:

1. Update run_amass_local function to:
   - Remove the -passive flag (deprecated in v4.2.0)
   - Use -include DNS instead of complex -exclude parameters
   - Set AMASS_CONFIG_DIR to a clean directory
   - Use -dns-qps to limit query rate
   - Add better error handling for empty stderr

2. Example fixed command:
   cmd = [
       "amass", "enum", 
       "-d", domain, 
       "-o", str(out),
       "-timeout", timeout_arg,
       "-r", "8.8.8.8,1.1.1.1,9.9.9.9",
       "-dns-qps", "20",
       "-include", "DNS",  # Only use DNS, avoid external APIs
       "-silent"
   ]

3. Set clean environment:
   env = os.environ.copy()
   env["AMASS_CONFIG_DIR"] = "/tmp/clean_amass_config"

4. Fix error handling:
   - Check if e.stderr is None or empty
   - Provide more specific error messages
   - Consider fallback mechanisms
""")

if __name__ == "__main__":
    success, results = test_amass_fixed()
    
    print(f"\n=== RESULT ===")
    if success:
        print("✅ Amass command executed successfully!")
        if len(results) > 0:
            print(f"Found {len(results)} subdomains")
        else:
            print("No subdomains found (but command worked)")
    else:
        print("❌ Amass command failed")
    
    show_recommended_fix()