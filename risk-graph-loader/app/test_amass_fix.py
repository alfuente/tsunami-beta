#!/usr/bin/env python3
"""
Test to identify and fix the amass issue
"""

import subprocess
import tempfile
from pathlib import Path
import time

def test_amass_without_config():
    """Test amass without using the problematic config."""
    print("=== TESTING AMASS WITHOUT CONFIG ===")
    
    test_domain = "example.com"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.txt"
        
        # Set empty config dir to avoid using the problematic datasources
        env = {"AMASS_CONFIG_DIR": tmp}
        
        # Simple command without problematic flags
        cmd = [
            "amass", "enum", 
            "-d", test_domain, 
            "-o", str(out),
            "-timeout", "3",
            "-silent"  # Reduce output noise
        ]
        
        print(f"Command: {' '.join(cmd)}")
        print(f"Config dir: {tmp}")
        
        start_time = time.time()
        try:
            result = subprocess.run(
                cmd, 
                env=env,
                check=False,
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                timeout=10,  # Short timeout for testing
                text=True
            )
            
            elapsed = time.time() - start_time
            print(f"Elapsed: {elapsed:.2f}s")
            print(f"Return code: {result.returncode}")
            print(f"STDOUT: '{result.stdout}'")
            print(f"STDERR: '{result.stderr}'")
            
            if out.exists():
                content = out.read_text()
                print(f"Output file size: {len(content)} chars")
                if content:
                    lines = content.strip().split('\n')
                    print(f"Lines found: {len(lines)}")
                    for i, line in enumerate(lines[:5], 1):
                        print(f"  {i}: {line}")
                else:
                    print("  (empty file)")
                return len(content) > 0
            else:
                print("No output file created")
                return False
                
        except subprocess.TimeoutExpired as e:
            elapsed = time.time() - start_time
            print(f"TIMEOUT after {elapsed:.2f}s")
            return False
        except Exception as e:
            print(f"Error: {e}")
            return False

def test_amass_with_include_filter():
    """Test amass with specific data source inclusion."""
    print("\n=== TESTING AMASS WITH INCLUDE FILTER ===")
    
    test_domain = "example.com"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.txt"
        
        # Set empty config dir
        env = {"AMASS_CONFIG_DIR": tmp}
        
        # Only use DNS-based sources, avoid external APIs
        cmd = [
            "amass", "enum", 
            "-d", test_domain, 
            "-o", str(out),
            "-timeout", "3",
            "-include", "DNS",  # Only DNS enumeration
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
                timeout=10,
                text=True
            )
            
            elapsed = time.time() - start_time
            print(f"Elapsed: {elapsed:.2f}s")
            print(f"Return code: {result.returncode}")
            print(f"STDERR: '{result.stderr}'")
            
            if out.exists():
                content = out.read_text()
                print(f"Output file size: {len(content)} chars")
                if content:
                    lines = content.strip().split('\n')
                    print(f"Lines found: {len(lines)}")
                    for i, line in enumerate(lines[:3], 1):
                        print(f"  {i}: {line}")
                return len(content) > 0
            else:
                print("No output file created")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"TIMEOUT after {time.time() - start_time:.2f}s")
            return False
        except Exception as e:
            print(f"Error: {e}")
            return False

def test_list_data_sources():
    """List available data sources."""
    print("\n=== LISTING AMASS DATA SOURCES ===")
    
    try:
        result = subprocess.run(
            ["amass", "enum", "-list"],
            capture_output=True,
            timeout=5,
            text=True
        )
        
        print(f"Return code: {result.returncode}")
        if result.stdout:
            print("Available sources:")
            for line in result.stdout.strip().split('\n')[:10]:
                print(f"  {line}")
        if result.stderr:
            print(f"STDERR: {result.stderr}")
            
    except Exception as e:
        print(f"Error listing sources: {e}")

def test_original_script_fix():
    """Test fix for the original script issue."""
    print("\n=== TESTING FIXED COMMAND FOR SCRIPT ===")
    
    test_domain = "example.com"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.txt"
        
        # Create minimal config to avoid external API issues
        config_dir = Path(tmp) / "amass_config"
        config_dir.mkdir()
        
        # Write minimal datasources.yaml
        (config_dir / "datasources.yaml").write_text("""
datasources:
global_options: 
  minimum_ttl: 1440
""")
        
        env = {"AMASS_CONFIG_DIR": str(config_dir)}
        
        # Fixed command - remove -passive (deprecated) and problematic excludes
        cmd = [
            "amass", "enum", 
            "-d", test_domain, 
            "-o", str(out),
            "-timeout", "5",
            "-r", "8.8.8.8,1.1.1.1",  # Use explicit resolvers
            "-include", "DNS",  # Only use DNS, avoid external APIs
            "-silent"
        ]
        
        print(f"Command: {' '.join(cmd)}")
        
        start_time = time.time()
        try:
            result = subprocess.run(
                cmd, 
                env=env,
                check=False,
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.PIPE,
                timeout=15,
                text=True
            )
            
            elapsed = time.time() - start_time
            print(f"Elapsed: {elapsed:.2f}s")
            print(f"Return code: {result.returncode}")
            print(f"STDERR: '{result.stderr}'")
            
            if out.exists():
                content = out.read_text()
                print(f"Output file size: {len(content)} chars")
                if content:
                    lines = content.strip().split('\n')
                    print(f"Lines found: {len(lines)}")
                    return lines
                else:
                    print("  (empty file)")
                    return []
            else:
                print("No output file created")
                return []
                
        except subprocess.TimeoutExpired:
            print(f"TIMEOUT after {time.time() - start_time:.2f}s")
            if out.exists():
                content = out.read_text()
                print(f"Partial results: {len(content)} chars")
            return []
        except Exception as e:
            print(f"Error: {e}")
            return []

if __name__ == "__main__":
    test_list_data_sources()
    success1 = test_amass_without_config()
    success2 = test_amass_with_include_filter()
    results = test_original_script_fix()
    
    print("\n=== SUMMARY ===")
    print(f"Test 1 (no config): {'SUCCESS' if success1 else 'FAILED'}")
    print(f"Test 2 (include filter): {'SUCCESS' if success2 else 'FAILED'}")
    print(f"Test 3 (script fix): {'SUCCESS' if len(results) > 0 else 'FAILED'}")
    
    if len(results) > 0:
        print(f"Fixed command returned {len(results)} results")
        print("Sample results:", results[:3])