#!/usr/bin/env python3
"""
Test script to debug the exact amass issue
"""

import subprocess
import tempfile
from pathlib import Path

def test_amass_exact_command():
    """Test the exact amass command from the script."""
    print("=== TESTING EXACT AMASS COMMAND ===")
    
    test_domain = "example.com"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.txt"
        
        # Exact command from the script
        cmd = [
            "amass", "enum", 
            "-d", test_domain, 
            "-o", str(out),
            "-max-dns-queries", "20",
            "-max-depth", "1",
            "-r", "8.8.8.8,1.1.1.1,9.9.9.9",
            "-timeout", "15",
            "-passive",
            "-exclude", "crtsh,dnsdumpster,hackertarget,threatcrowd,virustotal"
        ]
        
        print(f"Command: {' '.join(cmd)}")
        print(f"Output file: {out}")
        
        try:
            # Run with exact same settings as script
            result = subprocess.run(
                cmd, 
                check=False,  # Don't raise on non-zero exit
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.PIPE,
                timeout=45,  # 15s amass timeout + 30s buffer
                text=True
            )
            
            print(f"Return code: {result.returncode}")
            print(f"STDERR: '{result.stderr}'")
            print(f"STDERR length: {len(result.stderr) if result.stderr else 0}")
            print(f"STDERR repr: {repr(result.stderr)}")
            
            if out.exists():
                content = out.read_text()
                print(f"Output file exists: {out}")
                print(f"Content length: {len(content)}")
                print(f"Content: '{content}'")
                if content:
                    lines = content.strip().split('\n')
                    print(f"Lines: {len(lines)}")
                    for i, line in enumerate(lines[:5], 1):
                        print(f"  {i}: {repr(line)}")
                else:
                    print("  (empty file)")
            else:
                print(f"Output file does not exist: {out}")
                
        except subprocess.TimeoutExpired as e:
            print(f"TIMEOUT: {e}")
            print(f"STDOUT: {e.stdout}")
            print(f"STDERR: {e.stderr}")
            if out.exists():
                content = out.read_text()
                print(f"Partial results: {len(content)} chars")
                print(f"Content: '{content}'")
        except subprocess.CalledProcessError as e:
            print(f"CalledProcessError: {e}")
            print(f"Return code: {e.returncode}")
            print(f"STDOUT: {e.stdout}")
            print(f"STDERR: '{e.stderr}'")
            print(f"STDERR length: {len(e.stderr) if e.stderr else 0}")
        except Exception as e:
            print(f"Other error: {e}")

def test_minimal_amass():
    """Test minimal amass command."""
    print("\n=== TESTING MINIMAL AMASS COMMAND ===")
    
    test_domain = "example.com"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.txt"
        
        # Minimal command
        cmd = ["amass", "enum", "-d", test_domain, "-o", str(out), "-timeout", "10"]
        
        print(f"Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd, 
                check=False,
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                timeout=20,
                text=True
            )
            
            print(f"Return code: {result.returncode}")
            print(f"STDOUT: '{result.stdout}'")
            print(f"STDERR: '{result.stderr}'")
            
            if out.exists():
                content = out.read_text()
                print(f"Content length: {len(content)}")
                if content:
                    print(f"Content preview: {content[:200]}")
                else:
                    print("(empty file)")
            else:
                print("No output file created")
                
        except subprocess.TimeoutExpired as e:
            print(f"TIMEOUT: {e}")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    test_amass_exact_command()
    test_minimal_amass()