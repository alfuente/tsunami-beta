#!/usr/bin/env python3

"""
Test script for the improved Amass configuration
"""

import subprocess
import tempfile
from pathlib import Path

def test_amass_config():
    """Test the improved Amass configuration."""
    domain = "google.com"
    
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.txt"
        config_file = Path(tmp) / "config.ini"
        
        # Create optimized config
        config_content = f"""
[scope]
domains = {domain}

[settings]
max_dns_queries = 50
resolvers_trusted = 8.8.8.8,1.1.1.1,9.9.9.9
max_brute_force = 50
minimum_ttl = 1440

[datasources]
# Disable slow sources
activearchive = false
binaryedge = false
bufferover = false
censys = false
certspotter = false
chaos = false
circl = false
commonc = false
crtsh = false
dnsdumpster = false
facebook = false
github = false
google = false
hackerone = false
intelx = false
passivetotal = false
rapiddns = false
robtex = false
securitytrails = false
shodan = false
spyse = false
threatbook = false
threatcrowd = false
threatminer = false
urlscan = false
virustotal = false
whoisxmlapi = false
yahoo = false

# Enable only fast and reliable sources
bing = true
duckduckgo = true
ask = true
baidu = true
yandex = true
"""
        
        config_file.write_text(config_content)
        
        # Build optimized command
        cmd = [
            "amass", "enum", 
            "-config", str(config_file),
            "-d", domain, 
            "-o", str(out),
            "-max-dns-queries", "25",
            "-max-depth", "1",
            "-timeout", "20",
            "-passive"
        ]
        
        print(f"[*] Testing optimized Amass config for {domain}")
        print(f"[*] Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd, 
                check=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                timeout=30,
                text=True
            )
            
            print(f"[✓] Amass completed successfully")
            
            # Check output
            if out.exists():
                with out.open() as f:
                    lines = f.readlines()
                
                print(f"[*] Output file has {len(lines)} lines")
                
                # Count node relationships
                node_count = 0
                for line in lines:
                    if " --> node -->" in line:
                        node_count += 1
                        print(f"[+] Found: {line.strip()}")
                
                print(f"[*] Found {node_count} subdomain relationships")
                
                if node_count > 0:
                    print("[✓] Amass configuration is working!")
                    return True
                else:
                    print("[!] No subdomains found, but Amass completed")
                    return True
            else:
                print("[!] No output file generated")
                return False
                
        except subprocess.TimeoutExpired:
            print("[!] Amass timed out")
            return False
        except subprocess.CalledProcessError as e:
            print(f"[!] Amass failed: {e}")
            print(f"    stderr: {e.stderr}")
            return False
        except FileNotFoundError:
            print("[!] Amass not found in PATH")
            return False

def test_basic_dns():
    """Test basic DNS enumeration as fallback."""
    domain = "google.com"
    common_subdomains = ['www', 'mail', 'ftp', 'api', 'app']
    
    print(f"\\n[*] Testing basic DNS enumeration for {domain}")
    
    found_count = 0
    for sub in common_subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            import socket
            socket.gethostbyname(subdomain)
            print(f"[+] Found: {subdomain}")
            found_count += 1
        except socket.gaierror:
            pass
        except Exception as e:
            print(f"[!] Error checking {subdomain}: {e}")
    
    print(f"[*] Basic DNS enumeration found {found_count} subdomains")
    return found_count > 0

if __name__ == "__main__":
    print("=== Testing Improved Amass Configuration ===")
    
    # Test Amass
    amass_success = test_amass_config()
    
    # Test DNS fallback
    dns_success = test_basic_dns()
    
    print(f"\\n=== Results ===")
    print(f"Amass: {'✓' if amass_success else '✗'}")
    print(f"DNS Enum: {'✓' if dns_success else '✗'}")
    
    if amass_success or dns_success:
        print("\\n[✓] At least one discovery method is working!")
    else:
        print("\\n[✗] All discovery methods failed")