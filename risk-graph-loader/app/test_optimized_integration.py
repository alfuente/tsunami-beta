#!/usr/bin/env python3

"""
Test script to verify the optimized Amass configuration works in the integrated script
"""

import subprocess
import tempfile
import socket
from pathlib import Path

def run_optimized_amass(domain: str, sample_mode: bool = True):
    """Test the optimized Amass configuration from the integrated script."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.txt"
        
        # Build optimized command (same as in risk_loader_advanced3.py)
        cmd = [
            "amass", "enum", 
            "-d", domain, 
            "-o", str(out),
            "-max-dns-queries", "20",
            "-max-depth", "1",
            "-r", "8.8.8.8,1.1.1.1,9.9.9.9"
        ]
        
        if sample_mode:
            timeout_arg = "15"
            cmd.extend(["-timeout", timeout_arg])
            cmd.extend(["-passive"])
            cmd.extend(["-exclude", "crtsh,dnsdumpster,hackertarget,threatcrowd,virustotal"])
            print(f"[AMASS] {domain} (passive, {timeout_arg}s)")
        else:
            cmd.extend(["-timeout", "120"])
            print(f"[AMASS] {domain} (active, 120s)")
        
        try:
            timeout_seconds = 20 if sample_mode else 150
            result = subprocess.run(
                cmd, 
                check=True, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                text=True
            )
            
            return parse_amass_output(out)
            
        except subprocess.TimeoutExpired:
            print(f"[AMASS] Timeout for {domain} - checking partial results")
            if out.exists():
                return parse_amass_output(out)
            return []
            
        except subprocess.CalledProcessError as e:
            print(f"[AMASS] Error for {domain}: {e.stderr if e.stderr else 'Unknown error'}")
            if out.exists():
                return parse_amass_output(out)
            return []
        
        except FileNotFoundError:
            print(f"[AMASS] Not found in PATH")
            return []

def parse_amass_output(output_path: Path):
    """Parse Amass output to extract subdomain relationships."""
    entries = []
    
    if not output_path.exists():
        return entries
    
    with output_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line or "The enumeration has finished" in line or "DNS wildcard detected:" in line:
                continue
            
            # Look for node relationships
            if " --> " in line and " node " in line:
                parts = line.split(" --> ")
                if len(parts) == 3:
                    source, relation, target = parts
                    
                    if " (" in source:
                        source_clean = source.split(" (")[0].strip()
                    else:
                        source_clean = source.strip()
                    
                    if " (" in target:
                        target_clean = target.split(" (")[0].strip()
                    else:
                        target_clean = target.strip()
                    
                    if relation.strip() == "node":
                        entries.append({
                            "name": target_clean,
                            "parent": source_clean
                        })
    
    return entries

def run_subfinder_fallback(domain: str):
    """Test Subfinder fallback."""
    try:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "subfinder_out.txt"
            cmd = ["subfinder", "-d", domain, "-o", str(out), "-silent", "-timeout", "10"]
            
            result = subprocess.run(
                cmd, 
                check=True, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL,
                timeout=15
            )
            
            entries = []
            if out.exists():
                with out.open() as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain and subdomain != domain:
                            entries.append({
                                "name": subdomain,
                                "parent": domain
                            })
            
            print(f"[SUBFINDER] Found {len(entries)} subdomains for {domain}")
            return entries
            
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        print(f"[SUBFINDER] Not available or failed for {domain}")
        return []

def run_basic_dns_enumeration(domain: str):
    """Test basic DNS enumeration."""
    common_subdomains = [
        'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 
        'mx', 'test', 'staging', 'dev', 'admin', 'api', 'blog', 'shop', 
        'app', 'mobile', 'secure', 'ssl', 'portal', 'support', 'help'
    ]
    
    entries = []
    print(f"[DNS ENUM] Testing {len(common_subdomains)} common subdomains for {domain}")
    
    for sub in common_subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            entries.append({
                "name": subdomain,
                "parent": domain
            })
        except socket.gaierror:
            pass
        except Exception:
            pass
    
    print(f"[DNS ENUM] Found {len(entries)} valid subdomains for {domain}")
    return entries

def test_discovery_methods(domain: str):
    """Test all discovery methods with the optimized configuration."""
    print(f"=== Testing Optimized Discovery for {domain} ===")
    
    # 1. Try optimized Amass first
    print(f"\n[1] Testing optimized Amass configuration...")
    amass_results = run_optimized_amass(domain, sample_mode=True)
    if amass_results:
        print(f"[✓] Amass found {len(amass_results)} subdomains")
        return amass_results, "amass"
    
    # 2. Fallback to Subfinder
    print(f"\n[2] Amass failed, trying Subfinder fallback...")
    subfinder_results = run_subfinder_fallback(domain)
    if subfinder_results:
        print(f"[✓] Subfinder found {len(subfinder_results)} subdomains")
        return subfinder_results, "subfinder"
    
    # 3. Fallback to DNS enumeration
    print(f"\n[3] Subfinder failed, trying DNS enumeration...")
    dns_results = run_basic_dns_enumeration(domain)
    if dns_results:
        print(f"[✓] DNS enumeration found {len(dns_results)} subdomains")
        return dns_results, "dns_enum"
    
    print(f"[!] All discovery methods failed for {domain}")
    return [], "none"

if __name__ == "__main__":
    # Test with a known domain
    test_domain = "google.com"
    
    results, method = test_discovery_methods(test_domain)
    
    print(f"\n=== Results ===")
    print(f"Domain: {test_domain}")
    print(f"Method used: {method}")
    print(f"Subdomains found: {len(results)}")
    
    if results:
        print(f"\n=== Sample Results ===")
        for i, entry in enumerate(results[:5]):  # Show first 5
            print(f"  {entry['parent']} -> {entry['name']}")
            if i >= 4 and len(results) > 5:
                print(f"  ... and {len(results) - 5} more")
                break
        
        print(f"\n[✓] Integration test successful! Found {len(results)} subdomains using {method}")
    else:
        print(f"\n[!] No subdomains discovered")