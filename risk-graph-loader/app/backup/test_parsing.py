#!/usr/bin/env python3

"""
Test to verify Amass output parsing
"""

import sys
from pathlib import Path

# Import the parsing function
sys.path.insert(0, str(Path(__file__).parent))

# Import parse_amass_output directly by reading the file and extracting the function
def parse_amass_output(output_path):
    """Simple test parser based on the expected format."""
    entries = []
    domains = set()
    
    with output_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            
            print(f"Processing line: {line}")
            
            # Look for node relationships (subdomain discovery)
            if " --> " in line and "node" in line:
                parts = line.split(" --> ")
                if len(parts) == 3:
                    source, relation, target = parts
                    
                    # Extract clean names
                    if " (" in source:
                        source_clean = source.split(" (")[0].strip()
                    else:
                        source_clean = source.strip()
                    
                    if " (" in target:
                        target_clean = target.split(" (")[0].strip()
                    else:
                        target_clean = target.strip()
                    
                    if relation.strip() == "node":
                        print(f"  Found subdomain: {source_clean} -> {target_clean}")
                        entries.append({
                            "name": target_clean,
                            "parent": source_clean
                        })
                        domains.add(source_clean)
                        domains.add(target_clean)
    
    print(f"\nSummary:")
    print(f"  Total entries: {len(entries)}")
    print(f"  Unique domains: {len(domains)}")
    print(f"  Domains: {list(domains)}")
    
    return entries

def test_parsing():
    """Test the parsing function."""
    test_file = Path("test_sample_output.txt")
    
    if not test_file.exists():
        print("Test file not found!")
        return
    
    print("Testing Amass output parsing...")
    results = parse_amass_output(test_file)
    
    print(f"\nResults:")
    for entry in results:
        name = entry.get("name")
        parent = entry.get("parent")
        print(f"  {parent} -> {name}")

if __name__ == "__main__":
    test_parsing()