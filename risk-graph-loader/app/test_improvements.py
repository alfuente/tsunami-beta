#!/usr/bin/env python3
"""
Script para probar todas las mejoras implementadas
"""

import subprocess
import sys
import time

def run_test(description, command, expected_keywords=None):
    """Run a test command and verify output"""
    print(f"\n🧪 {description}")
    print("-" * 60)
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
        
        print(f"Exit code: {result.returncode}")
        if result.stdout:
            lines = result.stdout.split('\n')
            print("STDOUT (last 10 lines):")
            for line in lines[-10:]:
                if line.strip():
                    print(f"  {line}")
        
        if result.stderr:
            print("STDERR:")
            print(f"  {result.stderr[:500]}...")
        
        # Check for expected keywords if provided
        if expected_keywords:
            output = result.stdout + result.stderr
            found_keywords = []
            missing_keywords = []
            
            for keyword in expected_keywords:
                if keyword in output:
                    found_keywords.append(keyword)
                else:
                    missing_keywords.append(keyword)
            
            print(f"\n✅ Found keywords: {found_keywords}")
            if missing_keywords:
                print(f"❌ Missing keywords: {missing_keywords}")
            else:
                print("🎉 All expected keywords found!")
        
        return result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print("❌ Test timed out after 5 minutes")
        return False
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        return False

def main():
    print("🚀 TESTING ALL IMPROVEMENTS")
    print("=" * 60)
    
    tests = [
        {
            "description": "Test 1: Help shows new parameters",
            "command": "python3 subdomain_relationship_discovery_v4.py --help",
            "expected": ["--tls-timeout", "--tls-retries", "--discovery-depth"]
        },
        {
            "description": "Test 2: Single domain with enhanced TLS timeout", 
            "command": "python3 single_domain_test.py google.com --password test.password",
            "expected": ["TLS attempt", "Discovery completed", "Analysis completed"]
        },
        {
            "description": "Test 3: Script with new parameters (dry run)",
            "command": "echo 'google.com' > test_single.txt && python3 subdomain_relationship_discovery_v4.py --domains test_single.txt --password test.password --tls-timeout 60 --tls-retries 3 --discovery-depth 3 --phase1-only",
            "expected": ["Enhanced Subdomain Processor", "Phase 1", "discovery completed"]
        }
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        success = run_test(
            test["description"], 
            test["command"], 
            test.get("expected")
        )
        
        if success:
            passed += 1
            print("✅ PASSED")
        else:
            failed += 1 
            print("❌ FAILED")
    
    print(f"\n📊 FINAL RESULTS")
    print("=" * 60)
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"📈 Success rate: {passed}/{passed + failed} ({100 * passed / (passed + failed):.1f}%)")
    
    if failed == 0:
        print("\n🎉 ALL IMPROVEMENTS WORKING CORRECTLY!")
    else:
        print(f"\n⚠️ {failed} tests failed - review implementation")

if __name__ == "__main__":
    main()