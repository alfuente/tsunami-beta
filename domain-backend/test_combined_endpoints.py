#!/usr/bin/env python3
"""
Test script for the new combined discovery endpoints
"""
import requests
import time
import json

BASE_URL = "http://localhost:8001"

def test_combined_discovery():
    """Test the combined discovery endpoint for a single domain"""
    print("=== Testing Combined Discovery Endpoint ===")
    
    url = f"{BASE_URL}/api/v1/discover/combined/example.com"
    params = {
        "include_services": True,
        "include_dns": True,
        "include_mx": True,
        "include_tls": True,
        "include_tech": False  # Disable tech to speed up test
    }
    
    try:
        print(f"POST {url}")
        print(f"Parameters: {params}")
        response = requests.post(url, params=params)
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"Task ID: {result.get('task_id')}")
            print(f"Domain: {result.get('domain')}")
            print(f"Target: {result.get('target')}")
            print(f"Analysis Types: {json.dumps(result.get('analysis_types'), indent=2)}")
            
            # Check task status
            task_id = result.get('task_id')
            if task_id:
                print(f"\nChecking task status...")
                status_url = f"{BASE_URL}/api/v1/tasks/{task_id}/status"
                status_response = requests.get(status_url)
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    print(f"Task Status: {status_data.get('status')}")
                    print(f"Progress: {status_data.get('progress', 0)}%")
                
        else:
            print(f"Error: {response.text}")
            
    except Exception as e:
        print(f"Error: {e}")
    
    print()

def test_combined_recursive_discovery():
    """Test the combined recursive discovery endpoint"""
    print("=== Testing Combined Recursive Discovery Endpoint ===")
    print("Note: This uses existing subdomains from Neo4j, not Amass discovery")
    
    url = f"{BASE_URL}/api/v1/discover/combined-recursive/example.com"
    params = {
        "max_subdomains": 5,  # Limit subdomains for testing
        "include_services": True,
        "include_dns": True,
        "include_mx": True,
        "include_tls": False,  # Disable to speed up test
        "include_tech": False  # Disable to speed up test
    }
    
    try:
        print(f"POST {url}")
        print(f"Parameters: {params}")
        response = requests.post(url, params=params)
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"Task ID: {result.get('task_id')}")
            print(f"Domain: {result.get('domain')}")
            print(f"Data Source: {result.get('data_source')}")
            print(f"Max Subdomains: {result.get('max_subdomains')}")
            print(f"Analysis Types: {json.dumps(result.get('analysis_types'), indent=2)}")
            
            # Check task status
            task_id = result.get('task_id')
            if task_id:
                print(f"\nChecking task status...")
                status_url = f"{BASE_URL}/api/v1/tasks/{task_id}/status"
                status_response = requests.get(status_url)
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    print(f"Task Status: {status_data.get('status')}")
                    print(f"Progress: {status_data.get('progress', 0)}%")
                
        else:
            print(f"Error: {response.text}")
            
    except Exception as e:
        print(f"Error: {e}")
    
    print()

def test_api_health():
    """Test if API is running"""
    try:
        response = requests.get(f"{BASE_URL}/health")
        return response.status_code == 200
    except:
        return False

def main():
    print("Testing Combined Discovery API Endpoints")
    print("=" * 50)
    
    if not test_api_health():
        print("❌ API is not running at http://localhost:8001")
        print("Please start the API first with:")
        print("cd domain-backend && ./venv/bin/python async_domain_discovery_api.py")
        return
    
    print("✅ API is running\n")
    
    # Test both endpoints
    test_combined_discovery()
    test_combined_recursive_discovery()
    
    print("Testing completed!")
    print("\nAPI Documentation available at:")
    print(f"- Swagger UI: {BASE_URL}/docs")
    print(f"- ReDoc: {BASE_URL}/redoc")

if __name__ == "__main__":
    main()