#!/usr/bin/env python3

import requests
import json
import time

def test_bancochile_analysis():
    """Test complete analysis for bancochile.cl"""
    
    print("Testing bancochile.cl analysis...")
    
    # Start complete analysis
    url = "http://localhost:8001/domains/bancochile.cl/analyze"
    
    try:
        response = requests.post(url, json={"include_amass": True}, timeout=30)
        print(f"Analysis request status: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            task_id = result.get('task_id')
            print(f"Task ID: {task_id}")
            
            if task_id:
                # Monitor task for a few minutes
                for i in range(20):  # Check for 20 iterations (10 minutes max)
                    task_url = f"http://localhost:8001/tasks/{task_id}"
                    try:
                        task_response = requests.get(task_url, timeout=10)
                        if task_response.status_code == 200:
                            task_data = task_response.json()
                            status = task_data.get('status', 'unknown')
                            progress = task_data.get('progress', 0)
                            error = task_data.get('error', None)
                            
                            print(f"Iteration {i+1}: Status={status}, Progress={progress}%")
                            if error:
                                print(f"ERROR: {error}")
                                break
                            
                            if status in ['completed', 'failed']:
                                print(f"Task finished with status: {status}")
                                if status == 'completed':
                                    print("Analysis successful!")
                                else:
                                    print("Analysis failed!")
                                break
                        else:
                            print(f"Task status check failed: {task_response.status_code}")
                    except Exception as e:
                        print(f"Error checking task: {e}")
                    
                    time.sleep(30)  # Wait 30 seconds between checks
        else:
            print(f"Failed to start analysis: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error starting analysis: {e}")

if __name__ == "__main__":
    test_bancochile_analysis()