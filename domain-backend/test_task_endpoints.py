#!/usr/bin/env python3
"""
Test script for the updated task endpoints that fetch from database
"""
import requests
import json
import time

BASE_URL = "http://localhost:8081"

def test_get_all_tasks():
    """Test getting all tasks from database"""
    print("=== Testing GET /api/v1/tasks ===")
    
    try:
        url = f"{BASE_URL}/api/v1/tasks"
        print(f"GET {url}")
        
        response = requests.get(url)
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            tasks = data.get('tasks', [])
            print(f"Found {len(tasks)} tasks in database")
            
            if tasks:
                print("\nFirst few tasks:")
                for i, task in enumerate(tasks[:3]):
                    print(f"  {i+1}. {task.get('task_id')[:8]}... - {task.get('task_type')} - {task.get('status')} - {task.get('domain')}")
            
            return tasks
        else:
            print(f"Error: {response.text}")
            return []
            
    except Exception as e:
        print(f"Error: {e}")
        return []
    
    print()

def test_get_task_by_id(task_id):
    """Test getting a specific task by ID"""
    print(f"=== Testing GET /api/v1/tasks/{task_id[:8]}... ===")
    
    try:
        url = f"{BASE_URL}/api/v1/tasks/{task_id}"
        print(f"GET {url}")
        
        response = requests.get(url)
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            task = response.json()
            print(f"Task ID: {task.get('task_id')}")
            print(f"Type: {task.get('task_type')}")
            print(f"Domain: {task.get('domain')}")
            print(f"Status: {task.get('status')}")
            print(f"Progress: {task.get('progress')}%")
            print(f"Started: {task.get('started_at')}")
            if task.get('completed_at'):
                print(f"Completed: {task.get('completed_at')}")
            
        else:
            print(f"Error: {response.text}")
            
    except Exception as e:
        print(f"Error: {e}")
    
    print()

def test_get_task_logs(task_id):
    """Test getting task logs"""
    print(f"=== Testing GET /api/v1/tasks/{task_id[:8]}.../logs ===")
    
    try:
        url = f"{BASE_URL}/api/v1/tasks/{task_id}/logs"
        print(f"GET {url}")
        
        response = requests.get(url)
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            logs = data.get('logs', 'No logs available')
            print(f"Logs length: {len(logs)} characters")
            if logs:
                print("First 200 characters of logs:")
                print("-" * 40)
                print(logs[:200])
                if len(logs) > 200:
                    print("... (truncated)")
                print("-" * 40)
            
        else:
            print(f"Error: {response.text}")
            
    except Exception as e:
        print(f"Error: {e}")
    
    print()

def test_tasks_with_filters():
    """Test task filtering"""
    print("=== Testing Task Filtering ===")
    
    statuses = ['running', 'completed', 'failed', 'pending']
    
    for status in statuses:
        try:
            url = f"{BASE_URL}/api/v1/tasks"
            params = {'status': status, 'limit': 10}
            
            print(f"GET {url} with status={status}")
            response = requests.get(url, params=params)
            
            if response.status_code == 200:
                data = response.json()
                tasks = data.get('tasks', [])
                print(f"  Found {len(tasks)} {status} tasks")
            else:
                print(f"  Error: {response.text}")
                
        except Exception as e:
            print(f"  Error: {e}")
    
    print()

def test_api_health():
    """Test if API is running"""
    try:
        response = requests.get(f"{BASE_URL}/health")
        return response.status_code == 200
    except:
        return False

def main():
    print("Testing Updated Task API Endpoints (Database-backed)")
    print("=" * 60)
    
    if not test_api_health():
        print("❌ API is not running at http://localhost:8081")
        print("Please start the API first with:")
        print("cd domain-backend && ./venv/bin/python async_domain_discovery_api.py")
        return
    
    print("✅ API is running\n")
    
    # Test basic task listing
    tasks = test_get_all_tasks()
    
    # Test filtering
    test_tasks_with_filters()
    
    # If we have tasks, test getting specific task details
    if tasks:
        first_task_id = tasks[0]['task_id']
        test_get_task_by_id(first_task_id)
        test_get_task_logs(first_task_id)
    else:
        print("No tasks found in database to test individual endpoints")
        print("You may want to run some analysis tasks first")
    
    print("Task endpoint testing completed!")
    print("\nUpdated UI should now show tasks from PostgreSQL database")
    print("Start the React dashboard to see the changes:")
    print("cd ../risk-dashboard && npm start")

if __name__ == "__main__":
    main()