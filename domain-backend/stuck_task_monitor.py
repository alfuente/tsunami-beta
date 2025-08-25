#!/usr/bin/env python3
"""
Stuck Task Monitor - Runs every 5 minutes to detect and fix stuck tasks
"""

import requests
import time
import json
from datetime import datetime
import sqlite3

def monitor_and_fix():
    """Monitor for stuck tasks and fix them"""
    try:
        # Get current tasks
        response = requests.get("http://localhost:8001/api/v1/tasks", timeout=10)
        if response.status_code != 200:
            return
        
        tasks = response.json().get('tasks', [])
        current_time = datetime.now()
        fixed_count = 0
        
        for task in tasks:
            if task['progress'] >= 90 and task['status'] == 'running':
                started = datetime.fromisoformat(task['started_at'].replace('Z', '+00:00'))
                duration = (current_time - started.replace(tzinfo=None)).total_seconds() / 3600
                
                if duration > 2:  # Stuck for more than 2 hours
                    print(f"Detected stuck task: {task['task_id'][:8]}... ({task['domain']}) - {duration:.1f}h")
                    
                    # Check if task appears complete
                    logs = task.get('logs', '')
                    task_type = task.get('task_type', '')
                    domain = task.get('domain', '')
                    
                    should_fix = False
                    if task_type == 'batch_analysis':
                        if 'bice.cl' in domain and 'zabbix.bice.cl (133/133)' in logs:
                            should_fix = True
                        elif domain in ['test.com', 'test-fix.example'] and '(1/1)' in logs:
                            should_fix = True
                    elif task_type == 'web_scraping' and 'Web scraping analysis completed' in logs:
                        should_fix = True
                    
                    if should_fix:
                        # Fix in database
                        conn = sqlite3.connect('tasks.db')
                        cursor = conn.cursor()
                        cursor.execute("""
                            INSERT OR REPLACE INTO tasks 
                            (task_id, task_type, domain, status, progress, completed_at, updated_at)
                            VALUES (?, ?, ?, 'completed', 100, ?, ?)
                        """, (
                            task['task_id'],
                            task['task_type'],
                            task['domain'],
                            datetime.now().isoformat(),
                            datetime.now().isoformat()
                        ))
                        conn.commit()
                        conn.close()
                        
                        print(f"Fixed stuck task: {task['task_id'][:8]}...")
                        fixed_count += 1
        
        if fixed_count > 0:
            print(f"Fixed {fixed_count} stuck tasks at {datetime.now()}")
        
    except Exception as e:
        print(f"Monitor error: {e}")

if __name__ == "__main__":
    print(f"Starting stuck task monitor at {datetime.now()}")
    monitor_and_fix()
