#!/usr/bin/env python3

import json
import requests
from datetime import datetime, timezone

def analyze_stuck_tasks():
    """Analyze tasks stuck at 90% for more than 20 hours"""
    
    # Fetch current tasks
    try:
        response = requests.get('http://localhost:8001/api/v1/tasks')
        response.raise_for_status()
        data = response.json()
        tasks = data.get('tasks', [])
    except Exception as e:
        print(f"Error fetching tasks: {e}")
        return
    
    now = datetime.now(timezone.utc)
    stuck_tasks = []
    
    print("ANALYSIS OF TASKS STUCK AT 90% FOR MORE THAN 20 HOURS")
    print("=" * 80)
    print()
    
    for task in tasks:
        if task['progress'] >= 90 and task['status'] == 'running':
            try:
                started = datetime.fromisoformat(task['started_at'])
                duration = now - started
                hours = duration.total_seconds() / 3600
                
                if hours > 20:
                    stuck_tasks.append({
                        'task': task,
                        'duration_hours': hours
                    })
                    
                    print(f"🔴 STUCK TASK FOUND:")
                    print(f"   Task ID: {task['task_id']}")
                    print(f"   Type: {task['task_type']}")
                    print(f"   Domain: {task['domain']}")
                    print(f"   Status: {task['status']}")
                    print(f"   Progress: {task['progress']}%")
                    print(f"   Started: {task['started_at']}")
                    print(f"   Duration: {hours:.1f} hours")
                    
                    # Analyze specific issues
                    analyze_task_issue(task)
                    print("-" * 60)
                    print()
            except Exception as e:
                print(f"Error processing task {task.get('task_id', 'unknown')}: {e}")
    
    if not stuck_tasks:
        print("✅ No tasks found stuck at 90% for more than 20 hours")
        return
    
    print(f"\n📊 SUMMARY:")
    print(f"   Total stuck tasks: {len(stuck_tasks)}")
    print(f"   Average duration: {sum(t['duration_hours'] for t in stuck_tasks) / len(stuck_tasks):.1f} hours")
    
    # Recommend actions
    print(f"\n🔧 RECOMMENDED ACTIONS:")
    for i, stuck_task in enumerate(stuck_tasks, 1):
        task = stuck_task['task']
        print(f"   {i}. Task {task['task_id'][:8]}... ({task['domain']}):")
        recommend_action(task)
    
    return stuck_tasks

def analyze_task_issue(task):
    """Analyze what might be wrong with a specific task"""
    task_type = task.get('task_type', '')
    logs = task.get('logs', '')
    domain = task.get('domain', '')
    
    if task_type == 'batch_analysis' and 'bice.cl' in domain:
        if 'zabbix.bice.cl (133/133)' in logs:
            print(f"   🚨 ISSUE: Task completed all 133 subdomains but failed to update status to 'completed'")
            print(f"   📝 Last log entry shows completion of final subdomain (zabbix.bice.cl)")
            print(f"   🔧 Likely issue: Final status update or result saving failed")
        else:
            print(f"   🚨 ISSUE: Task may be stuck in processing loop")
    
    elif task_type == 'web_scraping':
        if 'Web scraping analysis completed' in logs:
            print(f"   🚨 ISSUE: Web scraping completed but stuck at 90%")
            print(f"   🔧 Likely issue: Final status update or result saving failed")
    
    elif task_type == 'batch_analysis' and domain in ['test.com', 'test-fix.example']:
        if '(1/1)' in logs:
            print(f"   🚨 ISSUE: Single domain analysis completed but stuck at 90%")
            print(f"   🔧 Likely issue: Final status update failed for simple domain")

def recommend_action(task):
    """Recommend specific action for a stuck task"""
    task_id = task['task_id']
    task_type = task.get('task_type', '')
    
    if task_type == 'batch_analysis':
        print(f"      - Force complete task: PATCH /api/v1/tasks/{task_id} {{\"status\": \"completed\", \"progress\": 100}}")
        print(f"      - Or restart task: POST /api/v1/discover/batch-analysis/{task['domain']}")
    elif task_type == 'web_scraping':
        print(f"      - Force complete task: PATCH /api/v1/tasks/{task_id} {{\"status\": \"completed\", \"progress\": 100}}")
        print(f"      - Or restart scraping: POST /api/v1/discover/web-scraping/{task['domain']}")
    else:
        print(f"      - Manual intervention required for task type: {task_type}")

def fix_stuck_tasks():
    """Attempt to automatically fix stuck tasks"""
    stuck_tasks = analyze_stuck_tasks()
    
    if not stuck_tasks:
        return
    
    print(f"\n🔧 ATTEMPTING TO FIX STUCK TASKS...")
    
    for stuck_task in stuck_tasks:
        task = stuck_task['task']
        task_id = task['task_id']
        
        # Check if task actually completed but status wasn't updated
        logs = task.get('logs', '')
        should_complete = False
        
        # Determine if task should be marked as completed
        if task.get('task_type') == 'batch_analysis':
            if 'bice.cl' in task.get('domain', '') and 'zabbix.bice.cl (133/133)' in logs:
                should_complete = True
            elif task.get('domain') in ['test.com', 'test-fix.example'] and '(1/1)' in logs:
                should_complete = True
        elif task.get('task_type') == 'web_scraping' and 'Web scraping analysis completed' in logs:
            should_complete = True
        
        if should_complete:
            try:
                # Try to update task status
                update_url = f'http://localhost:8001/api/v1/tasks/{task_id}'
                update_data = {
                    'status': 'completed',
                    'progress': 100,
                    'completed_at': datetime.now(timezone.utc).isoformat()
                }
                
                print(f"   Attempting to complete task {task_id[:8]}... for {task.get('domain')}")
                
                # This would be the actual fix - but we need to check if the API supports PATCH
                # For now, just report what should be done
                print(f"   ⚠️  Manual fix needed: PATCH {update_url} with data: {update_data}")
                
            except Exception as e:
                print(f"   ❌ Failed to fix task {task_id[:8]}...: {e}")
        else:
            print(f"   ⚠️  Task {task_id[:8]}... requires manual investigation")

if __name__ == "__main__":
    try:
        fix_stuck_tasks()
    except KeyboardInterrupt:
        print("\n⚠️  Analysis interrupted by user")
    except Exception as e:
        print(f"❌ Error during analysis: {e}")