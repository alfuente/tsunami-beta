#!/bin/bash
# Setup cron job to run stuck task monitor every 5 minutes

echo "Setting up stuck task monitor cron job..."

# Add to crontab (runs every 5 minutes)
(crontab -l 2>/dev/null; echo "*/5 * * * * cd /home/alf/dev/tsunami-beta/domain-backend && python3 stuck_task_monitor.py >> monitor.log 2>&1") | crontab -

echo "✅ Stuck task monitor cron job installed"
echo "Monitor will run every 5 minutes"
echo "Check monitor.log for activity"
