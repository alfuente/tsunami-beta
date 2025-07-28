#!/usr/bin/env python3
"""
Demo script for Risk Query CLI
"""

import subprocess
import time
import sys
import os

def run_command(cmd, description):
    """Run a command and show output"""
    print(f"\n{'='*60}")
    print(f"📋 {description}")
    print(f"🔧 Command: {cmd}")
    print('='*60)
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("⏱️  Command timed out")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    """Demo the CLI functionality"""
    print("🚀 Risk Query CLI Demo")
    
    # Change to the right directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    # Activate virtual environment and run commands
    base_cmd = "source venv/bin/activate && python risk_query_cli.py"
    
    commands = [
        (f"{base_cmd} --help", "Show CLI help"),
        (f"{base_cmd} --providers", "Show available AI providers"),
        (f"{base_cmd} --examples", "Show example queries"),
    ]
    
    for cmd, desc in commands:
        success = run_command(cmd, desc)
        time.sleep(1)
    
    print(f"\n{'='*60}")
    print("✅ CLI Demo Complete!")
    print("="*60)
    print("🎯 Next steps:")
    print("1. Try a real query: python risk_query_cli.py \"show high risk domains\"")
    print("2. Use --verbose for detailed output")
    print("3. Use --raw for JSON output")
    print("4. Configure different AI providers in config.yaml")

if __name__ == "__main__":
    main()