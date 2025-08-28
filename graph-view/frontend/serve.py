#!/usr/bin/env python3
"""
Simple HTTP server to serve the graph visualization frontend
"""

import http.server
import socketserver
import webbrowser
import os
import sys
from pathlib import Path

# Change to the directory containing this script
os.chdir(Path(__file__).parent)

PORT = 8083
Handler = http.server.SimpleHTTPRequestHandler

print("🌊 Starting Tsunami Graph Visualization Frontend...")
print(f"📁 Serving files from: {os.getcwd()}")
print(f"🌐 Server running on: http://localhost:{PORT}")
print("🔗 Opening browser automatically...")

try:
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        # Try to open browser
        try:
            webbrowser.open(f'http://localhost:{PORT}')
        except Exception as e:
            print(f"Could not open browser automatically: {e}")
        
        print(f"✅ Frontend server ready! Visit: http://localhost:{PORT}")
        print("Press Ctrl+C to stop the server")
        httpd.serve_forever()
        
except KeyboardInterrupt:
    print("\n🛑 Server stopped by user")
    sys.exit(0)
except Exception as e:
    print(f"❌ Error starting server: {e}")
    sys.exit(1)