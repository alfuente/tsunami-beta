#!/usr/bin/env python3
"""
Simple launcher for Risk Stats API that handles imports correctly
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

# Now import and run the API
from api import main

if __name__ == "__main__":
    main()
