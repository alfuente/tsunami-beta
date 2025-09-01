#!/usr/bin/env python3
"""
Launch script for the Async Risk Analysis API
"""

import uvicorn
from config import config

if __name__ == "__main__":
    uvicorn.run(
        "async_api:app",
        host=config.host,
        port=config.async_port,
        reload=config.debug,
        log_level="debug" if config.debug else "info",
        access_log=True
    )