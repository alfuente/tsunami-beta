#!/bin/bash

# Risk Analysis Async API Startup Script
# This script starts the asynchronous Risk Analysis API

echo "🚀 Starting Async Risk Analysis API..."

# Set working directory
cd "$(dirname "$0")"

# Check if Python environment exists
if [ ! -d "venv" ]; then
    echo "⚠️ Virtual environment not found. Creating one..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "📦 Activating virtual environment..."
source venv/bin/activate

# Install/update dependencies
echo "📋 Installing dependencies..."
pip install fastapi uvicorn psycopg2-binary neo4j networkx numpy scikit-learn pydantic

# Set environment variables for development
export DEBUG=true
export NEO4J_URI=${NEO4J_URI:-"bolt://localhost:7687"}
export NEO4J_USER=${NEO4J_USER:-"neo4j"}
export NEO4J_PASSWORD=${NEO4J_PASSWORD:-"test.password"}
export POSTGRES_HOST=${POSTGRES_HOST:-"localhost"}
export POSTGRES_PORT=${POSTGRES_PORT:-"5432"}
export POSTGRES_DB=${POSTGRES_DB:-"tsunami_backend"}
export POSTGRES_USER=${POSTGRES_USER:-"tsunami_user"}
export POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-"tsunami_password"}
export ASYNC_PORT=${ASYNC_PORT:-"8003"}

echo "🔧 Environment configured:"
echo "  - Neo4j URI: $NEO4J_URI"
echo "  - PostgreSQL: $POSTGRES_HOST:$POSTGRES_PORT/$POSTGRES_DB"
echo "  - Async API Port: $ASYNC_PORT"

# Check if Neo4j is running
echo "🔍 Checking Neo4j connection..."
python3 -c "
from neo4j import GraphDatabase
import os
try:
    driver = GraphDatabase.driver(
        os.getenv('NEO4J_URI', 'bolt://localhost:7687'),
        auth=(os.getenv('NEO4J_USER', 'neo4j'), os.getenv('NEO4J_PASSWORD', 'test.password'))
    )
    with driver.session() as session:
        session.run('RETURN 1')
    print('✅ Neo4j connection successful')
    driver.close()
except Exception as e:
    print(f'❌ Neo4j connection failed: {e}')
    exit(1)
"

# Check if PostgreSQL is running
echo "🔍 Checking PostgreSQL connection..."
python3 -c "
import psycopg2
import os
try:
    conn = psycopg2.connect(
        host=os.getenv('POSTGRES_HOST', 'localhost'),
        port=os.getenv('POSTGRES_PORT', '5432'),
        database=os.getenv('POSTGRES_DB', 'tsunami_backend'),
        user=os.getenv('POSTGRES_USER', 'tsunami_user'),
        password=os.getenv('POSTGRES_PASSWORD', 'tsunami_password')
    )
    conn.close()
    print('✅ PostgreSQL connection successful')
except Exception as e:
    print(f'❌ PostgreSQL connection failed: {e}')
    exit(1)
"

# Start the async API
echo "🎯 Starting Async Risk Analysis API on port $ASYNC_PORT..."
echo "📊 API Documentation will be available at: http://localhost:$ASYNC_PORT/docs"
echo "📈 Risk Analysis Monitor will be available at: http://localhost:8080/risk-analysis.html"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python3 launch_async_api.py