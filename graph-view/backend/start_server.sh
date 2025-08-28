#!/bin/bash

# Graph Visualization API Startup Script

echo "🌊 Starting Tsunami Graph Visualization API..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Check Neo4j connection
echo "Checking Neo4j connection..."
python3 -c "
from neo4j import GraphDatabase
try:
    driver = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', 'test.password'))
    with driver.session() as session:
        result = session.run('RETURN 1')
        result.single()
    print('✅ Neo4j connection successful')
    driver.close()
except Exception as e:
    print(f'❌ Neo4j connection failed: {e}')
    exit(1)
"

# Start the API server
echo "Starting Graph Visualization API on port 8082..."
python3 graph_visualization_api.py