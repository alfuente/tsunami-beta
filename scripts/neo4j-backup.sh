#!/bin/bash
echo "Backing up Neo4j database..."
mkdir -p backups

# Check if databases exist
if docker run --rm -v neo4j-data:/data neo4j:2025.06.0 ls /data/databases/ | grep -q .; then
    echo "Stopping Neo4j container..."
    docker stop neo4j
    
    echo "Creating database dump..."
    docker run --rm -v neo4j-data:/data -v $(pwd)/backups:/backup neo4j:2025.06.0 \
        neo4j-admin database dump neo4j --to-path=/backup 
    
    echo "Starting Neo4j container..."
    docker start neo4j
    echo "Neo4j backup completed successfully!"
else
    echo "No databases found to backup. Neo4j may not have been initialized yet."
fi
