#!/bin/bash
echo "Creating full stack (Neo4j + Iceberg)..."
bash ./neo4j-create.sh
bash ./iceberg-create.sh
