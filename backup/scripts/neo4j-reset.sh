#!/bin/bash
echo "Resetting Neo4j database..."
curl -X POST http://localhost:7474/db/data/transaction/commit -H "Content-Type: application/json" \
  -d '{"statements": [{"statement": "MATCH (n) DETACH DELETE n"}]}'
