#!/bin/bash
echo "Resetting full stack..."
bash ./neo4j-reset.sh
bash ./iceberg-reset.sh
