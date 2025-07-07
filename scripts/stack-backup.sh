#!/bin/bash
echo "Backing up full stack..."
bash ./neo4j-backup.sh
bash ./iceberg-backup.sh
