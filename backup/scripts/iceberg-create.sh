#!/bin/bash
echo "Creating Iceberg schema..."
curl -X POST http://localhost:8081/iceberg/create
