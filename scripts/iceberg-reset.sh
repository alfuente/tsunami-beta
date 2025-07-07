#!/bin/bash
echo "Resetting Iceberg data..."
curl -X POST http://localhost:8081/iceberg/reset
