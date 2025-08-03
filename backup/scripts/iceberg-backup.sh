#!/bin/bash
echo "Backing up Iceberg data..."
cp -r /warehouse/data /backups/iceberg_$(date +%F)
