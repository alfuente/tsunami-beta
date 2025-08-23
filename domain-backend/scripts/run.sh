#!/bin/bash
domain=$1

curl -X 'POST' \
  'http://localhost:8001/api/v1/discover/all-subdomains/'${domain}'?amass_timeout=3000&max_subdomains=1000&max_workers=10&timeout_per_subdomain=300&save_to_neo4j=true&analysis_type=all' \
  -H 'accept: application/json' \
  -d ''
