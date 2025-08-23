#!/bin/bash

subdomains=("www.bancochile.cl" "portal.bancochile.cl" "api.bancochile.cl" "portalpersonas.bancochile.cl" "portalempresas.bancochile.cl" "mail.bancochile.cl")

echo "🎯 Calculating individual risk scores..."

for subdomain in "${subdomains[@]}"; do
    echo "🔄 Calculating risk for: $subdomain"
    result=$(curl -s -X POST "http://localhost:8081/api/v1/calculations/domain/$subdomain")
    status=$(echo "$result" | jq -r '.status // "ERROR"')
    echo "   Status: $status"
    sleep 1
done

echo ""
echo "✅ Verifying results..."

for subdomain in "${subdomains[@]}"; do
    result=$(curl -s "http://localhost:8081/api/v1/domains/$subdomain")
    risk_score=$(echo "$result" | jq -r '.risk_score // 0')
    risk_tier=$(echo "$result" | jq -r '.risk_tier // "Unknown"')
    last_calculated=$(echo "$result" | jq -r '.last_calculated // "Never"')
    
    echo "📈 $subdomain: Score=$risk_score, Tier=$risk_tier"
done