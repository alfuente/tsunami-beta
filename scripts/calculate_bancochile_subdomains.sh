#!/bin/bash

# Script para analizar y calcular risk scores de subdominios bancochile.cl
echo "🔥 Starting comprehensive analysis for bancochile.cl subdomains..."

# Subdominios importantes para analizar
SUBDOMAINS=(
    "www.bancochile.cl"
    "portal.bancochile.cl"
    "portalpersonas.bancochile.cl"
    "portalempresas.bancochile.cl"
    "api.bancochile.cl"
    "mail.bancochile.cl"
    "login.bancochile.cl"
    "extranet.bancochile.cl"
    "servicios.bancochile.cl"
    "online.bancochile.cl"
)

BASE_URL_DOMAIN="http://localhost:8001/api/v1/discover"
BASE_URL_RISK="http://localhost:8081/api/v1/calculations/domain"

echo "📊 Step 1: Running service discovery for active subdomains..."
for subdomain in "${SUBDOMAINS[@]}"; do
    echo "  🔍 Analyzing services for: $subdomain"
    curl -s -X POST "$BASE_URL_DOMAIN/services/bancochile.cl?subdomain=$subdomain" > /dev/null
    sleep 2
done

echo ""
echo "⏳ Waiting 30 seconds for service discovery to complete..."
sleep 30

echo ""
echo "🔐 Step 2: Running technology analysis for active subdomains..."
for subdomain in "${SUBDOMAINS[@]}"; do
    echo "  💻 Analyzing technology for: $subdomain"
    curl -s -X POST "$BASE_URL_DOMAIN/tech/bancochile.cl?subdomain=$subdomain" > /dev/null
    sleep 2
done

echo ""
echo "⏳ Waiting 20 seconds for technology analysis to complete..."
sleep 20

echo ""
echo "🌍 Step 3: Running DNS analysis for subdomains..."
for subdomain in "${SUBDOMAINS[@]}"; do
    echo "  🌐 Analyzing DNS for: $subdomain"
    curl -s -X POST "$BASE_URL_DOMAIN/dns/bancochile.cl?subdomain=$subdomain" > /dev/null
    sleep 1
done

echo ""
echo "⏳ Waiting 15 seconds for DNS analysis to complete..."
sleep 15

echo ""
echo "🎯 Step 4: Calculating risk scores..."
for subdomain in "${SUBDOMAINS[@]}"; do
    echo "  ⚖️  Calculating risk for: $subdomain"
    result=$(curl -s -X POST "$BASE_URL_RISK/$subdomain")
    status=$(echo "$result" | jq -r '.status // "ERROR"')
    echo "    Status: $status"
    sleep 1
done

echo ""
echo "✅ Step 5: Verifying results..."
for subdomain in "${SUBDOMAINS[@]}"; do
    result=$(curl -s "http://localhost:8081/api/v1/domains/$subdomain")
    risk_score=$(echo "$result" | jq -r '.risk_score // 0')
    risk_tier=$(echo "$result" | jq -r '.risk_tier // "Unknown"')
    last_calculated=$(echo "$result" | jq -r '.last_calculated // "Never"')
    
    echo "  📈 $subdomain: Score=$risk_score, Tier=$risk_tier, Calculated=$last_calculated"
done

echo ""
echo "🎉 Analysis complete! Check the risk dashboard to see updated scores."