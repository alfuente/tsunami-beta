#!/bin/bash
# Domain completion script - CRITICAL priority
# Generated: 2025-08-30T12:32:11.449975
# Total domains: 892
# Estimated time: 48065 minutes

set -e  # Exit on error
set -u  # Exit on undefined variable

# Configuration
API_BASE="http://localhost:8001"
DELAY_BETWEEN_CALLS=2  # seconds
MAX_RETRIES=3
TIMEOUT=30  # seconds

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Retry function
retry_curl() {
    local url="$1"
    local retries=0
    
    while [ $retries -lt $MAX_RETRIES ]; do
        log "Attempting: $url (attempt $((retries+1))/$MAX_RETRIES)"
        
        if curl -s -X POST --max-time $TIMEOUT -H 'accept: application/json' -d '' "$url"; then
            log "Success: $url"
            sleep 1  # Brief pause after successful call
            return 0
        else
            log "Failed: $url (attempt $((retries+1)))"
            retries=$((retries+1))
            sleep $((DELAY_BETWEEN_CALLS * retries))  # Exponential backoff
        fi
    done
    
    log "ERROR: Failed all attempts for: $url"
    return 1
}

log "Starting CRITICAL priority domain completion"
log "Processing 892 domains"

# Domain 1/892: dvacapital.cl
log "Processing domain 1/892: dvacapital.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/dvacapital.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/dvacapital.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/dvacapital.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/dvacapital.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: dvacapital.cl"
echo "---"

# Domain 2/892: provida.cl
log "Processing domain 2/892: provida.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/provida.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/provida.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/provida.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/provida.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: provida.cl"
echo "---"

# Domain 3/892: hsbc.cl
log "Processing domain 3/892: hsbc.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/hsbc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/hsbc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/hsbc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/hsbc.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: hsbc.cl"
echo "---"

# Domain 4/892: fintonic.cl
log "Processing domain 4/892: fintonic.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/fintonic.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/fintonic.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/fintonic.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/fintonic.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: fintonic.cl"
echo "---"

# Domain 5/892: lautarorosas.cl
log "Processing domain 5/892: lautarorosas.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/lautarorosas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/lautarorosas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/lautarorosas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/lautarorosas.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: lautarorosas.cl"
echo "---"

# Domain 6/892: example.cl
log "Processing domain 6/892: example.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/example.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/example.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/example.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/example.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/example.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/example.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/example.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: example.cl"
echo "---"

# Domain 7/892: jquery.com
log "Processing domain 7/892: jquery.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/jquery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/jquery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/jquery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/jquery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/jquery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/jquery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/jquery.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: jquery.com"
echo "---"

# Domain 8/892: www.bancochile.cl
log "Processing domain 8/892: www.bancochile.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.bancochile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.bancochile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.bancochile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.bancochile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.bancochile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.bancochile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.bancochile.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.bancochile.cl"
echo "---"

# Domain 9/892: www.bci.cl
log "Processing domain 9/892: www.bci.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.bci.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.bci.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.bci.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.bci.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.bci.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.bci.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.bci.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.bci.cl"
echo "---"

# Domain 10/892: www.sii.cl
log "Processing domain 10/892: www.sii.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.sii.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.sii.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.sii.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.sii.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.sii.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.sii.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.sii.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.sii.cl"
echo "---"

# Domain 11/892: achs.cl
log "Processing domain 11/892: achs.cl"
log "Estimated time: 50 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/achs.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/achs.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/achs.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/achs.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/achs.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/achs.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: achs.cl"
echo "---"

# Domain 12/892: www.achs.cl
log "Processing domain 12/892: www.achs.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.achs.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.achs.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.achs.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.achs.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.achs.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.achs.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.achs.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.achs.cl"
echo "---"

# Domain 13/892: webpay.cl
log "Processing domain 13/892: webpay.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/webpay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/webpay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/webpay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/webpay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/webpay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/webpay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/webpay.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: webpay.cl"
echo "---"

# Domain 14/892: www.webpay.cl
log "Processing domain 14/892: www.webpay.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.webpay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.webpay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.webpay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.webpay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.webpay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.webpay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.webpay.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.webpay.cl"
echo "---"

# Domain 15/892: facebook.com
log "Processing domain 15/892: facebook.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/facebook.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: facebook.com"
echo "---"

# Domain 16/892: www.facebook.com
log "Processing domain 16/892: www.facebook.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.facebook.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.facebook.com"
echo "---"

# Domain 17/892: linkedin.com
log "Processing domain 17/892: linkedin.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/linkedin.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: linkedin.com"
echo "---"

# Domain 18/892: www.linkedin.com
log "Processing domain 18/892: www.linkedin.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.linkedin.com"
echo "---"

# Domain 19/892: twitter.com
log "Processing domain 19/892: twitter.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/twitter.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/twitter.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/twitter.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/twitter.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/twitter.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/twitter.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/twitter.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: twitter.com"
echo "---"

# Domain 20/892: www.cmfchile.cl
log "Processing domain 20/892: www.cmfchile.cl"
log "Estimated time: 50 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.cmfchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.cmfchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.cmfchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.cmfchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.cmfchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.cmfchile.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.cmfchile.cl"
echo "---"

# Domain 21/892: bootstrapcdn.com
log "Processing domain 21/892: bootstrapcdn.com"
log "Estimated time: 50 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: bootstrapcdn.com"
echo "---"

# Domain 22/892: maxcdn.bootstrapcdn.com
log "Processing domain 22/892: maxcdn.bootstrapcdn.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/maxcdn.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/maxcdn.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/maxcdn.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/maxcdn.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/maxcdn.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/maxcdn.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/maxcdn.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: maxcdn.bootstrapcdn.com"
echo "---"

# Domain 23/892: secure.webpay.cl
log "Processing domain 23/892: secure.webpay.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/secure.webpay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/secure.webpay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/secure.webpay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/secure.webpay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/secure.webpay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/secure.webpay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/secure.webpay.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: secure.webpay.cl"
echo "---"

# Domain 24/892: youtube.com
log "Processing domain 24/892: youtube.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/youtube.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/youtube.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/youtube.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/youtube.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/youtube.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/youtube.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/youtube.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: youtube.com"
echo "---"

# Domain 25/892: www.youtube.com
log "Processing domain 25/892: www.youtube.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.youtube.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.youtube.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.youtube.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.youtube.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.youtube.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.youtube.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.youtube.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.youtube.com"
echo "---"

# Domain 26/892: googletagmanager.com
log "Processing domain 26/892: googletagmanager.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/googletagmanager.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/googletagmanager.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/googletagmanager.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/googletagmanager.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/googletagmanager.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/googletagmanager.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/googletagmanager.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: googletagmanager.com"
echo "---"

# Domain 27/892: www.googletagmanager.com
log "Processing domain 27/892: www.googletagmanager.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.googletagmanager.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.googletagmanager.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.googletagmanager.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.googletagmanager.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.googletagmanager.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.googletagmanager.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.googletagmanager.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.googletagmanager.com"
echo "---"

# Domain 28/892: apache.org
log "Processing domain 28/892: apache.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/apache.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/apache.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/apache.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/apache.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/apache.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/apache.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/apache.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: apache.org"
echo "---"

# Domain 29/892: httpd.apache.org
log "Processing domain 29/892: httpd.apache.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/httpd.apache.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/httpd.apache.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/httpd.apache.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/httpd.apache.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/httpd.apache.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/httpd.apache.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/httpd.apache.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: httpd.apache.org"
echo "---"

# Domain 30/892: debian.org
log "Processing domain 30/892: debian.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/debian.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/debian.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/debian.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/debian.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/debian.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/debian.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/debian.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: debian.org"
echo "---"

# Domain 31/892: bugs.debian.org
log "Processing domain 31/892: bugs.debian.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/bugs.debian.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/bugs.debian.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/bugs.debian.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/bugs.debian.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/bugs.debian.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/bugs.debian.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/bugs.debian.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: bugs.debian.org"
echo "---"

# Domain 32/892: matomo.org
log "Processing domain 32/892: matomo.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/matomo.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/matomo.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/matomo.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/matomo.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/matomo.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/matomo.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/matomo.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: matomo.org"
echo "---"

# Domain 33/892: tiktok.com
log "Processing domain 33/892: tiktok.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/tiktok.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/tiktok.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/tiktok.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/tiktok.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/tiktok.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/tiktok.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/tiktok.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: tiktok.com"
echo "---"

# Domain 34/892: www.tiktok.com
log "Processing domain 34/892: www.tiktok.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.tiktok.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.tiktok.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.tiktok.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.tiktok.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.tiktok.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.tiktok.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.tiktok.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.tiktok.com"
echo "---"

# Domain 35/892: amazonaws.com
log "Processing domain 35/892: amazonaws.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: amazonaws.com"
echo "---"

# Domain 36/892: repo-diseno.s3.amazonaws.com
log "Processing domain 36/892: repo-diseno.s3.amazonaws.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/repo-diseno.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/repo-diseno.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/repo-diseno.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/repo-diseno.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/repo-diseno.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/repo-diseno.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/repo-diseno.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: repo-diseno.s3.amazonaws.com"
echo "---"

# Domain 37/892: jsdelivr.net
log "Processing domain 37/892: jsdelivr.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/jsdelivr.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/jsdelivr.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/jsdelivr.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/jsdelivr.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/jsdelivr.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/jsdelivr.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/jsdelivr.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: jsdelivr.net"
echo "---"

# Domain 38/892: cdn.jsdelivr.net
log "Processing domain 38/892: cdn.jsdelivr.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cdn.jsdelivr.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cdn.jsdelivr.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cdn.jsdelivr.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cdn.jsdelivr.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cdn.jsdelivr.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cdn.jsdelivr.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cdn.jsdelivr.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cdn.jsdelivr.net"
echo "---"

# Domain 39/892: google.com
log "Processing domain 39/892: google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: google.com"
echo "---"

# Domain 40/892: accounts.google.com
log "Processing domain 40/892: accounts.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/accounts.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/accounts.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/accounts.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/accounts.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/accounts.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/accounts.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/accounts.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: accounts.google.com"
echo "---"

# Domain 41/892: citrix.com
log "Processing domain 41/892: citrix.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/citrix.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/citrix.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/citrix.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/citrix.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/citrix.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/citrix.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/citrix.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: citrix.com"
echo "---"

# Domain 42/892: www.citrix.com
log "Processing domain 42/892: www.citrix.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.citrix.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.citrix.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.citrix.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.citrix.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.citrix.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.citrix.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.citrix.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.citrix.com"
echo "---"

# Domain 43/892: msftauth.net
log "Processing domain 43/892: msftauth.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/msftauth.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/msftauth.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/msftauth.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/msftauth.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/msftauth.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/msftauth.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/msftauth.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: msftauth.net"
echo "---"

# Domain 44/892: aadcdn.msftauth.net
log "Processing domain 44/892: aadcdn.msftauth.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/aadcdn.msftauth.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/aadcdn.msftauth.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/aadcdn.msftauth.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/aadcdn.msftauth.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/aadcdn.msftauth.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/aadcdn.msftauth.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/aadcdn.msftauth.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: aadcdn.msftauth.net"
echo "---"

# Domain 45/892: adsttc.com
log "Processing domain 45/892: adsttc.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/adsttc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/adsttc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/adsttc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/adsttc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/adsttc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/adsttc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/adsttc.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: adsttc.com"
echo "---"

# Domain 46/892: assets.adsttc.com
log "Processing domain 46/892: assets.adsttc.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/assets.adsttc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/assets.adsttc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/assets.adsttc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/assets.adsttc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/assets.adsttc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/assets.adsttc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/assets.adsttc.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: assets.adsttc.com"
echo "---"

# Domain 47/892: recaptcha.net
log "Processing domain 47/892: recaptcha.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/recaptcha.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/recaptcha.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/recaptcha.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/recaptcha.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/recaptcha.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/recaptcha.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/recaptcha.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: recaptcha.net"
echo "---"

# Domain 48/892: www.recaptcha.net
log "Processing domain 48/892: www.recaptcha.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.recaptcha.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.recaptcha.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.recaptcha.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.recaptcha.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.recaptcha.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.recaptcha.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.recaptcha.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.recaptcha.net"
echo "---"

# Domain 49/892: cloudflare.com
log "Processing domain 49/892: cloudflare.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cloudflare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cloudflare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cloudflare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cloudflare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cloudflare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cloudflare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cloudflare.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cloudflare.com"
echo "---"

# Domain 50/892: cdnjs.cloudflare.com
log "Processing domain 50/892: cdnjs.cloudflare.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cdnjs.cloudflare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cdnjs.cloudflare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cdnjs.cloudflare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cdnjs.cloudflare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cdnjs.cloudflare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cdnjs.cloudflare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cdnjs.cloudflare.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cdnjs.cloudflare.com"
echo "---"

# Domain 51/892: support.google.com
log "Processing domain 51/892: support.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/support.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/support.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/support.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/support.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/support.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/support.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/support.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: support.google.com"
echo "---"

# Domain 52/892: instagram.com
log "Processing domain 52/892: instagram.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/instagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/instagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/instagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/instagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/instagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/instagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/instagram.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: instagram.com"
echo "---"

# Domain 53/892: www.instagram.com
log "Processing domain 53/892: www.instagram.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.instagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.instagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.instagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.instagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.instagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.instagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.instagram.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.instagram.com"
echo "---"

# Domain 54/892: es-la.facebook.com
log "Processing domain 54/892: es-la.facebook.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/es-la.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/es-la.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/es-la.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/es-la.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/es-la.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/es-la.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/es-la.facebook.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: es-la.facebook.com"
echo "---"

# Domain 55/892: www.24horas.cl
log "Processing domain 55/892: www.24horas.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.24horas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.24horas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.24horas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.24horas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.24horas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.24horas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.24horas.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.24horas.cl"
echo "---"

# Domain 56/892: tvnplay.cl
log "Processing domain 56/892: tvnplay.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/tvnplay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/tvnplay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/tvnplay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/tvnplay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/tvnplay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/tvnplay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/tvnplay.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: tvnplay.cl"
echo "---"

# Domain 57/892: www.tvnplay.cl
log "Processing domain 57/892: www.tvnplay.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.tvnplay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.tvnplay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.tvnplay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.tvnplay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.tvnplay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.tvnplay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.tvnplay.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.tvnplay.cl"
echo "---"

# Domain 58/892: googleapis.com
log "Processing domain 58/892: googleapis.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/googleapis.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: googleapis.com"
echo "---"

# Domain 59/892: ajax.googleapis.com
log "Processing domain 59/892: ajax.googleapis.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ajax.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ajax.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ajax.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ajax.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ajax.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ajax.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ajax.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ajax.googleapis.com"
echo "---"

# Domain 60/892: fonts.googleapis.com
log "Processing domain 60/892: fonts.googleapis.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/fonts.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/fonts.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/fonts.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/fonts.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/fonts.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/fonts.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/fonts.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: fonts.googleapis.com"
echo "---"

# Domain 61/892: www.google.com
log "Processing domain 61/892: www.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.google.com"
echo "---"

# Domain 62/892: formsite.com
log "Processing domain 62/892: formsite.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/formsite.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/formsite.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/formsite.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/formsite.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/formsite.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/formsite.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/formsite.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: formsite.com"
echo "---"

# Domain 63/892: fs16.formsite.com
log "Processing domain 63/892: fs16.formsite.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/fs16.formsite.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/fs16.formsite.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/fs16.formsite.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/fs16.formsite.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/fs16.formsite.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/fs16.formsite.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/fs16.formsite.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: fs16.formsite.com"
echo "---"

# Domain 64/892: reqlut.com
log "Processing domain 64/892: reqlut.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/reqlut.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/reqlut.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/reqlut.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/reqlut.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/reqlut.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/reqlut.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/reqlut.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: reqlut.com"
echo "---"

# Domain 65/892: www.reqlut.com
log "Processing domain 65/892: www.reqlut.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.reqlut.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.reqlut.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.reqlut.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.reqlut.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.reqlut.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.reqlut.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.reqlut.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.reqlut.com"
echo "---"

# Domain 66/892: reqlut2.s3.amazonaws.com
log "Processing domain 66/892: reqlut2.s3.amazonaws.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/reqlut2.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/reqlut2.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/reqlut2.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/reqlut2.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/reqlut2.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/reqlut2.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/reqlut2.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: reqlut2.s3.amazonaws.com"
echo "---"

# Domain 67/892: userway.org
log "Processing domain 67/892: userway.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/userway.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/userway.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/userway.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/userway.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/userway.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/userway.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/userway.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: userway.org"
echo "---"

# Domain 68/892: cdn.userway.org
log "Processing domain 68/892: cdn.userway.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cdn.userway.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cdn.userway.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cdn.userway.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cdn.userway.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cdn.userway.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cdn.userway.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cdn.userway.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cdn.userway.org"
echo "---"

# Domain 69/892: reqlut2.s3.sa-east-1.amazonaws.com
log "Processing domain 69/892: reqlut2.s3.sa-east-1.amazonaws.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/reqlut2.s3.sa-east-1.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/reqlut2.s3.sa-east-1.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/reqlut2.s3.sa-east-1.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/reqlut2.s3.sa-east-1.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/reqlut2.s3.sa-east-1.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/reqlut2.s3.sa-east-1.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/reqlut2.s3.sa-east-1.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: reqlut2.s3.sa-east-1.amazonaws.com"
echo "---"

# Domain 70/892: adj.st
log "Processing domain 70/892: adj.st"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/adj.st"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/adj.st"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/adj.st"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/adj.st"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/adj.st"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/adj.st"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/adj.st"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: adj.st"
echo "---"

# Domain 71/892: ddnf.adj.st
log "Processing domain 71/892: ddnf.adj.st"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ddnf.adj.st"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ddnf.adj.st"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ddnf.adj.st"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ddnf.adj.st"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ddnf.adj.st"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ddnf.adj.st"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ddnf.adj.st"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ddnf.adj.st"
echo "---"

# Domain 72/892: mercadolibre.com
log "Processing domain 72/892: mercadolibre.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mercadolibre.com"
echo "---"

# Domain 73/892: www.mercadolibre.com
log "Processing domain 73/892: www.mercadolibre.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.mercadolibre.com"
echo "---"

# Domain 74/892: news.mercadolibre.com
log "Processing domain 74/892: news.mercadolibre.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/news.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/news.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/news.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/news.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/news.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/news.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/news.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: news.mercadolibre.com"
echo "---"

# Domain 75/892: investor.mercadolibre.com
log "Processing domain 75/892: investor.mercadolibre.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/investor.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/investor.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/investor.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/investor.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/investor.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/investor.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/investor.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: investor.mercadolibre.com"
echo "---"

# Domain 76/892: sustentabilidadmercadolibre.com
log "Processing domain 76/892: sustentabilidadmercadolibre.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/sustentabilidadmercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/sustentabilidadmercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/sustentabilidadmercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/sustentabilidadmercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/sustentabilidadmercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/sustentabilidadmercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/sustentabilidadmercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: sustentabilidadmercadolibre.com"
echo "---"

# Domain 77/892: developers.mercadolibre.com
log "Processing domain 77/892: developers.mercadolibre.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/developers.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/developers.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/developers.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/developers.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/developers.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/developers.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/developers.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: developers.mercadolibre.com"
echo "---"

# Domain 78/892: www.mercadopago.cl
log "Processing domain 78/892: www.mercadopago.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.mercadopago.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.mercadopago.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.mercadopago.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.mercadopago.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.mercadopago.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.mercadopago.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.mercadopago.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.mercadopago.cl"
echo "---"

# Domain 79/892: www.mercadoshops.cl
log "Processing domain 79/892: www.mercadoshops.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.mercadoshops.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.mercadoshops.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.mercadoshops.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.mercadoshops.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.mercadoshops.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.mercadoshops.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.mercadoshops.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.mercadoshops.cl"
echo "---"

# Domain 80/892: x.com
log "Processing domain 80/892: x.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/x.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/x.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/x.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/x.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/x.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/x.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/x.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: x.com"
echo "---"

# Domain 81/892: careers-meli.mercadolibre.com
log "Processing domain 81/892: careers-meli.mercadolibre.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/careers-meli.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/careers-meli.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/careers-meli.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/careers-meli.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/careers-meli.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/careers-meli.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/careers-meli.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: careers-meli.mercadolibre.com"
echo "---"

# Domain 82/892: hp.mercadolibre.com
log "Processing domain 82/892: hp.mercadolibre.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/hp.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/hp.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/hp.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/hp.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/hp.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/hp.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/hp.mercadolibre.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: hp.mercadolibre.com"
echo "---"

# Domain 83/892: mlstatic.com
log "Processing domain 83/892: mlstatic.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mlstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mlstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mlstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mlstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mlstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mlstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mlstatic.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mlstatic.com"
echo "---"

# Domain 84/892: http2.mlstatic.com
log "Processing domain 84/892: http2.mlstatic.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/http2.mlstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/http2.mlstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/http2.mlstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/http2.mlstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/http2.mlstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/http2.mlstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/http2.mlstatic.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: http2.mlstatic.com"
echo "---"

# Domain 85/892: getmdl.io
log "Processing domain 85/892: getmdl.io"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/getmdl.io"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/getmdl.io"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/getmdl.io"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/getmdl.io"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/getmdl.io"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/getmdl.io"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/getmdl.io"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: getmdl.io"
echo "---"

# Domain 86/892: code.getmdl.io
log "Processing domain 86/892: code.getmdl.io"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/code.getmdl.io"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/code.getmdl.io"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/code.getmdl.io"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/code.getmdl.io"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/code.getmdl.io"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/code.getmdl.io"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/code.getmdl.io"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: code.getmdl.io"
echo "---"

# Domain 87/892: pagina7.cl
log "Processing domain 87/892: pagina7.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: pagina7.cl"
echo "---"

# Domain 88/892: www.pagina7.cl
log "Processing domain 88/892: www.pagina7.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.pagina7.cl"
echo "---"

# Domain 89/892: threads.net
log "Processing domain 89/892: threads.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/threads.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/threads.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/threads.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/threads.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/threads.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/threads.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/threads.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: threads.net"
echo "---"

# Domain 90/892: www.threads.net
log "Processing domain 90/892: www.threads.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.threads.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.threads.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.threads.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.threads.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.threads.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.threads.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.threads.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.threads.net"
echo "---"

# Domain 91/892: googletagservices.com
log "Processing domain 91/892: googletagservices.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/googletagservices.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/googletagservices.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/googletagservices.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/googletagservices.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/googletagservices.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/googletagservices.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/googletagservices.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: googletagservices.com"
echo "---"

# Domain 92/892: www.googletagservices.com
log "Processing domain 92/892: www.googletagservices.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.googletagservices.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.googletagservices.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.googletagservices.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.googletagservices.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.googletagservices.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.googletagservices.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.googletagservices.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.googletagservices.com"
echo "---"

# Domain 93/892: teads.tv
log "Processing domain 93/892: teads.tv"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/teads.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/teads.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/teads.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/teads.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/teads.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/teads.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/teads.tv"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: teads.tv"
echo "---"

# Domain 94/892: a.teads.tv
log "Processing domain 94/892: a.teads.tv"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/a.teads.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/a.teads.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/a.teads.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/a.teads.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/a.teads.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/a.teads.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/a.teads.tv"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: a.teads.tv"
echo "---"

# Domain 95/892: crazyegg.com
log "Processing domain 95/892: crazyegg.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/crazyegg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/crazyegg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/crazyegg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/crazyegg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/crazyegg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/crazyegg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/crazyegg.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: crazyegg.com"
echo "---"

# Domain 96/892: script.crazyegg.com
log "Processing domain 96/892: script.crazyegg.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/script.crazyegg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/script.crazyegg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/script.crazyegg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/script.crazyegg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/script.crazyegg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/script.crazyegg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/script.crazyegg.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: script.crazyegg.com"
echo "---"

# Domain 97/892: media.pagina7.cl
log "Processing domain 97/892: media.pagina7.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/media.pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/media.pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/media.pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/media.pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/media.pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/media.pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/media.pagina7.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: media.pagina7.cl"
echo "---"

# Domain 98/892: ticketsimply.com
log "Processing domain 98/892: ticketsimply.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ticketsimply.com"
echo "---"

# Domain 99/892: admin.ticketsimply.com
log "Processing domain 99/892: admin.ticketsimply.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/admin.ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/admin.ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/admin.ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/admin.ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/admin.ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/admin.ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/admin.ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: admin.ticketsimply.com"
echo "---"

# Domain 100/892: bitlasoft.com
log "Processing domain 100/892: bitlasoft.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/bitlasoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/bitlasoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/bitlasoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/bitlasoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/bitlasoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/bitlasoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/bitlasoft.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: bitlasoft.com"
echo "---"

# Domain 101/892: www.bitlasoft.com
log "Processing domain 101/892: www.bitlasoft.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.bitlasoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.bitlasoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.bitlasoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.bitlasoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.bitlasoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.bitlasoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.bitlasoft.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.bitlasoft.com"
echo "---"

# Domain 102/892: www.ticketsimply.com
log "Processing domain 102/892: www.ticketsimply.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.ticketsimply.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.ticketsimply.com"
echo "---"

# Domain 103/892: maps.googleapis.com
log "Processing domain 103/892: maps.googleapis.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/maps.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/maps.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/maps.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/maps.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/maps.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/maps.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/maps.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: maps.googleapis.com"
echo "---"

# Domain 104/892: stackerhq.com
log "Processing domain 104/892: stackerhq.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/stackerhq.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/stackerhq.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/stackerhq.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/stackerhq.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/stackerhq.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/stackerhq.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/stackerhq.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: stackerhq.com"
echo "---"

# Domain 105/892: cdn.stackerhq.com
log "Processing domain 105/892: cdn.stackerhq.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cdn.stackerhq.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cdn.stackerhq.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cdn.stackerhq.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cdn.stackerhq.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cdn.stackerhq.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cdn.stackerhq.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cdn.stackerhq.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cdn.stackerhq.com"
echo "---"

# Domain 106/892: wordpress.org
log "Processing domain 106/892: wordpress.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/wordpress.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/wordpress.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/wordpress.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/wordpress.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/wordpress.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/wordpress.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/wordpress.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: wordpress.org"
echo "---"

# Domain 107/892: cl.wordpress.org
log "Processing domain 107/892: cl.wordpress.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cl.wordpress.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cl.wordpress.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cl.wordpress.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cl.wordpress.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cl.wordpress.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cl.wordpress.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cl.wordpress.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cl.wordpress.org"
echo "---"

# Domain 108/892: pucv.cl
log "Processing domain 108/892: pucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/pucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: pucv.cl"
echo "---"

# Domain 109/892: www.pucv.cl
log "Processing domain 109/892: www.pucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.pucv.cl"
echo "---"

# Domain 110/892: postgradospucv.cl
log "Processing domain 110/892: postgradospucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/postgradospucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/postgradospucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/postgradospucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/postgradospucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/postgradospucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/postgradospucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/postgradospucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: postgradospucv.cl"
echo "---"

# Domain 111/892: www.postgradospucv.cl
log "Processing domain 111/892: www.postgradospucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.postgradospucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.postgradospucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.postgradospucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.postgradospucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.postgradospucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.postgradospucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.postgradospucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.postgradospucv.cl"
echo "---"

# Domain 112/892: formacioncontinuapucv.cl
log "Processing domain 112/892: formacioncontinuapucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/formacioncontinuapucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/formacioncontinuapucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/formacioncontinuapucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/formacioncontinuapucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/formacioncontinuapucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/formacioncontinuapucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/formacioncontinuapucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: formacioncontinuapucv.cl"
echo "---"

# Domain 113/892: www.formacioncontinuapucv.cl
log "Processing domain 113/892: www.formacioncontinuapucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.formacioncontinuapucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.formacioncontinuapucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.formacioncontinuapucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.formacioncontinuapucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.formacioncontinuapucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.formacioncontinuapucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.formacioncontinuapucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.formacioncontinuapucv.cl"
echo "---"

# Domain 114/892: dgai.pucv.cl
log "Processing domain 114/892: dgai.pucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/dgai.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/dgai.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/dgai.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/dgai.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/dgai.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/dgai.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/dgai.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: dgai.pucv.cl"
echo "---"

# Domain 115/892: vinculacionpucv.cl
log "Processing domain 115/892: vinculacionpucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/vinculacionpucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/vinculacionpucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/vinculacionpucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/vinculacionpucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/vinculacionpucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/vinculacionpucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/vinculacionpucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: vinculacionpucv.cl"
echo "---"

# Domain 116/892: estudiantespucv.cl
log "Processing domain 116/892: estudiantespucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/estudiantespucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/estudiantespucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/estudiantespucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/estudiantespucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/estudiantespucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/estudiantespucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/estudiantespucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: estudiantespucv.cl"
echo "---"

# Domain 117/892: alumni.pucv.cl
log "Processing domain 117/892: alumni.pucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/alumni.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/alumni.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/alumni.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/alumni.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/alumni.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/alumni.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/alumni.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: alumni.pucv.cl"
echo "---"

# Domain 118/892: transparencia.pucv.cl
log "Processing domain 118/892: transparencia.pucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/transparencia.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/transparencia.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/transparencia.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/transparencia.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/transparencia.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/transparencia.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/transparencia.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: transparencia.pucv.cl"
echo "---"

# Domain 119/892: ucvtv.cl
log "Processing domain 119/892: ucvtv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ucvtv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ucvtv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ucvtv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ucvtv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ucvtv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ucvtv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ucvtv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ucvtv.cl"
echo "---"

# Domain 120/892: www.twitter.com
log "Processing domain 120/892: www.twitter.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.twitter.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.twitter.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.twitter.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.twitter.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.twitter.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.twitter.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.twitter.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.twitter.com"
echo "---"

# Domain 121/892: docs.google.com
log "Processing domain 121/892: docs.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/docs.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/docs.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/docs.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/docs.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/docs.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/docs.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/docs.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: docs.google.com"
echo "---"

# Domain 122/892: pcspucv.cl
log "Processing domain 122/892: pcspucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/pcspucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/pcspucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/pcspucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/pcspucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/pcspucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/pcspucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/pcspucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: pcspucv.cl"
echo "---"

# Domain 123/892: matricula.pcspucv.cl
log "Processing domain 123/892: matricula.pcspucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/matricula.pcspucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/matricula.pcspucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/matricula.pcspucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/matricula.pcspucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/matricula.pcspucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/matricula.pcspucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/matricula.pcspucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: matricula.pcspucv.cl"
echo "---"

# Domain 124/892: biblioteca.pucv.cl
log "Processing domain 124/892: biblioteca.pucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/biblioteca.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/biblioteca.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/biblioteca.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/biblioteca.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/biblioteca.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/biblioteca.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/biblioteca.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: biblioteca.pucv.cl"
echo "---"

# Domain 125/892: programadeingles.pucv.cl
log "Processing domain 125/892: programadeingles.pucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/programadeingles.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/programadeingles.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/programadeingles.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/programadeingles.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/programadeingles.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/programadeingles.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/programadeingles.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: programadeingles.pucv.cl"
echo "---"

# Domain 126/892: beneficiosestudiantiles.cl
log "Processing domain 126/892: beneficiosestudiantiles.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/beneficiosestudiantiles.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/beneficiosestudiantiles.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/beneficiosestudiantiles.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/beneficiosestudiantiles.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/beneficiosestudiantiles.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/beneficiosestudiantiles.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/beneficiosestudiantiles.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: beneficiosestudiantiles.cl"
echo "---"

# Domain 127/892: www.beneficiosestudiantiles.cl
log "Processing domain 127/892: www.beneficiosestudiantiles.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.beneficiosestudiantiles.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.beneficiosestudiantiles.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.beneficiosestudiantiles.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.beneficiosestudiantiles.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.beneficiosestudiantiles.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.beneficiosestudiantiles.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.beneficiosestudiantiles.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.beneficiosestudiantiles.cl"
echo "---"

# Domain 128/892: ingresa.cl
log "Processing domain 128/892: ingresa.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ingresa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ingresa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ingresa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ingresa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ingresa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ingresa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ingresa.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ingresa.cl"
echo "---"

# Domain 129/892: gratuidad.cl
log "Processing domain 129/892: gratuidad.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/gratuidad.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/gratuidad.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/gratuidad.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/gratuidad.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/gratuidad.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/gratuidad.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/gratuidad.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: gratuidad.cl"
echo "---"

# Domain 130/892: www.gratuidad.cl
log "Processing domain 130/892: www.gratuidad.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.gratuidad.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.gratuidad.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.gratuidad.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.gratuidad.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.gratuidad.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.gratuidad.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.gratuidad.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.gratuidad.cl"
echo "---"

# Domain 131/892: acceso.mineduc.cl
log "Processing domain 131/892: acceso.mineduc.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/acceso.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/acceso.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/acceso.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/acceso.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/acceso.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/acceso.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/acceso.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: acceso.mineduc.cl"
echo "---"

# Domain 132/892: universia.net
log "Processing domain 132/892: universia.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/universia.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/universia.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/universia.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/universia.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/universia.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/universia.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/universia.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: universia.net"
echo "---"

# Domain 133/892: www.universia.net
log "Processing domain 133/892: www.universia.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.universia.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.universia.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.universia.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.universia.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.universia.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.universia.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.universia.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.universia.net"
echo "---"

# Domain 134/892: mifuturo.cl
log "Processing domain 134/892: mifuturo.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mifuturo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mifuturo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mifuturo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mifuturo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mifuturo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mifuturo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mifuturo.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mifuturo.cl"
echo "---"

# Domain 135/892: www.mifuturo.cl
log "Processing domain 135/892: www.mifuturo.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.mifuturo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.mifuturo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.mifuturo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.mifuturo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.mifuturo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.mifuturo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.mifuturo.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.mifuturo.cl"
echo "---"

# Domain 136/892: demre.cl
log "Processing domain 136/892: demre.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/demre.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/demre.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/demre.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/demre.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/demre.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/demre.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/demre.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: demre.cl"
echo "---"

# Domain 137/892: navegador.pucv.cl
log "Processing domain 137/892: navegador.pucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/navegador.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/navegador.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/navegador.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/navegador.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/navegador.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/navegador.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/navegador.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: navegador.pucv.cl"
echo "---"

# Domain 138/892: euv.cl
log "Processing domain 138/892: euv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/euv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/euv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/euv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/euv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/euv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/euv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/euv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: euv.cl"
echo "---"

# Domain 139/892: www.google.cl
log "Processing domain 139/892: www.google.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.google.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.google.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.google.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.google.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.google.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.google.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.google.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.google.cl"
echo "---"

# Domain 140/892: cnachile.cl
log "Processing domain 140/892: cnachile.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cnachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cnachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cnachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cnachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cnachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cnachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cnachile.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cnachile.cl"
echo "---"

# Domain 141/892: www.cnachile.cl
log "Processing domain 141/892: www.cnachile.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.cnachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.cnachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.cnachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.cnachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.cnachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.cnachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.cnachile.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.cnachile.cl"
echo "---"

# Domain 142/892: mathtag.com
log "Processing domain 142/892: mathtag.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mathtag.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mathtag.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mathtag.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mathtag.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mathtag.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mathtag.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mathtag.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mathtag.com"
echo "---"

# Domain 143/892: pixel.mathtag.com
log "Processing domain 143/892: pixel.mathtag.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/pixel.mathtag.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/pixel.mathtag.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/pixel.mathtag.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/pixel.mathtag.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/pixel.mathtag.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/pixel.mathtag.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/pixel.mathtag.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: pixel.mathtag.com"
echo "---"

# Domain 144/892: adnxs.com
log "Processing domain 144/892: adnxs.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/adnxs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/adnxs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/adnxs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/adnxs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/adnxs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/adnxs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/adnxs.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: adnxs.com"
echo "---"

# Domain 145/892: secure.adnxs.com
log "Processing domain 145/892: secure.adnxs.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/secure.adnxs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/secure.adnxs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/secure.adnxs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/secure.adnxs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/secure.adnxs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/secure.adnxs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/secure.adnxs.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: secure.adnxs.com"
echo "---"

# Domain 146/892: matthewelsom.com
log "Processing domain 146/892: matthewelsom.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/matthewelsom.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/matthewelsom.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/matthewelsom.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/matthewelsom.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/matthewelsom.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/matthewelsom.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/matthewelsom.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: matthewelsom.com"
echo "---"

# Domain 147/892: platform.twitter.com
log "Processing domain 147/892: platform.twitter.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/platform.twitter.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/platform.twitter.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/platform.twitter.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/platform.twitter.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/platform.twitter.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/platform.twitter.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/platform.twitter.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: platform.twitter.com"
echo "---"

# Domain 148/892: ibm.com
log "Processing domain 148/892: ibm.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ibm.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ibm.com"
echo "---"

# Domain 149/892: publib.boulder.ibm.com
log "Processing domain 149/892: publib.boulder.ibm.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/publib.boulder.ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/publib.boulder.ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/publib.boulder.ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/publib.boulder.ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/publib.boulder.ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/publib.boulder.ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/publib.boulder.ibm.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: publib.boulder.ibm.com"
echo "---"

# Domain 150/892: www14.software.ibm.com
log "Processing domain 150/892: www14.software.ibm.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www14.software.ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www14.software.ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www14.software.ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www14.software.ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www14.software.ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www14.software.ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www14.software.ibm.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www14.software.ibm.com"
echo "---"

# Domain 151/892: www-306.ibm.com
log "Processing domain 151/892: www-306.ibm.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www-306.ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www-306.ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www-306.ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www-306.ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www-306.ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www-306.ibm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www-306.ibm.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www-306.ibm.com"
echo "---"

# Domain 152/892: whatsapp.com
log "Processing domain 152/892: whatsapp.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: whatsapp.com"
echo "---"

# Domain 153/892: api.whatsapp.com
log "Processing domain 153/892: api.whatsapp.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/api.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/api.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/api.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/api.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/api.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/api.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/api.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: api.whatsapp.com"
echo "---"

# Domain 154/892: cloudfront.net
log "Processing domain 154/892: cloudfront.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cloudfront.net"
echo "---"

# Domain 155/892: dojiw2m9tvv09.cloudfront.net
log "Processing domain 155/892: dojiw2m9tvv09.cloudfront.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/dojiw2m9tvv09.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/dojiw2m9tvv09.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/dojiw2m9tvv09.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/dojiw2m9tvv09.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/dojiw2m9tvv09.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/dojiw2m9tvv09.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/dojiw2m9tvv09.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: dojiw2m9tvv09.cloudfront.net"
echo "---"

# Domain 156/892: emol.com
log "Processing domain 156/892: emol.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/emol.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: emol.com"
echo "---"

# Domain 157/892: comentarista.emol.com
log "Processing domain 157/892: comentarista.emol.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/comentarista.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/comentarista.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/comentarista.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/comentarista.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/comentarista.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/comentarista.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/comentarista.emol.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: comentarista.emol.com"
echo "---"

# Domain 158/892: fontawesome.com
log "Processing domain 158/892: fontawesome.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: fontawesome.com"
echo "---"

# Domain 159/892: use.fontawesome.com
log "Processing domain 159/892: use.fontawesome.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/use.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/use.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/use.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/use.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/use.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/use.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/use.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: use.fontawesome.com"
echo "---"

# Domain 160/892: unpkg.com
log "Processing domain 160/892: unpkg.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/unpkg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/unpkg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/unpkg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/unpkg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/unpkg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/unpkg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/unpkg.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: unpkg.com"
echo "---"

# Domain 161/892: mercadoads.com
log "Processing domain 161/892: mercadoads.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mercadoads.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mercadoads.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mercadoads.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mercadoads.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mercadoads.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mercadoads.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mercadoads.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mercadoads.com"
echo "---"

# Domain 162/892: academy.mercadoads.com
log "Processing domain 162/892: academy.mercadoads.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/academy.mercadoads.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/academy.mercadoads.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/academy.mercadoads.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/academy.mercadoads.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/academy.mercadoads.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/academy.mercadoads.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/academy.mercadoads.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: academy.mercadoads.com"
echo "---"

# Domain 163/892: netline.net
log "Processing domain 163/892: netline.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/netline.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: netline.net"
echo "---"

# Domain 164/892: www.netline.net
log "Processing domain 164/892: www.netline.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.netline.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.netline.net"
echo "---"

# Domain 165/892: mi.netline.net
log "Processing domain 165/892: mi.netline.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mi.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mi.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mi.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mi.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mi.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mi.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mi.netline.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mi.netline.net"
echo "---"

# Domain 166/892: pagos.netline.net
log "Processing domain 166/892: pagos.netline.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/pagos.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/pagos.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/pagos.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/pagos.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/pagos.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/pagos.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/pagos.netline.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: pagos.netline.net"
echo "---"

# Domain 167/892: email.netline.net
log "Processing domain 167/892: email.netline.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/email.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/email.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/email.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/email.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/email.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/email.netline.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/email.netline.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: email.netline.net"
echo "---"

# Domain 168/892: plus.google.com
log "Processing domain 168/892: plus.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/plus.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/plus.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/plus.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/plus.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/plus.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/plus.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/plus.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: plus.google.com"
echo "---"

# Domain 169/892: xenforo.com
log "Processing domain 169/892: xenforo.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/xenforo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/xenforo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/xenforo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/xenforo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/xenforo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/xenforo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/xenforo.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: xenforo.com"
echo "---"

# Domain 170/892: nnowa.com
log "Processing domain 170/892: nnowa.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/nnowa.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/nnowa.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/nnowa.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/nnowa.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/nnowa.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/nnowa.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/nnowa.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: nnowa.com"
echo "---"

# Domain 171/892: st-n.nnowa.com
log "Processing domain 171/892: st-n.nnowa.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/st-n.nnowa.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/st-n.nnowa.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/st-n.nnowa.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/st-n.nnowa.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/st-n.nnowa.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/st-n.nnowa.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/st-n.nnowa.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: st-n.nnowa.com"
echo "---"

# Domain 172/892: business.google.com
log "Processing domain 172/892: business.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/business.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/business.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/business.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/business.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/business.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/business.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/business.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: business.google.com"
echo "---"

# Domain 173/892: myaccount.google.com
log "Processing domain 173/892: myaccount.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/myaccount.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/myaccount.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/myaccount.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/myaccount.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/myaccount.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/myaccount.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/myaccount.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: myaccount.google.com"
echo "---"

# Domain 174/892: merchants.google.com
log "Processing domain 174/892: merchants.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/merchants.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/merchants.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/merchants.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/merchants.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/merchants.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/merchants.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/merchants.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: merchants.google.com"
echo "---"

# Domain 175/892: analytics.google.com
log "Processing domain 175/892: analytics.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/analytics.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/analytics.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/analytics.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/analytics.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/analytics.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/analytics.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/analytics.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: analytics.google.com"
echo "---"

# Domain 176/892: policies.google.com
log "Processing domain 176/892: policies.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/policies.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/policies.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/policies.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/policies.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/policies.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/policies.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/policies.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: policies.google.com"
echo "---"

# Domain 177/892: ads.google.com
log "Processing domain 177/892: ads.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ads.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ads.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ads.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ads.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ads.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ads.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ads.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ads.google.com"
echo "---"

# Domain 178/892: blog.google
log "Processing domain 178/892: blog.google"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/blog.google"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/blog.google"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/blog.google"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/blog.google"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/blog.google"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/blog.google"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/blog.google"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: blog.google"
echo "---"

# Domain 179/892: withgoogle.com
log "Processing domain 179/892: withgoogle.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: withgoogle.com"
echo "---"

# Domain 180/892: partnersdirectory.withgoogle.com
log "Processing domain 180/892: partnersdirectory.withgoogle.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/partnersdirectory.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/partnersdirectory.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/partnersdirectory.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/partnersdirectory.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/partnersdirectory.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/partnersdirectory.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/partnersdirectory.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: partnersdirectory.withgoogle.com"
echo "---"

# Domain 181/892: developers.google.com
log "Processing domain 181/892: developers.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/developers.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/developers.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/developers.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/developers.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/developers.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/developers.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/developers.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: developers.google.com"
echo "---"

# Domain 182/892: google.com.mx
log "Processing domain 182/892: google.com.mx"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/google.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/google.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/google.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/google.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/google.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/google.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/google.com.mx"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: google.com.mx"
echo "---"

# Domain 183/892: workspace.google.com.mx
log "Processing domain 183/892: workspace.google.com.mx"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/workspace.google.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/workspace.google.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/workspace.google.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/workspace.google.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/workspace.google.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/workspace.google.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/workspace.google.com.mx"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: workspace.google.com.mx"
echo "---"

# Domain 184/892: cloud.google.com
log "Processing domain 184/892: cloud.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cloud.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cloud.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cloud.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cloud.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cloud.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cloud.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cloud.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cloud.google.com"
echo "---"

# Domain 185/892: adsense.google.com
log "Processing domain 185/892: adsense.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/adsense.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/adsense.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/adsense.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/adsense.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/adsense.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/adsense.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/adsense.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: adsense.google.com"
echo "---"

# Domain 186/892: admob.google.com
log "Processing domain 186/892: admob.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/admob.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/admob.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/admob.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/admob.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/admob.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/admob.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/admob.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: admob.google.com"
echo "---"

# Domain 187/892: about.google
log "Processing domain 187/892: about.google"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/about.google"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/about.google"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/about.google"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/about.google"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/about.google"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/about.google"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/about.google"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: about.google"
echo "---"

# Domain 188/892: gstatic.com
log "Processing domain 188/892: gstatic.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/gstatic.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: gstatic.com"
echo "---"

# Domain 189/892: www.gstatic.com
log "Processing domain 189/892: www.gstatic.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.gstatic.com"
echo "---"

# Domain 190/892: nginx.org
log "Processing domain 190/892: nginx.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/nginx.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/nginx.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/nginx.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/nginx.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/nginx.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/nginx.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/nginx.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: nginx.org"
echo "---"

# Domain 191/892: nginx.com
log "Processing domain 191/892: nginx.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/nginx.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/nginx.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/nginx.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/nginx.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/nginx.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/nginx.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/nginx.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: nginx.com"
echo "---"

# Domain 192/892: shopeemobile.com
log "Processing domain 192/892: shopeemobile.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/shopeemobile.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/shopeemobile.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/shopeemobile.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/shopeemobile.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/shopeemobile.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/shopeemobile.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/shopeemobile.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: shopeemobile.com"
echo "---"

# Domain 193/892: deo.shopeemobile.com
log "Processing domain 193/892: deo.shopeemobile.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/deo.shopeemobile.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/deo.shopeemobile.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/deo.shopeemobile.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/deo.shopeemobile.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/deo.shopeemobile.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/deo.shopeemobile.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/deo.shopeemobile.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: deo.shopeemobile.com"
echo "---"

# Domain 194/892: sirsidynix.net
log "Processing domain 194/892: sirsidynix.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/sirsidynix.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/sirsidynix.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/sirsidynix.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/sirsidynix.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/sirsidynix.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/sirsidynix.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/sirsidynix.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: sirsidynix.net"
echo "---"

# Domain 195/892: duchi.ent.sirsidynix.net
log "Processing domain 195/892: duchi.ent.sirsidynix.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/duchi.ent.sirsidynix.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/duchi.ent.sirsidynix.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/duchi.ent.sirsidynix.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/duchi.ent.sirsidynix.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/duchi.ent.sirsidynix.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/duchi.ent.sirsidynix.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/duchi.ent.sirsidynix.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: duchi.ent.sirsidynix.net"
echo "---"

# Domain 196/892: springshare.com
log "Processing domain 196/892: springshare.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/springshare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/springshare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/springshare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/springshare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/springshare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/springshare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/springshare.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: springshare.com"
echo "---"

# Domain 197/892: www.springshare.com
log "Processing domain 197/892: www.springshare.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.springshare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.springshare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.springshare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.springshare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.springshare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.springshare.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.springshare.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.springshare.com"
echo "---"

# Domain 198/892: libapps.com
log "Processing domain 198/892: libapps.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/libapps.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/libapps.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/libapps.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/libapps.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/libapps.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/libapps.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/libapps.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: libapps.com"
echo "---"

# Domain 199/892: duoc.libapps.com
log "Processing domain 199/892: duoc.libapps.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/duoc.libapps.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/duoc.libapps.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/duoc.libapps.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/duoc.libapps.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/duoc.libapps.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/duoc.libapps.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/duoc.libapps.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: duoc.libapps.com"
echo "---"

# Domain 200/892: duoclaboral.cl
log "Processing domain 200/892: duoclaboral.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/duoclaboral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/duoclaboral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/duoclaboral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/duoclaboral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/duoclaboral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/duoclaboral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/duoclaboral.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: duoclaboral.cl"
echo "---"

# Domain 201/892: libcal.com
log "Processing domain 201/892: libcal.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/libcal.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/libcal.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/libcal.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/libcal.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/libcal.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/libcal.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/libcal.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: libcal.com"
echo "---"

# Domain 202/892: static-assets-us.libcal.com
log "Processing domain 202/892: static-assets-us.libcal.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/static-assets-us.libcal.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/static-assets-us.libcal.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/static-assets-us.libcal.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/static-assets-us.libcal.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/static-assets-us.libcal.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/static-assets-us.libcal.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/static-assets-us.libcal.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: static-assets-us.libcal.com"
echo "---"

# Domain 203/892: libapps.s3.amazonaws.com
log "Processing domain 203/892: libapps.s3.amazonaws.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/libapps.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/libapps.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/libapps.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/libapps.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/libapps.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/libapps.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/libapps.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: libapps.s3.amazonaws.com"
echo "---"

# Domain 204/892: d68g328n4ug0e.cloudfront.net
log "Processing domain 204/892: d68g328n4ug0e.cloudfront.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/d68g328n4ug0e.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/d68g328n4ug0e.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/d68g328n4ug0e.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/d68g328n4ug0e.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/d68g328n4ug0e.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/d68g328n4ug0e.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/d68g328n4ug0e.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: d68g328n4ug0e.cloudfront.net"
echo "---"

# Domain 205/892: d2jv02qf7xgjwx.cloudfront.net
log "Processing domain 205/892: d2jv02qf7xgjwx.cloudfront.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/d2jv02qf7xgjwx.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/d2jv02qf7xgjwx.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/d2jv02qf7xgjwx.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/d2jv02qf7xgjwx.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/d2jv02qf7xgjwx.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/d2jv02qf7xgjwx.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/d2jv02qf7xgjwx.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: d2jv02qf7xgjwx.cloudfront.net"
echo "---"

# Domain 206/892: ubb.cl
log "Processing domain 206/892: ubb.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ubb.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ubb.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ubb.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ubb.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ubb.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ubb.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ubb.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ubb.cl"
echo "---"

# Domain 207/892: www.ubb.cl
log "Processing domain 207/892: www.ubb.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.ubb.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.ubb.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.ubb.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.ubb.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.ubb.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.ubb.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.ubb.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.ubb.cl"
echo "---"

# Domain 208/892: web.facebook.com
log "Processing domain 208/892: web.facebook.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/web.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/web.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/web.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/web.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/web.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/web.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/web.facebook.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: web.facebook.com"
echo "---"

# Domain 209/892: tapp.cl
log "Processing domain 209/892: tapp.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/tapp.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/tapp.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/tapp.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/tapp.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/tapp.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/tapp.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/tapp.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: tapp.cl"
echo "---"

# Domain 210/892: www.tapp.cl
log "Processing domain 210/892: www.tapp.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.tapp.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.tapp.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.tapp.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.tapp.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.tapp.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.tapp.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.tapp.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.tapp.cl"
echo "---"

# Domain 211/892: modyo.com
log "Processing domain 211/892: modyo.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/modyo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/modyo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/modyo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/modyo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/modyo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/modyo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/modyo.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: modyo.com"
echo "---"

# Domain 212/892: cla.cdn.modyo.com
log "Processing domain 212/892: cla.cdn.modyo.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cla.cdn.modyo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cla.cdn.modyo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cla.cdn.modyo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cla.cdn.modyo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cla.cdn.modyo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cla.cdn.modyo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cla.cdn.modyo.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cla.cdn.modyo.com"
echo "---"

# Domain 213/892: kit.fontawesome.com
log "Processing domain 213/892: kit.fontawesome.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/kit.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/kit.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/kit.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/kit.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/kit.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/kit.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/kit.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: kit.fontawesome.com"
echo "---"

# Domain 214/892: d2b2j57fl09mnx.cloudfront.net
log "Processing domain 214/892: d2b2j57fl09mnx.cloudfront.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/d2b2j57fl09mnx.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/d2b2j57fl09mnx.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/d2b2j57fl09mnx.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/d2b2j57fl09mnx.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/d2b2j57fl09mnx.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/d2b2j57fl09mnx.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/d2b2j57fl09mnx.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: d2b2j57fl09mnx.cloudfront.net"
echo "---"

# Domain 215/892: clubkino.cl
log "Processing domain 215/892: clubkino.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/clubkino.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/clubkino.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/clubkino.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/clubkino.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/clubkino.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/clubkino.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/clubkino.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: clubkino.cl"
echo "---"

# Domain 216/892: www.clubkino.cl
log "Processing domain 216/892: www.clubkino.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.clubkino.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.clubkino.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.clubkino.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.clubkino.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.clubkino.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.clubkino.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.clubkino.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.clubkino.cl"
echo "---"

# Domain 217/892: drupal.org
log "Processing domain 217/892: drupal.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/drupal.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/drupal.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/drupal.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/drupal.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/drupal.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/drupal.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/drupal.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: drupal.org"
echo "---"

# Domain 218/892: www.drupal.org
log "Processing domain 218/892: www.drupal.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.drupal.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.drupal.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.drupal.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.drupal.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.drupal.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.drupal.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.drupal.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.drupal.org"
echo "---"

# Domain 219/892: in.linkedin.com
log "Processing domain 219/892: in.linkedin.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/in.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/in.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/in.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/in.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/in.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/in.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/in.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: in.linkedin.com"
echo "---"

# Domain 220/892: vimeo.com
log "Processing domain 220/892: vimeo.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/vimeo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/vimeo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/vimeo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/vimeo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/vimeo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/vimeo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/vimeo.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: vimeo.com"
echo "---"

# Domain 221/892: telegram.org
log "Processing domain 221/892: telegram.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/telegram.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/telegram.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/telegram.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/telegram.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/telegram.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/telegram.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/telegram.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: telegram.org"
echo "---"

# Domain 222/892: web.whatsapp.com
log "Processing domain 222/892: web.whatsapp.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/web.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/web.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/web.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/web.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/web.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/web.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/web.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: web.whatsapp.com"
echo "---"

# Domain 223/892: github.com
log "Processing domain 223/892: github.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/github.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/github.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/github.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/github.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/github.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/github.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/github.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: github.com"
echo "---"

# Domain 224/892: magisterinnovagro.cl
log "Processing domain 224/892: magisterinnovagro.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/magisterinnovagro.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/magisterinnovagro.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/magisterinnovagro.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/magisterinnovagro.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/magisterinnovagro.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/magisterinnovagro.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/magisterinnovagro.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: magisterinnovagro.cl"
echo "---"

# Domain 225/892: forms.gle
log "Processing domain 225/892: forms.gle"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/forms.gle"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/forms.gle"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/forms.gle"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/forms.gle"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/forms.gle"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/forms.gle"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/forms.gle"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: forms.gle"
echo "---"

# Domain 226/892: flickr.com
log "Processing domain 226/892: flickr.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/flickr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/flickr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/flickr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/flickr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/flickr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/flickr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/flickr.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: flickr.com"
echo "---"

# Domain 227/892: www.flickr.com
log "Processing domain 227/892: www.flickr.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.flickr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.flickr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.flickr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.flickr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.flickr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.flickr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.flickr.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.flickr.com"
echo "---"

# Domain 228/892: www.mercadopublico.cl
log "Processing domain 228/892: www.mercadopublico.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.mercadopublico.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.mercadopublico.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.mercadopublico.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.mercadopublico.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.mercadopublico.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.mercadopublico.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.mercadopublico.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.mercadopublico.cl"
echo "---"

# Domain 229/892: stackpath.bootstrapcdn.com
log "Processing domain 229/892: stackpath.bootstrapcdn.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/stackpath.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/stackpath.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/stackpath.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/stackpath.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/stackpath.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/stackpath.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/stackpath.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: stackpath.bootstrapcdn.com"
echo "---"

# Domain 230/892: redclinica.cl
log "Processing domain 230/892: redclinica.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/redclinica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/redclinica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/redclinica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/redclinica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/redclinica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/redclinica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/redclinica.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: redclinica.cl"
echo "---"

# Domain 231/892: www.redclinica.cl
log "Processing domain 231/892: www.redclinica.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.redclinica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.redclinica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.redclinica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.redclinica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.redclinica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.redclinica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.redclinica.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.redclinica.cl"
echo "---"

# Domain 232/892: u-cursos.cl
log "Processing domain 232/892: u-cursos.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/u-cursos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/u-cursos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/u-cursos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/u-cursos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/u-cursos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/u-cursos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/u-cursos.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: u-cursos.cl"
echo "---"

# Domain 233/892: www.u-cursos.cl
log "Processing domain 233/892: www.u-cursos.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.u-cursos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.u-cursos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.u-cursos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.u-cursos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.u-cursos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.u-cursos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.u-cursos.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.u-cursos.cl"
echo "---"

# Domain 234/892: antumapu.cl
log "Processing domain 234/892: antumapu.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/antumapu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/antumapu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/antumapu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/antumapu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/antumapu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/antumapu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/antumapu.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: antumapu.cl"
echo "---"

# Domain 235/892: www.mi.antumapu.cl
log "Processing domain 235/892: www.mi.antumapu.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.mi.antumapu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.mi.antumapu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.mi.antumapu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.mi.antumapu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.mi.antumapu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.mi.antumapu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.mi.antumapu.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.mi.antumapu.cl"
echo "---"

# Domain 236/892: cl.linkedin.com
log "Processing domain 236/892: cl.linkedin.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cl.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cl.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cl.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cl.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cl.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cl.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cl.linkedin.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cl.linkedin.com"
echo "---"

# Domain 237/892: aguasantofagasta.cl
log "Processing domain 237/892: aguasantofagasta.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/aguasantofagasta.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/aguasantofagasta.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/aguasantofagasta.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/aguasantofagasta.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/aguasantofagasta.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/aguasantofagasta.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/aguasantofagasta.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: aguasantofagasta.cl"
echo "---"

# Domain 238/892: wwwprod.aguasantofagasta.cl
log "Processing domain 238/892: wwwprod.aguasantofagasta.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/wwwprod.aguasantofagasta.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/wwwprod.aguasantofagasta.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/wwwprod.aguasantofagasta.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/wwwprod.aguasantofagasta.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/wwwprod.aguasantofagasta.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/wwwprod.aguasantofagasta.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/wwwprod.aguasantofagasta.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: wwwprod.aguasantofagasta.cl"
echo "---"

# Domain 239/892: abfsa.cl
log "Processing domain 239/892: abfsa.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/abfsa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/abfsa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/abfsa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/abfsa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/abfsa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/abfsa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/abfsa.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: abfsa.cl"
echo "---"

# Domain 240/892: www.abfsa.cl
log "Processing domain 240/892: www.abfsa.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.abfsa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.abfsa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.abfsa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.abfsa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.abfsa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.abfsa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.abfsa.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.abfsa.cl"
echo "---"

# Domain 241/892: hiringroom.com
log "Processing domain 241/892: hiringroom.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/hiringroom.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/hiringroom.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/hiringroom.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/hiringroom.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/hiringroom.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/hiringroom.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/hiringroom.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: hiringroom.com"
echo "---"

# Domain 242/892: farmaciasahumada.hiringroom.com
log "Processing domain 242/892: farmaciasahumada.hiringroom.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/farmaciasahumada.hiringroom.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/farmaciasahumada.hiringroom.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/farmaciasahumada.hiringroom.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/farmaciasahumada.hiringroom.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/farmaciasahumada.hiringroom.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/farmaciasahumada.hiringroom.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/farmaciasahumada.hiringroom.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: farmaciasahumada.hiringroom.com"
echo "---"

# Domain 243/892: www.bcn.cl
log "Processing domain 243/892: www.bcn.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.bcn.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.bcn.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.bcn.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.bcn.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.bcn.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.bcn.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.bcn.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.bcn.cl"
echo "---"

# Domain 244/892: www.minsal.cl
log "Processing domain 244/892: www.minsal.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.minsal.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.minsal.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.minsal.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.minsal.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.minsal.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.minsal.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.minsal.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.minsal.cl"
echo "---"

# Domain 245/892: ahumadaexperiencia.cl
log "Processing domain 245/892: ahumadaexperiencia.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ahumadaexperiencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ahumadaexperiencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ahumadaexperiencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ahumadaexperiencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ahumadaexperiencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ahumadaexperiencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ahumadaexperiencia.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ahumadaexperiencia.cl"
echo "---"

# Domain 246/892: www.ahumadaexperiencia.cl
log "Processing domain 246/892: www.ahumadaexperiencia.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.ahumadaexperiencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.ahumadaexperiencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.ahumadaexperiencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.ahumadaexperiencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.ahumadaexperiencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.ahumadaexperiencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.ahumadaexperiencia.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.ahumadaexperiencia.cl"
echo "---"

# Domain 247/892: quimicambiental.cl
log "Processing domain 247/892: quimicambiental.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/quimicambiental.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/quimicambiental.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/quimicambiental.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/quimicambiental.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/quimicambiental.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/quimicambiental.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/quimicambiental.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: quimicambiental.cl"
echo "---"

# Domain 248/892: www.quimicambiental.cl
log "Processing domain 248/892: www.quimicambiental.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.quimicambiental.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.quimicambiental.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.quimicambiental.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.quimicambiental.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.quimicambiental.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.quimicambiental.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.quimicambiental.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.quimicambiental.cl"
echo "---"

# Domain 249/892: instana.io
log "Processing domain 249/892: instana.io"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/instana.io"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/instana.io"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/instana.io"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/instana.io"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/instana.io"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/instana.io"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/instana.io"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: instana.io"
echo "---"

# Domain 250/892: eum.instana.io
log "Processing domain 250/892: eum.instana.io"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/eum.instana.io"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/eum.instana.io"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/eum.instana.io"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/eum.instana.io"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/eum.instana.io"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/eum.instana.io"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/eum.instana.io"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: eum.instana.io"
echo "---"

# Domain 251/892: brandprotectionprogram.com
log "Processing domain 251/892: brandprotectionprogram.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/brandprotectionprogram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/brandprotectionprogram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/brandprotectionprogram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/brandprotectionprogram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/brandprotectionprogram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/brandprotectionprogram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/brandprotectionprogram.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: brandprotectionprogram.com"
echo "---"

# Domain 252/892: www.brandprotectionprogram.com
log "Processing domain 252/892: www.brandprotectionprogram.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.brandprotectionprogram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.brandprotectionprogram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.brandprotectionprogram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.brandprotectionprogram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.brandprotectionprogram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.brandprotectionprogram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.brandprotectionprogram.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.brandprotectionprogram.com"
echo "---"

# Domain 253/892: busesaltascumbres.cl
log "Processing domain 253/892: busesaltascumbres.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/busesaltascumbres.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/busesaltascumbres.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/busesaltascumbres.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/busesaltascumbres.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/busesaltascumbres.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/busesaltascumbres.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/busesaltascumbres.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: busesaltascumbres.cl"
echo "---"

# Domain 254/892: maps.google.com
log "Processing domain 254/892: maps.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/maps.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/maps.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/maps.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/maps.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/maps.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/maps.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/maps.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: maps.google.com"
echo "---"

# Domain 255/892: fiscalizacion.cl
log "Processing domain 255/892: fiscalizacion.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/fiscalizacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/fiscalizacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/fiscalizacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/fiscalizacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/fiscalizacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/fiscalizacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/fiscalizacion.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: fiscalizacion.cl"
echo "---"

# Domain 256/892: www.fiscalizacion.cl
log "Processing domain 256/892: www.fiscalizacion.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.fiscalizacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.fiscalizacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.fiscalizacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.fiscalizacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.fiscalizacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.fiscalizacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.fiscalizacion.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.fiscalizacion.cl"
echo "---"

# Domain 257/892: recorridoprod.s3.amazonaws.com
log "Processing domain 257/892: recorridoprod.s3.amazonaws.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/recorridoprod.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/recorridoprod.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/recorridoprod.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/recorridoprod.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/recorridoprod.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/recorridoprod.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/recorridoprod.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: recorridoprod.s3.amazonaws.com"
echo "---"

# Domain 258/892: buddypet.cl
log "Processing domain 258/892: buddypet.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/buddypet.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/buddypet.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/buddypet.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/buddypet.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/buddypet.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/buddypet.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/buddypet.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: buddypet.cl"
echo "---"

# Domain 259/892: www.buddypet.cl
log "Processing domain 259/892: www.buddypet.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.buddypet.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.buddypet.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.buddypet.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.buddypet.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.buddypet.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.buddypet.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.buddypet.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.buddypet.cl"
echo "---"

# Domain 260/892: freshdesk.com
log "Processing domain 260/892: freshdesk.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: freshdesk.com"
echo "---"

# Domain 261/892: assets1.freshdesk.com
log "Processing domain 261/892: assets1.freshdesk.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/assets1.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/assets1.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/assets1.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/assets1.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/assets1.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/assets1.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/assets1.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: assets1.freshdesk.com"
echo "---"

# Domain 262/892: assets8.freshdesk.com
log "Processing domain 262/892: assets8.freshdesk.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/assets8.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/assets8.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/assets8.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/assets8.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/assets8.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/assets8.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/assets8.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: assets8.freshdesk.com"
echo "---"

# Domain 263/892: freshworks.com
log "Processing domain 263/892: freshworks.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/freshworks.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/freshworks.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/freshworks.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/freshworks.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/freshworks.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/freshworks.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/freshworks.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: freshworks.com"
echo "---"

# Domain 264/892: widget.freshworks.com
log "Processing domain 264/892: widget.freshworks.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/widget.freshworks.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/widget.freshworks.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/widget.freshworks.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/widget.freshworks.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/widget.freshworks.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/widget.freshworks.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/widget.freshworks.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: widget.freshworks.com"
echo "---"

# Domain 265/892: assets6.freshdesk.com
log "Processing domain 265/892: assets6.freshdesk.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/assets6.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/assets6.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/assets6.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/assets6.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/assets6.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/assets6.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/assets6.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: assets6.freshdesk.com"
echo "---"

# Domain 266/892: assets9.freshdesk.com
log "Processing domain 266/892: assets9.freshdesk.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/assets9.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/assets9.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/assets9.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/assets9.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/assets9.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/assets9.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/assets9.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: assets9.freshdesk.com"
echo "---"

# Domain 267/892: s3.amazonaws.com
log "Processing domain 267/892: s3.amazonaws.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: s3.amazonaws.com"
echo "---"

# Domain 268/892: assets10.freshdesk.com
log "Processing domain 268/892: assets10.freshdesk.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/assets10.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/assets10.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/assets10.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/assets10.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/assets10.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/assets10.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/assets10.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: assets10.freshdesk.com"
echo "---"

# Domain 269/892: alumniunab.cl
log "Processing domain 269/892: alumniunab.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/alumniunab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/alumniunab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/alumniunab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/alumniunab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/alumniunab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/alumniunab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/alumniunab.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: alumniunab.cl"
echo "---"

# Domain 270/892: www.alumniunab.cl
log "Processing domain 270/892: www.alumniunab.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.alumniunab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.alumniunab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.alumniunab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.alumniunab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.alumniunab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.alumniunab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.alumniunab.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.alumniunab.cl"
echo "---"

# Domain 271/892: marfeel.com
log "Processing domain 271/892: marfeel.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/marfeel.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/marfeel.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/marfeel.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/marfeel.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/marfeel.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/marfeel.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/marfeel.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: marfeel.com"
echo "---"

# Domain 272/892: www.marfeel.com
log "Processing domain 272/892: www.marfeel.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.marfeel.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.marfeel.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.marfeel.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.marfeel.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.marfeel.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.marfeel.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.marfeel.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.marfeel.com"
echo "---"

# Domain 273/892: www.tvn.cl
log "Processing domain 273/892: www.tvn.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.tvn.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.tvn.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.tvn.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.tvn.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.tvn.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.tvn.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.tvn.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.tvn.cl"
echo "---"

# Domain 274/892: ampproject.org
log "Processing domain 274/892: ampproject.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ampproject.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ampproject.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ampproject.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ampproject.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ampproject.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ampproject.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ampproject.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ampproject.org"
echo "---"

# Domain 275/892: cdn.ampproject.org
log "Processing domain 275/892: cdn.ampproject.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cdn.ampproject.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cdn.ampproject.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cdn.ampproject.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cdn.ampproject.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cdn.ampproject.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cdn.ampproject.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cdn.ampproject.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cdn.ampproject.org"
echo "---"

# Domain 276/892: pressreader.com
log "Processing domain 276/892: pressreader.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/pressreader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/pressreader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/pressreader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/pressreader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/pressreader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/pressreader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/pressreader.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: pressreader.com"
echo "---"

# Domain 277/892: diariofinanciero.pressreader.com
log "Processing domain 277/892: diariofinanciero.pressreader.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/diariofinanciero.pressreader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/diariofinanciero.pressreader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/diariofinanciero.pressreader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/diariofinanciero.pressreader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/diariofinanciero.pressreader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/diariofinanciero.pressreader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/diariofinanciero.pressreader.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: diariofinanciero.pressreader.com"
echo "---"

# Domain 278/892: grupodf.cl
log "Processing domain 278/892: grupodf.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/grupodf.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/grupodf.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/grupodf.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/grupodf.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/grupodf.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/grupodf.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/grupodf.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: grupodf.cl"
echo "---"

# Domain 279/892: comercial.grupodf.cl
log "Processing domain 279/892: comercial.grupodf.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/comercial.grupodf.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/comercial.grupodf.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/comercial.grupodf.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/comercial.grupodf.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/comercial.grupodf.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/comercial.grupodf.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/comercial.grupodf.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: comercial.grupodf.cl"
echo "---"

# Domain 280/892: dfsud.com
log "Processing domain 280/892: dfsud.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/dfsud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/dfsud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/dfsud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/dfsud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/dfsud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/dfsud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/dfsud.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: dfsud.com"
echo "---"

# Domain 281/892: mail.google.com
log "Processing domain 281/892: mail.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mail.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mail.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mail.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mail.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mail.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mail.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mail.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mail.google.com"
echo "---"

# Domain 282/892: latercera.com
log "Processing domain 282/892: latercera.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/latercera.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/latercera.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/latercera.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/latercera.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/latercera.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/latercera.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/latercera.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: latercera.com"
echo "---"

# Domain 283/892: especiales.latercera.com
log "Processing domain 283/892: especiales.latercera.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/especiales.latercera.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/especiales.latercera.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/especiales.latercera.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/especiales.latercera.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/especiales.latercera.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/especiales.latercera.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/especiales.latercera.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: especiales.latercera.com"
echo "---"

# Domain 284/892: topuniversities.com
log "Processing domain 284/892: topuniversities.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/topuniversities.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/topuniversities.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/topuniversities.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/topuniversities.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/topuniversities.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/topuniversities.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/topuniversities.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: topuniversities.com"
echo "---"

# Domain 285/892: www.topuniversities.com
log "Processing domain 285/892: www.topuniversities.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.topuniversities.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.topuniversities.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.topuniversities.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.topuniversities.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.topuniversities.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.topuniversities.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.topuniversities.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.topuniversities.com"
echo "---"

# Domain 286/892: timeshighereducation.com
log "Processing domain 286/892: timeshighereducation.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/timeshighereducation.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/timeshighereducation.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/timeshighereducation.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/timeshighereducation.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/timeshighereducation.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/timeshighereducation.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/timeshighereducation.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: timeshighereducation.com"
echo "---"

# Domain 287/892: www.timeshighereducation.com
log "Processing domain 287/892: www.timeshighereducation.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.timeshighereducation.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.timeshighereducation.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.timeshighereducation.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.timeshighereducation.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.timeshighereducation.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.timeshighereducation.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.timeshighereducation.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.timeshighereducation.com"
echo "---"

# Domain 288/892: anid.cl
log "Processing domain 288/892: anid.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/anid.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: anid.cl"
echo "---"

# Domain 289/892: auregionales.cl
log "Processing domain 289/892: auregionales.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/auregionales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/auregionales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/auregionales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/auregionales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/auregionales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/auregionales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/auregionales.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: auregionales.cl"
echo "---"

# Domain 290/892: www.auregionales.cl
log "Processing domain 290/892: www.auregionales.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.auregionales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.auregionales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.auregionales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.auregionales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.auregionales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.auregionales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.auregionales.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.auregionales.cl"
echo "---"

# Domain 291/892: cned.cl
log "Processing domain 291/892: cned.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cned.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cned.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cned.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cned.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cned.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cned.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cned.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cned.cl"
echo "---"

# Domain 292/892: consejoderectores.cl
log "Processing domain 292/892: consejoderectores.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/consejoderectores.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/consejoderectores.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/consejoderectores.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/consejoderectores.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/consejoderectores.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/consejoderectores.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/consejoderectores.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: consejoderectores.cl"
echo "---"

# Domain 293/892: sesuperior.cl
log "Processing domain 293/892: sesuperior.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/sesuperior.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/sesuperior.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/sesuperior.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/sesuperior.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/sesuperior.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/sesuperior.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/sesuperior.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: sesuperior.cl"
echo "---"

# Domain 294/892: www.sesuperior.cl
log "Processing domain 294/892: www.sesuperior.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.sesuperior.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.sesuperior.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.sesuperior.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.sesuperior.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.sesuperior.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.sesuperior.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.sesuperior.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.sesuperior.cl"
echo "---"

# Domain 295/892: www.mineduc.cl
log "Processing domain 295/892: www.mineduc.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.mineduc.cl"
echo "---"

# Domain 296/892: minciencia.gob.cl
log "Processing domain 296/892: minciencia.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/minciencia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/minciencia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/minciencia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/minciencia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/minciencia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/minciencia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/minciencia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: minciencia.gob.cl"
echo "---"

# Domain 297/892: www.minciencia.gob.cl
log "Processing domain 297/892: www.minciencia.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.minciencia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.minciencia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.minciencia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.minciencia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.minciencia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.minciencia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.minciencia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.minciencia.gob.cl"
echo "---"

# Domain 298/892: datosabiertos.mineduc.cl
log "Processing domain 298/892: datosabiertos.mineduc.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/datosabiertos.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/datosabiertos.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/datosabiertos.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/datosabiertos.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/datosabiertos.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/datosabiertos.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/datosabiertos.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: datosabiertos.mineduc.cl"
echo "---"

# Domain 299/892: uestatales.cl
log "Processing domain 299/892: uestatales.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: uestatales.cl"
echo "---"

# Domain 300/892: www.uestatales.cl
log "Processing domain 300/892: www.uestatales.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.uestatales.cl"
echo "---"

# Domain 301/892: ine.gob.cl
log "Processing domain 301/892: ine.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ine.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ine.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ine.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ine.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ine.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ine.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ine.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ine.gob.cl"
echo "---"

# Domain 302/892: www.ine.gob.cl
log "Processing domain 302/892: www.ine.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.ine.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.ine.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.ine.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.ine.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.ine.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.ine.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.ine.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.ine.gob.cl"
echo "---"

# Domain 303/892: superdesalud.gob.cl
log "Processing domain 303/892: superdesalud.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/superdesalud.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/superdesalud.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/superdesalud.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/superdesalud.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/superdesalud.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/superdesalud.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/superdesalud.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: superdesalud.gob.cl"
echo "---"

# Domain 304/892: www.superdesalud.gob.cl
log "Processing domain 304/892: www.superdesalud.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.superdesalud.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.superdesalud.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.superdesalud.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.superdesalud.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.superdesalud.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.superdesalud.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.superdesalud.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.superdesalud.gob.cl"
echo "---"

# Domain 305/892: dfi.mineduc.cl
log "Processing domain 305/892: dfi.mineduc.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/dfi.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/dfi.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/dfi.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/dfi.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/dfi.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/dfi.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/dfi.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: dfi.mineduc.cl"
echo "---"

# Domain 306/892: cies.uestatales.cl
log "Processing domain 306/892: cies.uestatales.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cies.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cies.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cies.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cies.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cies.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cies.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cies.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cies.uestatales.cl"
echo "---"

# Domain 307/892: pes.mineduc.cl
log "Processing domain 307/892: pes.mineduc.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/pes.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/pes.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/pes.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/pes.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/pes.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/pes.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/pes.mineduc.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: pes.mineduc.cl"
echo "---"

# Domain 308/892: big.data.uestatales.cl
log "Processing domain 308/892: big.data.uestatales.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/big.data.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/big.data.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/big.data.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/big.data.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/big.data.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/big.data.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/big.data.uestatales.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: big.data.uestatales.cl"
echo "---"

# Domain 309/892: cwts.nl
log "Processing domain 309/892: cwts.nl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cwts.nl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cwts.nl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cwts.nl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cwts.nl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cwts.nl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cwts.nl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cwts.nl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cwts.nl"
echo "---"

# Domain 310/892: www.cwts.nl
log "Processing domain 310/892: www.cwts.nl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.cwts.nl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.cwts.nl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.cwts.nl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.cwts.nl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.cwts.nl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.cwts.nl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.cwts.nl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.cwts.nl"
echo "---"

# Domain 311/892: top2percentscientists.com
log "Processing domain 311/892: top2percentscientists.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/top2percentscientists.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/top2percentscientists.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/top2percentscientists.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/top2percentscientists.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/top2percentscientists.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/top2percentscientists.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/top2percentscientists.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: top2percentscientists.com"
echo "---"

# Domain 312/892: ac.id
log "Processing domain 312/892: ac.id"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ac.id"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ac.id"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ac.id"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ac.id"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ac.id"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ac.id"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ac.id"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ac.id"
echo "---"

# Domain 313/892: greenmetric.ui.ac.id
log "Processing domain 313/892: greenmetric.ui.ac.id"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/greenmetric.ui.ac.id"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/greenmetric.ui.ac.id"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/greenmetric.ui.ac.id"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/greenmetric.ui.ac.id"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/greenmetric.ui.ac.id"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/greenmetric.ui.ac.id"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/greenmetric.ui.ac.id"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: greenmetric.ui.ac.id"
echo "---"

# Domain 314/892: emailjs.com
log "Processing domain 314/892: emailjs.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/emailjs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/emailjs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/emailjs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/emailjs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/emailjs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/emailjs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/emailjs.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: emailjs.com"
echo "---"

# Domain 315/892: cdn.emailjs.com
log "Processing domain 315/892: cdn.emailjs.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cdn.emailjs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cdn.emailjs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cdn.emailjs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cdn.emailjs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cdn.emailjs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cdn.emailjs.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cdn.emailjs.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cdn.emailjs.com"
echo "---"

# Domain 316/892: www.emol.com
log "Processing domain 316/892: www.emol.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.emol.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.emol.com"
echo "---"

# Domain 317/892: elmercurio.com 
log "Processing domain 317/892: elmercurio.com "
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/elmercurio.com "
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/elmercurio.com "
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/elmercurio.com "
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/elmercurio.com "
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/elmercurio.com "
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/elmercurio.com "
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/elmercurio.com "
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: elmercurio.com "
echo "---"

# Domain 318/892: digital.elmercurio.com 
log "Processing domain 318/892: digital.elmercurio.com "
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/digital.elmercurio.com "
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/digital.elmercurio.com "
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/digital.elmercurio.com "
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/digital.elmercurio.com "
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/digital.elmercurio.com "
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/digital.elmercurio.com "
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/digital.elmercurio.com "
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: digital.elmercurio.com "
echo "---"

# Domain 319/892: elmercurio.com
log "Processing domain 319/892: elmercurio.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: elmercurio.com"
echo "---"

# Domain 320/892: www.elmercurio.com
log "Processing domain 320/892: www.elmercurio.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.elmercurio.com"
echo "---"

# Domain 321/892: automoviles.emol.com
log "Processing domain 321/892: automoviles.emol.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/automoviles.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/automoviles.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/automoviles.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/automoviles.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/automoviles.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/automoviles.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/automoviles.emol.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: automoviles.emol.com"
echo "---"

# Domain 322/892: propiedades.elmercurio.com
log "Processing domain 322/892: propiedades.elmercurio.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/propiedades.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/propiedades.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/propiedades.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/propiedades.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/propiedades.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/propiedades.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/propiedades.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: propiedades.elmercurio.com"
echo "---"

# Domain 323/892: mundolaboral.elmercurio.com
log "Processing domain 323/892: mundolaboral.elmercurio.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mundolaboral.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mundolaboral.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mundolaboral.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mundolaboral.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mundolaboral.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mundolaboral.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mundolaboral.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mundolaboral.elmercurio.com"
echo "---"

# Domain 324/892: economicos.cl
log "Processing domain 324/892: economicos.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/economicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/economicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/economicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/economicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/economicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/economicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/economicos.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: economicos.cl"
echo "---"

# Domain 325/892: www.economicos.cl
log "Processing domain 325/892: www.economicos.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.economicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.economicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.economicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.economicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.economicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.economicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.economicos.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.economicos.cl"
echo "---"

# Domain 326/892: lasegunda.com
log "Processing domain 326/892: lasegunda.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/lasegunda.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/lasegunda.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/lasegunda.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/lasegunda.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/lasegunda.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/lasegunda.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/lasegunda.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: lasegunda.com"
echo "---"

# Domain 327/892: www.lasegunda.com
log "Processing domain 327/892: www.lasegunda.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.lasegunda.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.lasegunda.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.lasegunda.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.lasegunda.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.lasegunda.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.lasegunda.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.lasegunda.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.lasegunda.com"
echo "---"

# Domain 328/892: lun.com
log "Processing domain 328/892: lun.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/lun.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/lun.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/lun.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/lun.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/lun.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/lun.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/lun.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: lun.com"
echo "---"

# Domain 329/892: www.lun.com
log "Processing domain 329/892: www.lun.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.lun.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.lun.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.lun.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.lun.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.lun.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.lun.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.lun.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.lun.com"
echo "---"

# Domain 330/892: tv.emol.com
log "Processing domain 330/892: tv.emol.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/tv.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/tv.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/tv.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/tv.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/tv.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/tv.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/tv.emol.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: tv.emol.com"
echo "---"

# Domain 331/892: restaurantes.emol.com
log "Processing domain 331/892: restaurantes.emol.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/restaurantes.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/restaurantes.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/restaurantes.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/restaurantes.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/restaurantes.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/restaurantes.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/restaurantes.emol.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: restaurantes.emol.com"
echo "---"

# Domain 332/892: clubdelectores.cl
log "Processing domain 332/892: clubdelectores.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/clubdelectores.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/clubdelectores.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/clubdelectores.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/clubdelectores.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/clubdelectores.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/clubdelectores.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/clubdelectores.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: clubdelectores.cl"
echo "---"

# Domain 333/892: www.clubdelectores.cl
log "Processing domain 333/892: www.clubdelectores.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.clubdelectores.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.clubdelectores.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.clubdelectores.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.clubdelectores.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.clubdelectores.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.clubdelectores.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.clubdelectores.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.clubdelectores.cl"
echo "---"

# Domain 334/892: digital.elmercurio.com
log "Processing domain 334/892: digital.elmercurio.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/digital.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/digital.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/digital.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/digital.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/digital.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/digital.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/digital.elmercurio.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: digital.elmercurio.com"
echo "---"

# Domain 335/892: www.soychile.cl
log "Processing domain 335/892: www.soychile.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.soychile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.soychile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.soychile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.soychile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.soychile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.soychile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.soychile.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.soychile.cl"
echo "---"

# Domain 336/892: adxion.com
log "Processing domain 336/892: adxion.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/adxion.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/adxion.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/adxion.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/adxion.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/adxion.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/adxion.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/adxion.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: adxion.com"
echo "---"

# Domain 337/892: www.adxion.com
log "Processing domain 337/892: www.adxion.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.adxion.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.adxion.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.adxion.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.adxion.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.adxion.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.adxion.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.adxion.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.adxion.com"
echo "---"

# Domain 338/892: valorfuturo.com
log "Processing domain 338/892: valorfuturo.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/valorfuturo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/valorfuturo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/valorfuturo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/valorfuturo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/valorfuturo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/valorfuturo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/valorfuturo.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: valorfuturo.com"
echo "---"

# Domain 339/892: www.valorfuturo.com
log "Processing domain 339/892: www.valorfuturo.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.valorfuturo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.valorfuturo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.valorfuturo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.valorfuturo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.valorfuturo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.valorfuturo.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.valorfuturo.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.valorfuturo.com"
echo "---"

# Domain 340/892: mercadomayorista.lun.com
log "Processing domain 340/892: mercadomayorista.lun.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mercadomayorista.lun.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mercadomayorista.lun.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mercadomayorista.lun.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mercadomayorista.lun.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mercadomayorista.lun.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mercadomayorista.lun.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mercadomayorista.lun.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mercadomayorista.lun.com"
echo "---"

# Domain 341/892: static.emol.cl
log "Processing domain 341/892: static.emol.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/static.emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/static.emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/static.emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/static.emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/static.emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/static.emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/static.emol.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: static.emol.cl"
echo "---"

# Domain 342/892: mediaserver.emol.cl
log "Processing domain 342/892: mediaserver.emol.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mediaserver.emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mediaserver.emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mediaserver.emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mediaserver.emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mediaserver.emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mediaserver.emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mediaserver.emol.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mediaserver.emol.cl"
echo "---"

# Domain 343/892: merreader.emol.cl
log "Processing domain 343/892: merreader.emol.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/merreader.emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/merreader.emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/merreader.emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/merreader.emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/merreader.emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/merreader.emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/merreader.emol.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: merreader.emol.cl"
echo "---"

# Domain 344/892: sspnm.emol.com
log "Processing domain 344/892: sspnm.emol.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/sspnm.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/sspnm.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/sspnm.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/sspnm.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/sspnm.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/sspnm.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/sspnm.emol.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: sspnm.emol.com"
echo "---"

# Domain 345/892: apps.emol.com
log "Processing domain 345/892: apps.emol.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/apps.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/apps.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/apps.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/apps.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/apps.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/apps.emol.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/apps.emol.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: apps.emol.com"
echo "---"

# Domain 346/892: campuscibelae.net
log "Processing domain 346/892: campuscibelae.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/campuscibelae.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/campuscibelae.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/campuscibelae.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/campuscibelae.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/campuscibelae.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/campuscibelae.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/campuscibelae.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: campuscibelae.net"
echo "---"

# Domain 347/892: www.campuscibelae.net
log "Processing domain 347/892: www.campuscibelae.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.campuscibelae.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.campuscibelae.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.campuscibelae.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.campuscibelae.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.campuscibelae.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.campuscibelae.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.campuscibelae.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.campuscibelae.net"
echo "---"

# Domain 348/892: moodle.org
log "Processing domain 348/892: moodle.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/moodle.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/moodle.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/moodle.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/moodle.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/moodle.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/moodle.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/moodle.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: moodle.org"
echo "---"

# Domain 349/892: conecti.me
log "Processing domain 349/892: conecti.me"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/conecti.me"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/conecti.me"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/conecti.me"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/conecti.me"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/conecti.me"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/conecti.me"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/conecti.me"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: conecti.me"
echo "---"

# Domain 350/892: guaufest.cl
log "Processing domain 350/892: guaufest.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/guaufest.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/guaufest.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/guaufest.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/guaufest.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/guaufest.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/guaufest.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/guaufest.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: guaufest.cl"
echo "---"

# Domain 351/892: aka.ms
log "Processing domain 351/892: aka.ms"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/aka.ms"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/aka.ms"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/aka.ms"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/aka.ms"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/aka.ms"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/aka.ms"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/aka.ms"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: aka.ms"
echo "---"

# Domain 352/892: microsoft.com
log "Processing domain 352/892: microsoft.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/microsoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/microsoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/microsoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/microsoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/microsoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/microsoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/microsoft.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: microsoft.com"
echo "---"

# Domain 353/892: go.microsoft.com
log "Processing domain 353/892: go.microsoft.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/go.microsoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/go.microsoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/go.microsoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/go.microsoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/go.microsoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/go.microsoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/go.microsoft.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: go.microsoft.com"
echo "---"

# Domain 354/892: identity.security
log "Processing domain 354/892: identity.security"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/identity.security"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/identity.security"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/identity.security"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/identity.security"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/identity.security"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/identity.security"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/identity.security"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: identity.security"
echo "---"

# Domain 355/892: signin.identity.security
log "Processing domain 355/892: signin.identity.security"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/signin.identity.security"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/signin.identity.security"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/signin.identity.security"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/signin.identity.security"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/signin.identity.security"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/signin.identity.security"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/signin.identity.security"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: signin.identity.security"
echo "---"

# Domain 356/892: jotform.com
log "Processing domain 356/892: jotform.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/jotform.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/jotform.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/jotform.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/jotform.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/jotform.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/jotform.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/jotform.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: jotform.com"
echo "---"

# Domain 357/892: form.jotform.com
log "Processing domain 357/892: form.jotform.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/form.jotform.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/form.jotform.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/form.jotform.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/form.jotform.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/form.jotform.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/form.jotform.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/form.jotform.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: form.jotform.com"
echo "---"

# Domain 358/892: twitch.tv
log "Processing domain 358/892: twitch.tv"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/twitch.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/twitch.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/twitch.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/twitch.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/twitch.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/twitch.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/twitch.tv"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: twitch.tv"
echo "---"

# Domain 359/892: www.twitch.tv
log "Processing domain 359/892: www.twitch.tv"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.twitch.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.twitch.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.twitch.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.twitch.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.twitch.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.twitch.tv"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.twitch.tv"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.twitch.tv"
echo "---"

# Domain 360/892: chilevision.trabajando.cl
log "Processing domain 360/892: chilevision.trabajando.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/chilevision.trabajando.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/chilevision.trabajando.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/chilevision.trabajando.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/chilevision.trabajando.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/chilevision.trabajando.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/chilevision.trabajando.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/chilevision.trabajando.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: chilevision.trabajando.cl"
echo "---"

# Domain 361/892: paramount.com
log "Processing domain 361/892: paramount.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/paramount.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/paramount.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/paramount.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/paramount.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/paramount.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/paramount.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/paramount.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: paramount.com"
echo "---"

# Domain 362/892: privacy.paramount.com
log "Processing domain 362/892: privacy.paramount.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/privacy.paramount.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/privacy.paramount.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/privacy.paramount.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/privacy.paramount.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/privacy.paramount.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/privacy.paramount.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/privacy.paramount.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: privacy.paramount.com"
echo "---"

# Domain 363/892: play.google.com
log "Processing domain 363/892: play.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/play.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/play.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/play.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/play.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/play.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/play.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/play.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: play.google.com"
echo "---"

# Domain 364/892: apple.com
log "Processing domain 364/892: apple.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/apple.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/apple.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/apple.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/apple.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/apple.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/apple.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/apple.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: apple.com"
echo "---"

# Domain 365/892: apps.apple.com
log "Processing domain 365/892: apps.apple.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/apps.apple.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/apps.apple.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/apps.apple.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/apps.apple.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/apps.apple.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/apps.apple.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/apps.apple.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: apps.apple.com"
echo "---"

# Domain 366/892: ebxcdn.com
log "Processing domain 366/892: ebxcdn.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ebxcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ebxcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ebxcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ebxcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ebxcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ebxcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ebxcdn.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ebxcdn.com"
echo "---"

# Domain 367/892: applets.ebxcdn.com
log "Processing domain 367/892: applets.ebxcdn.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/applets.ebxcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/applets.ebxcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/applets.ebxcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/applets.ebxcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/applets.ebxcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/applets.ebxcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/applets.ebxcdn.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: applets.ebxcdn.com"
echo "---"

# Domain 368/892: cookielaw.org
log "Processing domain 368/892: cookielaw.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cookielaw.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cookielaw.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cookielaw.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cookielaw.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cookielaw.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cookielaw.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cookielaw.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cookielaw.org"
echo "---"

# Domain 369/892: cdn.cookielaw.org
log "Processing domain 369/892: cdn.cookielaw.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cdn.cookielaw.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cdn.cookielaw.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cdn.cookielaw.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cdn.cookielaw.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cdn.cookielaw.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cdn.cookielaw.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cdn.cookielaw.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cdn.cookielaw.org"
echo "---"

# Domain 370/892: cdn.privacy.paramount.com
log "Processing domain 370/892: cdn.privacy.paramount.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cdn.privacy.paramount.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cdn.privacy.paramount.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cdn.privacy.paramount.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cdn.privacy.paramount.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cdn.privacy.paramount.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cdn.privacy.paramount.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cdn.privacy.paramount.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cdn.privacy.paramount.com"
echo "---"

# Domain 371/892: chartbeat.com
log "Processing domain 371/892: chartbeat.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/chartbeat.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/chartbeat.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/chartbeat.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/chartbeat.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/chartbeat.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/chartbeat.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/chartbeat.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: chartbeat.com"
echo "---"

# Domain 372/892: static.chartbeat.com
log "Processing domain 372/892: static.chartbeat.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/static.chartbeat.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/static.chartbeat.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/static.chartbeat.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/static.chartbeat.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/static.chartbeat.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/static.chartbeat.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/static.chartbeat.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: static.chartbeat.com"
echo "---"

# Domain 373/892: wa.me
log "Processing domain 373/892: wa.me"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/wa.me"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/wa.me"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/wa.me"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/wa.me"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/wa.me"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/wa.me"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/wa.me"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: wa.me"
echo "---"

# Domain 374/892: android.com
log "Processing domain 374/892: android.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/android.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/android.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/android.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/android.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/android.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/android.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/android.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: android.com"
echo "---"

# Domain 375/892: developer.android.com
log "Processing domain 375/892: developer.android.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/developer.android.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/developer.android.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/developer.android.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/developer.android.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/developer.android.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/developer.android.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/developer.android.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: developer.android.com"
echo "---"

# Domain 376/892: store.google.com
log "Processing domain 376/892: store.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/store.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/store.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/store.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/store.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/store.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/store.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/store.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: store.google.com"
echo "---"

# Domain 377/892: fonts.gstatic.com
log "Processing domain 377/892: fonts.gstatic.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/fonts.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/fonts.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/fonts.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/fonts.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/fonts.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/fonts.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/fonts.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: fonts.gstatic.com"
echo "---"

# Domain 378/892: ytimg.com
log "Processing domain 378/892: ytimg.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ytimg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ytimg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ytimg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ytimg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ytimg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ytimg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ytimg.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ytimg.com"
echo "---"

# Domain 379/892: i.ytimg.com
log "Processing domain 379/892: i.ytimg.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/i.ytimg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/i.ytimg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/i.ytimg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/i.ytimg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/i.ytimg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/i.ytimg.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/i.ytimg.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: i.ytimg.com"
echo "---"

# Domain 380/892: googleusercontent.com
log "Processing domain 380/892: googleusercontent.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: googleusercontent.com"
echo "---"

# Domain 381/892: play-lh.googleusercontent.com
log "Processing domain 381/892: play-lh.googleusercontent.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/play-lh.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/play-lh.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/play-lh.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/play-lh.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/play-lh.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/play-lh.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/play-lh.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: play-lh.googleusercontent.com"
echo "---"

# Domain 382/892: ssl.gstatic.com
log "Processing domain 382/892: ssl.gstatic.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ssl.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ssl.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ssl.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ssl.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ssl.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ssl.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ssl.gstatic.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ssl.gstatic.com"
echo "---"

# Domain 383/892: midt.dirtrab.cl
log "Processing domain 383/892: midt.dirtrab.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/midt.dirtrab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/midt.dirtrab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/midt.dirtrab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/midt.dirtrab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/midt.dirtrab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/midt.dirtrab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/midt.dirtrab.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: midt.dirtrab.cl"
echo "---"

# Domain 384/892: edu.google.com
log "Processing domain 384/892: edu.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/edu.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/edu.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/edu.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/edu.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/edu.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/edu.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/edu.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: edu.google.com"
echo "---"

# Domain 385/892: appsheet.com
log "Processing domain 385/892: appsheet.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/appsheet.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/appsheet.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/appsheet.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/appsheet.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/appsheet.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/appsheet.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/appsheet.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: appsheet.com"
echo "---"

# Domain 386/892: about.appsheet.com
log "Processing domain 386/892: about.appsheet.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/about.appsheet.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/about.appsheet.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/about.appsheet.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/about.appsheet.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/about.appsheet.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/about.appsheet.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/about.appsheet.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: about.appsheet.com"
echo "---"

# Domain 387/892: workspace.google.com
log "Processing domain 387/892: workspace.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/workspace.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/workspace.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/workspace.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/workspace.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/workspace.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/workspace.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/workspace.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: workspace.google.com"
echo "---"

# Domain 388/892: cloudonair.withgoogle.com
log "Processing domain 388/892: cloudonair.withgoogle.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cloudonair.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cloudonair.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cloudonair.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cloudonair.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cloudonair.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cloudonair.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cloudonair.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cloudonair.withgoogle.com"
echo "---"

# Domain 389/892: admin.google.com
log "Processing domain 389/892: admin.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/admin.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/admin.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/admin.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/admin.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/admin.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/admin.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/admin.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: admin.google.com"
echo "---"

# Domain 390/892: goo.gle
log "Processing domain 390/892: goo.gle"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/goo.gle"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/goo.gle"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/goo.gle"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/goo.gle"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/goo.gle"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/goo.gle"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/goo.gle"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: goo.gle"
echo "---"

# Domain 391/892: cloud.withgoogle.com
log "Processing domain 391/892: cloud.withgoogle.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cloud.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cloud.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cloud.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cloud.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cloud.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cloud.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cloud.withgoogle.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cloud.withgoogle.com"
echo "---"

# Domain 392/892: productforums.google.com
log "Processing domain 392/892: productforums.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/productforums.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/productforums.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/productforums.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/productforums.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/productforums.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/productforums.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/productforums.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: productforums.google.com"
echo "---"

# Domain 393/892: googlecloudcommunity.com
log "Processing domain 393/892: googlecloudcommunity.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/googlecloudcommunity.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/googlecloudcommunity.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/googlecloudcommunity.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/googlecloudcommunity.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/googlecloudcommunity.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/googlecloudcommunity.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/googlecloudcommunity.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: googlecloudcommunity.com"
echo "---"

# Domain 394/892: www.googlecloudcommunity.com
log "Processing domain 394/892: www.googlecloudcommunity.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.googlecloudcommunity.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.googlecloudcommunity.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.googlecloudcommunity.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.googlecloudcommunity.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.googlecloudcommunity.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.googlecloudcommunity.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.googlecloudcommunity.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.googlecloudcommunity.com"
echo "---"

# Domain 395/892: domains.google.com
log "Processing domain 395/892: domains.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/domains.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/domains.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/domains.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/domains.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/domains.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/domains.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/domains.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: domains.google.com"
echo "---"

# Domain 396/892: chromeenterprise.google
log "Processing domain 396/892: chromeenterprise.google"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/chromeenterprise.google"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/chromeenterprise.google"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/chromeenterprise.google"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/chromeenterprise.google"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/chromeenterprise.google"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/chromeenterprise.google"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/chromeenterprise.google"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: chromeenterprise.google"
echo "---"

# Domain 397/892: businessmessages.google
log "Processing domain 397/892: businessmessages.google"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/businessmessages.google"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/businessmessages.google"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/businessmessages.google"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/businessmessages.google"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/businessmessages.google"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/businessmessages.google"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/businessmessages.google"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: businessmessages.google"
echo "---"

# Domain 398/892: userresearch.google.com
log "Processing domain 398/892: userresearch.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/userresearch.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/userresearch.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/userresearch.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/userresearch.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/userresearch.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/userresearch.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/userresearch.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: userresearch.google.com"
echo "---"

# Domain 399/892: lh3.googleusercontent.com
log "Processing domain 399/892: lh3.googleusercontent.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/lh3.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/lh3.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/lh3.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/lh3.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/lh3.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/lh3.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/lh3.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: lh3.googleusercontent.com"
echo "---"

# Domain 400/892: storage.googleapis.com
log "Processing domain 400/892: storage.googleapis.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/storage.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/storage.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/storage.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/storage.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/storage.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/storage.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/storage.googleapis.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: storage.googleapis.com"
echo "---"

# Domain 401/892: cloudfunctions.net
log "Processing domain 401/892: cloudfunctions.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cloudfunctions.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cloudfunctions.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cloudfunctions.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cloudfunctions.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cloudfunctions.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cloudfunctions.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cloudfunctions.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cloudfunctions.net"
echo "---"

# Domain 402/892: us-central1-gweb-cloudx-marketo.cloudfunctions.net
log "Processing domain 402/892: us-central1-gweb-cloudx-marketo.cloudfunctions.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/us-central1-gweb-cloudx-marketo.cloudfunctions.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/us-central1-gweb-cloudx-marketo.cloudfunctions.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/us-central1-gweb-cloudx-marketo.cloudfunctions.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/us-central1-gweb-cloudx-marketo.cloudfunctions.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/us-central1-gweb-cloudx-marketo.cloudfunctions.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/us-central1-gweb-cloudx-marketo.cloudfunctions.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/us-central1-gweb-cloudx-marketo.cloudfunctions.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: us-central1-gweb-cloudx-marketo.cloudfunctions.net"
echo "---"

# Domain 403/892: walmart.cl
log "Processing domain 403/892: walmart.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/walmart.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/walmart.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/walmart.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/walmart.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/walmart.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/walmart.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/walmart.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: walmart.cl"
echo "---"

# Domain 404/892: marketplace.walmart.cl
log "Processing domain 404/892: marketplace.walmart.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/marketplace.walmart.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/marketplace.walmart.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/marketplace.walmart.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/marketplace.walmart.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/marketplace.walmart.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/marketplace.walmart.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/marketplace.walmart.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: marketplace.walmart.cl"
echo "---"

# Domain 405/892: liderbciserviciosfinancieros.cl
log "Processing domain 405/892: liderbciserviciosfinancieros.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/liderbciserviciosfinancieros.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/liderbciserviciosfinancieros.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/liderbciserviciosfinancieros.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/liderbciserviciosfinancieros.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/liderbciserviciosfinancieros.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/liderbciserviciosfinancieros.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/liderbciserviciosfinancieros.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: liderbciserviciosfinancieros.cl"
echo "---"

# Domain 406/892: tarjetadigital.liderbciserviciosfinancieros.cl
log "Processing domain 406/892: tarjetadigital.liderbciserviciosfinancieros.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/tarjetadigital.liderbciserviciosfinancieros.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/tarjetadigital.liderbciserviciosfinancieros.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/tarjetadigital.liderbciserviciosfinancieros.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/tarjetadigital.liderbciserviciosfinancieros.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/tarjetadigital.liderbciserviciosfinancieros.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/tarjetadigital.liderbciserviciosfinancieros.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/tarjetadigital.liderbciserviciosfinancieros.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: tarjetadigital.liderbciserviciosfinancieros.cl"
echo "---"

# Domain 407/892: miclublider.cl
log "Processing domain 407/892: miclublider.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/miclublider.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/miclublider.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/miclublider.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/miclublider.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/miclublider.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/miclublider.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/miclublider.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: miclublider.cl"
echo "---"

# Domain 408/892: www.miclublider.cl
log "Processing domain 408/892: www.miclublider.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.miclublider.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.miclublider.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.miclublider.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.miclublider.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.miclublider.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.miclublider.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.miclublider.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.miclublider.cl"
echo "---"

# Domain 409/892: walmartimages.com
log "Processing domain 409/892: walmartimages.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/walmartimages.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/walmartimages.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/walmartimages.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/walmartimages.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/walmartimages.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/walmartimages.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/walmartimages.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: walmartimages.com"
echo "---"

# Domain 410/892: i5.walmartimages.com
log "Processing domain 410/892: i5.walmartimages.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/i5.walmartimages.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/i5.walmartimages.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/i5.walmartimages.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/i5.walmartimages.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/i5.walmartimages.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/i5.walmartimages.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/i5.walmartimages.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: i5.walmartimages.com"
echo "---"

# Domain 411/892: walmartimages.cl
log "Processing domain 411/892: walmartimages.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/walmartimages.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/walmartimages.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/walmartimages.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/walmartimages.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/walmartimages.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/walmartimages.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/walmartimages.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: walmartimages.cl"
echo "---"

# Domain 412/892: i5.walmartimages.cl
log "Processing domain 412/892: i5.walmartimages.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/i5.walmartimages.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/i5.walmartimages.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/i5.walmartimages.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/i5.walmartimages.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/i5.walmartimages.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/i5.walmartimages.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/i5.walmartimages.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: i5.walmartimages.cl"
echo "---"

# Domain 413/892: tailwindcss.com
log "Processing domain 413/892: tailwindcss.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/tailwindcss.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/tailwindcss.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/tailwindcss.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/tailwindcss.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/tailwindcss.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/tailwindcss.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/tailwindcss.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: tailwindcss.com"
echo "---"

# Domain 414/892: cdn.tailwindcss.com
log "Processing domain 414/892: cdn.tailwindcss.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cdn.tailwindcss.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cdn.tailwindcss.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cdn.tailwindcss.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cdn.tailwindcss.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cdn.tailwindcss.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cdn.tailwindcss.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cdn.tailwindcss.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cdn.tailwindcss.com"
echo "---"

# Domain 415/892: icomoon.io
log "Processing domain 415/892: icomoon.io"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/icomoon.io"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/icomoon.io"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/icomoon.io"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/icomoon.io"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/icomoon.io"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/icomoon.io"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/icomoon.io"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: icomoon.io"
echo "---"

# Domain 416/892: cdn.icomoon.io
log "Processing domain 416/892: cdn.icomoon.io"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cdn.icomoon.io"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cdn.icomoon.io"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cdn.icomoon.io"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cdn.icomoon.io"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cdn.icomoon.io"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cdn.icomoon.io"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cdn.icomoon.io"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cdn.icomoon.io"
echo "---"

# Domain 417/892: download.moodle.org
log "Processing domain 417/892: download.moodle.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/download.moodle.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/download.moodle.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/download.moodle.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/download.moodle.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/download.moodle.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/download.moodle.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/download.moodle.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: download.moodle.org"
echo "---"

# Domain 418/892: media-partners.io
log "Processing domain 418/892: media-partners.io"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/media-partners.io"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/media-partners.io"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/media-partners.io"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/media-partners.io"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/media-partners.io"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/media-partners.io"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/media-partners.io"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: media-partners.io"
echo "---"

# Domain 419/892: hipodromochile.cl
log "Processing domain 419/892: hipodromochile.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/hipodromochile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/hipodromochile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/hipodromochile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/hipodromochile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/hipodromochile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/hipodromochile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/hipodromochile.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: hipodromochile.cl"
echo "---"

# Domain 420/892: www.clubhipico.cl
log "Processing domain 420/892: www.clubhipico.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.clubhipico.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.clubhipico.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.clubhipico.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.clubhipico.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.clubhipico.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.clubhipico.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.clubhipico.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.clubhipico.cl"
echo "---"

# Domain 421/892: sporting.cl
log "Processing domain 421/892: sporting.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/sporting.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/sporting.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/sporting.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/sporting.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/sporting.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/sporting.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/sporting.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: sporting.cl"
echo "---"

# Domain 422/892: www.sporting.cl
log "Processing domain 422/892: www.sporting.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.sporting.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.sporting.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.sporting.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.sporting.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.sporting.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.sporting.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.sporting.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.sporting.cl"
echo "---"

# Domain 423/892: clubhipicoconcepcion.cl
log "Processing domain 423/892: clubhipicoconcepcion.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/clubhipicoconcepcion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/clubhipicoconcepcion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/clubhipicoconcepcion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/clubhipicoconcepcion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/clubhipicoconcepcion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/clubhipicoconcepcion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/clubhipicoconcepcion.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: clubhipicoconcepcion.cl"
echo "---"

# Domain 424/892: www.clubhipicoconcepcion.cl
log "Processing domain 424/892: www.clubhipicoconcepcion.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.clubhipicoconcepcion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.clubhipicoconcepcion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.clubhipicoconcepcion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.clubhipicoconcepcion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.clubhipicoconcepcion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.clubhipicoconcepcion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.clubhipicoconcepcion.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.clubhipicoconcepcion.cl"
echo "---"

# Domain 425/892: youtu.be
log "Processing domain 425/892: youtu.be"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/youtu.be"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/youtu.be"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/youtu.be"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/youtu.be"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/youtu.be"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/youtu.be"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/youtu.be"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: youtu.be"
echo "---"

# Domain 426/892: mdstrm.com
log "Processing domain 426/892: mdstrm.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mdstrm.com"
echo "---"

# Domain 427/892: platform-static.cdn.mdstrm.com
log "Processing domain 427/892: platform-static.cdn.mdstrm.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/platform-static.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/platform-static.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/platform-static.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/platform-static.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/platform-static.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/platform-static.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/platform-static.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: platform-static.cdn.mdstrm.com"
echo "---"

# Domain 428/892: webclass.com
log "Processing domain 428/892: webclass.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/webclass.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/webclass.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/webclass.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/webclass.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/webclass.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/webclass.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/webclass.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: webclass.com"
echo "---"

# Domain 429/892: www.webclass.com
log "Processing domain 429/892: www.webclass.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.webclass.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.webclass.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.webclass.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.webclass.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.webclass.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.webclass.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.webclass.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.webclass.com"
echo "---"

# Domain 430/892: devsaran.com
log "Processing domain 430/892: devsaran.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/devsaran.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/devsaran.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/devsaran.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/devsaran.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/devsaran.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/devsaran.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/devsaran.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: devsaran.com"
echo "---"

# Domain 431/892: www.devsaran.com
log "Processing domain 431/892: www.devsaran.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.devsaran.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.devsaran.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.devsaran.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.devsaran.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.devsaran.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.devsaran.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.devsaran.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.devsaran.com"
echo "---"

# Domain 432/892: ibb.co
log "Processing domain 432/892: ibb.co"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ibb.co"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ibb.co"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ibb.co"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ibb.co"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ibb.co"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ibb.co"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ibb.co"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ibb.co"
echo "---"

# Domain 433/892: i.ibb.co
log "Processing domain 433/892: i.ibb.co"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/i.ibb.co"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/i.ibb.co"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/i.ibb.co"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/i.ibb.co"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/i.ibb.co"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/i.ibb.co"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/i.ibb.co"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: i.ibb.co"
echo "---"

# Domain 434/892: mma.gob.cl
log "Processing domain 434/892: mma.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mma.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mma.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mma.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mma.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mma.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mma.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mma.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mma.gob.cl"
echo "---"

# Domain 435/892: sncae.mma.gob.cl
log "Processing domain 435/892: sncae.mma.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/sncae.mma.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/sncae.mma.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/sncae.mma.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/sncae.mma.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/sncae.mma.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/sncae.mma.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/sncae.mma.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: sncae.mma.gob.cl"
echo "---"

# Domain 436/892: github.io
log "Processing domain 436/892: github.io"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/github.io"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/github.io"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/github.io"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/github.io"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/github.io"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/github.io"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/github.io"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: github.io"
echo "---"

# Domain 437/892: argoproj.github.io
log "Processing domain 437/892: argoproj.github.io"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/argoproj.github.io"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/argoproj.github.io"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/argoproj.github.io"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/argoproj.github.io"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/argoproj.github.io"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/argoproj.github.io"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/argoproj.github.io"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: argoproj.github.io"
echo "---"

# Domain 438/892: goo.gl
log "Processing domain 438/892: goo.gl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/goo.gl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/goo.gl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/goo.gl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/goo.gl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/goo.gl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/goo.gl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/goo.gl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: goo.gl"
echo "---"

# Domain 439/892: cdninstagram.com
log "Processing domain 439/892: cdninstagram.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cdninstagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cdninstagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cdninstagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cdninstagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cdninstagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cdninstagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cdninstagram.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cdninstagram.com"
echo "---"

# Domain 440/892: scontent-scl2-1.cdninstagram.com
log "Processing domain 440/892: scontent-scl2-1.cdninstagram.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/scontent-scl2-1.cdninstagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/scontent-scl2-1.cdninstagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/scontent-scl2-1.cdninstagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/scontent-scl2-1.cdninstagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/scontent-scl2-1.cdninstagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/scontent-scl2-1.cdninstagram.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/scontent-scl2-1.cdninstagram.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: scontent-scl2-1.cdninstagram.com"
echo "---"

# Domain 441/892: edicionesarq.cl
log "Processing domain 441/892: edicionesarq.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/edicionesarq.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/edicionesarq.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/edicionesarq.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/edicionesarq.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/edicionesarq.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/edicionesarq.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/edicionesarq.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: edicionesarq.cl"
echo "---"

# Domain 442/892: www.edicionesarq.cl
log "Processing domain 442/892: www.edicionesarq.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.edicionesarq.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.edicionesarq.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.edicionesarq.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.edicionesarq.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.edicionesarq.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.edicionesarq.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.edicionesarq.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.edicionesarq.cl"
echo "---"

# Domain 443/892: redg9.cl
log "Processing domain 443/892: redg9.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/redg9.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/redg9.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/redg9.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/redg9.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/redg9.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/redg9.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/redg9.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: redg9.cl"
echo "---"

# Domain 444/892: urantiacos.cl
log "Processing domain 444/892: urantiacos.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/urantiacos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/urantiacos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/urantiacos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/urantiacos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/urantiacos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/urantiacos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/urantiacos.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: urantiacos.cl"
echo "---"

# Domain 445/892: www.urantiacos.cl
log "Processing domain 445/892: www.urantiacos.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.urantiacos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.urantiacos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.urantiacos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.urantiacos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.urantiacos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.urantiacos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.urantiacos.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.urantiacos.cl"
echo "---"

# Domain 446/892: kit-digital-uc-prod.s3.amazonaws.com
log "Processing domain 446/892: kit-digital-uc-prod.s3.amazonaws.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/kit-digital-uc-prod.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/kit-digital-uc-prod.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/kit-digital-uc-prod.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/kit-digital-uc-prod.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/kit-digital-uc-prod.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/kit-digital-uc-prod.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/kit-digital-uc-prod.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: kit-digital-uc-prod.s3.amazonaws.com"
echo "---"

# Domain 447/892: readspeaker.com
log "Processing domain 447/892: readspeaker.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/readspeaker.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/readspeaker.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/readspeaker.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/readspeaker.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/readspeaker.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/readspeaker.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/readspeaker.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: readspeaker.com"
echo "---"

# Domain 448/892: cdn1.readspeaker.com
log "Processing domain 448/892: cdn1.readspeaker.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cdn1.readspeaker.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cdn1.readspeaker.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cdn1.readspeaker.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cdn1.readspeaker.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cdn1.readspeaker.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cdn1.readspeaker.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cdn1.readspeaker.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cdn1.readspeaker.com"
echo "---"

# Domain 449/892: translate.google.com
log "Processing domain 449/892: translate.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/translate.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/translate.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/translate.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/translate.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/translate.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/translate.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/translate.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: translate.google.com"
echo "---"

# Domain 450/892: cnstrc.com
log "Processing domain 450/892: cnstrc.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cnstrc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cnstrc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cnstrc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cnstrc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cnstrc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cnstrc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cnstrc.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cnstrc.com"
echo "---"

# Domain 451/892: mimolivesales.com.br
log "Processing domain 451/892: mimolivesales.com.br"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mimolivesales.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mimolivesales.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mimolivesales.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mimolivesales.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mimolivesales.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mimolivesales.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mimolivesales.com.br"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mimolivesales.com.br"
echo "---"

# Domain 452/892: pip.mimolivesales.com.br
log "Processing domain 452/892: pip.mimolivesales.com.br"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/pip.mimolivesales.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/pip.mimolivesales.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/pip.mimolivesales.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/pip.mimolivesales.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/pip.mimolivesales.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/pip.mimolivesales.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/pip.mimolivesales.com.br"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: pip.mimolivesales.com.br"
echo "---"

# Domain 453/892: assets5.freshdesk.com
log "Processing domain 453/892: assets5.freshdesk.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/assets5.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/assets5.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/assets5.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/assets5.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/assets5.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/assets5.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/assets5.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: assets5.freshdesk.com"
echo "---"

# Domain 454/892: assets3.freshdesk.com
log "Processing domain 454/892: assets3.freshdesk.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/assets3.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/assets3.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/assets3.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/assets3.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/assets3.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/assets3.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/assets3.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: assets3.freshdesk.com"
echo "---"

# Domain 455/892: assets2.freshdesk.com
log "Processing domain 455/892: assets2.freshdesk.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/assets2.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/assets2.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/assets2.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/assets2.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/assets2.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/assets2.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/assets2.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: assets2.freshdesk.com"
echo "---"

# Domain 456/892: zenlatam.com
log "Processing domain 456/892: zenlatam.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/zenlatam.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/zenlatam.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/zenlatam.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/zenlatam.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/zenlatam.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/zenlatam.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/zenlatam.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: zenlatam.com"
echo "---"

# Domain 457/892: sign.zenlatam.com
log "Processing domain 457/892: sign.zenlatam.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/sign.zenlatam.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/sign.zenlatam.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/sign.zenlatam.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/sign.zenlatam.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/sign.zenlatam.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/sign.zenlatam.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/sign.zenlatam.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: sign.zenlatam.com"
echo "---"

# Domain 458/892: dtpm.cl
log "Processing domain 458/892: dtpm.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/dtpm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/dtpm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/dtpm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/dtpm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/dtpm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/dtpm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/dtpm.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: dtpm.cl"
echo "---"

# Domain 459/892: www.dtpm.cl
log "Processing domain 459/892: www.dtpm.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.dtpm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.dtpm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.dtpm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.dtpm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.dtpm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.dtpm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.dtpm.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.dtpm.cl"
echo "---"

# Domain 460/892: assets4.freshdesk.com
log "Processing domain 460/892: assets4.freshdesk.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/assets4.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/assets4.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/assets4.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/assets4.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/assets4.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/assets4.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/assets4.freshdesk.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: assets4.freshdesk.com"
echo "---"

# Domain 461/892: telefonicachile.cl
log "Processing domain 461/892: telefonicachile.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/telefonicachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/telefonicachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/telefonicachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/telefonicachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/telefonicachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/telefonicachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/telefonicachile.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: telefonicachile.cl"
echo "---"

# Domain 462/892: error.telefonicachile.cl
log "Processing domain 462/892: error.telefonicachile.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/error.telefonicachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/error.telefonicachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/error.telefonicachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/error.telefonicachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/error.telefonicachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/error.telefonicachile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/error.telefonicachile.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: error.telefonicachile.cl"
echo "---"

# Domain 463/892: moodle.com
log "Processing domain 463/892: moodle.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/moodle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/moodle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/moodle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/moodle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/moodle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/moodle.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/moodle.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: moodle.com"
echo "---"

# Domain 464/892: www.microsoft.com
log "Processing domain 464/892: www.microsoft.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.microsoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.microsoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.microsoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.microsoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.microsoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.microsoft.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.microsoft.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.microsoft.com"
echo "---"

# Domain 465/892: bigbluebutton.org
log "Processing domain 465/892: bigbluebutton.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: bigbluebutton.org"
echo "---"

# Domain 466/892: docs.bigbluebutton.org
log "Processing domain 466/892: docs.bigbluebutton.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/docs.bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/docs.bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/docs.bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/docs.bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/docs.bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/docs.bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/docs.bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: docs.bigbluebutton.org"
echo "---"

# Domain 467/892: demo.bigbluebutton.org
log "Processing domain 467/892: demo.bigbluebutton.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/demo.bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/demo.bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/demo.bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/demo.bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/demo.bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/demo.bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/demo.bigbluebutton.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: demo.bigbluebutton.org"
echo "---"

# Domain 468/892: safesigner.com
log "Processing domain 468/892: safesigner.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/safesigner.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/safesigner.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/safesigner.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/safesigner.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/safesigner.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/safesigner.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/safesigner.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: safesigner.com"
echo "---"

# Domain 469/892: dev.safesigner.com
log "Processing domain 469/892: dev.safesigner.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/dev.safesigner.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/dev.safesigner.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/dev.safesigner.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/dev.safesigner.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/dev.safesigner.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/dev.safesigner.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/dev.safesigner.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: dev.safesigner.com"
echo "---"

# Domain 470/892: www.anid.cl
log "Processing domain 470/892: www.anid.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.anid.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.anid.cl"
echo "---"

# Domain 471/892: servicios.anid.cl
log "Processing domain 471/892: servicios.anid.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/servicios.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/servicios.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/servicios.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/servicios.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/servicios.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/servicios.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/servicios.anid.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: servicios.anid.cl"
echo "---"

# Domain 472/892: d22v5g7t6v513h.cloudfront.net
log "Processing domain 472/892: d22v5g7t6v513h.cloudfront.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/d22v5g7t6v513h.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/d22v5g7t6v513h.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/d22v5g7t6v513h.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/d22v5g7t6v513h.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/d22v5g7t6v513h.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/d22v5g7t6v513h.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/d22v5g7t6v513h.cloudfront.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: d22v5g7t6v513h.cloudfront.net"
echo "---"

# Domain 473/892: static.microsoft
log "Processing domain 473/892: static.microsoft"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/static.microsoft"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/static.microsoft"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/static.microsoft"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/static.microsoft"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/static.microsoft"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/static.microsoft"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/static.microsoft"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: static.microsoft"
echo "---"

# Domain 474/892: res.public.onecdn.static.microsoft
log "Processing domain 474/892: res.public.onecdn.static.microsoft"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/res.public.onecdn.static.microsoft"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/res.public.onecdn.static.microsoft"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/res.public.onecdn.static.microsoft"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/res.public.onecdn.static.microsoft"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/res.public.onecdn.static.microsoft"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/res.public.onecdn.static.microsoft"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/res.public.onecdn.static.microsoft"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: res.public.onecdn.static.microsoft"
echo "---"

# Domain 475/892: office.net
log "Processing domain 475/892: office.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/office.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/office.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/office.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/office.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/office.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/office.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/office.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: office.net"
echo "---"

# Domain 476/892: res.cdn.office.net
log "Processing domain 476/892: res.cdn.office.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/res.cdn.office.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/res.cdn.office.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/res.cdn.office.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/res.cdn.office.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/res.cdn.office.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/res.cdn.office.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/res.cdn.office.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: res.cdn.office.net"
echo "---"

# Domain 477/892: servicenow.com
log "Processing domain 477/892: servicenow.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/servicenow.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: servicenow.com"
echo "---"

# Domain 478/892: www.servicenow.com
log "Processing domain 478/892: www.servicenow.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.servicenow.com"
echo "---"

# Domain 479/892: mynow.servicenow.com
log "Processing domain 479/892: mynow.servicenow.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mynow.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mynow.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mynow.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mynow.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mynow.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mynow.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mynow.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mynow.servicenow.com"
echo "---"

# Domain 480/892: store.servicenow.com
log "Processing domain 480/892: store.servicenow.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/store.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/store.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/store.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/store.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/store.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/store.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/store.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: store.servicenow.com"
echo "---"

# Domain 481/892: learning.servicenow.com
log "Processing domain 481/892: learning.servicenow.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/learning.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/learning.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/learning.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/learning.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/learning.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/learning.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/learning.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: learning.servicenow.com"
echo "---"

# Domain 482/892: developer.servicenow.com
log "Processing domain 482/892: developer.servicenow.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/developer.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/developer.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/developer.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/developer.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/developer.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/developer.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/developer.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: developer.servicenow.com"
echo "---"

# Domain 483/892: horizon.servicenow.com
log "Processing domain 483/892: horizon.servicenow.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/horizon.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/horizon.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/horizon.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/horizon.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/horizon.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/horizon.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/horizon.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: horizon.servicenow.com"
echo "---"

# Domain 484/892: support.servicenow.com
log "Processing domain 484/892: support.servicenow.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/support.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/support.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/support.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/support.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/support.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/support.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/support.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: support.servicenow.com"
echo "---"

# Domain 485/892: service-now.com
log "Processing domain 485/892: service-now.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/service-now.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/service-now.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/service-now.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/service-now.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/service-now.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/service-now.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/service-now.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: service-now.com"
echo "---"

# Domain 486/892: partnerportal.service-now.com
log "Processing domain 486/892: partnerportal.service-now.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/partnerportal.service-now.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/partnerportal.service-now.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/partnerportal.service-now.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/partnerportal.service-now.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/partnerportal.service-now.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/partnerportal.service-now.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/partnerportal.service-now.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: partnerportal.service-now.com"
echo "---"

# Domain 487/892: careers.servicenow.com
log "Processing domain 487/892: careers.servicenow.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/careers.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/careers.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/careers.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/careers.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/careers.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/careers.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/careers.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: careers.servicenow.com"
echo "---"

# Domain 488/892: forrester.com
log "Processing domain 488/892: forrester.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/forrester.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/forrester.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/forrester.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/forrester.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/forrester.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/forrester.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/forrester.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: forrester.com"
echo "---"

# Domain 489/892: www.forrester.com
log "Processing domain 489/892: www.forrester.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.forrester.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.forrester.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.forrester.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.forrester.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.forrester.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.forrester.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.forrester.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.forrester.com"
echo "---"

# Domain 490/892: docs.servicenow.com
log "Processing domain 490/892: docs.servicenow.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/docs.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/docs.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/docs.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/docs.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/docs.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/docs.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/docs.servicenow.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: docs.servicenow.com"
echo "---"

# Domain 491/892: hlx.page
log "Processing domain 491/892: hlx.page"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/hlx.page"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/hlx.page"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/hlx.page"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/hlx.page"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/hlx.page"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/hlx.page"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/hlx.page"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: hlx.page"
echo "---"

# Domain 492/892: rum.hlx.page
log "Processing domain 492/892: rum.hlx.page"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/rum.hlx.page"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/rum.hlx.page"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/rum.hlx.page"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/rum.hlx.page"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/rum.hlx.page"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/rum.hlx.page"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/rum.hlx.page"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: rum.hlx.page"
echo "---"

# Domain 493/892: adobedtm.com
log "Processing domain 493/892: adobedtm.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/adobedtm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/adobedtm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/adobedtm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/adobedtm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/adobedtm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/adobedtm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/adobedtm.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: adobedtm.com"
echo "---"

# Domain 494/892: assets.adobedtm.com
log "Processing domain 494/892: assets.adobedtm.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/assets.adobedtm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/assets.adobedtm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/assets.adobedtm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/assets.adobedtm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/assets.adobedtm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/assets.adobedtm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/assets.adobedtm.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: assets.adobedtm.com"
echo "---"

# Domain 495/892: intercomassets.com
log "Processing domain 495/892: intercomassets.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/intercomassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/intercomassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/intercomassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/intercomassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/intercomassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/intercomassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/intercomassets.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: intercomassets.com"
echo "---"

# Domain 496/892: static.intercomassets.com
log "Processing domain 496/892: static.intercomassets.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/static.intercomassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/static.intercomassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/static.intercomassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/static.intercomassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/static.intercomassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/static.intercomassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/static.intercomassets.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: static.intercomassets.com"
echo "---"

# Domain 497/892: intercomcdn.com
log "Processing domain 497/892: intercomcdn.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/intercomcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/intercomcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/intercomcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/intercomcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/intercomcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/intercomcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/intercomcdn.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: intercomcdn.com"
echo "---"

# Domain 498/892: downloads.intercomcdn.com
log "Processing domain 498/892: downloads.intercomcdn.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/downloads.intercomcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/downloads.intercomcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/downloads.intercomcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/downloads.intercomcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/downloads.intercomcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/downloads.intercomcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/downloads.intercomcdn.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: downloads.intercomcdn.com"
echo "---"

# Domain 499/892: intercom.help
log "Processing domain 499/892: intercom.help"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/intercom.help"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/intercom.help"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/intercom.help"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/intercom.help"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/intercom.help"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/intercom.help"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/intercom.help"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: intercom.help"
echo "---"

# Domain 500/892: atl-paas.net
log "Processing domain 500/892: atl-paas.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/atl-paas.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/atl-paas.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/atl-paas.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/atl-paas.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/atl-paas.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/atl-paas.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/atl-paas.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: atl-paas.net"
echo "---"

# Domain 501/892: jsm-help-center-ui.prod-east.frontend.public.atl-paas.net
log "Processing domain 501/892: jsm-help-center-ui.prod-east.frontend.public.atl-paas.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/jsm-help-center-ui.prod-east.frontend.public.atl-paas.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/jsm-help-center-ui.prod-east.frontend.public.atl-paas.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/jsm-help-center-ui.prod-east.frontend.public.atl-paas.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/jsm-help-center-ui.prod-east.frontend.public.atl-paas.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/jsm-help-center-ui.prod-east.frontend.public.atl-paas.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/jsm-help-center-ui.prod-east.frontend.public.atl-paas.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/jsm-help-center-ui.prod-east.frontend.public.atl-paas.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: jsm-help-center-ui.prod-east.frontend.public.atl-paas.net"
echo "---"

# Domain 502/892: wp.me
log "Processing domain 502/892: wp.me"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/wp.me"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/wp.me"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/wp.me"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/wp.me"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/wp.me"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/wp.me"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/wp.me"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: wp.me"
echo "---"

# Domain 503/892: www.whatsapp.com
log "Processing domain 503/892: www.whatsapp.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.whatsapp.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.whatsapp.com"
echo "---"

# Domain 504/892: wp.com
log "Processing domain 504/892: wp.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/wp.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: wp.com"
echo "---"

# Domain 505/892: s0.wp.com
log "Processing domain 505/892: s0.wp.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/s0.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/s0.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/s0.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/s0.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/s0.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/s0.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/s0.wp.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: s0.wp.com"
echo "---"

# Domain 506/892: stats.wp.com
log "Processing domain 506/892: stats.wp.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/stats.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/stats.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/stats.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/stats.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/stats.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/stats.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/stats.wp.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: stats.wp.com"
echo "---"

# Domain 507/892: i0.wp.com
log "Processing domain 507/892: i0.wp.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/i0.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/i0.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/i0.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/i0.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/i0.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/i0.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/i0.wp.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: i0.wp.com"
echo "---"

# Domain 508/892: c0.wp.com
log "Processing domain 508/892: c0.wp.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/c0.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/c0.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/c0.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/c0.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/c0.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/c0.wp.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/c0.wp.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: c0.wp.com"
echo "---"

# Domain 509/892: we-stats.com
log "Processing domain 509/892: we-stats.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/we-stats.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/we-stats.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/we-stats.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/we-stats.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/we-stats.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/we-stats.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/we-stats.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: we-stats.com"
echo "---"

# Domain 510/892: bcdn-god.we-stats.com
log "Processing domain 510/892: bcdn-god.we-stats.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/bcdn-god.we-stats.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/bcdn-god.we-stats.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/bcdn-god.we-stats.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/bcdn-god.we-stats.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/bcdn-god.we-stats.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/bcdn-god.we-stats.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/bcdn-god.we-stats.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: bcdn-god.we-stats.com"
echo "---"

# Domain 511/892: vtex.com.br
log "Processing domain 511/892: vtex.com.br"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/vtex.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/vtex.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/vtex.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/vtex.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/vtex.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/vtex.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/vtex.com.br"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: vtex.com.br"
echo "---"

# Domain 512/892: io.vtex.com.br
log "Processing domain 512/892: io.vtex.com.br"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/io.vtex.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/io.vtex.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/io.vtex.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/io.vtex.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/io.vtex.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/io.vtex.com.br"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/io.vtex.com.br"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: io.vtex.com.br"
echo "---"

# Domain 513/892: vtexassets.com
log "Processing domain 513/892: vtexassets.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: vtexassets.com"
echo "---"

# Domain 514/892: b2bgourmet.vtexassets.com
log "Processing domain 514/892: b2bgourmet.vtexassets.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/b2bgourmet.vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/b2bgourmet.vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/b2bgourmet.vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/b2bgourmet.vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/b2bgourmet.vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/b2bgourmet.vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/b2bgourmet.vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: b2bgourmet.vtexassets.com"
echo "---"

# Domain 515/892: gourmetcl.vtexassets.com
log "Processing domain 515/892: gourmetcl.vtexassets.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/gourmetcl.vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/gourmetcl.vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/gourmetcl.vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/gourmetcl.vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/gourmetcl.vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/gourmetcl.vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/gourmetcl.vtexassets.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: gourmetcl.vtexassets.com"
echo "---"

# Domain 516/892: itaubeneficios.cl
log "Processing domain 516/892: itaubeneficios.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/itaubeneficios.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/itaubeneficios.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/itaubeneficios.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/itaubeneficios.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/itaubeneficios.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/itaubeneficios.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/itaubeneficios.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: itaubeneficios.cl"
echo "---"

# Domain 517/892: zonaestudiantes.cl
log "Processing domain 517/892: zonaestudiantes.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/zonaestudiantes.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/zonaestudiantes.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/zonaestudiantes.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/zonaestudiantes.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/zonaestudiantes.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/zonaestudiantes.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/zonaestudiantes.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: zonaestudiantes.cl"
echo "---"

# Domain 518/892: www.zonaestudiantes.cl
log "Processing domain 518/892: www.zonaestudiantes.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.zonaestudiantes.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.zonaestudiantes.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.zonaestudiantes.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.zonaestudiantes.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.zonaestudiantes.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.zonaestudiantes.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.zonaestudiantes.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.zonaestudiantes.cl"
echo "---"

# Domain 519/892: itauprivatebank.com
log "Processing domain 519/892: itauprivatebank.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/itauprivatebank.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/itauprivatebank.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/itauprivatebank.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/itauprivatebank.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/itauprivatebank.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/itauprivatebank.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/itauprivatebank.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: itauprivatebank.com"
echo "---"

# Domain 520/892: www.itauprivatebank.com
log "Processing domain 520/892: www.itauprivatebank.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.itauprivatebank.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.itauprivatebank.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.itauprivatebank.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.itauprivatebank.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.itauprivatebank.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.itauprivatebank.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.itauprivatebank.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.itauprivatebank.com"
echo "---"

# Domain 521/892: indexa.cl
log "Processing domain 521/892: indexa.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/indexa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/indexa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/indexa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/indexa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/indexa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/indexa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/indexa.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: indexa.cl"
echo "---"

# Domain 522/892: sire-itau.indexa.cl
log "Processing domain 522/892: sire-itau.indexa.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/sire-itau.indexa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/sire-itau.indexa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/sire-itau.indexa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/sire-itau.indexa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/sire-itau.indexa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/sire-itau.indexa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/sire-itau.indexa.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: sire-itau.indexa.cl"
echo "---"

# Domain 523/892: onelink.me
log "Processing domain 523/892: onelink.me"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/onelink.me"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/onelink.me"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/onelink.me"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/onelink.me"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/onelink.me"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/onelink.me"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/onelink.me"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: onelink.me"
echo "---"

# Domain 524/892: banco-itau.onelink.me
log "Processing domain 524/892: banco-itau.onelink.me"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/banco-itau.onelink.me"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/banco-itau.onelink.me"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/banco-itau.onelink.me"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/banco-itau.onelink.me"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/banco-itau.onelink.me"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/banco-itau.onelink.me"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/banco-itau.onelink.me"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: banco-itau.onelink.me"
echo "---"

# Domain 525/892: trabajaenitau.cl
log "Processing domain 525/892: trabajaenitau.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/trabajaenitau.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/trabajaenitau.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/trabajaenitau.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/trabajaenitau.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/trabajaenitau.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/trabajaenitau.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/trabajaenitau.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: trabajaenitau.cl"
echo "---"

# Domain 526/892: googleoptimize.com
log "Processing domain 526/892: googleoptimize.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/googleoptimize.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/googleoptimize.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/googleoptimize.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/googleoptimize.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/googleoptimize.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/googleoptimize.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/googleoptimize.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: googleoptimize.com"
echo "---"

# Domain 527/892: www.googleoptimize.com
log "Processing domain 527/892: www.googleoptimize.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.googleoptimize.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.googleoptimize.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.googleoptimize.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.googleoptimize.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.googleoptimize.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.googleoptimize.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.googleoptimize.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.googleoptimize.com"
echo "---"

# Domain 528/892: contentstack.io
log "Processing domain 528/892: contentstack.io"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/contentstack.io"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/contentstack.io"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/contentstack.io"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/contentstack.io"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/contentstack.io"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/contentstack.io"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/contentstack.io"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: contentstack.io"
echo "---"

# Domain 529/892: assets.contentstack.io
log "Processing domain 529/892: assets.contentstack.io"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/assets.contentstack.io"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/assets.contentstack.io"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/assets.contentstack.io"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/assets.contentstack.io"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/assets.contentstack.io"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/assets.contentstack.io"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/assets.contentstack.io"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: assets.contentstack.io"
echo "---"

# Domain 530/892: images.contentstack.io
log "Processing domain 530/892: images.contentstack.io"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/images.contentstack.io"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/images.contentstack.io"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/images.contentstack.io"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/images.contentstack.io"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/images.contentstack.io"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/images.contentstack.io"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/images.contentstack.io"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: images.contentstack.io"
echo "---"

# Domain 531/892: tiqcdn.com
log "Processing domain 531/892: tiqcdn.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/tiqcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/tiqcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/tiqcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/tiqcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/tiqcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/tiqcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/tiqcdn.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: tiqcdn.com"
echo "---"

# Domain 532/892: tags.tiqcdn.com
log "Processing domain 532/892: tags.tiqcdn.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/tags.tiqcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/tags.tiqcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/tags.tiqcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/tags.tiqcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/tags.tiqcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/tags.tiqcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/tags.tiqcdn.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: tags.tiqcdn.com"
echo "---"

# Domain 533/892: poderjudicialtv.cl
log "Processing domain 533/892: poderjudicialtv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/poderjudicialtv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/poderjudicialtv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/poderjudicialtv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/poderjudicialtv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/poderjudicialtv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/poderjudicialtv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/poderjudicialtv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: poderjudicialtv.cl"
echo "---"

# Domain 534/892: www.poderjudicialtv.cl
log "Processing domain 534/892: www.poderjudicialtv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.poderjudicialtv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.poderjudicialtv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.poderjudicialtv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.poderjudicialtv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.poderjudicialtv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.poderjudicialtv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.poderjudicialtv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.poderjudicialtv.cl"
echo "---"

# Domain 535/892: vi-sor.cl
log "Processing domain 535/892: vi-sor.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/vi-sor.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/vi-sor.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/vi-sor.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/vi-sor.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/vi-sor.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/vi-sor.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/vi-sor.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: vi-sor.cl"
echo "---"

# Domain 536/892: www.vi-sor.cl
log "Processing domain 536/892: www.vi-sor.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.vi-sor.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.vi-sor.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.vi-sor.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.vi-sor.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.vi-sor.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.vi-sor.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.vi-sor.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.vi-sor.cl"
echo "---"

# Domain 537/892: es-es.facebook.com
log "Processing domain 537/892: es-es.facebook.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/es-es.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/es-es.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/es-es.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/es-es.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/es-es.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/es-es.facebook.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/es-es.facebook.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: es-es.facebook.com"
echo "---"

# Domain 538/892: m.me
log "Processing domain 538/892: m.me"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/m.me"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/m.me"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/m.me"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/m.me"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/m.me"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/m.me"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/m.me"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: m.me"
echo "---"

# Domain 539/892: zoom.us
log "Processing domain 539/892: zoom.us"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/zoom.us"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/zoom.us"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/zoom.us"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/zoom.us"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/zoom.us"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/zoom.us"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/zoom.us"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: zoom.us"
echo "---"

# Domain 540/892: portaltransparencia.cl
log "Processing domain 540/892: portaltransparencia.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/portaltransparencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/portaltransparencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/portaltransparencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/portaltransparencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/portaltransparencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/portaltransparencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/portaltransparencia.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: portaltransparencia.cl"
echo "---"

# Domain 541/892: www.portaltransparencia.cl
log "Processing domain 541/892: www.portaltransparencia.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.portaltransparencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.portaltransparencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.portaltransparencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.portaltransparencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.portaltransparencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.portaltransparencia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.portaltransparencia.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.portaltransparencia.cl"
echo "---"

# Domain 542/892: paciellogroup.com
log "Processing domain 542/892: paciellogroup.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/paciellogroup.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/paciellogroup.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/paciellogroup.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/paciellogroup.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/paciellogroup.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/paciellogroup.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/paciellogroup.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: paciellogroup.com"
echo "---"

# Domain 543/892: www.paciellogroup.com
log "Processing domain 543/892: www.paciellogroup.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.paciellogroup.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.paciellogroup.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.paciellogroup.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.paciellogroup.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.paciellogroup.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.paciellogroup.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.paciellogroup.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.paciellogroup.com"
echo "---"

# Domain 544/892: nvaccess.org
log "Processing domain 544/892: nvaccess.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/nvaccess.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/nvaccess.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/nvaccess.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/nvaccess.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/nvaccess.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/nvaccess.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/nvaccess.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: nvaccess.org"
echo "---"

# Domain 545/892: www.nvaccess.org
log "Processing domain 545/892: www.nvaccess.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.nvaccess.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.nvaccess.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.nvaccess.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.nvaccess.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.nvaccess.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.nvaccess.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.nvaccess.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.nvaccess.org"
echo "---"

# Domain 546/892: livechatinc.com
log "Processing domain 546/892: livechatinc.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/livechatinc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/livechatinc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/livechatinc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/livechatinc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/livechatinc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/livechatinc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/livechatinc.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: livechatinc.com"
echo "---"

# Domain 547/892: www.livechatinc.com
log "Processing domain 547/892: www.livechatinc.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.livechatinc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.livechatinc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.livechatinc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.livechatinc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.livechatinc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.livechatinc.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.livechatinc.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.livechatinc.com"
echo "---"

# Domain 548/892: podcasts.apple.com
log "Processing domain 548/892: podcasts.apple.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/podcasts.apple.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/podcasts.apple.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/podcasts.apple.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/podcasts.apple.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/podcasts.apple.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/podcasts.apple.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/podcasts.apple.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: podcasts.apple.com"
echo "---"

# Domain 549/892: hubspotusercontent-na1.net
log "Processing domain 549/892: hubspotusercontent-na1.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/hubspotusercontent-na1.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/hubspotusercontent-na1.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/hubspotusercontent-na1.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/hubspotusercontent-na1.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/hubspotusercontent-na1.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/hubspotusercontent-na1.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/hubspotusercontent-na1.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: hubspotusercontent-na1.net"
echo "---"

# Domain 550/892: 7052064.fs1.hubspotusercontent-na1.net
log "Processing domain 550/892: 7052064.fs1.hubspotusercontent-na1.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/7052064.fs1.hubspotusercontent-na1.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/7052064.fs1.hubspotusercontent-na1.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/7052064.fs1.hubspotusercontent-na1.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/7052064.fs1.hubspotusercontent-na1.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/7052064.fs1.hubspotusercontent-na1.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/7052064.fs1.hubspotusercontent-na1.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/7052064.fs1.hubspotusercontent-na1.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: 7052064.fs1.hubspotusercontent-na1.net"
echo "---"

# Domain 551/892: queue-it.net
log "Processing domain 551/892: queue-it.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/queue-it.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/queue-it.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/queue-it.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/queue-it.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/queue-it.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/queue-it.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/queue-it.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: queue-it.net"
echo "---"

# Domain 552/892: static.queue-it.net
log "Processing domain 552/892: static.queue-it.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/static.queue-it.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/static.queue-it.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/static.queue-it.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/static.queue-it.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/static.queue-it.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/static.queue-it.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/static.queue-it.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: static.queue-it.net"
echo "---"

# Domain 553/892: satisfaccion.gob.cl
log "Processing domain 553/892: satisfaccion.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/satisfaccion.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/satisfaccion.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/satisfaccion.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/satisfaccion.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/satisfaccion.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/satisfaccion.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/satisfaccion.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: satisfaccion.gob.cl"
echo "---"

# Domain 554/892: ayuda.anid.cl
log "Processing domain 554/892: ayuda.anid.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ayuda.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ayuda.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ayuda.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ayuda.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ayuda.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ayuda.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ayuda.anid.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ayuda.anid.cl"
echo "---"

# Domain 555/892: informacioncientifica.cl
log "Processing domain 555/892: informacioncientifica.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/informacioncientifica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/informacioncientifica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/informacioncientifica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/informacioncientifica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/informacioncientifica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/informacioncientifica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/informacioncientifica.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: informacioncientifica.cl"
echo "---"

# Domain 556/892: revistascientificas.informacioncientifica.cl
log "Processing domain 556/892: revistascientificas.informacioncientifica.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/revistascientificas.informacioncientifica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/revistascientificas.informacioncientifica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/revistascientificas.informacioncientifica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/revistascientificas.informacioncientifica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/revistascientificas.informacioncientifica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/revistascientificas.informacioncientifica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/revistascientificas.informacioncientifica.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: revistascientificas.informacioncientifica.cl"
echo "---"

# Domain 557/892: acceso-abierto.anid.cl
log "Processing domain 557/892: acceso-abierto.anid.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/acceso-abierto.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/acceso-abierto.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/acceso-abierto.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/acceso-abierto.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/acceso-abierto.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/acceso-abierto.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/acceso-abierto.anid.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: acceso-abierto.anid.cl"
echo "---"

# Domain 558/892: beic.cl
log "Processing domain 558/892: beic.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/beic.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/beic.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/beic.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/beic.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/beic.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/beic.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/beic.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: beic.cl"
echo "---"

# Domain 559/892: www.beic.cl
log "Processing domain 559/892: www.beic.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.beic.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.beic.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.beic.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.beic.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.beic.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.beic.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.beic.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.beic.cl"
echo "---"

# Domain 560/892: dataciencia.anid.cl
log "Processing domain 560/892: dataciencia.anid.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/dataciencia.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/dataciencia.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/dataciencia.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/dataciencia.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/dataciencia.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/dataciencia.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/dataciencia.anid.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: dataciencia.anid.cl"
echo "---"

# Domain 561/892: investigadores.anid.cl
log "Processing domain 561/892: investigadores.anid.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/investigadores.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/investigadores.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/investigadores.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/investigadores.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/investigadores.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/investigadores.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/investigadores.anid.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: investigadores.anid.cl"
echo "---"

# Domain 562/892: repositorio.anid.cl
log "Processing domain 562/892: repositorio.anid.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/repositorio.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/repositorio.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/repositorio.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/repositorio.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/repositorio.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/repositorio.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/repositorio.anid.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: repositorio.anid.cl"
echo "---"

# Domain 563/892: scielo.anid.cl
log "Processing domain 563/892: scielo.anid.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/scielo.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/scielo.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/scielo.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/scielo.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/scielo.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/scielo.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/scielo.anid.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: scielo.anid.cl"
echo "---"

# Domain 564/892: territorios.anid.cl
log "Processing domain 564/892: territorios.anid.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/territorios.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/territorios.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/territorios.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/territorios.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/territorios.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/territorios.anid.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/territorios.anid.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: territorios.anid.cl"
echo "---"

# Domain 565/892: lab.gob.cl
log "Processing domain 565/892: lab.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/lab.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/lab.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/lab.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/lab.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/lab.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/lab.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/lab.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: lab.gob.cl"
echo "---"

# Domain 566/892: indice.lab.gob.cl
log "Processing domain 566/892: indice.lab.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/indice.lab.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/indice.lab.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/indice.lab.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/indice.lab.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/indice.lab.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/indice.lab.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/indice.lab.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: indice.lab.gob.cl"
echo "---"

# Domain 567/892: csirt.gob.cl
log "Processing domain 567/892: csirt.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/csirt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/csirt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/csirt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/csirt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/csirt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/csirt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/csirt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: csirt.gob.cl"
echo "---"

# Domain 568/892: www.csirt.gob.cl
log "Processing domain 568/892: www.csirt.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.csirt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.csirt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.csirt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.csirt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.csirt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.csirt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.csirt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.csirt.gob.cl"
echo "---"

# Domain 569/892: microsoftonline.com
log "Processing domain 569/892: microsoftonline.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/microsoftonline.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/microsoftonline.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/microsoftonline.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/microsoftonline.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/microsoftonline.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/microsoftonline.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/microsoftonline.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: microsoftonline.com"
echo "---"

# Domain 570/892: login.microsoftonline.com
log "Processing domain 570/892: login.microsoftonline.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/login.microsoftonline.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/login.microsoftonline.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/login.microsoftonline.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/login.microsoftonline.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/login.microsoftonline.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/login.microsoftonline.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/login.microsoftonline.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: login.microsoftonline.com"
echo "---"

# Domain 571/892: www.empleospublicos.cl
log "Processing domain 571/892: www.empleospublicos.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.empleospublicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.empleospublicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.empleospublicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.empleospublicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.empleospublicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.empleospublicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.empleospublicos.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.empleospublicos.cl"
echo "---"

# Domain 572/892: serviciocivil.cl
log "Processing domain 572/892: serviciocivil.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/serviciocivil.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/serviciocivil.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/serviciocivil.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/serviciocivil.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/serviciocivil.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/serviciocivil.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/serviciocivil.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: serviciocivil.cl"
echo "---"

# Domain 573/892: adp.serviciocivil.cl
log "Processing domain 573/892: adp.serviciocivil.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/adp.serviciocivil.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/adp.serviciocivil.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/adp.serviciocivil.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/adp.serviciocivil.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/adp.serviciocivil.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/adp.serviciocivil.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/adp.serviciocivil.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: adp.serviciocivil.cl"
echo "---"

# Domain 574/892: corfo.cl
log "Processing domain 574/892: corfo.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/corfo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/corfo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/corfo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/corfo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/corfo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/corfo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/corfo.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: corfo.cl"
echo "---"

# Domain 575/892: www.corfo.cl
log "Processing domain 575/892: www.corfo.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.corfo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.corfo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.corfo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.corfo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.corfo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.corfo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.corfo.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.corfo.cl"
echo "---"

# Domain 576/892: leylobby.gob.cl
log "Processing domain 576/892: leylobby.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/leylobby.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/leylobby.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/leylobby.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/leylobby.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/leylobby.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/leylobby.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/leylobby.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: leylobby.gob.cl"
echo "---"

# Domain 577/892: www.leylobby.gob.cl
log "Processing domain 577/892: www.leylobby.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.leylobby.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.leylobby.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.leylobby.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.leylobby.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.leylobby.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.leylobby.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.leylobby.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.leylobby.gob.cl"
echo "---"

# Domain 578/892: 5principios.cl
log "Processing domain 578/892: 5principios.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/5principios.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/5principios.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/5principios.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/5principios.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/5principios.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/5principios.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/5principios.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: 5principios.cl"
echo "---"

# Domain 579/892: www.5principios.cl
log "Processing domain 579/892: www.5principios.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.5principios.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.5principios.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.5principios.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.5principios.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.5principios.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.5principios.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.5principios.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.5principios.cl"
echo "---"

# Domain 580/892: accioncolectivaeducacion.cl
log "Processing domain 580/892: accioncolectivaeducacion.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/accioncolectivaeducacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/accioncolectivaeducacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/accioncolectivaeducacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/accioncolectivaeducacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/accioncolectivaeducacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/accioncolectivaeducacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/accioncolectivaeducacion.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: accioncolectivaeducacion.cl"
echo "---"

# Domain 581/892: www.accioncolectivaeducacion.cl
log "Processing domain 581/892: www.accioncolectivaeducacion.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.accioncolectivaeducacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.accioncolectivaeducacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.accioncolectivaeducacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.accioncolectivaeducacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.accioncolectivaeducacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.accioncolectivaeducacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.accioncolectivaeducacion.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.accioncolectivaeducacion.cl"
echo "---"

# Domain 582/892: elearning-quality.cl
log "Processing domain 582/892: elearning-quality.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/elearning-quality.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/elearning-quality.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/elearning-quality.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/elearning-quality.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/elearning-quality.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/elearning-quality.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/elearning-quality.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: elearning-quality.cl"
echo "---"

# Domain 583/892: docenciateleton.cl
log "Processing domain 583/892: docenciateleton.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/docenciateleton.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/docenciateleton.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/docenciateleton.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/docenciateleton.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/docenciateleton.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/docenciateleton.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/docenciateleton.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: docenciateleton.cl"
echo "---"

# Domain 584/892: usek.cl
log "Processing domain 584/892: usek.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/usek.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/usek.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/usek.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/usek.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/usek.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/usek.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/usek.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: usek.cl"
echo "---"

# Domain 585/892: eva.ecampus.usek.cl
log "Processing domain 585/892: eva.ecampus.usek.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/eva.ecampus.usek.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/eva.ecampus.usek.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/eva.ecampus.usek.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/eva.ecampus.usek.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/eva.ecampus.usek.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/eva.ecampus.usek.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/eva.ecampus.usek.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: eva.ecampus.usek.cl"
echo "---"

# Domain 586/892: finis.cl
log "Processing domain 586/892: finis.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/finis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/finis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/finis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/finis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/finis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/finis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/finis.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: finis.cl"
echo "---"

# Domain 587/892: admision.finis.cl
log "Processing domain 587/892: admision.finis.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/admision.finis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/admision.finis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/admision.finis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/admision.finis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/admision.finis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/admision.finis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/admision.finis.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: admision.finis.cl"
echo "---"

# Domain 588/892: ucentral.cl
log "Processing domain 588/892: ucentral.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ucentral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ucentral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ucentral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ucentral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ucentral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ucentral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ucentral.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ucentral.cl"
echo "---"

# Domain 589/892: admision.ucentral.cl
log "Processing domain 589/892: admision.ucentral.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/admision.ucentral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/admision.ucentral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/admision.ucentral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/admision.ucentral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/admision.ucentral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/admision.ucentral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/admision.ucentral.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: admision.ucentral.cl"
echo "---"

# Domain 590/892: admision.uft.cl
log "Processing domain 590/892: admision.uft.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/admision.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/admision.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/admision.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/admision.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/admision.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/admision.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/admision.uft.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: admision.uft.cl"
echo "---"

# Domain 591/892: uss.cl
log "Processing domain 591/892: uss.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/uss.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: uss.cl"
echo "---"

# Domain 592/892: admision.uss.cl
log "Processing domain 592/892: admision.uss.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/admision.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/admision.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/admision.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/admision.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/admision.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/admision.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/admision.uss.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: admision.uss.cl"
echo "---"

# Domain 593/892: aprendoencasa.org
log "Processing domain 593/892: aprendoencasa.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/aprendoencasa.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/aprendoencasa.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/aprendoencasa.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/aprendoencasa.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/aprendoencasa.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/aprendoencasa.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/aprendoencasa.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: aprendoencasa.org"
echo "---"

# Domain 594/892: www.aprendoencasa.org
log "Processing domain 594/892: www.aprendoencasa.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.aprendoencasa.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.aprendoencasa.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.aprendoencasa.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.aprendoencasa.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.aprendoencasa.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.aprendoencasa.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.aprendoencasa.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.aprendoencasa.org"
echo "---"

# Domain 595/892: bienvenida.uft.cl
log "Processing domain 595/892: bienvenida.uft.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/bienvenida.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/bienvenida.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/bienvenida.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/bienvenida.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/bienvenida.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/bienvenida.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/bienvenida.uft.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: bienvenida.uft.cl"
echo "---"

# Domain 596/892: cenia.cl
log "Processing domain 596/892: cenia.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cenia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cenia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cenia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cenia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cenia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cenia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cenia.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cenia.cl"
echo "---"

# Domain 597/892: www.cenia.cl
log "Processing domain 597/892: www.cenia.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.cenia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.cenia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.cenia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.cenia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.cenia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.cenia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.cenia.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.cenia.cl"
echo "---"

# Domain 598/892: centropoliticaspublicas.uft.cl
log "Processing domain 598/892: centropoliticaspublicas.uft.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/centropoliticaspublicas.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/centropoliticaspublicas.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/centropoliticaspublicas.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/centropoliticaspublicas.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/centropoliticaspublicas.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/centropoliticaspublicas.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/centropoliticaspublicas.uft.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: centropoliticaspublicas.uft.cl"
echo "---"

# Domain 599/892: politicaspublicas.uss.cl
log "Processing domain 599/892: politicaspublicas.uss.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/politicaspublicas.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/politicaspublicas.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/politicaspublicas.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/politicaspublicas.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/politicaspublicas.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/politicaspublicas.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/politicaspublicas.uss.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: politicaspublicas.uss.cl"
echo "---"

# Domain 600/892: cidoc.uft.cl
log "Processing domain 600/892: cidoc.uft.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cidoc.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cidoc.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cidoc.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cidoc.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cidoc.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cidoc.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cidoc.uft.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cidoc.uft.cl"
echo "---"

# Domain 601/892: cifras.uss.cl
log "Processing domain 601/892: cifras.uss.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cifras.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cifras.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cifras.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cifras.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cifras.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cifras.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cifras.uss.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cifras.uss.cl"
echo "---"

# Domain 602/892: codigomodelosismico.org
log "Processing domain 602/892: codigomodelosismico.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/codigomodelosismico.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/codigomodelosismico.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/codigomodelosismico.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/codigomodelosismico.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/codigomodelosismico.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/codigomodelosismico.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/codigomodelosismico.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: codigomodelosismico.org"
echo "---"

# Domain 603/892: mecanica.jmc.usm.cl
log "Processing domain 603/892: mecanica.jmc.usm.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mecanica.jmc.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mecanica.jmc.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mecanica.jmc.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mecanica.jmc.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mecanica.jmc.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mecanica.jmc.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mecanica.jmc.usm.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mecanica.jmc.usm.cl"
echo "---"

# Domain 604/892: convivenciaescolar.uft.cl
log "Processing domain 604/892: convivenciaescolar.uft.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/convivenciaescolar.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/convivenciaescolar.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/convivenciaescolar.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/convivenciaescolar.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/convivenciaescolar.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/convivenciaescolar.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/convivenciaescolar.uft.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: convivenciaescolar.uft.cl"
echo "---"

# Domain 605/892: cyk.cl
log "Processing domain 605/892: cyk.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cyk.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cyk.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cyk.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cyk.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cyk.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cyk.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cyk.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cyk.cl"
echo "---"

# Domain 606/892: www.cyk.cl
log "Processing domain 606/892: www.cyk.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.cyk.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.cyk.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.cyk.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.cyk.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.cyk.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.cyk.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.cyk.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.cyk.cl"
echo "---"

# Domain 607/892: dcp.usm.cl
log "Processing domain 607/892: dcp.usm.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/dcp.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/dcp.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/dcp.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/dcp.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/dcp.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/dcp.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/dcp.usm.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: dcp.usm.cl"
echo "---"

# Domain 608/892: eli.usm.cl
log "Processing domain 608/892: eli.usm.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/eli.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/eli.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/eli.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/eli.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/eli.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/eli.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/eli.usm.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: eli.usm.cl"
echo "---"

# Domain 609/892: mecanica.usm.cl
log "Processing domain 609/892: mecanica.usm.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mecanica.usm.cl"
echo "---"

# Domain 610/892: quimicaymedioambiente.usm.cl
log "Processing domain 610/892: quimicaymedioambiente.usm.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/quimicaymedioambiente.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/quimicaymedioambiente.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/quimicaymedioambiente.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/quimicaymedioambiente.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/quimicaymedioambiente.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/quimicaymedioambiente.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/quimicaymedioambiente.usm.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: quimicaymedioambiente.usm.cl"
echo "---"

# Domain 611/892: elinf.usm.cl
log "Processing domain 611/892: elinf.usm.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/elinf.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/elinf.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/elinf.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/elinf.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/elinf.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/elinf.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/elinf.usm.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: elinf.usm.cl"
echo "---"

# Domain 612/892: derechovespertino.uss.cl
log "Processing domain 612/892: derechovespertino.uss.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/derechovespertino.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/derechovespertino.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/derechovespertino.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/derechovespertino.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/derechovespertino.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/derechovespertino.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/derechovespertino.uss.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: derechovespertino.uss.cl"
echo "---"

# Domain 613/892: descubramosencasa.cl
log "Processing domain 613/892: descubramosencasa.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/descubramosencasa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/descubramosencasa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/descubramosencasa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/descubramosencasa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/descubramosencasa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/descubramosencasa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/descubramosencasa.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: descubramosencasa.cl"
echo "---"

# Domain 614/892: www.descubramosencasa.cl
log "Processing domain 614/892: www.descubramosencasa.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.descubramosencasa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.descubramosencasa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.descubramosencasa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.descubramosencasa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.descubramosencasa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.descubramosencasa.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.descubramosencasa.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.descubramosencasa.cl"
echo "---"

# Domain 615/892: capacitacionyasesoria.usm.cl
log "Processing domain 615/892: capacitacionyasesoria.usm.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/capacitacionyasesoria.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/capacitacionyasesoria.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/capacitacionyasesoria.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/capacitacionyasesoria.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/capacitacionyasesoria.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/capacitacionyasesoria.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/capacitacionyasesoria.usm.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: capacitacionyasesoria.usm.cl"
echo "---"

# Domain 616/892: dgiie.usm.cl
log "Processing domain 616/892: dgiie.usm.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/dgiie.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/dgiie.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/dgiie.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/dgiie.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/dgiie.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/dgiie.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/dgiie.usm.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: dgiie.usm.cl"
echo "---"

# Domain 617/892: directorio.mba.usm.cl
log "Processing domain 617/892: directorio.mba.usm.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/directorio.mba.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/directorio.mba.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/directorio.mba.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/directorio.mba.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/directorio.mba.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/directorio.mba.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/directorio.mba.usm.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: directorio.mba.usm.cl"
echo "---"

# Domain 618/892: doctoradomecanica.usm.cl
log "Processing domain 618/892: doctoradomecanica.usm.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/doctoradomecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/doctoradomecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/doctoradomecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/doctoradomecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/doctoradomecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/doctoradomecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/doctoradomecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: doctoradomecanica.usm.cl"
echo "---"

# Domain 619/892: dih.uft.cl
log "Processing domain 619/892: dih.uft.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/dih.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/dih.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/dih.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/dih.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/dih.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/dih.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/dih.uft.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: dih.uft.cl"
echo "---"

# Domain 620/892: ecosisteam.cl
log "Processing domain 620/892: ecosisteam.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ecosisteam.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ecosisteam.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ecosisteam.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ecosisteam.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ecosisteam.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ecosisteam.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ecosisteam.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ecosisteam.cl"
echo "---"

# Domain 621/892: www.ecosisteam.cl
log "Processing domain 621/892: www.ecosisteam.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.ecosisteam.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.ecosisteam.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.ecosisteam.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.ecosisteam.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.ecosisteam.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.ecosisteam.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.ecosisteam.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.ecosisteam.cl"
echo "---"

# Domain 622/892: ediciones.uss.cl
log "Processing domain 622/892: ediciones.uss.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ediciones.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ediciones.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ediciones.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ediciones.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ediciones.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ediciones.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ediciones.uss.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ediciones.uss.cl"
echo "---"

# Domain 623/892: cftmanpower.cl
log "Processing domain 623/892: cftmanpower.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cftmanpower.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cftmanpower.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cftmanpower.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cftmanpower.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cftmanpower.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cftmanpower.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cftmanpower.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cftmanpower.cl"
echo "---"

# Domain 624/892: educacioncontinua.cftmanpower.cl
log "Processing domain 624/892: educacioncontinua.cftmanpower.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/educacioncontinua.cftmanpower.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/educacioncontinua.cftmanpower.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/educacioncontinua.cftmanpower.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/educacioncontinua.cftmanpower.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/educacioncontinua.cftmanpower.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/educacioncontinua.cftmanpower.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/educacioncontinua.cftmanpower.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: educacioncontinua.cftmanpower.cl"
echo "---"

# Domain 625/892: eligeenergia.cl
log "Processing domain 625/892: eligeenergia.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/eligeenergia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/eligeenergia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/eligeenergia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/eligeenergia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/eligeenergia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/eligeenergia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/eligeenergia.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: eligeenergia.cl"
echo "---"

# Domain 626/892: escriturayaprendizaje.cl
log "Processing domain 626/892: escriturayaprendizaje.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/escriturayaprendizaje.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/escriturayaprendizaje.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/escriturayaprendizaje.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/escriturayaprendizaje.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/escriturayaprendizaje.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/escriturayaprendizaje.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/escriturayaprendizaje.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: escriturayaprendizaje.cl"
echo "---"

# Domain 627/892: www.escriturayaprendizaje.cl
log "Processing domain 627/892: www.escriturayaprendizaje.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.escriturayaprendizaje.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.escriturayaprendizaje.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.escriturayaprendizaje.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.escriturayaprendizaje.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.escriturayaprendizaje.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.escriturayaprendizaje.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.escriturayaprendizaje.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.escriturayaprendizaje.cl"
echo "---"

# Domain 628/892: eic.pucv.cl
log "Processing domain 628/892: eic.pucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/eic.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/eic.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/eic.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/eic.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/eic.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/eic.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/eic.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: eic.pucv.cl"
echo "---"

# Domain 629/892: eie.pucv.cl
log "Processing domain 629/892: eie.pucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/eie.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/eie.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/eie.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/eie.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/eie.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/eie.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/eie.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: eie.pucv.cl"
echo "---"

# Domain 630/892: feriavirtual.uft.cl
log "Processing domain 630/892: feriavirtual.uft.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/feriavirtual.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/feriavirtual.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/feriavirtual.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/feriavirtual.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/feriavirtual.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/feriavirtual.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/feriavirtual.uft.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: feriavirtual.uft.cl"
echo "---"

# Domain 631/892: fundacionrassmuss.org
log "Processing domain 631/892: fundacionrassmuss.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/fundacionrassmuss.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/fundacionrassmuss.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/fundacionrassmuss.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/fundacionrassmuss.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/fundacionrassmuss.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/fundacionrassmuss.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/fundacionrassmuss.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: fundacionrassmuss.org"
echo "---"

# Domain 632/892: iconstruccion.cl
log "Processing domain 632/892: iconstruccion.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/iconstruccion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/iconstruccion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/iconstruccion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/iconstruccion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/iconstruccion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/iconstruccion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/iconstruccion.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: iconstruccion.cl"
echo "---"

# Domain 633/892: www.iconstruccion.cl
log "Processing domain 633/892: www.iconstruccion.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.iconstruccion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.iconstruccion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.iconstruccion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.iconstruccion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.iconstruccion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.iconstruccion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.iconstruccion.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.iconstruccion.cl"
echo "---"

# Domain 634/892: knl.cl
log "Processing domain 634/892: knl.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/knl.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/knl.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/knl.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/knl.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/knl.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/knl.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/knl.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: knl.cl"
echo "---"

# Domain 635/892: ecampus.usek.cl
log "Processing domain 635/892: ecampus.usek.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ecampus.usek.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ecampus.usek.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ecampus.usek.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ecampus.usek.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ecampus.usek.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ecampus.usek.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ecampus.usek.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ecampus.usek.cl"
echo "---"

# Domain 636/892: lidereseducativos.cl
log "Processing domain 636/892: lidereseducativos.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: lidereseducativos.cl"
echo "---"

# Domain 637/892: www.lidereseducativos.cl
log "Processing domain 637/892: www.lidereseducativos.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.lidereseducativos.cl"
echo "---"

# Domain 638/892: sigeli.lidereseducativos.cl
log "Processing domain 638/892: sigeli.lidereseducativos.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/sigeli.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/sigeli.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/sigeli.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/sigeli.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/sigeli.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/sigeli.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/sigeli.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: sigeli.lidereseducativos.cl"
echo "---"

# Domain 639/892: redes.lidereseducativos.cl
log "Processing domain 639/892: redes.lidereseducativos.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/redes.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/redes.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/redes.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/redes.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/redes.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/redes.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/redes.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: redes.lidereseducativos.cl"
echo "---"

# Domain 640/892: magistermecanica.usm.cl
log "Processing domain 640/892: magistermecanica.usm.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/magistermecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/magistermecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/magistermecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/magistermecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/magistermecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/magistermecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/magistermecanica.usm.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: magistermecanica.usm.cl"
echo "---"

# Domain 641/892: mba.usm.cl
log "Processing domain 641/892: mba.usm.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mba.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mba.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mba.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mba.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mba.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mba.usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mba.usm.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mba.usm.cl"
echo "---"

# Domain 642/892: modernizacion.uss.cl
log "Processing domain 642/892: modernizacion.uss.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/modernizacion.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/modernizacion.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/modernizacion.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/modernizacion.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/modernizacion.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/modernizacion.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/modernizacion.uss.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: modernizacion.uss.cl"
echo "---"

# Domain 643/892: bpmcenter.cl
log "Processing domain 643/892: bpmcenter.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/bpmcenter.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/bpmcenter.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/bpmcenter.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/bpmcenter.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/bpmcenter.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/bpmcenter.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/bpmcenter.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: bpmcenter.cl"
echo "---"

# Domain 644/892: online.bpmcenter.cl
log "Processing domain 644/892: online.bpmcenter.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/online.bpmcenter.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/online.bpmcenter.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/online.bpmcenter.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/online.bpmcenter.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/online.bpmcenter.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/online.bpmcenter.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/online.bpmcenter.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: online.bpmcenter.cl"
echo "---"

# Domain 645/892: capacitacionenergetica.cl
log "Processing domain 645/892: capacitacionenergetica.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/capacitacionenergetica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/capacitacionenergetica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/capacitacionenergetica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/capacitacionenergetica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/capacitacionenergetica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/capacitacionenergetica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/capacitacionenergetica.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: capacitacionenergetica.cl"
echo "---"

# Domain 646/892: cursos.capacitacionenergetica.cl
log "Processing domain 646/892: cursos.capacitacionenergetica.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cursos.capacitacionenergetica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cursos.capacitacionenergetica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cursos.capacitacionenergetica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cursos.capacitacionenergetica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cursos.capacitacionenergetica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cursos.capacitacionenergetica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cursos.capacitacionenergetica.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cursos.capacitacionenergetica.cl"
echo "---"

# Domain 647/892: online-capatec.cl
log "Processing domain 647/892: online-capatec.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/online-capatec.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/online-capatec.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/online-capatec.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/online-capatec.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/online-capatec.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/online-capatec.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/online-capatec.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: online-capatec.cl"
echo "---"

# Domain 648/892: clubdejardinesdechile.cl
log "Processing domain 648/892: clubdejardinesdechile.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/clubdejardinesdechile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/clubdejardinesdechile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/clubdejardinesdechile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/clubdejardinesdechile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/clubdejardinesdechile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/clubdejardinesdechile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/clubdejardinesdechile.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: clubdejardinesdechile.cl"
echo "---"

# Domain 649/892: cursos.clubdejardinesdechile.cl
log "Processing domain 649/892: cursos.clubdejardinesdechile.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cursos.clubdejardinesdechile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cursos.clubdejardinesdechile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cursos.clubdejardinesdechile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cursos.clubdejardinesdechile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cursos.clubdejardinesdechile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cursos.clubdejardinesdechile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cursos.clubdejardinesdechile.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cursos.clubdejardinesdechile.cl"
echo "---"

# Domain 650/892: fundacioncrecer.net
log "Processing domain 650/892: fundacioncrecer.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/fundacioncrecer.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/fundacioncrecer.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/fundacioncrecer.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/fundacioncrecer.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/fundacioncrecer.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/fundacioncrecer.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/fundacioncrecer.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: fundacioncrecer.net"
echo "---"

# Domain 651/892: capacitaciones.fundacioncrecer.net
log "Processing domain 651/892: capacitaciones.fundacioncrecer.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/capacitaciones.fundacioncrecer.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/capacitaciones.fundacioncrecer.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/capacitaciones.fundacioncrecer.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/capacitaciones.fundacioncrecer.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/capacitaciones.fundacioncrecer.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/capacitaciones.fundacioncrecer.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/capacitaciones.fundacioncrecer.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: capacitaciones.fundacioncrecer.net"
echo "---"

# Domain 652/892: e.lidereseducativos.cl
log "Processing domain 652/892: e.lidereseducativos.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/e.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/e.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/e.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/e.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/e.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/e.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/e.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: e.lidereseducativos.cl"
echo "---"

# Domain 653/892: a2hosted.com
log "Processing domain 653/892: a2hosted.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/a2hosted.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/a2hosted.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/a2hosted.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/a2hosted.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/a2hosted.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/a2hosted.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/a2hosted.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: a2hosted.com"
echo "---"

# Domain 654/892: neyun.a2hosted.com
log "Processing domain 654/892: neyun.a2hosted.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/neyun.a2hosted.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/neyun.a2hosted.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/neyun.a2hosted.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/neyun.a2hosted.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/neyun.a2hosted.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/neyun.a2hosted.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/neyun.a2hosted.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: neyun.a2hosted.com"
echo "---"

# Domain 655/892: gov.co
log "Processing domain 655/892: gov.co"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/gov.co"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/gov.co"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/gov.co"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/gov.co"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/gov.co"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/gov.co"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/gov.co"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: gov.co"
echo "---"

# Domain 656/892: escuelavirtual.registraduria.gov.co
log "Processing domain 656/892: escuelavirtual.registraduria.gov.co"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/escuelavirtual.registraduria.gov.co"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/escuelavirtual.registraduria.gov.co"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/escuelavirtual.registraduria.gov.co"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/escuelavirtual.registraduria.gov.co"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/escuelavirtual.registraduria.gov.co"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/escuelavirtual.registraduria.gov.co"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/escuelavirtual.registraduria.gov.co"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: escuelavirtual.registraduria.gov.co"
echo "---"

# Domain 657/892: neyun.org
log "Processing domain 657/892: neyun.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/neyun.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/neyun.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/neyun.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/neyun.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/neyun.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/neyun.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/neyun.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: neyun.org"
echo "---"

# Domain 658/892: www.neyun.org
log "Processing domain 658/892: www.neyun.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.neyun.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.neyun.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.neyun.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.neyun.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.neyun.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.neyun.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.neyun.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.neyun.org"
echo "---"

# Domain 659/892: noticias.uft.cl
log "Processing domain 659/892: noticias.uft.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/noticias.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/noticias.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/noticias.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/noticias.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/noticias.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/noticias.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/noticias.uft.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: noticias.uft.cl"
echo "---"

# Domain 660/892: parquecultural.cl
log "Processing domain 660/892: parquecultural.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/parquecultural.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/parquecultural.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/parquecultural.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/parquecultural.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/parquecultural.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/parquecultural.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/parquecultural.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: parquecultural.cl"
echo "---"

# Domain 661/892: eli-usm.cl
log "Processing domain 661/892: eli-usm.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/eli-usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/eli-usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/eli-usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/eli-usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/eli-usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/eli-usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/eli-usm.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: eli-usm.cl"
echo "---"

# Domain 662/892: rpa.eli-usm.cl
log "Processing domain 662/892: rpa.eli-usm.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/rpa.eli-usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/rpa.eli-usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/rpa.eli-usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/rpa.eli-usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/rpa.eli-usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/rpa.eli-usm.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/rpa.eli-usm.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: rpa.eli-usm.cl"
echo "---"

# Domain 663/892: plataformamatch.cl
log "Processing domain 663/892: plataformamatch.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/plataformamatch.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/plataformamatch.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/plataformamatch.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/plataformamatch.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/plataformamatch.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/plataformamatch.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/plataformamatch.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: plataformamatch.cl"
echo "---"

# Domain 664/892: www.plataformamatch.cl
log "Processing domain 664/892: www.plataformamatch.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.plataformamatch.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.plataformamatch.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.plataformamatch.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.plataformamatch.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.plataformamatch.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.plataformamatch.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.plataformamatch.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.plataformamatch.cl"
echo "---"

# Domain 665/892: premiospulsar.cl
log "Processing domain 665/892: premiospulsar.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/premiospulsar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/premiospulsar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/premiospulsar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/premiospulsar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/premiospulsar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/premiospulsar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/premiospulsar.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: premiospulsar.cl"
echo "---"

# Domain 666/892: jurado.premiospulsar.cl
log "Processing domain 666/892: jurado.premiospulsar.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/jurado.premiospulsar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/jurado.premiospulsar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/jurado.premiospulsar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/jurado.premiospulsar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/jurado.premiospulsar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/jurado.premiospulsar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/jurado.premiospulsar.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: jurado.premiospulsar.cl"
echo "---"

# Domain 667/892: plena.cenia.cl
log "Processing domain 667/892: plena.cenia.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/plena.cenia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/plena.cenia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/plena.cenia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/plena.cenia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/plena.cenia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/plena.cenia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/plena.cenia.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: plena.cenia.cl"
echo "---"

# Domain 668/892: postgradomedicina.uss.cl
log "Processing domain 668/892: postgradomedicina.uss.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/postgradomedicina.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/postgradomedicina.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/postgradomedicina.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/postgradomedicina.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/postgradomedicina.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/postgradomedicina.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/postgradomedicina.uss.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: postgradomedicina.uss.cl"
echo "---"

# Domain 669/892: postgrados.uft.cl
log "Processing domain 669/892: postgrados.uft.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/postgrados.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/postgrados.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/postgrados.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/postgrados.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/postgrados.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/postgrados.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/postgrados.uft.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: postgrados.uft.cl"
echo "---"

# Domain 670/892: redayllusolar.cl
log "Processing domain 670/892: redayllusolar.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/redayllusolar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/redayllusolar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/redayllusolar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/redayllusolar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/redayllusolar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/redayllusolar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/redayllusolar.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: redayllusolar.cl"
echo "---"

# Domain 671/892: www.redayllusolar.cl
log "Processing domain 671/892: www.redayllusolar.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.redayllusolar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.redayllusolar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.redayllusolar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.redayllusolar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.redayllusolar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.redayllusolar.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.redayllusolar.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.redayllusolar.cl"
echo "---"

# Domain 672/892: redcampussustentable.cl
log "Processing domain 672/892: redcampussustentable.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/redcampussustentable.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/redcampussustentable.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/redcampussustentable.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/redcampussustentable.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/redcampussustentable.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/redcampussustentable.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/redcampussustentable.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: redcampussustentable.cl"
echo "---"

# Domain 673/892: www.redcampussustentable.cl
log "Processing domain 673/892: www.redcampussustentable.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.redcampussustentable.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.redcampussustentable.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.redcampussustentable.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.redcampussustentable.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.redcampussustentable.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.redcampussustentable.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.redcampussustentable.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.redcampussustentable.cl"
echo "---"

# Domain 674/892: constructorescomprometidos.cl
log "Processing domain 674/892: constructorescomprometidos.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/constructorescomprometidos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/constructorescomprometidos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/constructorescomprometidos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/constructorescomprometidos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/constructorescomprometidos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/constructorescomprometidos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/constructorescomprometidos.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: constructorescomprometidos.cl"
echo "---"

# Domain 675/892: www.constructorescomprometidos.cl
log "Processing domain 675/892: www.constructorescomprometidos.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.constructorescomprometidos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.constructorescomprometidos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.constructorescomprometidos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.constructorescomprometidos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.constructorescomprometidos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.constructorescomprometidos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.constructorescomprometidos.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.constructorescomprometidos.cl"
echo "---"

# Domain 676/892: sgmc.uft.cl
log "Processing domain 676/892: sgmc.uft.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/sgmc.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/sgmc.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/sgmc.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/sgmc.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/sgmc.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/sgmc.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/sgmc.uft.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: sgmc.uft.cl"
echo "---"

# Domain 677/892: spc.lidereseducativos.cl
log "Processing domain 677/892: spc.lidereseducativos.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/spc.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/spc.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/spc.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/spc.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/spc.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/spc.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/spc.lidereseducativos.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: spc.lidereseducativos.cl"
echo "---"

# Domain 678/892: svm.uft.cl
log "Processing domain 678/892: svm.uft.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/svm.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/svm.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/svm.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/svm.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/svm.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/svm.uft.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/svm.uft.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: svm.uft.cl"
echo "---"

# Domain 679/892: innedu.cl
log "Processing domain 679/892: innedu.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/innedu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/innedu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/innedu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/innedu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/innedu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/innedu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/innedu.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: innedu.cl"
echo "---"

# Domain 680/892: tae.innedu.cl
log "Processing domain 680/892: tae.innedu.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/tae.innedu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/tae.innedu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/tae.innedu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/tae.innedu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/tae.innedu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/tae.innedu.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/tae.innedu.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: tae.innedu.cl"
echo "---"

# Domain 681/892: vidauniversitaria.uss.cl
log "Processing domain 681/892: vidauniversitaria.uss.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/vidauniversitaria.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/vidauniversitaria.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/vidauniversitaria.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/vidauniversitaria.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/vidauniversitaria.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/vidauniversitaria.uss.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/vidauniversitaria.uss.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: vidauniversitaria.uss.cl"
echo "---"

# Domain 682/892: accuc.cl
log "Processing domain 682/892: accuc.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/accuc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/accuc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/accuc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/accuc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/accuc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/accuc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/accuc.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: accuc.cl"
echo "---"

# Domain 683/892: www.accuc.cl
log "Processing domain 683/892: www.accuc.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.accuc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.accuc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.accuc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.accuc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.accuc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.accuc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.accuc.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.accuc.cl"
echo "---"

# Domain 684/892: secretariadeparticipacion.cl
log "Processing domain 684/892: secretariadeparticipacion.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/secretariadeparticipacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/secretariadeparticipacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/secretariadeparticipacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/secretariadeparticipacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/secretariadeparticipacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/secretariadeparticipacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/secretariadeparticipacion.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: secretariadeparticipacion.cl"
echo "---"

# Domain 685/892: www.secretariadeparticipacion.cl
log "Processing domain 685/892: www.secretariadeparticipacion.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.secretariadeparticipacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.secretariadeparticipacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.secretariadeparticipacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.secretariadeparticipacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.secretariadeparticipacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.secretariadeparticipacion.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.secretariadeparticipacion.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.secretariadeparticipacion.cl"
echo "---"

# Domain 686/892: wa.link
log "Processing domain 686/892: wa.link"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/wa.link"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/wa.link"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/wa.link"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/wa.link"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/wa.link"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/wa.link"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/wa.link"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: wa.link"
echo "---"

# Domain 687/892: cdn-cookieyes.com
log "Processing domain 687/892: cdn-cookieyes.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cdn-cookieyes.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cdn-cookieyes.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cdn-cookieyes.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cdn-cookieyes.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cdn-cookieyes.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cdn-cookieyes.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cdn-cookieyes.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cdn-cookieyes.com"
echo "---"

# Domain 688/892: tarjetacruzverde.cl
log "Processing domain 688/892: tarjetacruzverde.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/tarjetacruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/tarjetacruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/tarjetacruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/tarjetacruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/tarjetacruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/tarjetacruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/tarjetacruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: tarjetacruzverde.cl"
echo "---"

# Domain 689/892: www.tarjetacruzverde.cl
log "Processing domain 689/892: www.tarjetacruzverde.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.tarjetacruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.tarjetacruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.tarjetacruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.tarjetacruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.tarjetacruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.tarjetacruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.tarjetacruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.tarjetacruzverde.cl"
echo "---"

# Domain 690/892: mensajescruzverde.cl
log "Processing domain 690/892: mensajescruzverde.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mensajescruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mensajescruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mensajescruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mensajescruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mensajescruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mensajescruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mensajescruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mensajescruzverde.cl"
echo "---"

# Domain 691/892: cloud.mensajescruzverde.cl
log "Processing domain 691/892: cloud.mensajescruzverde.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cloud.mensajescruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cloud.mensajescruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cloud.mensajescruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cloud.mensajescruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cloud.mensajescruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cloud.mensajescruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cloud.mensajescruzverde.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cloud.mensajescruzverde.cl"
echo "---"

# Domain 692/892: igodigital.com
log "Processing domain 692/892: igodigital.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/igodigital.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/igodigital.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/igodigital.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/igodigital.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/igodigital.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/igodigital.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/igodigital.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: igodigital.com"
echo "---"

# Domain 693/892: 110006489.collect.igodigital.com
log "Processing domain 693/892: 110006489.collect.igodigital.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/110006489.collect.igodigital.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/110006489.collect.igodigital.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/110006489.collect.igodigital.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/110006489.collect.igodigital.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/110006489.collect.igodigital.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/110006489.collect.igodigital.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/110006489.collect.igodigital.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: 110006489.collect.igodigital.com"
echo "---"

# Domain 694/892: cquotient.com
log "Processing domain 694/892: cquotient.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cquotient.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cquotient.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cquotient.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cquotient.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cquotient.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cquotient.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cquotient.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cquotient.com"
echo "---"

# Domain 695/892: cdn.cquotient.com
log "Processing domain 695/892: cdn.cquotient.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cdn.cquotient.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cdn.cquotient.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cdn.cquotient.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cdn.cquotient.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cdn.cquotient.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cdn.cquotient.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cdn.cquotient.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cdn.cquotient.com"
echo "---"

# Domain 696/892: mailmaicao.cl
log "Processing domain 696/892: mailmaicao.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mailmaicao.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mailmaicao.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mailmaicao.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mailmaicao.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mailmaicao.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mailmaicao.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mailmaicao.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mailmaicao.cl"
echo "---"

# Domain 697/892: cloud.mailmaicao.cl
log "Processing domain 697/892: cloud.mailmaicao.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cloud.mailmaicao.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cloud.mailmaicao.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cloud.mailmaicao.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cloud.mailmaicao.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cloud.mailmaicao.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cloud.mailmaicao.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cloud.mailmaicao.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cloud.mailmaicao.cl"
echo "---"

# Domain 698/892: spotify.com
log "Processing domain 698/892: spotify.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/spotify.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/spotify.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/spotify.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/spotify.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/spotify.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/spotify.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/spotify.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: spotify.com"
echo "---"

# Domain 699/892: open.spotify.com
log "Processing domain 699/892: open.spotify.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/open.spotify.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/open.spotify.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/open.spotify.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/open.spotify.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/open.spotify.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/open.spotify.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/open.spotify.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: open.spotify.com"
echo "---"

# Domain 700/892: www.mega.cl
log "Processing domain 700/892: www.mega.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.mega.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.mega.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.mega.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.mega.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.mega.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.mega.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.mega.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.mega.cl"
echo "---"

# Domain 701/892: www.megatiempo.cl
log "Processing domain 701/892: www.megatiempo.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.megatiempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.megatiempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.megatiempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.megatiempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.megatiempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.megatiempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.megatiempo.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.megatiempo.cl"
echo "---"

# Domain 702/892: megamedia.cl
log "Processing domain 702/892: megamedia.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: megamedia.cl"
echo "---"

# Domain 703/892: www.megamedia.cl
log "Processing domain 703/892: www.megamedia.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.megamedia.cl"
echo "---"

# Domain 704/892: infinita.cl
log "Processing domain 704/892: infinita.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/infinita.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/infinita.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/infinita.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/infinita.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/infinita.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/infinita.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/infinita.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: infinita.cl"
echo "---"

# Domain 705/892: www.infinita.cl
log "Processing domain 705/892: www.infinita.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.infinita.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.infinita.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.infinita.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.infinita.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.infinita.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.infinita.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.infinita.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.infinita.cl"
echo "---"

# Domain 706/892: romantica.cl
log "Processing domain 706/892: romantica.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/romantica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/romantica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/romantica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/romantica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/romantica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/romantica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/romantica.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: romantica.cl"
echo "---"

# Domain 707/892: www.romantica.cl
log "Processing domain 707/892: www.romantica.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.romantica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.romantica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.romantica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.romantica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.romantica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.romantica.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.romantica.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.romantica.cl"
echo "---"

# Domain 708/892: fmtiempo.cl
log "Processing domain 708/892: fmtiempo.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/fmtiempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/fmtiempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/fmtiempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/fmtiempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/fmtiempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/fmtiempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/fmtiempo.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: fmtiempo.cl"
echo "---"

# Domain 709/892: www.fmtiempo.cl
log "Processing domain 709/892: www.fmtiempo.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.fmtiempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.fmtiempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.fmtiempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.fmtiempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.fmtiempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.fmtiempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.fmtiempo.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.fmtiempo.cl"
echo "---"

# Domain 710/892: carolina.cl
log "Processing domain 710/892: carolina.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/carolina.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/carolina.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/carolina.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/carolina.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/carolina.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/carolina.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/carolina.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: carolina.cl"
echo "---"

# Domain 711/892: www.carolina.cl
log "Processing domain 711/892: www.carolina.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.carolina.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.carolina.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.carolina.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.carolina.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.carolina.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.carolina.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.carolina.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.carolina.cl"
echo "---"

# Domain 712/892: radiodisney.com
log "Processing domain 712/892: radiodisney.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/radiodisney.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/radiodisney.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/radiodisney.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/radiodisney.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/radiodisney.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/radiodisney.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/radiodisney.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: radiodisney.com"
echo "---"

# Domain 713/892: cl.radiodisney.com
log "Processing domain 713/892: cl.radiodisney.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cl.radiodisney.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cl.radiodisney.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cl.radiodisney.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cl.radiodisney.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cl.radiodisney.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cl.radiodisney.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cl.radiodisney.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cl.radiodisney.com"
echo "---"

# Domain 714/892: etc.cl
log "Processing domain 714/892: etc.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/etc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/etc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/etc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/etc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/etc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/etc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/etc.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: etc.cl"
echo "---"

# Domain 715/892: www.etc.cl
log "Processing domain 715/892: www.etc.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.etc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.etc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.etc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.etc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.etc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.etc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.etc.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.etc.cl"
echo "---"

# Domain 716/892: mediakit.megamedia.cl
log "Processing domain 716/892: mediakit.megamedia.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mediakit.megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/mediakit.megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mediakit.megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/mediakit.megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/mediakit.megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mediakit.megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mediakit.megamedia.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mediakit.megamedia.cl"
echo "---"

# Domain 717/892: static2-meganoticias.cdn.mdstrm.com
log "Processing domain 717/892: static2-meganoticias.cdn.mdstrm.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/static2-meganoticias.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/static2-meganoticias.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/static2-meganoticias.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/static2-meganoticias.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/static2-meganoticias.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/static2-meganoticias.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/static2-meganoticias.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: static2-meganoticias.cdn.mdstrm.com"
echo "---"

# Domain 718/892: images2-mega.cdn.mdstrm.com
log "Processing domain 718/892: images2-mega.cdn.mdstrm.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/images2-mega.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/images2-mega.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/images2-mega.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/images2-mega.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/images2-mega.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/images2-mega.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/images2-mega.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: images2-mega.cdn.mdstrm.com"
echo "---"

# Domain 719/892: static-mega.cdn.mdstrm.com
log "Processing domain 719/892: static-mega.cdn.mdstrm.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/static-mega.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/static-mega.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/static-mega.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/static-mega.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/static-mega.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/static-mega.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/static-mega.cdn.mdstrm.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: static-mega.cdn.mdstrm.com"
echo "---"

# Domain 720/892: puntoscencosud.cl
log "Processing domain 720/892: puntoscencosud.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/puntoscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/puntoscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/puntoscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/puntoscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/puntoscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/puntoscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/puntoscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: puntoscencosud.cl"
echo "---"

# Domain 721/892: www.puntoscencosud.cl
log "Processing domain 721/892: www.puntoscencosud.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.puntoscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.puntoscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.puntoscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.puntoscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.puntoscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.puntoscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.puntoscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.puntoscencosud.cl"
echo "---"

# Domain 722/892: cencopay.cl
log "Processing domain 722/892: cencopay.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cencopay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cencopay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cencopay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cencopay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cencopay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cencopay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cencopay.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cencopay.cl"
echo "---"

# Domain 723/892: www.cencopay.cl
log "Processing domain 723/892: www.cencopay.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.cencopay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.cencopay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.cencopay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.cencopay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.cencopay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.cencopay.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.cencopay.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.cencopay.cl"
echo "---"

# Domain 724/892: www.jumbo.cl
log "Processing domain 724/892: www.jumbo.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.jumbo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.jumbo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.jumbo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.jumbo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.jumbo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.jumbo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.jumbo.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.jumbo.cl"
echo "---"

# Domain 725/892: santaisabel.cl
log "Processing domain 725/892: santaisabel.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/santaisabel.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/santaisabel.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/santaisabel.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/santaisabel.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/santaisabel.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/santaisabel.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/santaisabel.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: santaisabel.cl"
echo "---"

# Domain 726/892: www.santaisabel.cl
log "Processing domain 726/892: www.santaisabel.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.santaisabel.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.santaisabel.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.santaisabel.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.santaisabel.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.santaisabel.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.santaisabel.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.santaisabel.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.santaisabel.cl"
echo "---"

# Domain 727/892: spidchile.cl
log "Processing domain 727/892: spidchile.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/spidchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/spidchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/spidchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/spidchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/spidchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/spidchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/spidchile.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: spidchile.cl"
echo "---"

# Domain 728/892: www.mitarjetacencosud.cl
log "Processing domain 728/892: www.mitarjetacencosud.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.mitarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.mitarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.mitarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.mitarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.mitarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.mitarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.mitarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.mitarjetacencosud.cl"
echo "---"

# Domain 729/892: seguroscencosud.cl
log "Processing domain 729/892: seguroscencosud.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/seguroscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/seguroscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/seguroscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/seguroscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/seguroscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/seguroscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/seguroscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: seguroscencosud.cl"
echo "---"

# Domain 730/892: www.seguroscencosud.cl
log "Processing domain 730/892: www.seguroscencosud.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.seguroscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.seguroscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.seguroscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.seguroscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.seguroscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.seguroscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.seguroscencosud.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.seguroscencosud.cl"
echo "---"

# Domain 731/892: noviosparis.cl
log "Processing domain 731/892: noviosparis.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: noviosparis.cl"
echo "---"

# Domain 732/892: club.noviosparis.cl
log "Processing domain 732/892: club.noviosparis.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/club.noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/club.noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/club.noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/club.noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/club.noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/club.noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/club.noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: club.noviosparis.cl"
echo "---"

# Domain 733/892: bebeparis.cl
log "Processing domain 733/892: bebeparis.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/bebeparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/bebeparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/bebeparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/bebeparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/bebeparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/bebeparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/bebeparis.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: bebeparis.cl"
echo "---"

# Domain 734/892: www.bebeparis.cl
log "Processing domain 734/892: www.bebeparis.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.bebeparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.bebeparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.bebeparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.bebeparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.bebeparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.bebeparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.bebeparis.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.bebeparis.cl"
echo "---"

# Domain 735/892: tarjetacencosud.cl
log "Processing domain 735/892: tarjetacencosud.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/tarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/tarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/tarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/tarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/tarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/tarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/tarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: tarjetacencosud.cl"
echo "---"

# Domain 736/892: www.tarjetacencosud.cl
log "Processing domain 736/892: www.tarjetacencosud.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.tarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.tarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.tarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.tarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.tarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.tarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.tarjetacencosud.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.tarjetacencosud.cl"
echo "---"

# Domain 737/892: www.noviosparis.cl
log "Processing domain 737/892: www.noviosparis.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.noviosparis.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.noviosparis.cl"
echo "---"

# Domain 738/892: www.easy.cl
log "Processing domain 738/892: www.easy.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.easy.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.easy.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.easy.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.easy.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.easy.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.easy.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.easy.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.easy.cl"
echo "---"

# Domain 739/892: www.scotiabankchile.cl
log "Processing domain 739/892: www.scotiabankchile.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.scotiabankchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.scotiabankchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.scotiabankchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.scotiabankchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.scotiabankchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.scotiabankchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.scotiabankchile.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.scotiabankchile.cl"
echo "---"

# Domain 740/892: ventaempresascencosud.cl
log "Processing domain 740/892: ventaempresascencosud.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ventaempresascencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ventaempresascencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ventaempresascencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ventaempresascencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ventaempresascencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ventaempresascencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ventaempresascencosud.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ventaempresascencosud.cl"
echo "---"

# Domain 741/892: www.ventaempresascencosud.cl
log "Processing domain 741/892: www.ventaempresascencosud.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.ventaempresascencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.ventaempresascencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.ventaempresascencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.ventaempresascencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.ventaempresascencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.ventaempresascencosud.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.ventaempresascencosud.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.ventaempresascencosud.cl"
echo "---"

# Domain 742/892: trabajando.com
log "Processing domain 742/892: trabajando.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/trabajando.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/trabajando.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/trabajando.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/trabajando.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/trabajando.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/trabajando.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/trabajando.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: trabajando.com"
echo "---"

# Domain 743/892: cencosud.trabajando.com
log "Processing domain 743/892: cencosud.trabajando.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cencosud.trabajando.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cencosud.trabajando.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cencosud.trabajando.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cencosud.trabajando.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cencosud.trabajando.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cencosud.trabajando.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cencosud.trabajando.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cencosud.trabajando.com"
echo "---"

# Domain 744/892: cencosud.com
log "Processing domain 744/892: cencosud.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cencosud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cencosud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cencosud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cencosud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cencosud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cencosud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cencosud.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cencosud.com"
echo "---"

# Domain 745/892: www.cencosud.com
log "Processing domain 745/892: www.cencosud.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.cencosud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.cencosud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.cencosud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.cencosud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.cencosud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.cencosud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.cencosud.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.cencosud.com"
echo "---"

# Domain 746/892: cl-paris-media-hub.ecomm.cencosud.com
log "Processing domain 746/892: cl-paris-media-hub.ecomm.cencosud.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cl-paris-media-hub.ecomm.cencosud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cl-paris-media-hub.ecomm.cencosud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cl-paris-media-hub.ecomm.cencosud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cl-paris-media-hub.ecomm.cencosud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cl-paris-media-hub.ecomm.cencosud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cl-paris-media-hub.ecomm.cencosud.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cl-paris-media-hub.ecomm.cencosud.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cl-paris-media-hub.ecomm.cencosud.com"
echo "---"

# Domain 747/892: openathens.net
log "Processing domain 747/892: openathens.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/openathens.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/openathens.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/openathens.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/openathens.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/openathens.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/openathens.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/openathens.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: openathens.net"
echo "---"

# Domain 748/892: go.openathens.net
log "Processing domain 748/892: go.openathens.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/go.openathens.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/go.openathens.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/go.openathens.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/go.openathens.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/go.openathens.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/go.openathens.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/go.openathens.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: go.openathens.net"
echo "---"

# Domain 749/892: ebscohost.com
log "Processing domain 749/892: ebscohost.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ebscohost.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ebscohost.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ebscohost.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ebscohost.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ebscohost.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ebscohost.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ebscohost.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ebscohost.com"
echo "---"

# Domain 750/892: search.ebscohost.com
log "Processing domain 750/892: search.ebscohost.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/search.ebscohost.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/search.ebscohost.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/search.ebscohost.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/search.ebscohost.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/search.ebscohost.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/search.ebscohost.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/search.ebscohost.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: search.ebscohost.com"
echo "---"

# Domain 751/892: springeropen.com
log "Processing domain 751/892: springeropen.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/springeropen.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/springeropen.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/springeropen.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/springeropen.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/springeropen.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/springeropen.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/springeropen.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: springeropen.com"
echo "---"

# Domain 752/892: ccj.springeropen.com
log "Processing domain 752/892: ccj.springeropen.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ccj.springeropen.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ccj.springeropen.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ccj.springeropen.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ccj.springeropen.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ccj.springeropen.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ccj.springeropen.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ccj.springeropen.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ccj.springeropen.com"
echo "---"

# Domain 753/892: chemspider.com
log "Processing domain 753/892: chemspider.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/chemspider.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/chemspider.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/chemspider.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/chemspider.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/chemspider.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/chemspider.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/chemspider.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: chemspider.com"
echo "---"

# Domain 754/892: www.chemspider.com
log "Processing domain 754/892: www.chemspider.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.chemspider.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.chemspider.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.chemspider.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.chemspider.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.chemspider.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.chemspider.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.chemspider.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.chemspider.com"
echo "---"

# Domain 755/892: nih.gov
log "Processing domain 755/892: nih.gov"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/nih.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/nih.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/nih.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/nih.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/nih.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/nih.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/nih.gov"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: nih.gov"
echo "---"

# Domain 756/892: pubchem.ncbi.nlm.nih.gov
log "Processing domain 756/892: pubchem.ncbi.nlm.nih.gov"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/pubchem.ncbi.nlm.nih.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/pubchem.ncbi.nlm.nih.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/pubchem.ncbi.nlm.nih.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/pubchem.ncbi.nlm.nih.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/pubchem.ncbi.nlm.nih.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/pubchem.ncbi.nlm.nih.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/pubchem.ncbi.nlm.nih.gov"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: pubchem.ncbi.nlm.nih.gov"
echo "---"

# Domain 757/892: oclc.org
log "Processing domain 757/892: oclc.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/oclc.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: oclc.org"
echo "---"

# Domain 758/892: uchile.idm.oclc.org
log "Processing domain 758/892: uchile.idm.oclc.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/uchile.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/uchile.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/uchile.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/uchile.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/uchile.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/uchile.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/uchile.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: uchile.idm.oclc.org"
echo "---"

# Domain 759/892: aflip.in
log "Processing domain 759/892: aflip.in"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/aflip.in"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/aflip.in"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/aflip.in"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/aflip.in"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/aflip.in"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/aflip.in"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/aflip.in"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: aflip.in"
echo "---"

# Domain 760/892: indualimentos.aflip.in
log "Processing domain 760/892: indualimentos.aflip.in"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/indualimentos.aflip.in"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/indualimentos.aflip.in"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/indualimentos.aflip.in"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/indualimentos.aflip.in"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/indualimentos.aflip.in"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/indualimentos.aflip.in"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/indualimentos.aflip.in"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: indualimentos.aflip.in"
echo "---"

# Domain 761/892: doabooks.org
log "Processing domain 761/892: doabooks.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/doabooks.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/doabooks.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/doabooks.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/doabooks.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/doabooks.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/doabooks.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/doabooks.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: doabooks.org"
echo "---"

# Domain 762/892: www.doabooks.org
log "Processing domain 762/892: www.doabooks.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.doabooks.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.doabooks.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.doabooks.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.doabooks.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.doabooks.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.doabooks.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.doabooks.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.doabooks.org"
echo "---"

# Domain 763/892: com.pk
log "Processing domain 763/892: com.pk"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/com.pk"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/com.pk"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/com.pk"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/com.pk"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/com.pk"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/com.pk"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/com.pk"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: com.pk"
echo "---"

# Domain 764/892: chemistry.com.pk
log "Processing domain 764/892: chemistry.com.pk"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/chemistry.com.pk"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/chemistry.com.pk"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/chemistry.com.pk"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/chemistry.com.pk"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/chemistry.com.pk"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/chemistry.com.pk"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/chemistry.com.pk"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: chemistry.com.pk"
echo "---"

# Domain 765/892: books.google.com
log "Processing domain 765/892: books.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/books.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/books.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/books.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/books.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/books.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/books.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/books.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: books.google.com"
echo "---"

# Domain 766/892: tesischilenas.cl
log "Processing domain 766/892: tesischilenas.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/tesischilenas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/tesischilenas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/tesischilenas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/tesischilenas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/tesischilenas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/tesischilenas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/tesischilenas.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: tesischilenas.cl"
echo "---"

# Domain 767/892: www.tesischilenas.cl
log "Processing domain 767/892: www.tesischilenas.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.tesischilenas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.tesischilenas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.tesischilenas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.tesischilenas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.tesischilenas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.tesischilenas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.tesischilenas.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.tesischilenas.cl"
echo "---"

# Domain 768/892: cse.google.com
log "Processing domain 768/892: cse.google.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cse.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cse.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cse.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cse.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cse.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cse.google.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cse.google.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cse.google.com"
echo "---"

# Domain 769/892: guiastematicas.pucv.cl
log "Processing domain 769/892: guiastematicas.pucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/guiastematicas.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/guiastematicas.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/guiastematicas.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/guiastematicas.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/guiastematicas.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/guiastematicas.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/guiastematicas.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: guiastematicas.pucv.cl"
echo "---"

# Domain 770/892: catalogo.pucv.cl
log "Processing domain 770/892: catalogo.pucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/catalogo.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/catalogo.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/catalogo.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/catalogo.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/catalogo.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/catalogo.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/catalogo.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: catalogo.pucv.cl"
echo "---"

# Domain 771/892: biblioespacios.pucv.cl
log "Processing domain 771/892: biblioespacios.pucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/biblioespacios.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/biblioespacios.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/biblioespacios.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/biblioespacios.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/biblioespacios.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/biblioespacios.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/biblioespacios.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: biblioespacios.pucv.cl"
echo "---"

# Domain 772/892: pucv.idm.oclc.org
log "Processing domain 772/892: pucv.idm.oclc.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: pucv.idm.oclc.org"
echo "---"

# Domain 773/892: bibliografiadigital.pucv.cl
log "Processing domain 773/892: bibliografiadigital.pucv.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/bibliografiadigital.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/bibliografiadigital.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/bibliografiadigital.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/bibliografiadigital.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/bibliografiadigital.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/bibliografiadigital.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/bibliografiadigital.pucv.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: bibliografiadigital.pucv.cl"
echo "---"

# Domain 774/892: scielo.conicyt.cl
log "Processing domain 774/892: scielo.conicyt.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/scielo.conicyt.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/scielo.conicyt.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/scielo.conicyt.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/scielo.conicyt.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/scielo.conicyt.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/scielo.conicyt.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/scielo.conicyt.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: scielo.conicyt.cl"
echo "---"

# Domain 775/892: infoweb-newsbank-com.pucv.idm.oclc.org
log "Processing domain 775/892: infoweb-newsbank-com.pucv.idm.oclc.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/infoweb-newsbank-com.pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/infoweb-newsbank-com.pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/infoweb-newsbank-com.pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/infoweb-newsbank-com.pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/infoweb-newsbank-com.pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/infoweb-newsbank-com.pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/infoweb-newsbank-com.pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: infoweb-newsbank-com.pucv.idm.oclc.org"
echo "---"

# Domain 776/892: elibrary-asabe-org.pucv.idm.oclc.org
log "Processing domain 776/892: elibrary-asabe-org.pucv.idm.oclc.org"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/elibrary-asabe-org.pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/elibrary-asabe-org.pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/elibrary-asabe-org.pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/elibrary-asabe-org.pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/elibrary-asabe-org.pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/elibrary-asabe-org.pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/elibrary-asabe-org.pucv.idm.oclc.org"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: elibrary-asabe-org.pucv.idm.oclc.org"
echo "---"

# Domain 777/892: www.ncbi.nlm.nih.gov
log "Processing domain 777/892: www.ncbi.nlm.nih.gov"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.ncbi.nlm.nih.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.ncbi.nlm.nih.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.ncbi.nlm.nih.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.ncbi.nlm.nih.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.ncbi.nlm.nih.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.ncbi.nlm.nih.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.ncbi.nlm.nih.gov"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.ncbi.nlm.nih.gov"
echo "---"

# Domain 778/892: scimagojr.com
log "Processing domain 778/892: scimagojr.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/scimagojr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/scimagojr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/scimagojr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/scimagojr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/scimagojr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/scimagojr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/scimagojr.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: scimagojr.com"
echo "---"

# Domain 779/892: www.scimagojr.com
log "Processing domain 779/892: www.scimagojr.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.scimagojr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.scimagojr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.scimagojr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.scimagojr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.scimagojr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.scimagojr.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.scimagojr.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.scimagojr.com"
echo "---"

# Domain 780/892: wiley.com
log "Processing domain 780/892: wiley.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/wiley.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/wiley.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/wiley.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/wiley.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/wiley.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/wiley.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/wiley.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: wiley.com"
echo "---"

# Domain 781/892: authorservices.wiley.com
log "Processing domain 781/892: authorservices.wiley.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/authorservices.wiley.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/authorservices.wiley.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/authorservices.wiley.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/authorservices.wiley.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/authorservices.wiley.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/authorservices.wiley.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/authorservices.wiley.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: authorservices.wiley.com"
echo "---"

# Domain 782/892: springer.com
log "Processing domain 782/892: springer.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/springer.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/springer.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/springer.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/springer.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/springer.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/springer.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/springer.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: springer.com"
echo "---"

# Domain 783/892: www.springer.com
log "Processing domain 783/892: www.springer.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.springer.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.springer.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.springer.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.springer.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.springer.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.springer.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.springer.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.springer.com"
echo "---"

# Domain 784/892: ebsco.com
log "Processing domain 784/892: ebsco.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ebsco.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ebsco.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ebsco.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ebsco.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ebsco.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ebsco.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ebsco.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ebsco.com"
echo "---"

# Domain 785/892: searchbox.ebsco.com
log "Processing domain 785/892: searchbox.ebsco.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/searchbox.ebsco.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/searchbox.ebsco.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/searchbox.ebsco.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/searchbox.ebsco.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/searchbox.ebsco.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/searchbox.ebsco.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/searchbox.ebsco.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: searchbox.ebsco.com"
echo "---"

# Domain 786/892: digital.gob.cl
log "Processing domain 786/892: digital.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/digital.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/digital.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/digital.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/digital.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/digital.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/digital.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/digital.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: digital.gob.cl"
echo "---"

# Domain 787/892: cdn.digital.gob.cl
log "Processing domain 787/892: cdn.digital.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cdn.digital.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cdn.digital.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cdn.digital.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cdn.digital.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cdn.digital.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cdn.digital.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cdn.digital.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cdn.digital.gob.cl"
echo "---"

# Domain 788/892: sidoc.cl
log "Processing domain 788/892: sidoc.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/sidoc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/sidoc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/sidoc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/sidoc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/sidoc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/sidoc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/sidoc.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: sidoc.cl"
echo "---"

# Domain 789/892: www.sidoc.cl
log "Processing domain 789/892: www.sidoc.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.sidoc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.sidoc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.sidoc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.sidoc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.sidoc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.sidoc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.sidoc.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.sidoc.cl"
echo "---"

# Domain 790/892: harvard.edu
log "Processing domain 790/892: harvard.edu"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/harvard.edu"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/harvard.edu"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/harvard.edu"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/harvard.edu"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/harvard.edu"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/harvard.edu"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/harvard.edu"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: harvard.edu"
echo "---"

# Domain 791/892: hbsp.harvard.edu
log "Processing domain 791/892: hbsp.harvard.edu"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/hbsp.harvard.edu"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/hbsp.harvard.edu"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/hbsp.harvard.edu"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/hbsp.harvard.edu"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/hbsp.harvard.edu"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/hbsp.harvard.edu"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/hbsp.harvard.edu"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: hbsp.harvard.edu"
echo "---"

# Domain 792/892: sharepoint.com
log "Processing domain 792/892: sharepoint.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/sharepoint.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/sharepoint.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/sharepoint.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/sharepoint.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/sharepoint.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/sharepoint.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/sharepoint.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: sharepoint.com"
echo "---"

# Domain 793/892: duoccl0.sharepoint.com
log "Processing domain 793/892: duoccl0.sharepoint.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/duoccl0.sharepoint.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/duoccl0.sharepoint.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/duoccl0.sharepoint.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/duoccl0.sharepoint.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/duoccl0.sharepoint.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/duoccl0.sharepoint.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/duoccl0.sharepoint.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: duoccl0.sharepoint.com"
echo "---"

# Domain 794/892: libguides.com
log "Processing domain 794/892: libguides.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/libguides.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/libguides.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/libguides.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/libguides.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/libguides.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/libguides.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/libguides.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: libguides.com"
echo "---"

# Domain 795/892: static-assets-us.libguides.com
log "Processing domain 795/892: static-assets-us.libguides.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/static-assets-us.libguides.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/static-assets-us.libguides.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/static-assets-us.libguides.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/static-assets-us.libguides.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/static-assets-us.libguides.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/static-assets-us.libguides.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/static-assets-us.libguides.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: static-assets-us.libguides.com"
echo "---"

# Domain 796/892: libanswers.com
log "Processing domain 796/892: libanswers.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/libanswers.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/libanswers.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/libanswers.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/libanswers.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/libanswers.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/libanswers.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/libanswers.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: libanswers.com"
echo "---"

# Domain 797/892: duoc.libanswers.com
log "Processing domain 797/892: duoc.libanswers.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/duoc.libanswers.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/duoc.libanswers.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/duoc.libanswers.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/duoc.libanswers.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/duoc.libanswers.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/duoc.libanswers.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/duoc.libanswers.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: duoc.libanswers.com"
echo "---"

# Domain 798/892: lgapi-us.libapps.com
log "Processing domain 798/892: lgapi-us.libapps.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/lgapi-us.libapps.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/lgapi-us.libapps.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/lgapi-us.libapps.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/lgapi-us.libapps.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/lgapi-us.libapps.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/lgapi-us.libapps.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/lgapi-us.libapps.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: lgapi-us.libapps.com"
echo "---"

# Domain 799/892: duoc.libcal.com
log "Processing domain 799/892: duoc.libcal.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/duoc.libcal.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/duoc.libcal.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/duoc.libcal.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/duoc.libcal.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/duoc.libcal.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/duoc.libcal.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/duoc.libcal.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: duoc.libcal.com"
echo "---"

# Domain 800/892: netdna.bootstrapcdn.com
log "Processing domain 800/892: netdna.bootstrapcdn.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/netdna.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/netdna.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/netdna.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/netdna.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/netdna.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/netdna.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/netdna.bootstrapcdn.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: netdna.bootstrapcdn.com"
echo "---"

# Domain 801/892: webclass.cl
log "Processing domain 801/892: webclass.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/webclass.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/webclass.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/webclass.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/webclass.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/webclass.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/webclass.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/webclass.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: webclass.cl"
echo "---"

# Domain 802/892: www.webclass.cl
log "Processing domain 802/892: www.webclass.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.webclass.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.webclass.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.webclass.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.webclass.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.webclass.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.webclass.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.webclass.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.webclass.cl"
echo "---"

# Domain 803/892: desafiocrecer.cl
log "Processing domain 803/892: desafiocrecer.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/desafiocrecer.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/desafiocrecer.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/desafiocrecer.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/desafiocrecer.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/desafiocrecer.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/desafiocrecer.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/desafiocrecer.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: desafiocrecer.cl"
echo "---"

# Domain 804/892: popt.in
log "Processing domain 804/892: popt.in"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/popt.in"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/popt.in"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/popt.in"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/popt.in"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/popt.in"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/popt.in"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/popt.in"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: popt.in"
echo "---"

# Domain 805/892: cdn.popt.in
log "Processing domain 805/892: cdn.popt.in"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cdn.popt.in"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cdn.popt.in"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cdn.popt.in"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cdn.popt.in"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cdn.popt.in"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cdn.popt.in"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cdn.popt.in"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cdn.popt.in"
echo "---"

# Domain 806/892: pro.fontawesome.com
log "Processing domain 806/892: pro.fontawesome.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/pro.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/pro.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/pro.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/pro.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/pro.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/pro.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/pro.fontawesome.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: pro.fontawesome.com"
echo "---"

# Domain 807/892: hubspot.com
log "Processing domain 807/892: hubspot.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/hubspot.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: hubspot.com"
echo "---"

# Domain 808/892: policy.hubspot.com
log "Processing domain 808/892: policy.hubspot.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/policy.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/policy.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/policy.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/policy.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/policy.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/policy.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/policy.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: policy.hubspot.com"
echo "---"

# Domain 809/892: www.hubspot.com
log "Processing domain 809/892: www.hubspot.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.hubspot.com"
echo "---"

# Domain 810/892: legal.hubspot.com
log "Processing domain 810/892: legal.hubspot.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/legal.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/legal.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/legal.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/legal.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/legal.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/legal.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/legal.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: legal.hubspot.com"
echo "---"

# Domain 811/892: knowledge.hubspot.com
log "Processing domain 811/892: knowledge.hubspot.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/knowledge.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/knowledge.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/knowledge.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/knowledge.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/knowledge.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/knowledge.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/knowledge.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: knowledge.hubspot.com"
echo "---"

# Domain 812/892: help.hubspot.com
log "Processing domain 812/892: help.hubspot.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/help.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/help.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/help.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/help.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/help.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/help.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/help.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: help.hubspot.com"
echo "---"

# Domain 813/892: bugcrowd.com
log "Processing domain 813/892: bugcrowd.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/bugcrowd.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/bugcrowd.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/bugcrowd.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/bugcrowd.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/bugcrowd.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/bugcrowd.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/bugcrowd.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: bugcrowd.com"
echo "---"

# Domain 814/892: trust.hubspot.com
log "Processing domain 814/892: trust.hubspot.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/trust.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/trust.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/trust.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/trust.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/trust.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/trust.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/trust.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: trust.hubspot.com"
echo "---"

# Domain 815/892: copyright.gov
log "Processing domain 815/892: copyright.gov"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/copyright.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/copyright.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/copyright.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/copyright.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/copyright.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/copyright.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/copyright.gov"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: copyright.gov"
echo "---"

# Domain 816/892: www.copyright.gov
log "Processing domain 816/892: www.copyright.gov"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.copyright.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.copyright.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.copyright.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.copyright.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.copyright.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.copyright.gov"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.copyright.gov"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.copyright.gov"
echo "---"

# Domain 817/892: grader.com
log "Processing domain 817/892: grader.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/grader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/grader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/grader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/grader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/grader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/grader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/grader.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: grader.com"
echo "---"

# Domain 818/892: website.grader.com
log "Processing domain 818/892: website.grader.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/website.grader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/website.grader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/website.grader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/website.grader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/website.grader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/website.grader.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/website.grader.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: website.grader.com"
echo "---"

# Domain 819/892: ir.hubspot.com
log "Processing domain 819/892: ir.hubspot.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ir.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ir.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ir.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ir.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ir.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ir.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ir.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ir.hubspot.com"
echo "---"

# Domain 820/892: blog.hubspot.com
log "Processing domain 820/892: blog.hubspot.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/blog.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/blog.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/blog.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/blog.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/blog.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/blog.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/blog.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: blog.hubspot.com"
echo "---"

# Domain 821/892: academy.hubspot.com
log "Processing domain 821/892: academy.hubspot.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/academy.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/academy.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/academy.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/academy.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/academy.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/academy.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/academy.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: academy.hubspot.com"
echo "---"

# Domain 822/892: typekit.net
log "Processing domain 822/892: typekit.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/typekit.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/typekit.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/typekit.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/typekit.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/typekit.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/typekit.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/typekit.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: typekit.net"
echo "---"

# Domain 823/892: use.typekit.net
log "Processing domain 823/892: use.typekit.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/use.typekit.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/use.typekit.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/use.typekit.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/use.typekit.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/use.typekit.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/use.typekit.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/use.typekit.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: use.typekit.net"
echo "---"

# Domain 824/892: compete.com
log "Processing domain 824/892: compete.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/compete.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/compete.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/compete.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/compete.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/compete.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/compete.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/compete.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: compete.com"
echo "---"

# Domain 825/892: c.compete.com
log "Processing domain 825/892: c.compete.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/c.compete.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/c.compete.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/c.compete.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/c.compete.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/c.compete.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/c.compete.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/c.compete.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: c.compete.com"
echo "---"

# Domain 826/892: wistia.com
log "Processing domain 826/892: wistia.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/wistia.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/wistia.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/wistia.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/wistia.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/wistia.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/wistia.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/wistia.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: wistia.com"
echo "---"

# Domain 827/892: fast.wistia.com
log "Processing domain 827/892: fast.wistia.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/fast.wistia.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/fast.wistia.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/fast.wistia.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/fast.wistia.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/fast.wistia.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/fast.wistia.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/fast.wistia.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: fast.wistia.com"
echo "---"

# Domain 828/892: hubspot.net
log "Processing domain 828/892: hubspot.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/hubspot.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/hubspot.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/hubspot.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/hubspot.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/hubspot.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/hubspot.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/hubspot.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: hubspot.net"
echo "---"

# Domain 829/892: cdn2.hubspot.net
log "Processing domain 829/892: cdn2.hubspot.net"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/cdn2.hubspot.net"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cdn2.hubspot.net"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cdn2.hubspot.net"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cdn2.hubspot.net"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cdn2.hubspot.net"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cdn2.hubspot.net"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cdn2.hubspot.net"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cdn2.hubspot.net"
echo "---"

# Domain 830/892: c-col.com
log "Processing domain 830/892: c-col.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/c-col.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/c-col.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/c-col.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/c-col.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/c-col.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/c-col.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/c-col.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: c-col.com"
echo "---"

# Domain 831/892: ssl-hubspot-com-f286a8.c-col.com
log "Processing domain 831/892: ssl-hubspot-com-f286a8.c-col.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ssl-hubspot-com-f286a8.c-col.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ssl-hubspot-com-f286a8.c-col.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ssl-hubspot-com-f286a8.c-col.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ssl-hubspot-com-f286a8.c-col.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ssl-hubspot-com-f286a8.c-col.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ssl-hubspot-com-f286a8.c-col.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ssl-hubspot-com-f286a8.c-col.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ssl-hubspot-com-f286a8.c-col.com"
echo "---"

# Domain 832/892: static2cdn.hubspot.com
log "Processing domain 832/892: static2cdn.hubspot.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/static2cdn.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/static2cdn.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/static2cdn.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/static2cdn.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/static2cdn.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/static2cdn.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/static2cdn.hubspot.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: static2cdn.hubspot.com"
echo "---"

# Domain 833/892: newfold.com
log "Processing domain 833/892: newfold.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/newfold.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/newfold.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/newfold.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/newfold.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/newfold.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/newfold.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/newfold.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: newfold.com"
echo "---"

# Domain 834/892: dipres.gob.cl
log "Processing domain 834/892: dipres.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/dipres.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/dipres.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/dipres.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/dipres.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/dipres.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/dipres.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/dipres.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: dipres.gob.cl"
echo "---"

# Domain 835/892: www.dipres.gob.cl
log "Processing domain 835/892: www.dipres.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.dipres.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.dipres.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.dipres.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.dipres.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.dipres.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.dipres.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.dipres.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.dipres.gob.cl"
echo "---"

# Domain 836/892: bidat.gob.cl
log "Processing domain 836/892: bidat.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/bidat.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/bidat.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/bidat.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/bidat.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/bidat.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/bidat.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/bidat.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: bidat.gob.cl"
echo "---"

# Domain 837/892: sni.gob.cl
log "Processing domain 837/892: sni.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/sni.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/sni.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/sni.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/sni.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/sni.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/sni.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/sni.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: sni.gob.cl"
echo "---"

# Domain 838/892: desarrollosocialyfamilia.gob.cl
log "Processing domain 838/892: desarrollosocialyfamilia.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/desarrollosocialyfamilia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/desarrollosocialyfamilia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/desarrollosocialyfamilia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/desarrollosocialyfamilia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/desarrollosocialyfamilia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/desarrollosocialyfamilia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/desarrollosocialyfamilia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: desarrollosocialyfamilia.gob.cl"
echo "---"

# Domain 839/892: www.desarrollosocialyfamilia.gob.cl
log "Processing domain 839/892: www.desarrollosocialyfamilia.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.desarrollosocialyfamilia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.desarrollosocialyfamilia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.desarrollosocialyfamilia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.desarrollosocialyfamilia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.desarrollosocialyfamilia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.desarrollosocialyfamilia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.desarrollosocialyfamilia.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.desarrollosocialyfamilia.gob.cl"
echo "---"

# Domain 840/892: adis.gob.cl
log "Processing domain 840/892: adis.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/adis.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/adis.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/adis.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/adis.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/adis.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/adis.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/adis.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: adis.gob.cl"
echo "---"

# Domain 841/892: observatorio.ministeriodesarrollosocial.gob.cl
log "Processing domain 841/892: observatorio.ministeriodesarrollosocial.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/observatorio.ministeriodesarrollosocial.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/observatorio.ministeriodesarrollosocial.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/observatorio.ministeriodesarrollosocial.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/observatorio.ministeriodesarrollosocial.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/observatorio.ministeriodesarrollosocial.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/observatorio.ministeriodesarrollosocial.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/observatorio.ministeriodesarrollosocial.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: observatorio.ministeriodesarrollosocial.gob.cl"
echo "---"

# Domain 842/892: bipdata.cl
log "Processing domain 842/892: bipdata.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/bipdata.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/bipdata.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/bipdata.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/bipdata.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/bipdata.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/bipdata.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/bipdata.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: bipdata.cl"
echo "---"

# Domain 843/892: code.jquery.com
log "Processing domain 843/892: code.jquery.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/code.jquery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/code.jquery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/code.jquery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/code.jquery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/code.jquery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/code.jquery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/code.jquery.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: code.jquery.com"
echo "---"

# Domain 844/892: buscalibre.com.ar
log "Processing domain 844/892: buscalibre.com.ar"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/buscalibre.com.ar"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/buscalibre.com.ar"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/buscalibre.com.ar"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/buscalibre.com.ar"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/buscalibre.com.ar"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/buscalibre.com.ar"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/buscalibre.com.ar"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: buscalibre.com.ar"
echo "---"

# Domain 845/892: www.buscalibre.com.ar
log "Processing domain 845/892: www.buscalibre.com.ar"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.buscalibre.com.ar"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.buscalibre.com.ar"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.buscalibre.com.ar"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.buscalibre.com.ar"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.buscalibre.com.ar"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.buscalibre.com.ar"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.buscalibre.com.ar"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.buscalibre.com.ar"
echo "---"

# Domain 846/892: bookdelivery.com
log "Processing domain 846/892: bookdelivery.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/bookdelivery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/bookdelivery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/bookdelivery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/bookdelivery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/bookdelivery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/bookdelivery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/bookdelivery.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: bookdelivery.com"
echo "---"

# Domain 847/892: www.bookdelivery.com
log "Processing domain 847/892: www.bookdelivery.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.bookdelivery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.bookdelivery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.bookdelivery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.bookdelivery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.bookdelivery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.bookdelivery.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.bookdelivery.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.bookdelivery.com"
echo "---"

# Domain 848/892: buscalibre.com.co
log "Processing domain 848/892: buscalibre.com.co"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/buscalibre.com.co"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/buscalibre.com.co"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/buscalibre.com.co"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/buscalibre.com.co"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/buscalibre.com.co"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/buscalibre.com.co"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/buscalibre.com.co"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: buscalibre.com.co"
echo "---"

# Domain 849/892: www.buscalibre.com.co
log "Processing domain 849/892: www.buscalibre.com.co"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.buscalibre.com.co"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.buscalibre.com.co"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.buscalibre.com.co"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.buscalibre.com.co"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.buscalibre.com.co"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.buscalibre.com.co"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.buscalibre.com.co"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.buscalibre.com.co"
echo "---"

# Domain 850/892: buscalibre.ec
log "Processing domain 850/892: buscalibre.ec"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/buscalibre.ec"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/buscalibre.ec"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/buscalibre.ec"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/buscalibre.ec"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/buscalibre.ec"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/buscalibre.ec"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/buscalibre.ec"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: buscalibre.ec"
echo "---"

# Domain 851/892: www.buscalibre.ec
log "Processing domain 851/892: www.buscalibre.ec"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.buscalibre.ec"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.buscalibre.ec"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.buscalibre.ec"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.buscalibre.ec"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.buscalibre.ec"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.buscalibre.ec"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.buscalibre.ec"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.buscalibre.ec"
echo "---"

# Domain 852/892: buscalibre.us
log "Processing domain 852/892: buscalibre.us"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/buscalibre.us"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/buscalibre.us"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/buscalibre.us"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/buscalibre.us"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/buscalibre.us"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/buscalibre.us"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/buscalibre.us"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: buscalibre.us"
echo "---"

# Domain 853/892: www.buscalibre.us
log "Processing domain 853/892: www.buscalibre.us"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.buscalibre.us"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.buscalibre.us"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.buscalibre.us"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.buscalibre.us"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.buscalibre.us"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.buscalibre.us"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.buscalibre.us"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.buscalibre.us"
echo "---"

# Domain 854/892: buscalibre.com.mx
log "Processing domain 854/892: buscalibre.com.mx"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/buscalibre.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/buscalibre.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/buscalibre.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/buscalibre.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/buscalibre.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/buscalibre.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/buscalibre.com.mx"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: buscalibre.com.mx"
echo "---"

# Domain 855/892: www.buscalibre.com.mx
log "Processing domain 855/892: www.buscalibre.com.mx"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.buscalibre.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.buscalibre.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.buscalibre.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.buscalibre.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.buscalibre.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.buscalibre.com.mx"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.buscalibre.com.mx"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.buscalibre.com.mx"
echo "---"

# Domain 856/892: buscalibre.pe
log "Processing domain 856/892: buscalibre.pe"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/buscalibre.pe"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/buscalibre.pe"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/buscalibre.pe"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/buscalibre.pe"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/buscalibre.pe"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/buscalibre.pe"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/buscalibre.pe"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: buscalibre.pe"
echo "---"

# Domain 857/892: www.buscalibre.pe
log "Processing domain 857/892: www.buscalibre.pe"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.buscalibre.pe"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.buscalibre.pe"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.buscalibre.pe"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.buscalibre.pe"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.buscalibre.pe"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.buscalibre.pe"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.buscalibre.pe"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.buscalibre.pe"
echo "---"

# Domain 858/892: buscalibre.com
log "Processing domain 858/892: buscalibre.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: buscalibre.com"
echo "---"

# Domain 859/892: www.buscalibre.com
log "Processing domain 859/892: www.buscalibre.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.buscalibre.com"
echo "---"

# Domain 860/892: buscalibre.uy
log "Processing domain 860/892: buscalibre.uy"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/buscalibre.uy"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/buscalibre.uy"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/buscalibre.uy"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/buscalibre.uy"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/buscalibre.uy"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/buscalibre.uy"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/buscalibre.uy"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: buscalibre.uy"
echo "---"

# Domain 861/892: www.buscalibre.uy
log "Processing domain 861/892: www.buscalibre.uy"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.buscalibre.uy"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.buscalibre.uy"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.buscalibre.uy"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.buscalibre.uy"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.buscalibre.uy"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.buscalibre.uy"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.buscalibre.uy"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.buscalibre.uy"
echo "---"

# Domain 862/892: buscalibre.es
log "Processing domain 862/892: buscalibre.es"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/buscalibre.es"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/buscalibre.es"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/buscalibre.es"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/buscalibre.es"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/buscalibre.es"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/buscalibre.es"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/buscalibre.es"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: buscalibre.es"
echo "---"

# Domain 863/892: www.buscalibre.es
log "Processing domain 863/892: www.buscalibre.es"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.buscalibre.es"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.buscalibre.es"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.buscalibre.es"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.buscalibre.es"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.buscalibre.es"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.buscalibre.es"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.buscalibre.es"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.buscalibre.es"
echo "---"

# Domain 864/892: buscalibre.co
log "Processing domain 864/892: buscalibre.co"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/buscalibre.co"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/buscalibre.co"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/buscalibre.co"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/buscalibre.co"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/buscalibre.co"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/buscalibre.co"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/buscalibre.co"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: buscalibre.co"
echo "---"

# Domain 865/892: www.buscalibre.co
log "Processing domain 865/892: www.buscalibre.co"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.buscalibre.co"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.buscalibre.co"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.buscalibre.co"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.buscalibre.co"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.buscalibre.co"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.buscalibre.co"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.buscalibre.co"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.buscalibre.co"
echo "---"

# Domain 866/892: r5rh2u0m2h.execute-api.us-east-1.amazonaws.com
log "Processing domain 866/892: r5rh2u0m2h.execute-api.us-east-1.amazonaws.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/r5rh2u0m2h.execute-api.us-east-1.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/r5rh2u0m2h.execute-api.us-east-1.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/r5rh2u0m2h.execute-api.us-east-1.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/r5rh2u0m2h.execute-api.us-east-1.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/r5rh2u0m2h.execute-api.us-east-1.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/r5rh2u0m2h.execute-api.us-east-1.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/r5rh2u0m2h.execute-api.us-east-1.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: r5rh2u0m2h.execute-api.us-east-1.amazonaws.com"
echo "---"

# Domain 867/892: statics.cdn0.buscalibre.com
log "Processing domain 867/892: statics.cdn0.buscalibre.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/statics.cdn0.buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/statics.cdn0.buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/statics.cdn0.buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/statics.cdn0.buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/statics.cdn0.buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/statics.cdn0.buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/statics.cdn0.buscalibre.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: statics.cdn0.buscalibre.com"
echo "---"

# Domain 868/892: awswaf.com
log "Processing domain 868/892: awswaf.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/awswaf.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/awswaf.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/awswaf.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/awswaf.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/awswaf.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/awswaf.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/awswaf.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: awswaf.com"
echo "---"

# Domain 869/892: 9589e48bd177.us-east-1.sdk.awswaf.com
log "Processing domain 869/892: 9589e48bd177.us-east-1.sdk.awswaf.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/9589e48bd177.us-east-1.sdk.awswaf.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/9589e48bd177.us-east-1.sdk.awswaf.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/9589e48bd177.us-east-1.sdk.awswaf.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/9589e48bd177.us-east-1.sdk.awswaf.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/9589e48bd177.us-east-1.sdk.awswaf.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/9589e48bd177.us-east-1.sdk.awswaf.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/9589e48bd177.us-east-1.sdk.awswaf.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: 9589e48bd177.us-east-1.sdk.awswaf.com"
echo "---"

# Domain 870/892: blogger.com
log "Processing domain 870/892: blogger.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/blogger.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/blogger.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/blogger.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/blogger.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/blogger.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/blogger.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/blogger.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: blogger.com"
echo "---"

# Domain 871/892: www.blogger.com
log "Processing domain 871/892: www.blogger.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.blogger.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.blogger.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.blogger.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.blogger.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.blogger.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.blogger.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.blogger.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.blogger.com"
echo "---"

# Domain 872/892: ctrlitcl.blogspot.cl
log "Processing domain 872/892: ctrlitcl.blogspot.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ctrlitcl.blogspot.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ctrlitcl.blogspot.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ctrlitcl.blogspot.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ctrlitcl.blogspot.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ctrlitcl.blogspot.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ctrlitcl.blogspot.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ctrlitcl.blogspot.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ctrlitcl.blogspot.cl"
echo "---"

# Domain 873/892: blogblog.com
log "Processing domain 873/892: blogblog.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/blogblog.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/blogblog.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/blogblog.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/blogblog.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/blogblog.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/blogblog.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/blogblog.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: blogblog.com"
echo "---"

# Domain 874/892: resources.blogblog.com
log "Processing domain 874/892: resources.blogblog.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/resources.blogblog.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/resources.blogblog.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/resources.blogblog.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/resources.blogblog.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/resources.blogblog.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/resources.blogblog.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/resources.blogblog.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: resources.blogblog.com"
echo "---"

# Domain 875/892: blogspot.com
log "Processing domain 875/892: blogspot.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/blogspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/blogspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/blogspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/blogspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/blogspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/blogspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/blogspot.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: blogspot.com"
echo "---"

# Domain 876/892: 1.bp.blogspot.com
log "Processing domain 876/892: 1.bp.blogspot.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/1.bp.blogspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/1.bp.blogspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/1.bp.blogspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/1.bp.blogspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/1.bp.blogspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/1.bp.blogspot.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/1.bp.blogspot.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: 1.bp.blogspot.com"
echo "---"

# Domain 877/892: www.meteochile.gob.cl
log "Processing domain 877/892: www.meteochile.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.meteochile.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.meteochile.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.meteochile.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.meteochile.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.meteochile.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.meteochile.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.meteochile.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.meteochile.gob.cl"
echo "---"

# Domain 878/892: dgac.gob.cl
log "Processing domain 878/892: dgac.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/dgac.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/dgac.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/dgac.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/dgac.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/dgac.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/dgac.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/dgac.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: dgac.gob.cl"
echo "---"

# Domain 879/892: www.dgac.gob.cl
log "Processing domain 879/892: www.dgac.gob.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.dgac.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.dgac.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.dgac.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.dgac.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.dgac.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.dgac.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.dgac.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.dgac.gob.cl"
echo "---"

# Domain 880/892: blogger.googleusercontent.com
log "Processing domain 880/892: blogger.googleusercontent.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/blogger.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/blogger.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/blogger.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/blogger.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/blogger.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/blogger.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/blogger.googleusercontent.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: blogger.googleusercontent.com"
echo "---"

# Domain 881/892: shareaholic.com
log "Processing domain 881/892: shareaholic.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/shareaholic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/shareaholic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/shareaholic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/shareaholic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/shareaholic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/shareaholic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/shareaholic.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: shareaholic.com"
echo "---"

# Domain 882/892: apps.shareaholic.com
log "Processing domain 882/892: apps.shareaholic.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/apps.shareaholic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/apps.shareaholic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/apps.shareaholic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/apps.shareaholic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/apps.shareaholic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/apps.shareaholic.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/apps.shareaholic.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: apps.shareaholic.com"
echo "---"

# Domain 883/892: zendesk.com
log "Processing domain 883/892: zendesk.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/zendesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/zendesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/zendesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/zendesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/zendesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/zendesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/zendesk.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: zendesk.com"
echo "---"

# Domain 884/892: ticketmaster-cl.zendesk.com
log "Processing domain 884/892: ticketmaster-cl.zendesk.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ticketmaster-cl.zendesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ticketmaster-cl.zendesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ticketmaster-cl.zendesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ticketmaster-cl.zendesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ticketmaster-cl.zendesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ticketmaster-cl.zendesk.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ticketmaster-cl.zendesk.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ticketmaster-cl.zendesk.com"
echo "---"

# Domain 885/892: postgradounab.cl
log "Processing domain 885/892: postgradounab.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/postgradounab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/postgradounab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/postgradounab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/postgradounab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/postgradounab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/postgradounab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/postgradounab.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: postgradounab.cl"
echo "---"

# Domain 886/892: www.postgradounab.cl
log "Processing domain 886/892: www.postgradounab.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.postgradounab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.postgradounab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.postgradounab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.postgradounab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/www.postgradounab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.postgradounab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.postgradounab.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.postgradounab.cl"
echo "---"

# Domain 887/892: unabwps3.s3.amazonaws.com
log "Processing domain 887/892: unabwps3.s3.amazonaws.com"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/unabwps3.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/unabwps3.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/unabwps3.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/unabwps3.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/unabwps3.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/unabwps3.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/unabwps3.s3.amazonaws.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: unabwps3.s3.amazonaws.com"
echo "---"

# Domain 888/892: campuscreativo.cl
log "Processing domain 888/892: campuscreativo.cl"
log "Estimated time: 54 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/campuscreativo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/campuscreativo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/campuscreativo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/campuscreativo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/campuscreativo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/campuscreativo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 7: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/campuscreativo.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: campuscreativo.cl"
echo "---"

# Domain 889/892: tempo.cl
log "Processing domain 889/892: tempo.cl"
log "Estimated time: 40 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/tempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/tempo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/tempo.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: tempo.cl"
echo "---"

# Domain 890/892: api.test.com
log "Processing domain 890/892: api.test.com"
log "Estimated time: 40 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/api.test.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/api.test.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/api.test.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: api.test.com"
echo "---"

# Domain 891/892: empty.example.com
log "Processing domain 891/892: empty.example.com"
log "Estimated time: 50 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/empty.example.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/empty.example.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/empty.example.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/empty.example.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/empty.example.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/empty.example.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: empty.example.com"
echo "---"

# Domain 892/892: example.com
log "Processing domain 892/892: example.com"
log "Estimated time: 50 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/example.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/example.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/example.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/example.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/example.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/example.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: example.com"
echo "---"

log "Completed CRITICAL priority domain completion"
