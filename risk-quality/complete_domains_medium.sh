#!/bin/bash
# Domain completion script - MEDIUM priority
# Generated: 2025-08-30T12:32:11.459903
# Total domains: 46
# Estimated time: 679 minutes

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

log "Starting MEDIUM priority domain completion"
log "Processing 46 domains"

# Domain 1/46: data.xepelin.com
log "Processing domain 1/46: data.xepelin.com"
log "Estimated time: 24 minutes"

# Step 1: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/data.xepelin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/data.xepelin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/data.xepelin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/data.xepelin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/data.xepelin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/data.xepelin.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: data.xepelin.com"
echo "---"

# Domain 2/46: cl.xepelin.com
log "Processing domain 2/46: cl.xepelin.com"
log "Estimated time: 24 minutes"

# Step 1: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/cl.xepelin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cl.xepelin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/cl.xepelin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/cl.xepelin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cl.xepelin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cl.xepelin.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cl.xepelin.com"
echo "---"

# Domain 3/46: debt.xepelin.com
log "Processing domain 3/46: debt.xepelin.com"
log "Estimated time: 24 minutes"

# Step 1: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/debt.xepelin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/debt.xepelin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/debt.xepelin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 4: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/debt.xepelin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 5: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/debt.xepelin.com"
sleep $DELAY_BETWEEN_CALLS

# Step 6: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/debt.xepelin.com"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: debt.xepelin.com"
echo "---"

# Domain 4/46: drsimi.cl
log "Processing domain 4/46: drsimi.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/drsimi.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/drsimi.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/drsimi.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: drsimi.cl"
echo "---"

# Domain 5/46: scotiabankchile.cl
log "Processing domain 5/46: scotiabankchile.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/scotiabankchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/scotiabankchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/scotiabankchile.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: scotiabankchile.cl"
echo "---"

# Domain 6/46: kameone.cl
log "Processing domain 6/46: kameone.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/kameone.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/kameone.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/kameone.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: kameone.cl"
echo "---"

# Domain 7/46: capual.cl
log "Processing domain 7/46: capual.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/capual.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/capual.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/capual.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: capual.cl"
echo "---"

# Domain 8/46: abif.cl
log "Processing domain 8/46: abif.cl"
log "Estimated time: 20 minutes"

# Step 1: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/abif.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/abif.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/abif.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/abif.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/abif.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: abif.cl"
echo "---"

# Domain 9/46: gob.cl
log "Processing domain 9/46: gob.cl"
log "Estimated time: 24 minutes"

# Step 1: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: gob.cl"
echo "---"

# Domain 10/46: ctrlit.cl
log "Processing domain 10/46: ctrlit.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ctrlit.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ctrlit.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ctrlit.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ctrlit.cl"
echo "---"

# Domain 11/46: virtualhosting.cl
log "Processing domain 11/46: virtualhosting.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/virtualhosting.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/virtualhosting.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/virtualhosting.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: virtualhosting.cl"
echo "---"

# Domain 12/46: meteochile.gob.cl
log "Processing domain 12/46: meteochile.gob.cl"
log "Estimated time: 24 minutes"

# Step 1: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/meteochile.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/meteochile.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/meteochile.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/meteochile.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/meteochile.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/meteochile.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: meteochile.gob.cl"
echo "---"

# Domain 13/46: extranjeria.gob.cl
log "Processing domain 13/46: extranjeria.gob.cl"
log "Estimated time: 24 minutes"

# Step 1: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/extranjeria.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/extranjeria.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/extranjeria.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/extranjeria.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/extranjeria.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/extranjeria.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: extranjeria.gob.cl"
echo "---"

# Domain 14/46: ibus.cl
log "Processing domain 14/46: ibus.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ibus.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ibus.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ibus.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ibus.cl"
echo "---"

# Domain 15/46: ssmaule.cl
log "Processing domain 15/46: ssmaule.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ssmaule.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ssmaule.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ssmaule.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ssmaule.cl"
echo "---"

# Domain 16/46: redip.cl
log "Processing domain 16/46: redip.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/redip.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/redip.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/redip.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: redip.cl"
echo "---"

# Domain 17/46: bancoedwards.cl
log "Processing domain 17/46: bancoedwards.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/bancoedwards.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/bancoedwards.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/bancoedwards.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: bancoedwards.cl"
echo "---"

# Domain 18/46: registrocivil.cl
log "Processing domain 18/46: registrocivil.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/registrocivil.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/registrocivil.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/registrocivil.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: registrocivil.cl"
echo "---"

# Domain 19/46: adnradio.cl
log "Processing domain 19/46: adnradio.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/adnradio.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/adnradio.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/adnradio.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: adnradio.cl"
echo "---"

# Domain 20/46: cge.cl
log "Processing domain 20/46: cge.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cge.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cge.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cge.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cge.cl"
echo "---"

# Domain 21/46: btgpactual.cl
log "Processing domain 21/46: btgpactual.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/btgpactual.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/btgpactual.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/btgpactual.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: btgpactual.cl"
echo "---"

# Domain 22/46: cmfchile.cl
log "Processing domain 22/46: cmfchile.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cmfchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cmfchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cmfchile.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cmfchile.cl"
echo "---"

# Domain 23/46: tie.cl
log "Processing domain 23/46: tie.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/tie.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/tie.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/tie.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: tie.cl"
echo "---"

# Domain 24/46: scotiabank.cl
log "Processing domain 24/46: scotiabank.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/scotiabank.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/scotiabank.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/scotiabank.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: scotiabank.cl"
echo "---"

# Domain 25/46: walmartdigital.cl
log "Processing domain 25/46: walmartdigital.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/walmartdigital.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/walmartdigital.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/walmartdigital.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: walmartdigital.cl"
echo "---"

# Domain 26/46: ecn.cl
log "Processing domain 26/46: ecn.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ecn.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ecn.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ecn.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ecn.cl"
echo "---"

# Domain 27/46: sfdc.cl
log "Processing domain 27/46: sfdc.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/sfdc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/sfdc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/sfdc.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: sfdc.cl"
echo "---"

# Domain 28/46: loteria.cl
log "Processing domain 28/46: loteria.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/loteria.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/loteria.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/loteria.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: loteria.cl"
echo "---"

# Domain 29/46: metlife.cl
log "Processing domain 29/46: metlife.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/metlife.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/metlife.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/metlife.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: metlife.cl"
echo "---"

# Domain 30/46: soychile.cl
log "Processing domain 30/46: soychile.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/soychile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/soychile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/soychile.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: soychile.cl"
echo "---"

# Domain 31/46: sii.cl
log "Processing domain 31/46: sii.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/sii.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/sii.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/sii.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: sii.cl"
echo "---"

# Domain 32/46: inc.cl
log "Processing domain 32/46: inc.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/inc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/inc.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/inc.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: inc.cl"
echo "---"

# Domain 33/46: dirtrab.cl
log "Processing domain 33/46: dirtrab.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/dirtrab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/dirtrab.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/dirtrab.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: dirtrab.cl"
echo "---"

# Domain 34/46: hostname.cl
log "Processing domain 34/46: hostname.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/hostname.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/hostname.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/hostname.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: hostname.cl"
echo "---"

# Domain 35/46: emol.cl
log "Processing domain 35/46: emol.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/emol.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/emol.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: emol.cl"
echo "---"

# Domain 36/46: ufro.cl
log "Processing domain 36/46: ufro.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ufro.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ufro.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ufro.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ufro.cl"
echo "---"

# Domain 37/46: bice.cl
log "Processing domain 37/46: bice.cl"
log "Estimated time: 10 minutes"

# Step 1: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/bice.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/bice.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: bice.cl"
echo "---"

# Domain 38/46: ministeriodesarrollosocial.gob.cl
log "Processing domain 38/46: ministeriodesarrollosocial.gob.cl"
log "Estimated time: 24 minutes"

# Step 1: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/ministeriodesarrollosocial.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ministeriodesarrollosocial.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/ministeriodesarrollosocial.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: services analysis
retry_curl "http://localhost:8001/api/v1/discover/services/ministeriodesarrollosocial.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ministeriodesarrollosocial.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ministeriodesarrollosocial.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ministeriodesarrollosocial.gob.cl"
echo "---"

# Domain 39/46: hostingplus.cl
log "Processing domain 39/46: hostingplus.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/hostingplus.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/hostingplus.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/hostingplus.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: hostingplus.cl"
echo "---"

# Domain 40/46: bancoestado.cl
log "Processing domain 40/46: bancoestado.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/bancoestado.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/bancoestado.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/bancoestado.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: bancoestado.cl"
echo "---"

# Domain 41/46: telmexchile.cl
log "Processing domain 41/46: telmexchile.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/telmexchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/telmexchile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/telmexchile.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: telmexchile.cl"
echo "---"

# Domain 42/46: cajalosandes.cl
log "Processing domain 42/46: cajalosandes.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/cajalosandes.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/cajalosandes.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/cajalosandes.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: cajalosandes.cl"
echo "---"

# Domain 43/46: bcentral.cl
log "Processing domain 43/46: bcentral.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/bcentral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/bcentral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/bcentral.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: bcentral.cl"
echo "---"

# Domain 44/46: webescuela.cl
log "Processing domain 44/46: webescuela.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/webescuela.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/webescuela.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/webescuela.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: webescuela.cl"
echo "---"

# Domain 45/46: netline.cl
log "Processing domain 45/46: netline.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/netline.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/netline.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/netline.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: netline.cl"
echo "---"

# Domain 46/46: santander.cl
log "Processing domain 46/46: santander.cl"
log "Estimated time: 13 minutes"

# Step 1: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/santander.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/santander.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/santander.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: santander.cl"
echo "---"

log "Completed MEDIUM priority domain completion"
