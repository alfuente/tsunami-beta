#!/bin/bash
# Domain completion script - HIGH priority
# Generated: 2025-08-30T12:32:11.459515
# Total domains: 31
# Estimated time: 1375 minutes

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

log "Starting HIGH priority domain completion"
log "Processing 31 domains"

# Domain 1/31: www.santander.cl
log "Processing domain 1/31: www.santander.cl"
log "Estimated time: 50 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.santander.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.santander.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.santander.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.santander.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.santander.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.santander.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.santander.cl"
echo "---"

# Domain 2/31: www.registrocivil.cl
log "Processing domain 2/31: www.registrocivil.cl"
log "Estimated time: 50 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.registrocivil.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.registrocivil.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.registrocivil.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.registrocivil.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.registrocivil.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.registrocivil.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.registrocivil.cl"
echo "---"

# Domain 3/31: www.chileatiende.gob.cl
log "Processing domain 3/31: www.chileatiende.gob.cl"
log "Estimated time: 50 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.chileatiende.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.chileatiende.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.chileatiende.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.chileatiende.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.chileatiende.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.chileatiende.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.chileatiende.gob.cl"
echo "---"

# Domain 4/31: mercadoshops.cl
log "Processing domain 4/31: mercadoshops.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/mercadoshops.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/mercadoshops.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/mercadoshops.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/mercadoshops.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: mercadoshops.cl"
echo "---"

# Domain 5/31: dump.cl
log "Processing domain 5/31: dump.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/dump.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/dump.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/dump.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/dump.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: dump.cl"
echo "---"

# Domain 6/31: theclinic.cl
log "Processing domain 6/31: theclinic.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/theclinic.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/theclinic.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/theclinic.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/theclinic.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: theclinic.cl"
echo "---"

# Domain 7/31: scielo.cl
log "Processing domain 7/31: scielo.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/scielo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/scielo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/scielo.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/scielo.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: scielo.cl"
echo "---"

# Domain 8/31: decathlon.cl
log "Processing domain 8/31: decathlon.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/decathlon.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/decathlon.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/decathlon.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/decathlon.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: decathlon.cl"
echo "---"

# Domain 9/31: locanto.cl
log "Processing domain 9/31: locanto.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/locanto.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/locanto.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/locanto.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/locanto.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: locanto.cl"
echo "---"

# Domain 10/31: minsal.cl
log "Processing domain 10/31: minsal.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/minsal.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/minsal.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/minsal.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/minsal.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: minsal.cl"
echo "---"

# Domain 11/31: twinkl.cl
log "Processing domain 11/31: twinkl.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/twinkl.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/twinkl.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/twinkl.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/twinkl.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: twinkl.cl"
echo "---"

# Domain 12/31: escaladenotas.cl
log "Processing domain 12/31: escaladenotas.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/escaladenotas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/escaladenotas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/escaladenotas.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/escaladenotas.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: escaladenotas.cl"
echo "---"

# Domain 13/31: www.bcentral.cl
log "Processing domain 13/31: www.bcentral.cl"
log "Estimated time: 50 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.bcentral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.bcentral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.bcentral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.bcentral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.bcentral.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.bcentral.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.bcentral.cl"
echo "---"

# Domain 14/31: www.mutual.cl
log "Processing domain 14/31: www.mutual.cl"
log "Estimated time: 50 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.mutual.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.mutual.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.mutual.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.mutual.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.mutual.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.mutual.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.mutual.cl"
echo "---"

# Domain 15/31: www.dt.gob.cl
log "Processing domain 15/31: www.dt.gob.cl"
log "Estimated time: 50 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/www.dt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: dns analysis
retry_curl "http://localhost:8001/api/v1/discover/dns/www.dt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/www.dt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: tech analysis
retry_curl "http://localhost:8001/api/v1/discover/tech/www.dt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 5: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/www.dt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 6: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/www.dt.gob.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: www.dt.gob.cl"
echo "---"

# Domain 16/31: clarochile.cl
log "Processing domain 16/31: clarochile.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/clarochile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/clarochile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/clarochile.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/clarochile.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: clarochile.cl"
echo "---"

# Domain 17/31: pcfactory.cl
log "Processing domain 17/31: pcfactory.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/pcfactory.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/pcfactory.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/pcfactory.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/pcfactory.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: pcfactory.cl"
echo "---"

# Domain 18/31: tricot.cl
log "Processing domain 18/31: tricot.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/tricot.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/tricot.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/tricot.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/tricot.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: tricot.cl"
echo "---"

# Domain 19/31: antronio.cl
log "Processing domain 19/31: antronio.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/antronio.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/antronio.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/antronio.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/antronio.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: antronio.cl"
echo "---"

# Domain 20/31: tracktec.cl
log "Processing domain 20/31: tracktec.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/tracktec.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/tracktec.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/tracktec.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/tracktec.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: tracktec.cl"
echo "---"

# Domain 21/31: ninjahosting.cl
log "Processing domain 21/31: ninjahosting.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ninjahosting.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ninjahosting.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ninjahosting.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ninjahosting.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ninjahosting.cl"
echo "---"

# Domain 22/31: ilustrado.cl
log "Processing domain 22/31: ilustrado.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/ilustrado.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/ilustrado.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/ilustrado.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/ilustrado.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: ilustrado.cl"
echo "---"

# Domain 23/31: afphabitat.cl
log "Processing domain 23/31: afphabitat.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/afphabitat.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/afphabitat.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/afphabitat.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/afphabitat.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: afphabitat.cl"
echo "---"

# Domain 24/31: detacoop.cl
log "Processing domain 24/31: detacoop.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/detacoop.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/detacoop.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/detacoop.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/detacoop.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: detacoop.cl"
echo "---"

# Domain 25/31: registrodeempresasysociedades.cl
log "Processing domain 25/31: registrodeempresasysociedades.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/registrodeempresasysociedades.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/registrodeempresasysociedades.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/registrodeempresasysociedades.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/registrodeempresasysociedades.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: registrodeempresasysociedades.cl"
echo "---"

# Domain 26/31: eldesconcierto.cl
log "Processing domain 26/31: eldesconcierto.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/eldesconcierto.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/eldesconcierto.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/eldesconcierto.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/eldesconcierto.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: eldesconcierto.cl"
echo "---"

# Domain 27/31: empleospublicos.cl
log "Processing domain 27/31: empleospublicos.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/empleospublicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/empleospublicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/empleospublicos.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/empleospublicos.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: empleospublicos.cl"
echo "---"

# Domain 28/31: sismologia.cl
log "Processing domain 28/31: sismologia.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/sismologia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/sismologia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/sismologia.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/sismologia.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: sismologia.cl"
echo "---"

# Domain 29/31: sodimac.cl
log "Processing domain 29/31: sodimac.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/sodimac.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/sodimac.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/sodimac.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/sodimac.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: sodimac.cl"
echo "---"

# Domain 30/31: limonada.cl
log "Processing domain 30/31: limonada.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/limonada.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/limonada.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/limonada.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/limonada.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: limonada.cl"
echo "---"

# Domain 31/31: pinterest.cl
log "Processing domain 31/31: pinterest.cl"
log "Estimated time: 43 minutes"

# Step 1: amass analysis
retry_curl "http://localhost:8001/api/v1/discover/amass/pinterest.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 2: tls analysis
retry_curl "http://localhost:8001/api/v1/discover/tls/pinterest.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 3: web-scraping analysis
retry_curl "http://localhost:8001/api/v1/discover/web-scraping/pinterest.cl"
sleep $DELAY_BETWEEN_CALLS

# Step 4: risk analysis
retry_curl "http://localhost:8001/api/v1/calculate/risk/pinterest.cl"
sleep $DELAY_BETWEEN_CALLS

log "Completed domain: pinterest.cl"
echo "---"

log "Completed HIGH priority domain completion"
