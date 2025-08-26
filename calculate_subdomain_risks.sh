#!/bin/bash

# Script para calcular riesgo en lote para subdominios existentes
# Uso: ./calculate_subdomain_risks.sh <domain> [options]

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuración
DOMAIN_API_BASE="http://localhost:8001"
MAX_WAIT_TIME=120
POLL_INTERVAL=5

# Función para mostrar ayuda
show_help() {
    echo "Uso: $0 <domain> [options]"
    echo ""
    echo "Calcula risk scores para todos los subdominios existentes en Neo4j"
    echo ""
    echo "Argumentos:"
    echo "  domain        Dominio base (ej: entel.cl)"
    echo ""
    echo "Opciones:"
    echo "  -h, --help         Mostrar esta ayuda"
    echo "  -t, --timeout SEC  Timeout máximo por cálculo (default: 120)"
    echo "  -v, --verbose      Mostrar output detallado"
    echo "  --max-subs NUM     Máximo número de subdominios (default: 500)"
    echo "  --parallel NUM     Número de cálculos en paralelo (default: 5)"
    echo ""
    echo "Ejemplos:"
    echo "  $0 entel.cl                    # Calcular riesgo para todos"
    echo "  $0 entel.cl --max-subs 50      # Primeros 50 subdominios"
    echo "  $0 entel.cl --parallel 10 -v   # 10 en paralelo, verbose"
}

# Función para logging
log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')] ✅${NC} $1"
}

log_error() {
    echo -e "${RED}[$(date '+%H:%M:%S')] ❌${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%H:%M:%S')] ⚠️${NC} $1"
}

# Función para calcular riesgo de un subdomain
calculate_risk_for_subdomain() {
    local subdomain=$1
    local base_domain=$2
    
    log "Calculando riesgo para $subdomain..."
    
    local response=$(curl -s -X POST "$DOMAIN_API_BASE/api/v1/calculate/risk/$base_domain?subdomain=$subdomain" 2>/dev/null)
    local task_id=$(echo "$response" | jq -r '.task_id // empty' 2>/dev/null)
    
    if [ -z "$task_id" ]; then
        log_error "No se pudo iniciar cálculo de riesgo para $subdomain"
        return 1
    fi
    
    if [ "$VERBOSE" = true ]; then
        log "Task ID para $subdomain: $task_id"
    fi
    
    # Esperar completación
    local elapsed=0
    while [ $elapsed -lt $MAX_WAIT_TIME ]; do
        local status_response=$(curl -s "$DOMAIN_API_BASE/api/v1/tasks/$task_id" 2>/dev/null)
        local status=$(echo "$status_response" | jq -r '.status // "unknown"' 2>/dev/null)
        
        case $status in
            "completed")
                log_success "Riesgo calculado para $subdomain"
                return 0
                ;;
            "failed"|"error")
                log_error "Cálculo de riesgo falló para $subdomain"
                return 1
                ;;
            *)
                if [ "$VERBOSE" = true ]; then
                    printf "\r${YELLOW}[$(date '+%H:%M:%S')] ⏳${NC} Calculando $subdomain... (${elapsed}s)"
                fi
                sleep $POLL_INTERVAL
                elapsed=$((elapsed + POLL_INTERVAL))
                ;;
        esac
    done
    
    echo ""
    log_error "Timeout para $subdomain después de ${MAX_WAIT_TIME}s"
    return 1
}

# Función para obtener subdominios sin risk score
get_subdomains_without_risk() {
    local domain=$1
    local max_subs=$2
    
    python3 -c "
from neo4j import GraphDatabase
try:
    driver = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', 'test.password'))
    with driver.session() as session:
        result = session.run('''
            MATCH (s:Subdomain)
            WHERE s.fqdn ENDS WITH '.$domain'
            AND s.risk_score IS NULL AND s.riskScore IS NULL
            RETURN s.fqdn as subdomain
            ORDER BY s.fqdn
            LIMIT \$max_subs
        ''', max_subs=$max_subs)
        
        subdomains = [record['subdomain'] for record in result if record['subdomain']]
        for subdomain in subdomains:
            print(subdomain)
        
    driver.close()
except Exception as e:
    import sys
    print(f'Error querying Neo4j: {e}', file=sys.stderr)
" 2>/dev/null
}

# Parsear argumentos
DOMAIN=""
VERBOSE=false
MAX_SUBDOMAINS=500
PARALLEL_JOBS=5

while [[ \$# -gt 0 ]]; do
    case \$1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -t|--timeout)
            MAX_WAIT_TIME="\$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --max-subs)
            MAX_SUBDOMAINS="\$2"
            shift 2
            ;;
        --parallel)
            PARALLEL_JOBS="\$2"
            shift 2
            ;;
        -*)
            log_error "Opción desconocida: \$1"
            show_help
            exit 1
            ;;
        *)
            if [ -z "\$DOMAIN" ]; then
                DOMAIN="\$1"
            else
                log_error "Argumentos extra: \$1"
                show_help
                exit 1
            fi
            shift
            ;;
    esac
done

# Validar argumentos
if [ -z "\$DOMAIN" ]; then
    log_error "Debe especificar un dominio"
    show_help
    exit 1
fi

echo ""
echo "=========================================="
echo "🎯 CÁLCULO DE RIESGO PARA SUBDOMINIOS"
echo "=========================================="
echo "Dominio base: \$DOMAIN"
echo "Máximo subdominios: \$MAX_SUBDOMAINS"
echo "Jobs paralelos: \$PARALLEL_JOBS"
echo "Timeout por cálculo: \${MAX_WAIT_TIME}s"
echo "=========================================="
echo ""

# Verificar conectividad
log "Verificando conectividad con domain-backend..."
if ! curl -s "\$DOMAIN_API_BASE/health" >/dev/null 2>&1; then
    log_error "No se puede conectar a \$DOMAIN_API_BASE"
    exit 1
fi
log_success "Conectividad confirmada"

# Obtener subdominios sin risk score
log "Consultando subdominios sin risk score..."
subdomain_list=\$(get_subdomains_without_risk "\$DOMAIN" "\$MAX_SUBDOMAINS")

if [ -z "\$subdomain_list" ]; then
    log_success "Todos los subdominios de \$DOMAIN ya tienen risk score calculado"
    exit 0
fi

# Convertir a array
readarray -t SUBDOMAIN_ARRAY <<< "\$(echo "\$subdomain_list" | grep -E "^[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}\$")"

# Contar subdominios válidos
valid_count=0
for sub in "\${SUBDOMAIN_ARRAY[@]}"; do
    if [[ "\$sub" =~ ^[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}\$ ]]; then
        valid_count=\$((valid_count + 1))
    fi
done

log "Encontrados \$valid_count subdominios sin risk score"

if [ \$valid_count -eq 0 ]; then
    log_success "No hay subdominios pendientes de cálculo de riesgo"
    exit 0
fi

echo ""
log "Subdominios a procesar:"
for subdomain in "\${SUBDOMAIN_ARRAY[@]}"; do
    if [[ "\$subdomain" =~ ^[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}\$ ]]; then
        echo "  • \$subdomain"
    fi
done
echo ""

# Calcular riesgo para cada subdomain (en paralelo usando xargs)
SUCCESSFUL_CALCULATIONS=0
FAILED_CALCULATIONS=0
START_TIME=\$(date +%s)

# Crear función exportable para usar con xargs
export -f calculate_risk_for_subdomain log log_success log_error log_warning
export DOMAIN_API_BASE MAX_WAIT_TIME POLL_INTERVAL VERBOSE BLUE GREEN RED YELLOW NC

# Procesar en lotes paralelos
echo "\${SUBDOMAIN_ARRAY[@]}" | tr ' ' '\\n' | grep -E "^[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}\$" | \
xargs -n 1 -P \$PARALLEL_JOBS -I {} bash -c "calculate_risk_for_subdomain {} \$DOMAIN"

# Verificar resultados finales
log "Verificando resultados..."
python3 -c "
from neo4j import GraphDatabase
try:
    driver = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', 'test.password'))
    with driver.session() as session:
        result = session.run('''
            MATCH (s:Subdomain)
            WHERE s.fqdn ENDS WITH '.\$DOMAIN'
            RETURN 
                count(s) as total,
                count(CASE WHEN s.risk_score IS NOT NULL OR s.riskScore IS NOT NULL THEN 1 END) as with_risk,
                count(CASE WHEN s.risk_score IS NULL AND s.riskScore IS NULL THEN 1 END) as without_risk
        ''')
        
        record = result.single()
        total = record['total']
        with_risk = record['with_risk']
        without_risk = record['without_risk']
        
        print(f'Resultados finales:')
        print(f'  Total subdominios: {total}')
        print(f'  Con risk score: {with_risk} ({with_risk/total*100:.1f}%)')
        print(f'  Sin risk score: {without_risk} ({without_risk/total*100:.1f}%)')
        
    driver.close()
except Exception as e:
    print(f'Error: {e}')
"

END_TIME=\$(date +%s)
TOTAL_TIME=\$((END_TIME - START_TIME))

echo ""
echo "=========================================="
echo "📊 RESUMEN FINAL"
echo "=========================================="
echo "Dominio: \$DOMAIN"
echo "Tiempo total: \${TOTAL_TIME}s (\$((\$TOTAL_TIME / 60))m \$((\$TOTAL_TIME % 60))s)"
echo "=========================================="

log_success "Cálculo de riesgo completado para \$DOMAIN"