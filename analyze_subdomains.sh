#!/bin/bash

# Script para analizar subdominios específicos o todos los subdominios de un dominio
# Uso: ./analyze_subdomains.sh <domain> [subdomain1,subdomain2,...] [options]

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuración
DOMAIN_API_BASE="http://localhost:8001"
MAX_WAIT_TIME=600
POLL_INTERVAL=10

# Función para mostrar ayuda
show_help() {
    echo "Uso: $0 <domain> [subdomains] [options]"
    echo ""
    echo "Argumentos:"
    echo "  domain        Dominio base (ej: entel.cl)"
    echo "  subdomains    Lista de subdominios separados por coma (opcional)"
    echo "                Si no se especifica, analiza TODOS los subdominios en Neo4j"
    echo ""
    echo "Opciones:"
    echo "  -h, --help         Mostrar esta ayuda"
    echo "  -t, --timeout SEC  Timeout máximo por tarea (default: 600)"
    echo "  -v, --verbose      Mostrar output detallado"
    echo "  --services-only    Solo análisis de servicios"
    echo "  --tech-only        Solo análisis de tecnologías"
    echo "  --max-subs NUM     Máximo número de subdominios a analizar (default: 500)"
    echo ""
    echo "Ejemplos:"
    echo "  $0 entel.cl                                    # Analizar todos los subdominios"
    echo "  $0 entel.cl www.entel.cl,api.entel.cl         # Analizar subdominios específicos"
    echo "  $0 entel.cl --tech-only --max-subs 100        # Solo tecnologías, máximo 100"
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

# Función para obtener subdominios de Neo4j
get_subdomains_from_neo4j() {
    local domain=$1
    local max_subs=$2
    
    log "Consultando subdominios de $domain en Neo4j..."
    
    # Usar python3 para consultar Neo4j directamente
    python3 -c "
import sys
from neo4j import GraphDatabase
try:
    driver = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', 'test.password'))
    with driver.session() as session:
        result = session.run('''
            MATCH (d:Domain {fqdn: \$domain})-[:HAS_SUBDOMAIN]->(s:Subdomain)
            RETURN s.fqdn as subdomain
            ORDER BY s.fqdn
            LIMIT \$max_subs
        ''', domain='$domain', max_subs=$max_subs)
        
        subdomains = [record['subdomain'] for record in result if record['subdomain']]
        for subdomain in subdomains:
            print(subdomain)
        
    driver.close()
except Exception as e:
    print(f'Error querying Neo4j: {e}', file=sys.stderr)
" 2>/dev/null
}

# Función para analizar un subdomain individual
analyze_subdomain() {
    local subdomain=$1
    local include_services=$2
    local include_tech=$3
    
    log "Analizando subdomain: $subdomain"
    
    # Paso 1: Análisis combinado
    local base_domain=$(echo $subdomain | cut -d. -f2-)
    local url="$DOMAIN_API_BASE/api/v1/discover/combined/$base_domain"
    url="$url?subdomain=$subdomain&include_services=$include_services&include_tech=$include_tech&include_dns=true&include_tls=true&include_mx=false"
    
    local response=$(curl -s -X POST "$url" 2>/dev/null)
    local task_id=$(echo "$response" | jq -r '.task_id // empty' 2>/dev/null)
    
    if [ -z "$task_id" ]; then
        log_error "No se pudo iniciar análisis para $subdomain"
        return 1
    fi
    
    log "Task ID para análisis de $subdomain: $task_id"
    
    # Esperar completación del análisis
    local elapsed=0
    while [ $elapsed -lt $MAX_WAIT_TIME ]; do
        local status_response=$(curl -s "$DOMAIN_API_BASE/api/v1/tasks/$task_id" 2>/dev/null)
        local status=$(echo "$status_response" | jq -r '.status // "unknown"' 2>/dev/null)
        
        case $status in
            "completed")
                log_success "Análisis de $subdomain completado"
                break
                ;;
            "failed"|"error")
                log_error "Análisis de $subdomain falló"
                return 1
                ;;
            *)
                printf "\r${YELLOW}[$(date '+%H:%M:%S')] ⏳${NC} Analizando $subdomain... (${elapsed}s)"
                sleep $POLL_INTERVAL
                elapsed=$((elapsed + POLL_INTERVAL))
                ;;
        esac
    done
    
    if [ $elapsed -ge $MAX_WAIT_TIME ]; then
        echo ""
        log_error "Timeout para análisis de $subdomain después de ${MAX_WAIT_TIME}s"
        return 1
    fi
    
    # Paso 2: Cálculo de riesgo para el subdomain
    echo ""
    log "Calculando riesgo para $subdomain..."
    local risk_response=$(curl -s -X POST "$DOMAIN_API_BASE/api/v1/calculate/risk/$base_domain?subdomain=$subdomain" 2>/dev/null)
    local risk_task_id=$(echo "$risk_response" | jq -r '.task_id // empty' 2>/dev/null)
    
    if [ -n "$risk_task_id" ]; then
        log "Risk calculation task ID: $risk_task_id"
        # Esperar completación del cálculo de riesgo (timeout más corto)
        local risk_elapsed=0
        local risk_timeout=120  # 2 minutos para cálculo de riesgo
        
        while [ $risk_elapsed -lt $risk_timeout ]; do
            local risk_status_response=$(curl -s "$DOMAIN_API_BASE/api/v1/tasks/$risk_task_id" 2>/dev/null)
            local risk_status=$(echo "$risk_status_response" | jq -r '.status // "unknown"' 2>/dev/null)
            
            case $risk_status in
                "completed")
                    log_success "Cálculo de riesgo completado para $subdomain"
                    return 0
                    ;;
                "failed"|"error")
                    log_error "Cálculo de riesgo falló para $subdomain"
                    return 0  # Still count as success since main analysis worked
                    ;;
                *)
                    printf "\r${YELLOW}[$(date '+%H:%M:%S')] 🎯${NC} Calculando riesgo para $subdomain... (${risk_elapsed}s)"
                    sleep 5
                    risk_elapsed=$((risk_elapsed + 5))
                    ;;
            esac
        done
        
        echo ""
        log_warning "Timeout en cálculo de riesgo para $subdomain, pero análisis principal completado"
    else
        log_warning "No se pudo iniciar cálculo de riesgo para $subdomain"
    fi
    
    return 0
}

# Parsear argumentos
DOMAIN=""
SUBDOMAINS=""
VERBOSE=false
SERVICES_ONLY=false
TECH_ONLY=false
MAX_SUBDOMAINS=500

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -t|--timeout)
            MAX_WAIT_TIME="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --services-only)
            SERVICES_ONLY=true
            TECH_ONLY=false
            shift
            ;;
        --tech-only)
            TECH_ONLY=true
            SERVICES_ONLY=false
            shift
            ;;
        --max-subs)
            MAX_SUBDOMAINS="$2"
            shift 2
            ;;
        -*)
            log_error "Opción desconocida: $1"
            show_help
            exit 1
            ;;
        *)
            if [ -z "$DOMAIN" ]; then
                DOMAIN="$1"
            elif [ -z "$SUBDOMAINS" ]; then
                SUBDOMAINS="$1"
            else
                log_error "Argumentos extra: $1"
                show_help
                exit 1
            fi
            shift
            ;;
    esac
done

# Validar argumentos
if [ -z "$DOMAIN" ]; then
    log_error "Debe especificar un dominio"
    show_help
    exit 1
fi

# Determinar qué analizar
include_services="true"
include_tech="true"

if [ "$SERVICES_ONLY" = true ]; then
    include_tech="false"
elif [ "$TECH_ONLY" = true ]; then
    include_services="false"
fi

echo ""
echo "=========================================="
echo "🔍 ANÁLISIS DE SUBDOMINIOS"
echo "=========================================="
echo "Dominio base: $DOMAIN"
echo "Incluir servicios: $include_services"
echo "Incluir tecnologías: $include_tech"
echo "Timeout por subdomain: ${MAX_WAIT_TIME}s"
echo "=========================================="
echo ""

# Verificar conectividad
log "Verificando conectividad con domain-backend..."
if ! curl -s "$DOMAIN_API_BASE/health" >/dev/null 2>&1; then
    log_error "No se puede conectar a $DOMAIN_API_BASE"
    exit 1
fi
log_success "Conectividad confirmada"

# Obtener lista de subdominios
if [ -n "$SUBDOMAINS" ]; then
    # Subdominios específicos proporcionados
    IFS=',' read -ra SUBDOMAIN_ARRAY <<< "$SUBDOMAINS"
    log "Analizando subdominios específicos: ${#SUBDOMAIN_ARRAY[@]} subdominios"
else
    # Obtener todos los subdominios de Neo4j
    subdomain_list=$(get_subdomains_from_neo4j "$DOMAIN" "$MAX_SUBDOMAINS")
    if [ -z "$subdomain_list" ]; then
        log_error "No se encontraron subdominios para $DOMAIN en Neo4j"
        log "Sugerencia: Ejecutar primero 'bash complete_domain_phases.sh $DOMAIN' para descubrir subdominios"
        exit 1
    fi
    
    # Convertir a array, filtrando líneas vacías y mensajes de log
    readarray -t SUBDOMAIN_ARRAY <<< "$(echo "$subdomain_list" | grep -E "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")"
    # Contar solo subdominios válidos
    valid_count=0
    for sub in "${SUBDOMAIN_ARRAY[@]}"; do
        if [[ "$sub" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            valid_count=$((valid_count + 1))
        fi
    done
    log "Encontrados $valid_count subdominios válidos en Neo4j"
fi

# Mostrar lista de subdominios a analizar
echo ""
log "Subdominios a analizar:"
for subdomain in "${SUBDOMAIN_ARRAY[@]}"; do
    if [[ "$subdomain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo "  • $subdomain"
    fi
done
echo ""

# Analizar cada subdomain
SUCCESSFUL_ANALYSES=0
FAILED_ANALYSES=0
START_TIME=$(date +%s)

for subdomain in "${SUBDOMAIN_ARRAY[@]}"; do
    # Validar que sea un subdomain real
    if [[ ! "$subdomain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        continue
    fi
    
    echo ""
    log "═══════════════════════════════════════"
    log "🔄 Analizando: $subdomain"
    log "═══════════════════════════════════════"
    
    if analyze_subdomain "$subdomain" "$include_services" "$include_tech"; then
        SUCCESSFUL_ANALYSES=$((SUCCESSFUL_ANALYSES + 1))
    else
        FAILED_ANALYSES=$((FAILED_ANALYSES + 1))
    fi
done

# Mostrar resumen final
END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))

echo ""
echo "=========================================="
echo "📊 RESUMEN FINAL"
echo "=========================================="
echo "Dominio base: $DOMAIN"
echo "Total subdominios procesados: $((SUCCESSFUL_ANALYSES + FAILED_ANALYSES))"
echo "Análisis exitosos: $SUCCESSFUL_ANALYSES"
echo "Análisis fallidos: $FAILED_ANALYSES"
echo "Tiempo total: ${TOTAL_TIME}s ($(($TOTAL_TIME / 60))m $(($TOTAL_TIME % 60))s)"
echo "=========================================="

if [ $FAILED_ANALYSES -eq 0 ]; then
    log_success "Todos los subdominios analizados exitosamente"
    exit 0
else
    log_error "$FAILED_ANALYSES subdominios fallaron"
    exit 1
fi