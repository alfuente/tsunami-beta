#!/bin/bash

# Script para realizar todas las fases de análisis de un dominio usando el domain-backend
# Uso: ./complete_domain_phases.sh <domain>

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuración
DOMAIN_API_BASE="http://localhost:8001/api/v1"
MAX_WAIT_TIME=300  # 5 minutos máximo por tarea
POLL_INTERVAL=5    # Revisar cada 5 segundos

# Función para mostrar ayuda
show_help() {
    echo "Uso: $0 <domain> [options]"
    echo ""
    echo "Opciones:"
    echo "  -h, --help         Mostrar esta ayuda"
    echo "  -t, --timeout SEC  Timeout máximo por tarea (default: 300)"
    echo "  -i, --interval SEC Intervalo de polling (default: 5)"
    echo "  -v, --verbose      Mostrar output detallado"
    echo ""
    echo "Ejemplo:"
    echo "  $0 www.ejemplo.cl"
    echo "  $0 api.banco.cl --timeout 600 --verbose"
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

# Función para esperar que una tarea termine
wait_for_task() {
    local task_id=$1
    local phase_name=$2
    local elapsed=0
    
    log "Esperando completación de $phase_name (Task ID: $task_id)"
    
    while [ $elapsed -lt $MAX_WAIT_TIME ]; do
        local response=$(curl -s "$DOMAIN_API_BASE/tasks/$task_id" 2>/dev/null || echo '{"status":"error"}')
        local status=$(echo "$response" | jq -r '.status // "unknown"' 2>/dev/null || echo "error")
        
        case $status in
            "completed")
                log_success "$phase_name completada en ${elapsed}s"
                if [ "$VERBOSE" = true ]; then
                    echo "$response" | jq '.' 2>/dev/null || echo "$response"
                fi
                return 0
                ;;
            "failed"|"error")
                log_error "$phase_name falló después de ${elapsed}s"
                local error_msg=$(echo "$response" | jq -r '.error // "Error desconocido"' 2>/dev/null || echo "Error de parsing JSON")
                echo "Error: $error_msg"
                return 1
                ;;
            "running"|"pending")
                printf "\r${YELLOW}[$(date '+%H:%M:%S')] ⏳${NC} $phase_name ejecutándose... (${elapsed}s)"
                sleep $POLL_INTERVAL
                elapsed=$((elapsed + POLL_INTERVAL))
                ;;
            *)
                log_warning "Estado desconocido para $phase_name: $status"
                sleep $POLL_INTERVAL
                elapsed=$((elapsed + POLL_INTERVAL))
                ;;
        esac
    done
    
    echo ""
    log_error "$phase_name timeout después de ${MAX_WAIT_TIME}s"
    return 1
}

# Función para ejecutar una fase
execute_phase() {
    local endpoint=$1
    local phase_name=$2
    local domain=$3
    local extra_params=$4
    
    log "Iniciando $phase_name para $domain..."
    local start_time=$(date +%s)
    
    local url="$DOMAIN_API_BASE/$endpoint/$domain"
    if [ -n "$extra_params" ]; then
        url="$url?$extra_params"
    fi
    
    local response=$(curl -s -X POST "$url" 2>/dev/null)
    local curl_exit=$?
    
    if [ $curl_exit -ne 0 ]; then
        log_error "Error en curl para $phase_name (exit code: $curl_exit)"
        return 1
    fi
    
    if [ "$VERBOSE" = true ]; then
        log "Respuesta de $phase_name:"
        echo "$response" | jq '.' 2>/dev/null || echo "$response"
    fi
    
    local task_id=$(echo "$response" | jq -r '.task_id // empty' 2>/dev/null)
    
    if [ -z "$task_id" ]; then
        log_error "No se pudo obtener task_id para $phase_name"
        echo "Respuesta: $response"
        return 1
    fi
    
    # Esperar que la tarea complete
    if wait_for_task "$task_id" "$phase_name"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        PHASE_TIMES["$phase_name"]=$duration
        TOTAL_TIME=$((TOTAL_TIME + duration))
        return 0
    else
        return 1
    fi
}

# Parsear argumentos
DOMAIN=""
VERBOSE=false

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
        -i|--interval)
            POLL_INTERVAL="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -*)
            log_error "Opción desconocida: $1"
            show_help
            exit 1
            ;;
        *)
            if [ -z "$DOMAIN" ]; then
                DOMAIN="$1"
            else
                log_error "Solo se permite un dominio"
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

# Verificar dependencias
if ! command -v curl &> /dev/null; then
    log_error "curl no está instalado"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    log_error "jq no está instalado"
    exit 1
fi

# Variables para tracking de tiempo
declare -A PHASE_TIMES
TOTAL_TIME=0
SCRIPT_START_TIME=$(date +%s)

echo ""
echo "=========================================="
echo "🚀 ANÁLISIS COMPLETO DE DOMINIO"
echo "=========================================="
echo "Dominio: $DOMAIN"
echo "API Base: $DOMAIN_API_BASE"
echo "Timeout por fase: ${MAX_WAIT_TIME}s"
echo "Intervalo de polling: ${POLL_INTERVAL}s"
echo "=========================================="
echo ""

# Verificar que el API esté funcionando
log "Verificando conectividad con domain-backend..."
if ! curl -s "$DOMAIN_API_BASE/health" >/dev/null 2>&1; then
    log_error "No se puede conectar a $DOMAIN_API_BASE"
    log_error "Asegúrate de que domain-backend esté ejecutándose en puerto 8001"
    exit 1
fi
log_success "Conectividad confirmada"

# Definir las fases en orden
declare -a PHASES=(
    "discover/all-subdomains:Subdomain Discovery"
    "discover/amass:Advanced Subdomain Discovery"
    "discover/services:Service Detection"
    "discover/tech:Technology Detection"
    "discover/tls:TLS Analysis"
    "discover/dns:DNS Analysis"
    "discover/mx:MX Records Analysis"
    "calculate/risk:Risk Calculation"
)

# Ejecutar cada fase
FAILED_PHASES=()

for phase_def in "${PHASES[@]}"; do
    IFS=':' read -r endpoint phase_name <<< "$phase_def"
    
    echo ""
    log "═══════════════════════════════════════"
    log "🔄 Ejecutando: $phase_name"
    log "═══════════════════════════════════════"
    
    if execute_phase "$endpoint" "$phase_name" "$DOMAIN"; then
        log_success "$phase_name completada exitosamente"
    else
        log_error "$phase_name falló"
        FAILED_PHASES+=("$phase_name")
    fi
done

# Calcular tiempo total del script
SCRIPT_END_TIME=$(date +%s)
SCRIPT_TOTAL_TIME=$((SCRIPT_END_TIME - SCRIPT_START_TIME))

# Mostrar resumen final
echo ""
echo "=========================================="
echo "📊 RESUMEN DE EJECUCIÓN"
echo "=========================================="
echo "Dominio analizado: $DOMAIN"
echo "Tiempo total del script: ${SCRIPT_TOTAL_TIME}s ($(($SCRIPT_TOTAL_TIME / 60))m $(($SCRIPT_TOTAL_TIME % 60))s)"
echo "Tiempo total de fases: ${TOTAL_TIME}s"
echo "Overhead del script: $((SCRIPT_TOTAL_TIME - TOTAL_TIME))s"
echo ""

# Mostrar tiempos por fase
echo "⏱️  TIEMPOS POR FASE:"
echo "----------------------------------------"
for phase_name in "${!PHASE_TIMES[@]}"; do
    duration=${PHASE_TIMES[$phase_name]}
    printf "%-25s %3ds (%2dm %2ds)\n" "$phase_name:" "$duration" "$((duration / 60))" "$((duration % 60))"
done

echo ""

# Mostrar fases fallidas
if [ ${#FAILED_PHASES[@]} -gt 0 ]; then
    echo "❌ FASES FALLIDAS:"
    echo "----------------------------------------"
    for failed_phase in "${FAILED_PHASES[@]}"; do
        echo "  • $failed_phase"
    done
    echo ""
    log_error "El análisis completó con ${#FAILED_PHASES[@]} fase(s) fallida(s)"
    exit 1
else
    echo "✅ TODAS LAS FASES COMPLETADAS EXITOSAMENTE"
    echo ""
    log_success "Análisis completo de $DOMAIN finalizado exitosamente"
    exit 0
fi