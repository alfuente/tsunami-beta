#!/bin/bash
set -euo pipefail

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuración
BACKUP_DIR="./backups/$(date +%Y%m%d_%H%M%S)"
NEO4J_CONTAINER="neo4j"
MINIO_CONTAINER="minio"
ICEBERG_REST_CONTAINER="iceberg-rest"
SPARK_CONTAINER="spark"

# Función para logging
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Función para verificar si un container está corriendo
is_container_running() {
    docker ps --format "table {{.Names}}" | grep -q "^$1$"
}

# Función para hacer backup de Neo4j
backup_neo4j() {
    log_info "Starting Neo4j backup..."
    
    if is_container_running "$NEO4J_CONTAINER"; then
        log_info "Neo4j container is running, creating backup..."
        
        # Crear directorio de backup
        mkdir -p "$BACKUP_DIR/neo4j"
        
        # Backup usando neo4j-admin dump
        docker exec "$NEO4J_CONTAINER" neo4j-admin database dump neo4j --to-path=/backups/
        
        # Copiar el backup al host
        docker cp "$NEO4J_CONTAINER":/backups/neo4j.dump "$BACKUP_DIR/neo4j/"
        
        # También hacer backup de los datos completos por si acaso
        docker cp "$NEO4J_CONTAINER":/data "$BACKUP_DIR/neo4j/data_complete"
        
        log_info "Neo4j backup completed: $BACKUP_DIR/neo4j/"
    else
        log_warn "Neo4j container is not running, skipping backup"
    fi
}

# Función para hacer backup de Iceberg/MinIO
backup_iceberg() {
    log_info "Starting Iceberg/MinIO backup..."
    
    if is_container_running "$MINIO_CONTAINER"; then
        log_info "MinIO container is running, creating backup..."
        
        # Crear directorio de backup
        mkdir -p "$BACKUP_DIR/iceberg"
        
        # Backup de los datos de MinIO (donde está el warehouse de Iceberg)
        docker cp "$MINIO_CONTAINER":/data "$BACKUP_DIR/iceberg/minio_data"
        
        log_info "Iceberg/MinIO backup completed: $BACKUP_DIR/iceberg/"
    else
        log_warn "MinIO container is not running, skipping backup"
    fi
}

# Función para parar todos los servicios
stop_services() {
    log_info "Stopping all services..."
    docker compose down
    log_info "All services stopped"
}

# Función para limpiar datos
reset_data() {
    log_info "Cleaning up data volumes..."
    
    # Remover volumes de datos (esto borrará toda la información)
    docker volume rm tsunami-beta-v1_neo4j-data 2>/dev/null || log_warn "neo4j-data volume not found"
    docker volume rm tsunami-beta-v1_neo4j-plugins 2>/dev/null || log_warn "neo4j-plugins volume not found"
    docker volume rm tsunami-beta-v1_neo4j-import 2>/dev/null || log_warn "neo4j-import volume not found"
    docker volume rm tsunami-beta-v1_neo4j-backups 2>/dev/null || log_warn "neo4j-backups volume not found"
    docker volume rm tsunami-beta-v1_minio-data 2>/dev/null || log_warn "minio-data volume not found"
    
    log_info "Data volumes cleaned"
}

# Función para restaurar servicios
restart_services() {
    log_info "Starting services..."
    docker compose up -d
    
    # Esperar a que Neo4j esté listo
    log_info "Waiting for Neo4j to be ready..."
    timeout=60
    while [ $timeout -gt 0 ]; do
        if docker exec "$NEO4J_CONTAINER" cypher-shell -u neo4j -p test.password "RETURN 1" >/dev/null 2>&1; then
            log_info "Neo4j is ready!"
            break
        fi
        sleep 2
        timeout=$((timeout-2))
    done
    
    if [ $timeout -le 0 ]; then
        log_error "Neo4j failed to start within timeout"
        exit 1
    fi
    
    log_info "All services started successfully"
}

# Función para restaurar backup de Neo4j
restore_neo4j() {
    local backup_path="$1"
    
    if [ ! -f "$backup_path" ]; then
        log_error "Backup file not found: $backup_path"
        exit 1
    fi
    
    log_info "Restoring Neo4j from backup: $backup_path"
    
    # Parar Neo4j
    docker compose stop neo4j
    
    # Copiar backup al container
    docker cp "$backup_path" "$NEO4J_CONTAINER":/backups/restore.dump
    
    # Restaurar la base de datos
    docker exec "$NEO4J_CONTAINER" neo4j-admin database load neo4j --from-path=/backups/ --overwrite-destination=true
    
    # Reiniciar Neo4j
    docker compose start neo4j
    
    log_info "Neo4j restoration completed"
}

# Función principal
main() {
    case "${1:-}" in
        "backup")
            log_info "=== Starting Backup Process ==="
            backup_neo4j
            backup_iceberg
            log_info "=== Backup Process Completed ==="
            echo "Backup saved to: $BACKUP_DIR"
            ;;
        "reset")
            log_warn "=== Starting Reset Process ==="
            log_warn "This will DELETE ALL DATA. Are you sure? (type 'yes' to continue)"
            read -r confirmation
            if [ "$confirmation" = "yes" ]; then
                stop_services
                reset_data
                restart_services
                log_info "=== Reset Process Completed ==="
            else
                log_info "Reset cancelled"
            fi
            ;;
        "backup-and-reset")
            log_info "=== Starting Backup and Reset Process ==="
            backup_neo4j
            backup_iceberg
            log_warn "Backup completed. Proceeding with reset..."
            log_warn "This will DELETE ALL DATA. Are you sure? (type 'yes' to continue)"
            read -r confirmation
            if [ "$confirmation" = "yes" ]; then
                stop_services
                reset_data
                restart_services
                log_info "=== Backup and Reset Process Completed ==="
                echo "Backup saved to: $BACKUP_DIR"
            else
                log_info "Reset cancelled, but backup was completed"
                echo "Backup saved to: $BACKUP_DIR"
            fi
            ;;
        "restore")
            if [ -z "${2:-}" ]; then
                log_error "Usage: $0 restore <backup_dump_file>"
                exit 1
            fi
            restore_neo4j "$2"
            ;;
        *)
            echo "Usage: $0 {backup|reset|backup-and-reset|restore <backup_file>}"
            echo ""
            echo "Commands:"
            echo "  backup           - Create backup of Neo4j and Iceberg data"
            echo "  reset            - Stop services, delete all data, restart services"
            echo "  backup-and-reset - Create backup then reset (recommended)"
            echo "  restore <file>   - Restore Neo4j from backup dump file"
            echo ""
            echo "Examples:"
            echo "  $0 backup"
            echo "  $0 reset"
            echo "  $0 backup-and-reset"
            echo "  $0 restore ./backups/20250106_143022/neo4j/neo4j.dump"
            exit 1
            ;;
    esac
}

main "$@"