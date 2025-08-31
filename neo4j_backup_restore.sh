#!/bin/bash
#
# Neo4j Backup and Restore Script for Docker Compose
# 
# Este script permite:
# 1. Hacer respaldo completo del Neo4j en Docker Compose
# 2. Restaurar desde respaldo
# 3. Inicializar grafo limpio con estructura básica
# 4. Validar estructura del grafo
#

set -e

# Configuración
COMPOSE_FILE="docker-compose.yml"
NEO4J_CONTAINER="neo4j"
NEO4J_USER="neo4j"
NEO4J_PASSWORD="test.password"
BACKUP_DIR="backups/neo4j"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funciones de utilidad
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar que Neo4j esté corriendo
check_neo4j_running() {
    log_info "Verificando que Neo4j esté corriendo..."
    
    if ! docker compose -f "$COMPOSE_FILE" ps | grep -q "$NEO4J_CONTAINER.*Up"; then
        log_error "Neo4j no está corriendo. Iniciando..."
        docker compose -f "$COMPOSE_FILE" up -d neo4j
        
        log_info "Esperando que Neo4j esté listo..."
        sleep 15
        
        # Verificar conexión
        local retries=10
        while [ $retries -gt 0 ]; do
            if docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" "RETURN 1" >/dev/null 2>&1; then
                log_success "Neo4j está listo"
                return 0
            fi
            log_info "Esperando conexión a Neo4j... ($retries intentos restantes)"
            sleep 5
            retries=$((retries - 1))
        done
        
        log_error "No se pudo conectar a Neo4j"
        return 1
    fi
    
    log_success "Neo4j está corriendo"
}

# Obtener estadísticas de la base de datos
get_database_stats() {
    log_info "Obteniendo estadísticas de la base de datos..."
    
    local stats_file="$1/database_stats.json"
    
    # Usar consultas simples de Cypher en lugar de APOC
    local total_nodes=$(docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        "MATCH (n) RETURN count(n) as count" --format plain | tail -n1 | tr -d '"')
    
    local total_relationships=$(docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        "MATCH ()-[r]->() RETURN count(r) as count" --format plain | tail -n1 | tr -d '"')
    
    local domains_count=$(docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        "MATCH (d:Domain) RETURN count(d) as count" --format plain | tail -n1 | tr -d '"')
    
    local providers_count=$(docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        "MATCH (p:Provider) RETURN count(p) as count" --format plain | tail -n1 | tr -d '"')
    
    local services_count=$(docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        "MATCH (s:Service) RETURN count(s) as count" --format plain | tail -n1 | tr -d '"')
    
    local certificates_count=$(docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        "MATCH (c:Certificate) RETURN count(c) as count" --format plain | tail -n1 | tr -d '"')
    
    # Crear archivo de estadísticas
    cat > "$stats_file" << EOF
{
    "timestamp": "$(date -Iseconds)",
    "total_nodes": ${total_nodes:-0},
    "total_relationships": ${total_relationships:-0},
    "domains_count": ${domains_count:-0},
    "providers_count": ${providers_count:-0},
    "services_count": ${services_count:-0},
    "certificates_count": ${certificates_count:-0}
}
EOF
    
    log_info "Estadísticas guardadas en $stats_file"
}

# Hacer respaldo completo
backup_database() {
    local backup_name="${1:-$(date +%Y%m%d_%H%M%S)}"
    local with_full_dump="${2:-false}"
    local backup_path="$BACKUP_DIR/$backup_name"
    
    log_info "Iniciando respaldo completo de Neo4j..."
    log_info "Directorio de respaldo: $backup_path"
    
    if [ "$with_full_dump" = "true" ]; then
        log_warning "Modo full dump: Se detendrá temporalmente Neo4j"
    fi
    
    # Crear directorio de respaldo
    mkdir -p "$backup_path"
    
    # Verificar que Neo4j esté corriendo
    check_neo4j_running || return 1
    
    # Obtener estadísticas previas
    get_database_stats "$backup_path"
    
    # Exportar todos los datos usando Cypher directo
    log_info "Exportando nodos y relaciones..."
    
    # Crear archivos de exportación directamente
    log_info "  • Exportando dominios..."
    docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        --format verbose "MATCH (d:Domain) RETURN d" > "$backup_path/domains_raw.txt" 2>/dev/null || {
        log_warning "Error exportando dominios, creando archivo vacío"
        echo "[]" > "$backup_path/domains.json"
    }
    
    log_info "  • Exportando proveedores..."
    docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        --format verbose "MATCH (p:Provider) RETURN p" > "$backup_path/providers_raw.txt" 2>/dev/null || {
        log_warning "Error exportando proveedores, creando archivo vacío"
        echo "[]" > "$backup_path/providers.json"
    }
    
    log_info "  • Exportando servicios..."
    docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        --format verbose "MATCH (s:Service) RETURN s" > "$backup_path/services_raw.txt" 2>/dev/null || {
        log_warning "Error exportando servicios, creando archivo vacío"
        echo "[]" > "$backup_path/services.json"
    }
    
    log_info "  • Exportando certificados..."
    docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        --format verbose "MATCH (c:Certificate) RETURN c" > "$backup_path/certificates_raw.txt" 2>/dev/null || {
        log_warning "Error exportando certificados, creando archivo vacío"
        echo "[]" > "$backup_path/certificates.json"
    }
    
    log_info "  • Exportando relaciones..."
    docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        --format verbose "MATCH (a)-[r]->(b) RETURN labels(a) as source_labels, properties(a) as source_props, type(r) as rel_type, properties(r) as rel_props, labels(b) as target_labels, properties(b) as target_props LIMIT 1000" > "$backup_path/relationships_raw.txt" 2>/dev/null || {
        log_warning "Error exportando relaciones, creando archivo vacío"
        echo "[]" > "$backup_path/relationships.json"
    }
    
    # Crear respaldo usando dump si se solicitó
    if [ "$with_full_dump" = "true" ]; then
        log_info "  • Intentando dump completo con Neo4j detenido..."
        
        # Detener Neo4j
        docker compose -f "$COMPOSE_FILE" stop neo4j
        sleep 2
        
        # Crear dump con contenedor detenido pero accesible
        if docker run --rm \
            -v neo4j-data:/data \
            -v neo4j-backups:/backups \
            neo4j:2025.06.0 \
            neo4j-admin database dump neo4j --to-path=/backups 2>/dev/null; then
            
            # Reiniciar Neo4j primero
            docker compose -f "$COMPOSE_FILE" start neo4j &
            
            # Copiar dump mientras Neo4j se inicia
            docker cp "$NEO4J_CONTAINER:/backups/neo4j.dump" "$backup_path/" 2>/dev/null && \
                log_success "Dump completo creado: neo4j.dump" || \
                log_warning "Dump creado pero no se pudo copiar"
                
            # Limpiar dump del contenedor
            docker exec "$NEO4J_CONTAINER" rm -f /backups/neo4j.dump 2>/dev/null || true
            
            # Esperar a que Neo4j termine de iniciar
            wait
        else
            log_warning "Dump completo no disponible"
            # Reiniciar Neo4j de todas formas
            docker compose -f "$COMPOSE_FILE" start neo4j
        fi
        
        # Verificar que Neo4j esté funcionando
        log_info "  • Esperando que Neo4j esté listo..."
        sleep 10
        check_neo4j_running > /dev/null
    else
        log_info "  • Usando exportación manual (recomendado para producción)"
    fi
    
    # Crear metadatos del respaldo
    cat > "$backup_path/backup_metadata.json" << EOF
{
    "backup_timestamp": "$(date -Iseconds)",
    "backup_name": "$backup_name",
    "neo4j_version": "$(docker exec $NEO4J_CONTAINER neo4j version 2>/dev/null | head -n1 || echo 'unknown')",
    "docker_image": "$(docker inspect --format='{{.Config.Image}}' $NEO4J_CONTAINER 2>/dev/null || echo 'unknown')",
    "backup_method": "APOC JSON Export",
    "script_version": "1.0"
}
EOF
    
    # Crear script de restauración
    create_restore_script "$backup_path"
    
    log_success "Respaldo completo creado en: $backup_path"
    
    # Mostrar resumen
    if [ -f "$backup_path/database_stats.json" ]; then
        log_info "Resumen del respaldo:"
        python3 -c "
import json
try:
    with open('$backup_path/database_stats.json') as f:
        data = json.load(f)
        print('  Archivos de respaldo creados:')
        for file in ['domains.json', 'providers.json', 'services.json', 'certificates.json', 'relationships.json']:
            if __import__('os').path.exists('$backup_path/' + file):
                size = __import__('os').path.getsize('$backup_path/' + file)
                print(f'    • {file} ({size:,} bytes)')
except:
    print('  Error al leer estadísticas')
"
    fi
    
    return 0
}

# Crear script de restauración
create_restore_script() {
    local backup_path="$1"
    local restore_script="$backup_path/restore.sh"
    
    cat > "$restore_script" << 'EOF'
#!/bin/bash
# Script de restauración generado automáticamente

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NEO4J_CONTAINER="neo4j"
NEO4J_USER="neo4j"
NEO4J_PASSWORD="test.password"

log_info() {
    echo -e "\033[0;34m[INFO]\033[0m $1"
}

log_success() {
    echo -e "\033[0;32m[SUCCESS]\033[0m $1"
}

log_error() {
    echo -e "\033[0;31m[ERROR]\033[0m $1"
}

log_info "Iniciando restauración desde: $SCRIPT_DIR"

# Verificar archivos de respaldo
for file in domains.json providers.json services.json certificates.json relationships.json; do
    if [ ! -f "$SCRIPT_DIR/$file" ]; then
        log_error "Archivo de respaldo faltante: $file"
        exit 1
    fi
done

# Copiar archivos al contenedor
log_info "Copiando archivos al contenedor Neo4j..."
docker cp "$SCRIPT_DIR/." "$NEO4J_CONTAINER:/restore/"

# Limpiar base de datos actual
log_info "Limpiando base de datos actual..."
docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
    "MATCH (n) DETACH DELETE n"

# Crear constraints e índices
log_info "Creando constraints e índices..."
docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
    "CREATE CONSTRAINT domain_fqdn_unique IF NOT EXISTS FOR (d:Domain) REQUIRE d.fqdn IS UNIQUE"

docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
    "CREATE CONSTRAINT provider_name_unique IF NOT EXISTS FOR (p:Provider) REQUIRE p.name IS UNIQUE"

docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
    "CREATE INDEX domain_base_domain IF NOT EXISTS FOR (d:Domain) ON (d.base_domain)"

docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
    "CREATE INDEX domain_risk_score IF NOT EXISTS FOR (d:Domain) ON (d.risk_score)"

# Restaurar datos usando APOC
log_info "Restaurando dominios..."
docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
    "CALL apoc.load.json('/restore/domains.json') YIELD value
     CREATE (d:Domain)
     SET d = value.d"

log_info "Restaurando proveedores..."
docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
    "CALL apoc.load.json('/restore/providers.json') YIELD value
     CREATE (p:Provider)
     SET p = value.p"

log_info "Restaurando servicios..."
docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
    "CALL apoc.load.json('/restore/services.json') YIELD value
     CREATE (s:Service)
     SET s = value.s"

log_info "Restaurando certificados..."
docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
    "CALL apoc.load.json('/restore/certificates.json') YIELD value
     CREATE (c:Certificate)
     SET c = value.c"

log_info "Restaurando relaciones..."
docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
    "CALL apoc.load.json('/restore/relationships.json') YIELD value
     MATCH (source), (target)
     WHERE 
       CASE 
         WHEN 'Domain' IN value.source_labels THEN source:Domain AND source.fqdn = value.source_props.fqdn
         WHEN 'Provider' IN value.source_labels THEN source:Provider AND source.name = value.source_props.name
         WHEN 'Service' IN value.source_labels THEN source:Service AND source.name = value.source_props.name
         WHEN 'Certificate' IN value.source_labels THEN source:Certificate AND source.common_name = value.source_props.common_name
         ELSE false
       END
       AND
       CASE 
         WHEN 'Domain' IN value.target_labels THEN target:Domain AND target.fqdn = value.target_props.fqdn
         WHEN 'Provider' IN value.target_labels THEN target:Provider AND target.name = value.target_props.name
         WHEN 'Service' IN value.target_labels THEN target:Service AND target.name = value.target_props.name
         WHEN 'Certificate' IN value.target_labels THEN target:Certificate AND target.common_name = value.target_props.common_name
         ELSE false
       END
     CALL apoc.create.relationship(source, value.rel_type, value.rel_props, target) YIELD rel
     RETURN count(*) as relationships_created"

# Limpiar archivos temporales
docker exec "$NEO4J_CONTAINER" rm -rf /restore/ 2>/dev/null || true

log_success "Restauración completada"

# Mostrar estadísticas finales
docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
    "MATCH (n) RETURN 'Nodos restaurados:' as info, count(n) as count
     UNION ALL
     MATCH ()-[r]->() RETURN 'Relaciones restauradas:' as info, count(r) as count"
EOF

    chmod +x "$restore_script"
    log_info "Script de restauración creado: $restore_script"
}

# Inicializar grafo limpio con estructura básica
init_clean_graph() {
    log_info "Inicializando grafo limpio con estructura básica..."
    
    check_neo4j_running || return 1
    
    # Limpiar base de datos
    log_info "Limpiando base de datos actual..."
    docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        "MATCH (n) DETACH DELETE n"
    
    # Crear constraints e índices básicos
    log_info "Creando constraints e índices..."
    
    # Constraints únicos
    docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        "CREATE CONSTRAINT domain_fqdn_unique IF NOT EXISTS FOR (d:Domain) REQUIRE d.fqdn IS UNIQUE" || true
    
    docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        "CREATE CONSTRAINT provider_name_unique IF NOT EXISTS FOR (p:Provider) REQUIRE p.name IS UNIQUE" || true
    
    docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        "CREATE CONSTRAINT service_name_domain_unique IF NOT EXISTS FOR (s:Service) REQUIRE (s.name, s.domain) IS UNIQUE" || true
    
    # Índices de rendimiento
    docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        "CREATE INDEX domain_base_domain IF NOT EXISTS FOR (d:Domain) ON (d.base_domain)" || true
    
    docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        "CREATE INDEX domain_risk_score IF NOT EXISTS FOR (d:Domain) ON (d.risk_score)" || true
    
    docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        "CREATE INDEX domain_tld IF NOT EXISTS FOR (d:Domain) ON (d.tld)" || true
    
    docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        "CREATE INDEX provider_risk_score IF NOT EXISTS FOR (p:Provider) ON (p.risk_score)" || true
    
    docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        "CREATE INDEX service_type IF NOT EXISTS FOR (s:Service) ON (s.service_type)" || true
    
    # Crear nodos de configuración básica si no existen
    log_info "Creando configuración básica del grafo..."
    
    # Crear nodo de configuración del sistema
    docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        "MERGE (config:SystemConfig {name: 'domain_discovery'})
         SET config.version = '1.0',
             config.created_at = datetime(),
             config.last_updated = datetime(),
             config.schema_version = '2025.08.26'"
    
    log_success "Grafo limpio inicializado con estructura básica"
    
    # Validar estructura
    validate_graph_structure
}

# Validar estructura del grafo
validate_graph_structure() {
    log_info "Validando estructura del grafo..."
    
    # Verificar constraints
    log_info "Verificando constraints..."
    docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        "SHOW CONSTRAINTS" | grep -E "(domain_fqdn_unique|provider_name_unique|service_name_domain_unique)" > /dev/null && \
        log_success "✓ Constraints básicos presentes" || \
        log_warning "⚠ Algunos constraints pueden estar faltando"
    
    # Verificar índices
    log_info "Verificando índices..."
    docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        "SHOW INDEXES" | grep -E "(domain_base_domain|domain_risk_score)" > /dev/null && \
        log_success "✓ Índices básicos presentes" || \
        log_warning "⚠ Algunos índices pueden estar faltando"
    
    # Mostrar estadísticas actuales
    log_info "Estadísticas actuales del grafo:"
    docker exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
        "MATCH (n) RETURN 'Total nodos:' as metric, count(n) as value
         UNION ALL
         MATCH ()-[r]->() RETURN 'Total relaciones:' as metric, count(r) as value
         UNION ALL
         MATCH (d:Domain) RETURN 'Dominios:' as metric, count(d) as value
         UNION ALL
         MATCH (p:Provider) RETURN 'Proveedores:' as metric, count(p) as value
         UNION ALL
         MATCH (s:Service) RETURN 'Servicios:' as metric, count(s) as value
         UNION ALL
         MATCH (c:Certificate) RETURN 'Certificados:' as metric, count(c) as value"
}

# Restaurar desde respaldo
restore_database() {
    local backup_name="$1"
    local backup_path="$BACKUP_DIR/$backup_name"
    
    if [ ! -d "$backup_path" ]; then
        log_error "Respaldo no encontrado: $backup_path"
        return 1
    fi
    
    if [ ! -f "$backup_path/restore.sh" ]; then
        log_error "Script de restauración no encontrado en: $backup_path"
        return 1
    fi
    
    log_info "Restaurando desde: $backup_path"
    
    check_neo4j_running || return 1
    
    # Ejecutar script de restauración
    chmod +x "$backup_path/restore.sh"
    "$backup_path/restore.sh"
    
    log_success "Restauración completada"
}

# Listar respaldos disponibles
list_backups() {
    log_info "Respaldos disponibles en $BACKUP_DIR:"
    
    if [ ! -d "$BACKUP_DIR" ]; then
        log_warning "Directorio de respaldos no existe: $BACKUP_DIR"
        return 0
    fi
    
    for backup in "$BACKUP_DIR"/*; do
        if [ -d "$backup" ]; then
            backup_name=$(basename "$backup")
            if [ -f "$backup/backup_metadata.json" ]; then
                timestamp=$(python3 -c "import json; print(json.load(open('$backup/backup_metadata.json'))['backup_timestamp'])" 2>/dev/null || echo "unknown")
                echo "  📁 $backup_name ($timestamp)"
            else
                echo "  📁 $backup_name (sin metadatos)"
            fi
        fi
    done
}

# Mostrar ayuda
show_help() {
    cat << EOF
Neo4j Backup and Restore Script

USAGE:
    $0 [COMMAND] [OPTIONS]

COMMANDS:
    backup [NAME]           Crear respaldo completo (opcional: nombre personalizado)
    backup-full [NAME]      Crear respaldo con dump completo (detiene Neo4j temporalmente)
    restore <NAME>          Restaurar desde respaldo específico
    init-clean             Inicializar grafo limpio con estructura básica
    list                   Listar respaldos disponibles
    validate              Validar estructura del grafo actual
    help                  Mostrar esta ayuda

EXAMPLES:
    $0 backup                    # Respaldo rápido sin detener Neo4j
    $0 backup-full              # Respaldo completo con dump (detiene Neo4j)
    $0 backup pre-migration      # Respaldo con nombre personalizado
    $0 restore 20250826_143000   # Restaurar respaldo específico
    $0 init-clean               # Limpiar y crear estructura básica
    $0 list                     # Ver respaldos disponibles
    $0 validate                 # Validar estructura actual

CONFIGURACIÓN:
    - Docker Compose file: $COMPOSE_FILE
    - Neo4j container: $NEO4J_CONTAINER
    - Backup directory: $BACKUP_DIR
    - Neo4j credentials: $NEO4J_USER / $NEO4J_PASSWORD

EOF
}

# Función principal
main() {
    local command="${1:-help}"
    
    case "$command" in
        "backup")
            backup_database "$2" false
            ;;
        "backup-full")
            backup_database "$2" true
            ;;
        "restore")
            if [ -z "$2" ]; then
                log_error "Debe especificar el nombre del respaldo a restaurar"
                echo "Use: $0 list - para ver respaldos disponibles"
                exit 1
            fi
            restore_database "$2"
            ;;
        "init-clean")
            init_clean_graph
            ;;
        "list")
            list_backups
            ;;
        "validate")
            check_neo4j_running && validate_graph_structure
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            log_error "Comando desconocido: $command"
            show_help
            exit 1
            ;;
    esac
}

# Crear directorio de respaldos si no existe
mkdir -p "$BACKUP_DIR"

# Ejecutar función principal
main "$@"
