#!/bin/bash

# Script inteligente para backup de Neo4j que detecta automáticamente las bases de datos

CONTAINER_NAME="neo4j"
NEO4J_USER="neo4j"
NEO4J_PASSWORD="test.password"
BACKUP_DIR="./backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "=== Neo4j Smart Backup Script ==="
echo "Timestamp: $(date)"

# Crear directorio de backup
mkdir -p "$BACKUP_DIR"

# Verificar que el contenedor esté ejecutándose
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    echo "Error: El contenedor $CONTAINER_NAME no está ejecutándose."
    exit 1
fi

echo "Detectando bases de datos disponibles..."

# Función para obtener bases de datos
get_databases() {
    # Intentar varios métodos para obtener las bases de datos
    
    # Método 1: SHOW DATABASES (Neo4j 4.0+)
    DATABASES=$(docker exec "$CONTAINER_NAME" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" "SHOW DATABASES YIELD name" --format plain 2>/dev/null | grep -v "^name$" | grep -v "^$")
    
    if [ -n "$DATABASES" ]; then
        echo "Bases de datos encontradas con SHOW DATABASES:"
        echo "$DATABASES"
        return 0
    fi
    
    # Método 2: Verificar archivos físicos
    echo "SHOW DATABASES no funcionó, verificando archivos físicos..."
    PHYSICAL_DBS=$(docker exec "$CONTAINER_NAME" ls /data/databases/ 2>/dev/null | grep -v "^$")
    
    if [ -n "$PHYSICAL_DBS" ]; then
        echo "Bases de datos encontradas físicamente:"
        echo "$PHYSICAL_DBS"
        DATABASES="$PHYSICAL_DBS"
        return 0
    fi
    
    # Método 3: Asumir base de datos por defecto
    echo "No se encontraron bases de datos específicas, usando 'neo4j' por defecto..."
    DATABASES="neo4j"
    return 0
}

# Obtener lista de bases de datos
get_databases

# Verificar si hay datos
echo "Verificando si hay datos..."
NODE_COUNT=$(docker exec "$CONTAINER_NAME" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" "MATCH (n) RETURN count(n) as count" --format plain 2>/dev/null | tail -1)
echo "Número de nodos encontrados: $NODE_COUNT"

if [ "$NODE_COUNT" = "0" ] || [ -z "$NODE_COUNT" ]; then
    echo "⚠ No se encontraron datos para respaldar."
    read -p "¿Continuar con el backup de todas formas? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Backup cancelado."
        exit 0
    fi
fi

# Función para hacer backup de una base de datos
backup_database() {
    local db_name="$1"
    local backup_file="neo4j_${db_name}_${TIMESTAMP}"
    
    echo "Haciendo backup de la base de datos: $db_name"
    
    # Detener el contenedor
    echo "Deteniendo contenedor Neo4j..."
    docker stop "$CONTAINER_NAME"
    
    # Intentar dump primero
    echo "Intentando crear dump de $db_name..."
    if docker run --rm \
        -v neo4j-data:/data \
        -v "$(pwd)/$BACKUP_DIR:/backup" \
        neo4j:2025.06.0 \
        neo4j-admin database dump "$db_name" --to-path=/backup 2>/dev/null; then
        
        echo "✓ Dump creado exitosamente para $db_name"
        
        # Renombrar archivo
        docker run --rm \
            -v "$(pwd)/$BACKUP_DIR:/backup" \
            alpine:latest \
            sh -c "if [ -f /backup/${db_name}.dump ]; then mv /backup/${db_name}.dump /backup/${backup_file}.dump; fi"
        
        echo "✓ Backup guardado como: $BACKUP_DIR/${backup_file}.dump"
        
    else
        echo "⚠ Dump falló para $db_name, intentando backup físico..."
        
        # Backup físico de los archivos de la base de datos
        docker run --rm \
            -v neo4j-data:/data \
            -v "$(pwd)/$BACKUP_DIR:/backup" \
            alpine:latest \
            sh -c "if [ -d /data/databases/$db_name ]; then tar -czf /backup/${backup_file}_physical.tar.gz -C /data/databases/$db_name .; else echo 'No se encontró directorio para $db_name'; fi"
        
        if [ $? -eq 0 ]; then
            echo "✓ Backup físico creado: $BACKUP_DIR/${backup_file}_physical.tar.gz"
        else
            echo "✗ Error al crear backup físico para $db_name"
        fi
    fi
}

# Hacer backup de todas las bases de datos encontradas
echo "Iniciando proceso de backup..."
while IFS= read -r db_name; do
    if [ -n "$db_name" ]; then
        backup_database "$db_name"
    fi
done <<< "$DATABASES"

# Si no funcionó nada, hacer backup completo de /data
if [ ! "$(ls -A $BACKUP_DIR 2>/dev/null)" ]; then
    echo "No se crearon backups específicos, creando backup completo de datos..."
    docker run --rm \
        -v neo4j-data:/data \
        -v "$(pwd)/$BACKUP_DIR:/backup" \
        alpine:latest \
        sh -c "tar -czf /backup/neo4j_complete_${TIMESTAMP}.tar.gz -C /data ."
    
    echo "✓ Backup completo creado: $BACKUP_DIR/neo4j_complete_${TIMESTAMP}.tar.gz"
fi

# Reiniciar el contenedor
echo "Reiniciando contenedor Neo4j..."
docker start "$CONTAINER_NAME"

# Esperar a que esté listo
echo "Esperando a que Neo4j esté listo..."
sleep 15

# Verificar que esté funcionando
for i in {1..10}; do
    if docker exec "$CONTAINER_NAME" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" "RETURN 1" >/dev/null 2>&1; then
        echo "✓ Neo4j está funcionando correctamente."
        break
    else
        echo "Intento $i/10 - Esperando a que Neo4j esté listo..."
        sleep 5
    fi
done

echo "=== Backup completado ==="
echo "Archivos creados:"
ls -la "$BACKUP_DIR"
