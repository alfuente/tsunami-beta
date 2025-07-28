#!/bin/bash

# Script para extraer el esquema completo de Neo4j
# Uso: ./extract_neo4j_schema.sh [host] [port] [username] [password] [database]

# Configuración por defecto
NEO4J_HOST=${1:-"localhost"}
NEO4J_PORT=${2:-"7687"}
NEO4J_USER=${3:-"neo4j"}
NEO4J_PASSWORD=${4:-"test.password"}
NEO4J_DATABASE=${5:-"neo4j"}

# Archivo de salida
OUTPUT_FILE="neo4j_schema.txt"

echo "=== EXTRAYENDO ESQUEMA DE NEO4J ===" > "$OUTPUT_FILE"
echo "Fecha: $(date)" >> "$OUTPUT_FILE"
echo "Host: $NEO4J_HOST:$NEO4J_PORT" >> "$OUTPUT_FILE"
echo "Base de datos: $NEO4J_DATABASE" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Función para ejecutar consultas Cypher
execute_cypher() {
    local query="$1"
    local description="$2"
    
    echo "=== $description ===" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    # Usar cypher-shell para ejecutar la consulta
    echo "$query" | cypher-shell -a "bolt://$NEO4J_HOST:$NEO4J_PORT" \
        -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" -d "$NEO4J_DATABASE" \
        --format plain 2>/dev/null >> "$OUTPUT_FILE"
    
    if [ $? -ne 0 ]; then
        echo "Error ejecutando consulta: $description" >> "$OUTPUT_FILE"
        echo "Consulta: $query" >> "$OUTPUT_FILE"
    fi
    
    echo "" >> "$OUTPUT_FILE"
    echo "----------------------------------------" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
}

# Verificar si cypher-shell está disponible
if ! command -v cypher-shell &> /dev/null; then
    echo "Error: cypher-shell no está instalado o no está en el PATH"
    exit 1
fi

echo "Extrayendo esquema de Neo4j..."

# 1. Obtener etiquetas de nodos
execute_cypher "CALL db.labels() YIELD label RETURN label ORDER BY label" "ETIQUETAS DE NODOS"

# 2. Obtener tipos de relaciones
execute_cypher "CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType ORDER BY relationshipType" "TIPOS DE RELACIONES"

# 3. Obtener propiedades de nodos
execute_cypher "CALL db.propertyKeys() YIELD propertyKey RETURN propertyKey ORDER BY propertyKey" "CLAVES DE PROPIEDADES"

# 4. Obtener esquema completo con conteos
execute_cypher "
CALL db.labels() YIELD label
CALL {
    WITH label
    MATCH (n) WHERE n:\`\${label}\`
    RETURN count(n) as count
}
RETURN label, count ORDER BY count DESC
" "CONTEO DE NODOS POR ETIQUETA"

# 5. Obtener conteo de relaciones
execute_cypher "
CALL db.relationshipTypes() YIELD relationshipType
CALL {
    WITH relationshipType
    MATCH ()-[r]-() WHERE type(r) = relationshipType
    RETURN count(r) as count
}
RETURN relationshipType, count ORDER BY count DESC
" "CONTEO DE RELACIONES POR TIPO"

# 6. Obtener sample de cada tipo de nodo con sus propiedades
execute_cypher "
CALL db.labels() YIELD label
CALL {
    WITH label
    MATCH (n) WHERE n:\`\${label}\`
    WITH n, keys(n) as props
    RETURN label, props, count(*) as nodes_with_these_props
    ORDER BY nodes_with_these_props DESC
    LIMIT 5
}
RETURN label, props, nodes_with_these_props
" "PROPIEDADES POR TIPO DE NODO"

# 7. Obtener patrones de conexión entre nodos
execute_cypher "
MATCH (a)-[r]->(b)
WITH labels(a)[0] as source_label, type(r) as rel_type, labels(b)[0] as target_label, count(*) as frequency
WHERE source_label IS NOT NULL AND target_label IS NOT NULL
RETURN source_label, rel_type, target_label, frequency
ORDER BY frequency DESC
LIMIT 50
" "PATRONES DE CONEXIÓN MÁS FRECUENTES"

# 8. Obtener índices
execute_cypher "CALL db.indexes() YIELD name, labelsOrTypes, properties, type, state RETURN name, labelsOrTypes, properties, type, state" "ÍNDICES DISPONIBLES"

# 9. Obtener restricciones
execute_cypher "CALL db.constraints() YIELD name, description RETURN name, description" "RESTRICCIONES"

# 10. Estadísticas generales
execute_cypher "
MATCH (n) 
OPTIONAL MATCH (n)-[r]-()
RETURN 
    count(DISTINCT n) as total_nodes,
    count(r) as total_relationships,
    count(DISTINCT labels(n)) as unique_label_combinations
" "ESTADÍSTICAS GENERALES"

# 11. Obtener ejemplos de nodos para cada etiqueta
echo "=== EJEMPLOS DE NODOS ===" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Obtener las etiquetas primero
labels=$(echo "CALL db.labels() YIELD label RETURN label ORDER BY label" | \
    cypher-shell -a "bolt://$NEO4J_HOST:$NEO4J_PORT" \
    -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" -d "$NEO4J_DATABASE" \
    --format plain 2>/dev/null | grep -v "^label$" | grep -v "^+")

# Para cada etiqueta, obtener ejemplos
while IFS= read -r label; do
    if [[ -n "$label" && "$label" != *"+"* ]]; then
        label=$(echo "$label" | xargs) # trim whitespace
        echo "Ejemplos para etiqueta: $label" >> "$OUTPUT_FILE"
        execute_cypher "MATCH (n:\`$label\`) RETURN n LIMIT 3" "MUESTRA DE NODOS $label"
    fi
done <<< "$labels"

echo "Esquema extraído exitosamente en: $OUTPUT_FILE"
echo ""
echo "Para usar este esquema con el generador de consultas, ejecuta:"
echo "./generate_cypher_query.sh \"tu pregunta sobre los datos\""
