#!/bin/bash

# Script para generar consultas Cypher usando Ollama
# Uso: ./generate_cypher_query.sh "pregunta sobre los datos" [modelo] [ejecutar]

# Configuración
SCHEMA_FILE="neo4j_schema.txt"
OLLAMA_MODEL=${2:-"llama3.2:1b"}
EXECUTE_QUERY=${3:-"false"}
OUTPUT_FILE="generated_query.cypher"

# Verificar argumentos
if [ $# -lt 1 ]; then
    echo "Uso: $0 \"pregunta sobre los datos\" [modelo_ollama] [ejecutar]"
    echo "Ejemplo: $0 \"¿Cuántos usuarios hay en la base de datos?\" llama3.1 true"
    exit 1
fi

USER_QUESTION="$1"

# Verificar si existe el archivo de esquema
if [ ! -f "$SCHEMA_FILE" ]; then
    echo "Error: No se encuentra el archivo de esquema '$SCHEMA_FILE'"
    echo "Ejecuta primero: ./extract_neo4j_schema.sh"
    exit 1
fi

# Verificar si Ollama está disponible
if ! command -v ollama &> /dev/null; then
    echo "Error: Ollama no está instalado o no está en el PATH"
    exit 1
fi

echo "Generando consulta Cypher para: \"$USER_QUESTION\""
echo "Usando modelo: $OLLAMA_MODEL"

# Leer el esquema de la base de datos
SCHEMA_CONTENT=$(cat "$SCHEMA_FILE")

# Crear el prompt para Ollama
PROMPT="Eres un experto en Neo4j y Cypher. Tu tarea es generar consultas Cypher precisas y eficientes basándote en el esquema de la base de datos proporcionado.

ESQUEMA DE LA BASE DE DATOS:
$SCHEMA_CONTENT

PREGUNTA DEL USUARIO: $USER_QUESTION

INSTRUCCIONES:
1. Analiza cuidadosamente el esquema proporcionado
2. Identifica las etiquetas de nodos, tipos de relaciones y propiedades relevantes
3. Genera una consulta Cypher que responda exactamente a la pregunta
4. La consulta debe ser eficiente y usar índices cuando sea posible
5. Incluye comentarios explicativos en la consulta
6. Si la pregunta es ambigua, proporciona la interpretación más lógica
7. Si necesitas hacer suposiciones, explícalas en comentarios

FORMATO DE RESPUESTA:
Proporciona SOLO la consulta Cypher, sin explicaciones adicionales fuera de los comentarios en la consulta.
La consulta debe estar lista para ejecutar directamente en Neo4j.

CONSULTA CYPHER:"

# Generar la consulta usando Ollama
echo "Consultando a Ollama..."
GENERATED_QUERY=$(echo "$PROMPT" | ollama run "$OLLAMA_MODEL" 2>/dev/null)

if [ $? -ne 0 ]; then
    echo "Error: No se pudo conectar con Ollama o el modelo '$OLLAMA_MODEL' no está disponible"
    echo "Modelos disponibles:"
    ollama list 2>/dev/null || echo "No se pudo listar los modelos"
    exit 1
fi

# Limpiar la respuesta (remover posibles prefijos/sufijos)
CLEANED_QUERY=$(echo "$GENERATED_QUERY" | sed -n '/MATCH\|WITH\|RETURN\|CREATE\|MERGE\|DELETE\|SET\|REMOVE\|CALL/,$p' | head -n -1)

# Si no encontró una consulta válida, usar toda la respuesta
if [ -z "$CLEANED_QUERY" ]; then
    CLEANED_QUERY="$GENERATED_QUERY"
fi

# Guardar la consulta generada
echo "$CLEANED_QUERY" > "$OUTPUT_FILE"

echo ""
echo "=== CONSULTA GENERADA ==="
echo "$CLEANED_QUERY"
echo ""
echo "Consulta guardada en: $OUTPUT_FILE"

# Opción de ejecutar la consulta
if [ "$EXECUTE_QUERY" = "true" ]; then
    echo ""
    read -p "¿Deseas ejecutar esta consulta? (y/N): " confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then
        echo ""
        echo "=== EJECUTANDO CONSULTA ==="
        
        # Solicitar credenciales si no están en variables de entorno
        NEO4J_HOST=${NEO4J_HOST:-"localhost"}
        NEO4J_PORT=${NEO4J_PORT:-"7687"}
        NEO4J_USER=${NEO4J_USER:-"neo4j"}
        NEO4J_DATABASE=${NEO4J_DATABASE:-"neo4j"}
        
        if [ -z "$NEO4J_PASSWORD" ]; then
            read -s -p "Contraseña de Neo4j: " NEO4J_PASSWORD
            echo ""
        fi
        
        # Ejecutar la consulta
        echo "$CLEANED_QUERY" | cypher-shell -a "bolt://$NEO4J_HOST:$NEO4J_PORT" \
            -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" -d "$NEO4J_DATABASE" \
            --format table
            
        if [ $? -eq 0 ]; then
            echo ""
            echo "Consulta ejecutada exitosamente"
        else
            echo ""
            echo "Error ejecutando la consulta. Verifica la sintaxis y los datos."
        fi
    fi
fi

echo ""
echo "=== COMANDOS ÚTILES ==="
echo "Para ejecutar manualmente:"
echo "cypher-shell -a bolt://localhost:7687 -u neo4j -p password -d neo4j < $OUTPUT_FILE"
echo ""
echo "Para mejorar la consulta:"
echo "$0 \"pregunta más específica\" $OLLAMA_MODEL"
