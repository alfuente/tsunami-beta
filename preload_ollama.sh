#!/bin/bash

# Script simple para precargar modelo en Ollama
# Uso: ./preload_ollama.sh [modelo] [url]

MODEL_NAME=${1:-"mistral:7b"}
OLLAMA_URL=${2:-"http://localhost:11434"}

echo "Precargando modelo: $MODEL_NAME"
echo "URL Ollama: $OLLAMA_URL"
echo ""

# Verificar conexión
if ! curl -s --connect-timeout 5 "$OLLAMA_URL/api/tags" >/dev/null; then
    echo "ERROR: No se puede conectar con Ollama"
    echo "Asegúrate de ejecutar: ollama serve"
    exit 1
fi

echo "Enviando solicitud de precarga..."

# Precargar modelo
curl -X POST \
    -H "Content-Type: application/json" \
    -d "{\"model\": \"$MODEL_NAME\", \"prompt\": \"\", \"keep_alive\": -1}" \
    "$OLLAMA_URL/api/generate" \
    --silent --show-error

if [ $? -eq 0 ]; then
    echo ""
    echo "¡Modelo precargado exitosamente!"
    echo "El modelo $MODEL_NAME permanecerá en memoria hasta que reinicies Ollama"
else
    echo ""
    echo "Error al precargar el modelo"
    echo "Verifica que el modelo esté instalado: ollama pull $MODEL_NAME"
fi
