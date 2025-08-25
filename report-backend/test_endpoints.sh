#!/bin/bash

BASE_URL="http://localhost:8082"

echo "🧪 Probando endpoints del Tsunami Report Backend..."
echo "Base URL: $BASE_URL"
echo ""

# Test 1: Health check del grafo
echo "1. 📊 Probando health check del grafo..."
curl -s -w "\nStatus: %{http_code}\n" \
     -H "Accept: application/json" \
     "$BASE_URL/api/v1/graph/health" | head -20
echo ""

# Test 2: OpenAPI specification
echo "2. 📖 Verificando especificación OpenAPI..."
curl -s -w "\nStatus: %{http_code}\n" \
     -H "Accept: application/json" \
     "$BASE_URL/openapi" | head -10
echo ""

# Test 3: Trigger análisis (POST)
echo "3. 🔄 Iniciando análisis del grafo..."
curl -s -X POST -w "\nStatus: %{http_code}\n" \
     -H "Accept: application/json" \
     -H "Content-Type: application/json" \
     "$BASE_URL/api/v1/graph/analyze"
echo ""

# Esperar un momento para que se genere el análisis
echo "⏳ Esperando análisis..."
sleep 5

# Test 4: Obtener análisis completo
echo "4. 📈 Obteniendo análisis del grafo..."
curl -s -w "\nStatus: %{http_code}\n" \
     -H "Accept: application/json" \
     "$BASE_URL/api/v1/graph/analysis" | head -30
echo ""

# Test 5: Obtener reporte en texto
echo "5. 📄 Obteniendo reporte de texto..."
curl -s -w "\nStatus: %{http_code}\n" \
     -H "Accept: text/plain" \
     "$BASE_URL/api/v1/graph/report" | head -20
echo ""

# Test 6: Análisis de dominio específico
echo "6. 🌐 Probando análisis de dominio específico..."
curl -s -w "\nStatus: %{http_code}\n" \
     -H "Accept: application/json" \
     "$BASE_URL/api/v1/reports/domain/bancochile.cl/analysis" | head -20
echo ""

echo "✅ Pruebas completadas!"
echo ""
echo "🌐 URLs importantes:"
echo "  • Swagger UI: $BASE_URL/swagger-ui"
echo "  • OpenAPI: $BASE_URL/openapi" 
echo "  • Graph Health: $BASE_URL/api/v1/graph/health"
echo "  • Graph Analysis: $BASE_URL/api/v1/graph/analysis"