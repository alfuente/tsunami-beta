#!/bin/bash

# curl_examples.sh - Ejemplos de curl para todas las funcionalidades del Domain Backend
# Script con ejemplos prácticos para usar el Domain Backend API

# Configuración
API_BASE="http://localhost:8000"
DOMAIN="bice.cl"

echo "🌐 Domain Backend API - Ejemplos de curl"
echo "========================================"
echo "Base URL: $API_BASE"
echo "Domain de ejemplo: $DOMAIN"
echo ""

cat << 'EOF'
📋 ÍNDICE DE EJEMPLOS:
1. Health y Status
2. Descubrimiento Básico
3. Detección de Providers
4. Detección de Servicios
5. Análisis TLS
6. Análisis de Riesgo (Risk.md)
7. Análisis Completo
8. Jobs Asíncronos
9. Configuración
10. Documentación

EOF

echo "1️⃣ HEALTH Y STATUS"
echo "=================="
echo ""

echo "# Health check básico"
echo "curl $API_BASE/health"
echo ""

echo "# Status detallado del API"
echo "curl $API_BASE/api/v1/status"
echo ""

echo "2️⃣ DESCUBRIMIENTO BÁSICO"
echo "======================="
echo ""

echo "# Descubrimiento básico con timeout corto"
echo "curl \"$API_BASE/api/v1/discovery/$DOMAIN?amassTimeout=60&maxSubdomains=10\""
echo ""

echo "# Descubrimiento básico con más subdominios"
echo "curl \"$API_BASE/api/v1/discovery/$DOMAIN?amassTimeout=120&maxSubdomains=50&maxWorkers=5\""
echo ""

echo "# Descubrimiento sin guardar en Neo4j"
echo "curl \"$API_BASE/api/v1/discovery/$DOMAIN?amassTimeout=60&maxSubdomains=10&saveToNeo4j=false\""
echo ""

echo "3️⃣ DETECCIÓN DE PROVIDERS"
echo "========================"
echo ""

echo "# Descubrimiento con detección de providers"
echo "curl \"$API_BASE/api/v1/discoveryWithProviders/$DOMAIN?amassTimeout=120&maxSubdomains=20\""
echo ""

echo "# Análisis solo de providers (incluye MX records)"
echo "curl \"$API_BASE/api/v1/analysis/providers/$DOMAIN?includeMx=true&timeout=60\""
echo ""

echo "# Análisis solo de providers (sin MX records)"
echo "curl \"$API_BASE/api/v1/analysis/providers/$DOMAIN?includeMx=false&timeout=30\""
echo ""

echo "4️⃣ DETECCIÓN DE SERVICIOS"
echo "========================"
echo ""

echo "# Descubrimiento con detección de servicios"
echo "curl \"$API_BASE/api/v1/discoveryWithServices/$DOMAIN?amassTimeout=120&maxSubdomains=15\""
echo ""

echo "# Análisis solo de servicios (con port scan)"
echo "curl \"$API_BASE/api/v1/analysis/services/$DOMAIN?includePortScan=true&timeout=90\""
echo ""

echo "# Análisis solo de servicios (sin port scan)"
echo "curl \"$API_BASE/api/v1/analysis/services/$DOMAIN?includePortScan=false&timeout=30\""
echo ""

echo "# Descubrimiento con servicios Y providers"
echo "curl \"$API_BASE/api/v1/discoveryWithServicesAndProviders/$DOMAIN?amassTimeout=120&maxSubdomains=15\""
echo ""

echo "5️⃣ ANÁLISIS TLS"
echo "==============="
echo ""

echo "# Descubrimiento con análisis TLS"
echo "curl \"$API_BASE/api/v1/discoveryWithTLS/$DOMAIN?amassTimeout=120&maxSubdomains=10\""
echo ""

echo "# Análisis solo TLS"
echo "curl \"$API_BASE/api/v1/analysis/tls/$DOMAIN?timeout=60\""
echo ""

echo "6️⃣ ANÁLISIS DE RIESGO (Risk.md)"
echo "==============================="
echo ""

echo "# Análisis de riesgo puro (actualiza Neo4j)"
echo "curl \"$API_BASE/api/v1/analysis/risk/$DOMAIN?timeout=120&updateNeo4j=true\""
echo ""

echo "# Análisis de riesgo solo lectura (sin actualizar Neo4j)"
echo "curl \"$API_BASE/api/v1/analysis/risk/$DOMAIN?timeout=60&updateNeo4j=false\""
echo ""

echo "# Descubrimiento con análisis de riesgo"
echo "curl \"$API_BASE/api/v1/discoveryWithRisk/$DOMAIN?amassTimeout=120&maxSubdomains=10\""
echo ""

echo "7️⃣ ANÁLISIS COMPLETO"
echo "==================="
echo ""

echo "# Análisis completo con todas las funcionalidades"
echo "curl \"$API_BASE/api/v1/discoveryComplete/$DOMAIN?amassTimeout=180&maxSubdomains=20&maxWorkers=5\""
echo ""

echo "# Análisis completo rápido"
echo "curl \"$API_BASE/api/v1/discoveryComplete/$DOMAIN?amassTimeout=60&maxSubdomains=5&maxWorkers=3\""
echo ""

echo "8️⃣ JOBS ASÍNCRONOS"
echo "=================="
echo ""

echo "# Crear job asíncrono con providers y servicios"
echo "curl -X POST \"$API_BASE/api/v1/jobs/discovery/$DOMAIN?enableProviders=true&enableServices=true&amassTimeout=120&maxSubdomains=10\""
echo ""

echo "# Crear job asíncrono completo"
echo "curl -X POST \"$API_BASE/api/v1/jobs/discovery/$DOMAIN?enableProviders=true&enableServices=true&enableTls=true&enableRisk=true&enableMx=true&amassTimeout=180&maxSubdomains=15\""
echo ""

echo "# Listar todos los jobs"
echo "curl \"$API_BASE/api/v1/jobs?limit=20\""
echo ""

echo "# Verificar status de un job específico (reemplazar JOB_ID)"
echo "curl \"$API_BASE/api/v1/jobs/JOB_ID\""
echo ""

echo "# Eliminar un job completado (reemplazar JOB_ID)"
echo "curl -X DELETE \"$API_BASE/api/v1/jobs/JOB_ID\""
echo ""

echo "9️⃣ CONFIGURACIÓN"
echo "==============="
echo ""

echo "# Obtener configuración actual"
echo "curl \"$API_BASE/api/v1/config\""
echo ""

echo "# Actualizar configuración (ejemplo - cambiar timeouts)"
echo "curl -X POST \"$API_BASE/api/v1/config\" -H \"Content-Type: application/json\" -d '{\"default_amass_timeout\": 600, \"default_max_subdomains\": 2000}'"
echo ""

echo "🔟 DOCUMENTACIÓN"
echo "==============="
echo ""

echo "# Swagger UI (abrir en navegador)"
echo "curl \"$API_BASE/docs\""
echo "# O abrir en navegador: $API_BASE/docs"
echo ""

echo "# ReDoc UI (abrir en navegador)"
echo "curl \"$API_BASE/redoc\""
echo "# O abrir en navegador: $API_BASE/redoc"
echo ""

echo "# Schema OpenAPI"
echo "curl \"$API_BASE/openapi.json\" | jq ."
echo ""

echo ""
echo "💡 EJEMPLOS PRÁCTICOS DE USO"
echo "==========================="
echo ""

echo "# Ejemplo 1: Análisis rápido de providers (bueno para investigación inicial)"
echo "curl \"$API_BASE/api/v1/analysis/providers/$DOMAIN?includeMx=true&timeout=30\" | jq '.providers[].name'"
echo ""

echo "# Ejemplo 2: Score de riesgo rápido"
echo "curl \"$API_BASE/api/v1/analysis/risk/$DOMAIN?timeout=60&updateNeo4j=false\" | jq '{domain, final_score, tier}'"
echo ""

echo "# Ejemplo 3: Descubrimiento básico con formato de salida"
echo "curl \"$API_BASE/api/v1/discovery/$DOMAIN?amassTimeout=60&maxSubdomains=10\" | jq '{domain, subdomains: .subdomains | length, processing_time}'"
echo ""

echo "# Ejemplo 4: Job asíncrono y seguimiento"
echo "JOB_ID=\$(curl -s -X POST \"$API_BASE/api/v1/jobs/discovery/$DOMAIN?enableProviders=true&enableRisk=true\" | jq -r '.job_id')"
echo "echo \"Job ID: \$JOB_ID\""
echo "sleep 30"
echo "curl \"$API_BASE/api/v1/jobs/\$JOB_ID\" | jq '{status, progress, domain}'"
echo ""

echo "🔧 TESTING Y DEBUGGING"
echo "====================="
echo ""

echo "# Test de conectividad"
echo "curl -I $API_BASE/health"
echo ""

echo "# Test con dominio inválido (para probar manejo de errores)"
echo "curl \"$API_BASE/api/v1/discovery/invalid-domain-test.invalid?amassTimeout=30&maxSubdomains=1\""
echo ""

echo "# Test con timeout muy corto (para probar manejo de timeouts)"
echo "curl \"$API_BASE/api/v1/analysis/providers/$DOMAIN?timeout=5\""
echo ""

echo "# Verificar logs del servidor"
echo "tail -f discovery-api-dev.log"
echo ""

echo "⚙️ VARIABLES DE ENTORNO"
echo "======================"
echo ""

echo "# Configurar variables de entorno antes de iniciar el API"
echo "export NEO4J_URI=\"bolt://localhost:7687\""
echo "export NEO4J_USER=\"neo4j\""
echo "export NEO4J_PASS=\"test.password\""
echo "export IPINFO_TOKEN=\"your_ipinfo_token_here\""
echo ""

echo "🚀 COMANDOS DE GESTIÓN"
echo "====================="
echo ""

echo "# Iniciar el Domain Backend"
echo "./manage-services.sh start-discovery"
echo ""

echo "# Ver logs en tiempo real"
echo "./manage-services.sh logs discovery"
echo ""

echo "# Verificar status de todos los servicios"
echo "./manage-services.sh status"
echo ""

echo "# Parar el Domain Backend"
echo "./manage-services.sh stop-discovery"
echo ""

echo ""
echo "✅ TODAS LAS FUNCIONALIDADES INCLUIDAS:"
echo "======================================="
echo "• ✅ Descubrimiento básico de subdominios (Amass)"
echo "• ✅ Detección de providers (IP + MX records)"
echo "• ✅ Detección de servicios (pattern + port scan)"
echo "• ✅ Análisis TLS completo"
echo "• ✅ Cálculo de riesgo según Risk.md (4 componentes)"
echo "• ✅ Jobs asíncronos para procesos largos"
echo "• ✅ Configuración dinámica"
echo "• ✅ Documentación Swagger completa"
echo "• ✅ Integración con Neo4j"
echo "• ✅ Manejo de errores y timeouts"
echo ""
echo "🎯 COMPONENTES DE RIESGO (Risk.md):"
echo "===================================="
echo "• Base Tech Score (40%) - DNS, TLS, CVEs, Redundancia"
echo "• Third-Party Score (25%) - Dependencias con weights"
echo "• Incident Impact (30%) - Incidentes con decay temporal"
echo "• Context Boost (5%) - Certificaciones y controles"
echo ""

exit 0