#!/bin/bash

# Script de ejecución para el sistema mejorado de detección de proveedores
# Este script muestra cómo usar el risk_loader_two_phase.py mejorado

echo "🚀 Sistema Mejorado de Detección de Proveedores"
echo "================================================"
echo ""

# Configuración
NEO4J_URI="bolt://localhost:7687"
NEO4J_USER="neo4j"
NEO4J_PASSWORD="test.password"
DOMAINS_FILE="domains.txt"

# Verificar si el archivo de dominios existe
if [ ! -f "$DOMAINS_FILE" ]; then
    echo "📝 Creando archivo de dominios de prueba..."
    cat > "$DOMAINS_FILE" << EOF
google.com
amazon.com
microsoft.com
cloudflare.com
github.com
akamai.com
EOF
    echo "✅ Archivo $DOMAINS_FILE creado con dominios de prueba"
fi

echo ""
echo "🔧 Configuración:"
echo "   Neo4j URI: $NEO4J_URI"
echo "   Neo4j User: $NEO4J_USER"
echo "   Dominios: $DOMAINS_FILE"
echo ""

# Verificar token IPInfo
if [ -z "$IPINFO_TOKEN" ]; then
    echo "⚠️  WARNING: No se encontró token IPInfo en variable de entorno"
    echo "   Para mejores resultados, configure: export IPINFO_TOKEN='your_token_here'"
    echo ""
else
    echo "✅ Token IPInfo configurado"
    echo ""
fi

echo "🎯 Comandos disponibles:"
echo ""

echo "1. Ejecutar solo Phase 1 (Discovery):"
echo "   python3 risk_loader_two_phase.py --domains $DOMAINS_FILE --bolt $NEO4J_URI --user $NEO4J_USER --password $NEO4J_PASSWORD --phase1-only --mock-mode"
echo ""

echo "2. Ejecutar Phase 2 (Processing):"
echo "   python3 risk_loader_two_phase.py --domains $DOMAINS_FILE --bolt $NEO4J_URI --user $NEO4J_USER --password $NEO4J_PASSWORD --phase2-only"
echo ""

echo "3. Ejecutar proceso completo:"
echo "   python3 risk_loader_two_phase.py --domains $DOMAINS_FILE --bolt $NEO4J_URI --user $NEO4J_USER --password $NEO4J_PASSWORD --mock-mode"
echo ""

echo "4. Con token IPInfo:"
echo "   python3 risk_loader_two_phase.py --domains $DOMAINS_FILE --bolt $NEO4J_URI --user $NEO4J_USER --password $NEO4J_PASSWORD --ipinfo-token \$IPINFO_TOKEN"
echo ""

echo "📊 Mejoras implementadas:"
echo "   ✅ Warnings detallados para configuración faltante"
echo "   ✅ Logging comprehensivo en provider_detection.log"
echo "   ✅ Fallback robusto para proveedores desconocidos"
echo "   ✅ Creación de nodos Service mejorada"
echo "   ✅ Detección de proveedores mejorada (AWS, GCP, Cloudflare, Akamai, etc.)"
echo ""

echo "🧪 Para probar las mejoras sin Neo4j:"
echo "   python3 test_provider_detection_simple.py"
echo ""

echo "📝 Revisar logs detallados en:"
echo "   tail -f provider_detection.log"
echo ""

echo "🎉 Sistema listo para usar!"
