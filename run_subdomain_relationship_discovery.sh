#!/bin/bash

# Script de ejecución para subdomain relationship discovery mejorado
# Este script muestra cómo usar el subdomain_relationship_discovery.py mejorado

echo "🚀 Sistema Mejorado de Descubrimiento de Relaciones de Subdominios"
echo "=================================================================="
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
netflix.com
spotify.com
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

echo "1. Usar como módulo de Python:"
echo "   python3 -c \"from subdomain_relationship_discovery import EnhancedSubdomainGraphIngester; print('Módulo importado correctamente')\""
echo ""

echo "2. Ejecutar el script principal (si tiene función main):"
echo "   python3 subdomain_relationship_discovery.py --domains $DOMAINS_FILE --bolt $NEO4J_URI --user $NEO4J_USER --password $NEO4J_PASSWORD"
echo ""

echo "3. Con token IPInfo:"
echo "   python3 subdomain_relationship_discovery.py --domains $DOMAINS_FILE --bolt $NEO4J_URI --user $NEO4J_USER --password $NEO4J_PASSWORD --ipinfo-token \$IPINFO_TOKEN"
echo ""

echo "4. Usar desde otro script:"
echo "   # Ejemplo de uso:"
echo "   from subdomain_relationship_discovery import EnhancedSubdomainGraphIngester"
echo "   ingester = EnhancedSubdomainGraphIngester('$NEO4J_URI', '$NEO4J_USER', '$NEO4J_PASSWORD')"
echo "   ingester.set_input_domains(['google.com', 'amazon.com'])"
echo "   # ... usar las funciones del ingester"
echo ""

echo "📊 Mejoras implementadas:"
echo "   ✅ Warnings detallados para configuración faltante"
echo "   ✅ Logging comprehensivo en subdomain_relationship_discovery.log"
echo "   ✅ Fallback robusto para proveedores desconocidos"
echo "   ✅ Creación de nodos Service mejorada"
echo "   ✅ Detección de proveedores mejorada (AWS, GCP, Cloudflare, Akamai, etc.)"
echo "   ✅ Descubrimiento de relaciones entre subdominios"
echo "   ✅ Clasificación mejorada de dominios base vs subdominios"
echo ""

echo "🧪 Para probar las mejoras sin Neo4j:"
echo "   python3 test_subdomain_relationship_simple.py"
echo ""

echo "🧪 Para probar con Neo4j (requiere instancia corriendo):"
echo "   python3 test_subdomain_relationship_discovery.py"
echo ""

echo "📝 Revisar logs detallados en:"
echo "   tail -f subdomain_relationship_discovery.log"
echo ""

echo "🔍 Funcionalidades principales del módulo:"
echo "   • EnhancedSubdomainGraphIngester: Ingesta mejorada con detección de proveedores"
echo "   • EnhancedDomainInfo: Clasificación inteligente de dominios"
echo "   • RelationshipInfo: Tracking de relaciones entre dominios"
echo "   • Cross-domain relationship discovery: Descubrimiento de relaciones cruzadas"
echo "   • Provider-based relationship mapping: Mapeo de relaciones por proveedor"
echo ""

echo "🎉 Sistema listo para usar!"