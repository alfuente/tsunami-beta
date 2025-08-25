#!/bin/bash

echo "🚀 Iniciando Tsunami Report Backend Service..."
echo "Puerto: 8082"
echo "Swagger UI: http://localhost:8082/swagger-ui"
echo "OpenAPI Spec: http://localhost:8082/openapi"
echo ""

# Verificar que Neo4j esté disponible
echo "📡 Verificando conectividad con Neo4j..."
python3 -c "
try:
    from neo4j import GraphDatabase
    driver = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', 'test.password'))
    with driver.session() as session:
        result = session.run('RETURN 1 as test')
        print('✅ Neo4j conectado exitosamente')
    driver.close()
except Exception as e:
    print('❌ Error conectando a Neo4j:', str(e))
    print('   Asegúrate de que Neo4j esté ejecutándose en docker-compose')
" 2>/dev/null

echo ""
echo "🔧 Compilando aplicación Quarkus..."

# Compilar en modo desarrollo
mvn quarkus:dev -Dquarkus.http.port=8082

echo ""
echo "🎯 URLs disponibles:"
echo "  • API Base: http://localhost:8082/api/v1"
echo "  • Graph Analysis: http://localhost:8082/api/v1/graph/analysis"
echo "  • Graph Health: http://localhost:8082/api/v1/graph/health"
echo "  • Domain Analysis: http://localhost:8082/api/v1/reports/domain/{domain}/analysis"
echo "  • Swagger UI: http://localhost:8082/swagger-ui"
echo "  • OpenAPI JSON: http://localhost:8082/openapi"
echo ""