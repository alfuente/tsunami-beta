#!/bin/bash
set -euo pipefail

echo "🧹 Limpiando bases de datos y manteniendo solo el modelo de datos..."

# Limpiar Neo4j - mantener solo constraints e indices del modelo
echo "Limpiando datos de Neo4j pero manteniendo esquema..."
cypher-shell -u neo4j -p test.password <<'CQL'
// Eliminar todos los nodos y relaciones
MATCH (n) DETACH DELETE n;

// Verificar que el esquema (constraints e indices) permanece intacto
SHOW CONSTRAINTS;
SHOW INDEXES;
CQL

# Limpiar Iceberg - mantener solo estructura de tablas
echo "Limpiando datos de Iceberg pero manteniendo esquema..."
python3 -c "
import requests
from pyspark.sql import SparkSession
import sys
import os

# Configurar Spark para Iceberg
spark = SparkSession.builder \
    .appName('cleanup-iceberg-data') \
    .config('spark.sql.extensions', 'org.apache.iceberg.spark.extensions.IcebergSparkSessionExtensions') \
    .config('spark.sql.catalog.ice', 'org.apache.iceberg.spark.SparkCatalog') \
    .config('spark.sql.catalog.ice.catalog-impl', 'org.apache.iceberg.rest.RESTCatalog') \
    .config('spark.sql.catalog.ice.uri', 'http://localhost:8181') \
    .config('spark.sql.catalog.ice.warehouse', 's3a://warehouse/') \
    .config('spark.sql.catalog.ice.io-impl', 'org.apache.iceberg.aws.s3.S3FileIO') \
    .config('spark.hadoop.fs.s3a.endpoint', 'http://localhost:9000') \
    .config('spark.hadoop.fs.s3a.access.key', 'admin') \
    .config('spark.hadoop.fs.s3a.secret.key', 'password') \
    .config('spark.hadoop.fs.s3a.path.style.access', 'true') \
    .master('local[*]').getOrCreate()

try:
    # Tablas del modelo de datos
    tables = [
        'organizations', 'domains', 'providers', 'services', 'certificates',
        'ips', 'asns', 'netblocks', 'incidents',
        'rel_depends_on', 'rel_announces', 'rel_contains', 'rel_affects',
        'rel_secured_by', 'rel_resolves_to', 'rel_has_subdomain', 'rel_cname_to'
    ]
    
    for table in tables:
        try:
            # Eliminar datos pero mantener estructura
            spark.sql(f'DELETE FROM ice.risk_db.{table}')
            print(f'✅ Limpiado: {table}')
        except Exception as e:
            print(f'⚠️  Tabla {table} no existe o error: {e}')
    
    # Verificar que las tablas siguen existiendo (vacías)
    for table in tables:
        try:
            count = spark.sql(f'SELECT COUNT(*) FROM ice.risk_db.{table}').collect()[0][0]
            print(f'📊 {table}: {count} registros')
        except Exception as e:
            print(f'❌ Error verificando {table}: {e}')
            
finally:
    spark.stop()
"

echo "✅ Limpieza completada"
echo "🏗️  Modelo de datos Neo4j mantenido (constraints e indices)"
echo "🏗️  Esquema de tablas Iceberg mantenido (sin datos)"
echo ""
echo "Para verificar el estado:"
echo "  Neo4j: cypher-shell -u neo4j -p test.password 'SHOW CONSTRAINTS; SHOW INDEXES;'"
echo "  Iceberg: Ejecutar consultas SELECT COUNT(*) en las tablas"