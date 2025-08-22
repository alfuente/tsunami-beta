# Domain Management Scripts

Este directorio contiene scripts para la gestión completa del ciclo de vida de los dominios en el sistema Tsunami Beta, incluyendo extracción, respaldo, limpieza y recarga con estadísticas de rendimiento.

## 📋 Descripción General

El sistema incluye:

1. **Extracción de dominios** del grafo Neo4j actual
2. **Respaldo completo** de la base de datos
3. **Limpieza** de la base de datos (opcional)
4. **Recarga** de dominios usando domain-backend para análisis fresco
5. **Seguimiento de estadísticas** de rendimiento en PostgreSQL

## 🚀 Uso Rápido

### Script Maestro (Recomendado)

```bash
# Proceso completo: extraer → respaldar → limpiar → recargar
python domain_management.py full-cycle --confirm-clean

# Solo extraer dominios del grafo actual
python domain_management.py extract

# Solo respaldar (sin limpiar)
python domain_management.py backup

# Solo recargar desde archivo existente
python domain_management.py reload domains_list.json
```

### Scripts Individuales

```bash
# 1. Extraer dominios base del grafo
python extract_base_domains.py

# 2. Respaldar y limpiar el grafo
python backup_and_clean_graph.py --clean --confirm

# 3. Recargar dominios via API
python reload_domains_via_api.py base_domains_list.json
```

## 📁 Scripts Disponibles

### 1. `extract_base_domains.py`

Extrae todos los dominios base únicos del grafo Neo4j junto con estadísticas.

**Uso:**
```bash
python extract_base_domains.py
```

**Salida:**
- `domain_extraction_YYYYMMDD_HHMMSS/`
  - `complete_domain_export.json` - Exportación completa con metadatos
  - `base_domains.csv` - Dominios base con información detallada
  - `base_domains_list.json` - Lista simple para scripts
  - `base_domains_list.txt` - Archivo de texto, un dominio por línea
  - `providers.csv` - Información de proveedores
  - `services.csv` - Información de servicios

### 2. `backup_and_clean_graph.py`

Crea un respaldo completo de Neo4j y opcionalmente limpia la base de datos.

**Uso:**
```bash
# Solo respaldo
python backup_and_clean_graph.py

# Respaldo y limpieza
python backup_and_clean_graph.py --clean --confirm

# Respaldo personalizado
python backup_and_clean_graph.py --output-dir my_backup --uri bolt://localhost:7687
```

**Parámetros:**
- `--clean` - Limpiar base de datos después del respaldo
- `--confirm` - Confirmar operaciones destructivas
- `--output-dir` - Directorio personalizado de salida
- `--uri` - URI de conexión Neo4j
- `--user` - Usuario Neo4j
- `--password` - Contraseña Neo4j

**Salida:**
- `neo4j_backup_YYYYMMDD_HHMMSS/`
  - `backup_metadata.json` - Metadatos del respaldo
  - `domains.json` - Todos los datos de dominios
  - `providers.json` - Datos de proveedores
  - `services.json` - Datos de servicios
  - `certificates.json` - Datos de certificados
  - `relationships.json` - Todas las relaciones
  - `restore_database.cypher` - Script de restauración

### 3. `reload_domains_via_api.py`

Recarga dominios usando el API de domain-backend con análisis completo y seguimiento de estadísticas.

**Uso:**
```bash
# Análisis completo
python reload_domains_via_api.py base_domains_list.json

# Análisis personalizado
python reload_domains_via_api.py domains.json \
  --analysis-type complete \
  --max-concurrent 3 \
  --delay 5 \
  --api-url http://localhost:8000

# Prueba con límite
python reload_domains_via_api.py domains.json --limit 10 --dry-run
```

**Parámetros:**
- `domains_file` - Archivo con dominios (JSON o texto)
- `--analysis-type` - Tipo de análisis: basic, providers, services, tls, risk, complete
- `--max-concurrent` - Máximo de solicitudes concurrentes (default: 3)
- `--delay` - Retraso entre solicitudes en segundos (default: 5)
- `--api-url` - URL del API domain-backend (default: http://localhost:8000)
- `--limit` - Limitar número de dominios (para pruebas)
- `--dry-run` - Mostrar lo que se haría sin ejecutar

**Salida:**
- `reload_results_YYYYMMDD_HHMMSS.json` - Resultados detallados
- `successful_domains_YYYYMMDD_HHMMSS.json` - Dominios exitosos
- `failed_domains_YYYYMMDD_HHMMSS.json` - Dominios fallidos (para reintentos)

### 4. `domain_management.py` (Script Maestro)

Orquesta el proceso completo con manejo de errores y reportes.

**Comandos:**

```bash
# Proceso completo
python domain_management.py full-cycle [opciones]

# Pasos individuales
python domain_management.py extract
python domain_management.py backup [--clean --confirm]
python domain_management.py reload domains_file.json [opciones]
```

**Opciones del proceso completo:**
- `--api-url` - URL del API (default: http://localhost:8000)
- `--analysis-type` - Tipo de análisis (default: complete)
- `--max-concurrent` - Concurrencia máxima (default: 3)
- `--delay` - Retraso entre solicitudes (default: 5)
- `--limit` - Limitar dominios para pruebas
- `--confirm-clean` - Confirmar limpieza de la base de datos

**Salida:**
- `domain_cycle_YYYYMMDD_HHMMSS/`
  - `extraction/` - Datos extraídos
  - `backup/` - Respaldo completo
  - `reload/` - Resultados de recarga
  - `cycle_report.json` - Reporte completo del ciclo

## 📊 Sistema de Estadísticas

Los scripts están integrados con el sistema de estadísticas PostgreSQL que:

- **Rastrea automáticamente** cada ejecución de análisis de dominio
- **Almacena métricas** de rendimiento (tiempo, subdominios encontrados, etc.)
- **Proporciona estimaciones** de tiempo basadas en datos históricos
- **Genera reportes** de rendimiento por dominio y globales

### Endpoints de Estadísticas en domain-backend:

```bash
# Resumen general de estadísticas
curl http://localhost:8000/api/v1/statistics/summary

# Estadísticas de un dominio específico
curl http://localhost:8000/api/v1/statistics/cooperativa.cl

# Rendimiento detallado de un dominio
curl http://localhost:8000/api/v1/domains/cooperativa.cl/performance

# Estimación de tiempo para análisis
curl "http://localhost:8000/api/v1/estimate/nuevobanco.com?task_type=complete_discovery"
```

## 🔧 Configuración

### Requisitos

1. **Neo4j** ejecutándose en `bolt://localhost:7687`
2. **PostgreSQL 15** ejecutándose en `localhost:5432` (para estadísticas)
3. **domain-backend API** ejecutándose en `http://localhost:8000`
4. **Python packages**: `neo4j`, `asyncpg`, `aiohttp`

### Variables de Entorno (Opcionales)

```bash
# Neo4j
export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=test.password

# PostgreSQL (para estadísticas)
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
export POSTGRES_DB=domain_stats
export POSTGRES_USER=stats_user
export POSTGRES_PASSWORD=stats_password

# Domain Backend API
export DOMAIN_BACKEND_URL=http://localhost:8000
```

### Instalación de Dependencias

```bash
pip install neo4j asyncpg aiohttp
```

O usando el requirements:

```bash
pip install -r ../requirements_api.txt
```

## 📈 Casos de Uso

### 1. Migración Completa del Sistema

Cuando necesitas limpiar completamente el grafo y recargar con la última versión del código:

```bash
python domain_management.py full-cycle --confirm-clean
```

### 2. Prueba con Subconjunto de Dominios

Para probar cambios en el sistema sin procesar todos los dominios:

```bash
python domain_management.py full-cycle --limit 50 --confirm-clean
```

### 3. Respaldo de Seguridad

Antes de cambios importantes al sistema:

```bash
python domain_management.py backup
```

### 4. Recarga Incremental

Recargar solo algunos dominios específicos:

```bash
echo "cooperativa.cl\\nbci.cl\\nbancoestado.cl" > test_domains.txt
python reload_domains_via_api.py test_domains.txt --analysis-type complete
```

### 5. Análisis de Rendimiento

Obtener estadísticas de rendimiento después de una recarga:

```bash
# Estadísticas generales
curl http://localhost:8000/api/v1/statistics/summary | jq

# Rendimiento por dominio
curl http://localhost:8000/api/v1/domains/cooperativa.cl/performance | jq
```

## ⚠️ Consideraciones Importantes

### Seguridad

- ⚠️ Los scripts con `--clean --confirm` **BORRAN TODOS LOS DATOS** de Neo4j
- 💾 **Siempre respalda** antes de limpiar la base de datos
- 🔒 Los scripts asumen credenciales por defecto - configura según tu entorno

### Rendimiento

- 🚀 **Concurrencia**: Ajusta `--max-concurrent` según la capacidad del servidor
- ⏱️ **Timeouts**: Algunos dominios pueden tomar 10+ minutos en analizar
- 📊 **Monitoreo**: Usa las estadísticas para optimizar configuraciones

### Recuperación de Errores

- 🔄 Los scripts guardan **listas de dominios fallidos** para reintento
- 📝 **Logs detallados** para debug en caso de errores
- 🛡️ **Manejo graceful** de interrupciones (Ctrl+C)

## 🐛 Troubleshooting

### Error: "Failed to connect to Neo4j"
```bash
# Verificar que Neo4j esté ejecutándose
docker compose ps neo4j

# Verificar conectividad
cypher-shell -u neo4j -p test.password "RETURN 1"
```

### Error: "API is not available"
```bash
# Verificar que domain-backend esté ejecutándose
curl http://localhost:8000/api/v1/status

# Verificar logs del servicio
docker compose logs domain-backend
```

### Error: "Statistics service not available"
```bash
# Verificar PostgreSQL
docker compose ps postgres

# Verificar conexión
psql -h localhost -U stats_user -d domain_stats -c "\\dt"
```

### Dominios que fallan consistentemente

1. Revisar logs del domain-backend para errores específicos
2. Verificar que amass esté funcionando correctamente
3. Considerar aumentar timeouts para dominios complejos
4. Usar análisis menos intensivos (`--analysis-type basic`)

## 📚 Ejemplos de Flujos Completos

### Flujo 1: Migración de Producción

```bash
# 1. Respaldo completo
python domain_management.py backup

# 2. Extraer dominios actuales
python domain_management.py extract

# 3. Verificar que domain-backend esté actualizado
curl http://localhost:8000/api/v1/status

# 4. Proceso completo con confirmación
python domain_management.py full-cycle --confirm-clean

# 5. Verificar resultados
curl http://localhost:8000/api/v1/statistics/summary
```

### Flujo 2: Desarrollo y Testing

```bash
# 1. Prueba con pocos dominios
python domain_management.py full-cycle --limit 10 --confirm-clean

# 2. Verificar estadísticas
curl http://localhost:8000/api/v1/statistics/summary

# 3. Si todo funciona, proceso completo
python domain_management.py full-cycle --confirm-clean
```

### Flujo 3: Análisis de Rendimiento

```bash
# 1. Recarga con configuración optimizada
python reload_domains_via_api.py domains.json \
  --max-concurrent 5 \
  --delay 3 \
  --analysis-type complete

# 2. Analizar resultados
curl http://localhost:8000/api/v1/statistics/summary | jq '.avg_processing_time'

# 3. Ajustar configuración basado en resultados
```

---

## 🎯 Resumen

Estos scripts proporcionan un **sistema completo de gestión de dominios** que:

- ✅ **Preserva datos** con respaldos automáticos
- 📊 **Rastrea rendimiento** con estadísticas detalladas  
- 🔄 **Automatiza procesos** complejos de migración
- 🛡️ **Maneja errores** gracefully con recuperación
- 📈 **Optimiza rendimiento** basado en datos históricos

Para la mayoría de casos de uso, el **script maestro** `domain_management.py` es la mejor opción.
