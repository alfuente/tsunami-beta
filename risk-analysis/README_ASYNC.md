# Risk Analysis Async System

Sistema de análisis de riesgo asíncrono para el ecosistema digital chileno, basado en el sistema de tareas de domain-backend.

## 🚀 Características

- **Análisis Asíncrono**: Todos los algoritmos de riesgo ejecutan en background tasks
- **Monitoreo en Tiempo Real**: Interface web para monitorear el progreso de las tareas
- **Logs Detallados**: Cada tarea genera logs detallados del proceso de análisis
- **Persistencia**: Las tareas se guardan en PostgreSQL para sobrevivir reinicios
- **API RESTful**: Endpoints para iniciar, monitorear y gestionar tareas

## 📊 Algoritmos Implementados

### ACCS - Algoritmo de Centralidad y Criticidad Sistémica
Calcula el Índice de Criticidad Sistémica (ICS) para entidades en el ecosistema.

### AEPC - Algoritmo de Evaluación de Proveedores Críticos  
Evalúa el Índice de Importancia Sistémica de Proveedores (IISP).

### Cálculo de Riesgo por Lotes
Calcula riesgos extendidos para múltiples nodos simultáneamente.

## 🛠 Instalación y Configuración

### Pre-requisitos

1. **Neo4j** ejecutándose en `bolt://localhost:7687`
2. **PostgreSQL** ejecutándose en `localhost:5432`
   - Base de datos: `tsunami_backend`
   - Usuario: `tsunami_user`
   - Contraseña: `tsunami_password`

### Variables de Entorno

```bash
# Neo4j Configuration
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=test.password

# PostgreSQL Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=tsunami_backend
POSTGRES_USER=tsunami_user
POSTGRES_PASSWORD=tsunami_password

# API Configuration
ASYNC_PORT=8003
DEBUG=true
```

## 🚀 Inicio Rápido

### 1. Ejecutar el Script de Inicio

```bash
cd /home/alf/dev/tsunami-beta/risk-analysis
./start_async_risk_analysis.sh
```

### 2. Acceder a las Interfaces

- **API Documentación**: http://localhost:8003/docs
- **Risk Analysis Monitor**: http://localhost:8080/risk-analysis.html

### 3. Ejemplo de Uso via cURL

```bash
# Iniciar análisis ACCS
curl -X 'POST' \
  'http://localhost:8003/algorithms/accs/async' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "node_types": ["Provider", "Domain"],
  "sectors": ["banking"],
  "include_critical_bonus": true
}'

# Obtener estado de tarea
curl 'http://localhost:8003/tasks/{task_id}'

# Listar todas las tareas
curl 'http://localhost:8003/tasks'
```

## 📊 Interface Web

### Risk Analysis Monitor

La nueva pestaña "Risk Analysis" en la interfaz gráfica proporciona:

1. **Panel de Algoritmos**: Formularios para ejecutar diferentes algoritmos
2. **Monitor de Tareas**: Lista en tiempo real de tareas activas y completadas
3. **Detalles de Tarea**: Vista detallada con logs y resultados
4. **Actualización Automática**: Refresco automático cada 5 segundos

### Navegación

- **2D View**: Visualización de grafos en 2D
- **3D View**: Visualización de grafos en 3D  
- **Risk Analysis**: Monitor de tareas asíncronas de análisis de riesgo

## 🔧 Estructura del Sistema

```
risk-analysis/
├── async_api.py              # API asíncrona principal
├── task_manager.py           # Gestor de tareas con PostgreSQL
├── task_models.py            # Modelos de datos para tareas
├── neo4j_connector.py        # Conector Neo4j (actualizado)
├── risk_calculator.py        # Calculadora de riesgos
├── config.py                 # Configuración (actualizada)
├── launch_async_api.py       # Launcher para la API
├── start_async_risk_analysis.sh  # Script de inicio
└── README_ASYNC.md           # Esta documentación
```

## 📋 Estados de Tareas

- **PENDING**: Tarea creada, esperando ejecución
- **RUNNING**: Tarea en ejecución
- **COMPLETED**: Tarea completada exitosamente
- **FAILED**: Tarea falló con error
- **PARTIAL**: Tarea parcialmente completada

## 🔍 Logs Detallados

Cada tarea mantiene un log detallado que incluye:

- Timestamps de cada paso
- Parámetros de entrada
- Progreso del análisis
- Estadísticas de grafos cargados
- Métricas calculadas
- Errores y excepciones
- Tiempo total de ejecución

## 📈 Base de Datos

### Tabla `risk_analysis_tasks`

```sql
CREATE TABLE risk_analysis_tasks (
    task_id VARCHAR(255) PRIMARY KEY,
    task_type VARCHAR(100) NOT NULL,
    parameters JSONB DEFAULT '{}',
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    progress INTEGER DEFAULT 0,
    logs TEXT DEFAULT '',
    error TEXT,
    result JSONB,
    execution_time REAL
);
```

## 🐛 Solución de Problemas

### Error: "Services not available"
- Verificar que Neo4j esté ejecutándose
- Verificar que PostgreSQL esté ejecutándose
- Revisar las variables de entorno

### Error: NetworkX "multiple values for keyword argument 'name'"
- Este error ha sido corregido en `neo4j_connector.py`
- El parámetro `name` se cambió a `node_name`
- Las propiedades se filtran para evitar conflictos

### Tareas no aparecen en la interfaz
- Verificar que la API esté ejecutándose en el puerto 8003
- Revisar la consola del navegador por errores CORS
- Confirmar que PostgreSQL esté accesible

## 🔄 Migración desde API Síncrona

La nueva API asíncrona coexiste con la API síncrona existente:

- **API Síncrona**: Puerto 8002 (existing functionality)
- **API Asíncrona**: Puerto 8003 (new task-based system)

Para usar la nueva funcionalidad asíncrona, apuntar los requests a puerto 8003 y usar endpoints `/async`.

## 📞 Soporte

Para problemas o preguntas sobre el sistema asíncrono de Risk Analysis:
1. Revisar logs en la interfaz web
2. Verificar estado de servicios (Neo4j, PostgreSQL)
3. Consultar documentación de la API en `/docs`