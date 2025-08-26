# Tsunami Beta - Gestión de Servicios Actualizada

## ✅ Report Backend Integrado en manage-services.sh

El **report-backend** ya está completamente integrado en el script `manage-services.sh` con dos modalidades:

### 🚀 **Python/FastAPI Mode (Por defecto - Recomendado)**
- **Comando**: `./manage-services.sh start-report`
- **Puerto**: 8082
- **Ventajas**: Inicio rápido, sin problemas de dependencias Maven
- **Framework**: Python + FastAPI + Neo4j Driver

### ⚙️ **Quarkus Mode (Alternativo)**
- **Comando**: `./manage-services.sh start-report-quarkus`
- **Puerto**: 8082
- **Framework**: Java + Quarkus + Neo4j Driver

## Comandos Disponibles

### Gestión del Report Backend
```bash
# Iniciar Report Backend (Python/FastAPI - recomendado)
./manage-services.sh start-report

# Iniciar Report Backend (Quarkus - alternativo)  
./manage-services.sh start-report-quarkus

# Detener Report Backend
./manage-services.sh stop-report

# Ver logs del Report Backend
./manage-services.sh logs report
```

### Gestión de Todos los Servicios
```bash
# Iniciar todos los servicios (incluye report-backend)
./manage-services.sh start-dev

# Detener todos los servicios
./manage-services.sh stop

# Reiniciar todos los servicios
./manage-services.sh restart-dev

# Ver estado de todos los servicios
./manage-services.sh status
```

## URLs del Report Backend

### 🌐 **Endpoints Principales**
- **API Base**: `http://localhost:8082/api/v1`
- **Swagger UI**: `http://localhost:8082/swagger-ui`
- **OpenAPI Spec**: `http://localhost:8082/openapi`

### 📊 **Análisis del Grafo Neo4j**
- **Health Check**: `http://localhost:8082/api/v1/graph/health`
- **Análisis Completo**: `http://localhost:8082/api/v1/graph/analysis`
- **Reporte Texto**: `http://localhost:8082/api/v1/graph/report`
- **Nuevo Análisis**: `POST http://localhost:8082/api/v1/graph/analyze`

### 🌐 **Análisis por Dominio**
- **Análisis Específico**: `http://localhost:8082/api/v1/reports/domain/{domain}/analysis`
- **Ejemplo**: `http://localhost:8082/api/v1/reports/domain/bancochile.cl/analysis`

## Estado de Servicios (Todos Integrados)

Cuando ejecutes `./manage-services.sh status` verás:

```
=== Service Status ===
✅ Ollama: RUNNING (PID: 1654)
✅ Quarkus: RUNNING (PID: 4126762)
✅ React Dashboard: RUNNING (PID: 4126796)
✅ Risk Query: RUNNING (PID: 4126821, Port: 8003)
⚠️ Legacy Discovery API: STOPPED
✅ Async Discovery API: RUNNING (PID: 4126826, Port: 8001)
✅ Report Backend: RUNNING (PID: 110283, Port: 8082)
  ↳ Swagger UI: http://localhost:8082/swagger-ui
  ↳ Graph Analysis: http://localhost:8082/api/v1/graph/analysis
```

## Ejemplos de Uso

### Iniciar Sistema Completo
```bash
cd /home/alf/dev/tsunami-beta
./manage-services.sh start-dev
```

### Probar Report Backend
```bash
# Health check
curl http://localhost:8082/api/v1/graph/health

# Análisis completo del grafo
curl http://localhost:8082/api/v1/graph/analysis

# Análisis de dominio específico
curl http://localhost:8082/api/v1/reports/domain/bancochile.cl/analysis
```

### Ver Logs en Tiempo Real
```bash
# Report Backend
./manage-services.sh logs report

# Otros servicios
./manage-services.sh logs quarkus
./manage-services.sh logs react
./manage-services.sh logs async
```

## Arquitectura Integrada

### Todos los Servicios en Puertos Dedicados
- **Risk Graph Service (Quarkus)**: Puerto 8080
- **Async Discovery API (Python)**: Puerto 8001  
- **Risk Query (Python)**: Puerto 8003
- **Report Backend (Python/FastAPI)**: Puerto 8082
- **Risk Dashboard (React)**: Puerto 3000

### Neo4j Integration
El Report Backend se conecta directamente a Neo4j:
- **URI**: `bolt://localhost:7687`
- **Auth**: `neo4j/test.password`
- **Features**: Análisis en tiempo real del grafo

## Datos Disponibles

El Report Backend proporciona acceso a:
- **6,889 nodos** (dominios, subdominios, servicios, tecnologías)
- **8,375 relaciones** (mapeo completo de infraestructura)
- **28 dominios base** del sector financiero chileno
- **Análisis de riesgos** con puntuaciones y distribución
- **43 tecnologías** y **36 proveedores** detectados

## Ventajas del Python/FastAPI Mode

### ✅ **Recomendado por defecto**
- **Inicio rápido**: ~3 segundos vs ~30-60 segundos Quarkus
- **Sin problemas Maven**: No depende de configuración Java compleja
- **Mismas funcionalidades**: APIs idénticas, documentación OpenAPI
- **Mejor debugging**: Logs más claros y directos

### 📊 **Funcionalidades Completas**
- Swagger UI automático en `/swagger-ui`
- OpenAPI 3.0 en `/openapi`
- CORS habilitado para frontend
- Análisis en tiempo real de Neo4j
- Caching inteligente de análisis

---

**El Report Backend está listo y completamente integrado en manage-services.sh** 🎉

Usa `./manage-services.sh start-dev` para iniciar todo el sistema incluyendo el Report Backend en puerto 8082.