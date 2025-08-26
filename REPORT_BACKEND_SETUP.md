# Tsunami Report Backend - Configuración Completa

## Información del Servicio

### 🚀 **Puerto del Servicio: 8082**

### 📋 **URLs Principales**
- **API Base**: `http://localhost:8082/api/v1`
- **Swagger UI**: `http://localhost:8082/swagger-ui`
- **OpenAPI Spec**: `http://localhost:8082/openapi`
- **Health Check**: `http://localhost:8082/api/v1/graph/health`

## Endpoints de la API

### 🔍 **Análisis del Grafo Neo4j**

#### 1. Health Check
```http
GET /api/v1/graph/health
Accept: application/json
```
Verifica conectividad con Neo4j y estado del sistema.

#### 2. Análisis Completo del Grafo
```http
GET /api/v1/graph/analysis
Accept: application/json
```
Retorna análisis completo del grafo en formato JSON con:
- Estadísticas de nodos y relaciones
- Distribución de dominios y tecnologías
- Análisis de riesgos y proveedores
- Métricas de conectividad

#### 3. Reporte en Texto
```http
GET /api/v1/graph/report
Accept: text/plain
```
Retorna reporte detallado en formato texto legible.

#### 4. Iniciar Nuevo Análisis
```http
POST /api/v1/graph/analyze
Content-Type: application/json
```
Inicia análisis del grafo en segundo plano.

### 🌐 **Análisis de Dominios Específicos**

#### 5. Análisis de Dominio
```http
GET /api/v1/reports/domain/{domain}/analysis
Accept: application/json
```
Ejemplo: `/api/v1/reports/domain/bancochile.cl/analysis`

Retorna análisis detallado para un dominio específico incluyendo:
- Puntuación de riesgo
- Subdominios descubiertos
- Tecnologías detectadas
- Proveedores utilizados
- Servicios ejecutándose

## Cómo Iniciar el Servicio

### Opción 1: Script Automático
```bash
cd /home/alf/dev/tsunami-beta/report-backend
./start_service.sh
```

### Opción 2: Maven Manual
```bash
cd /home/alf/dev/tsunami-beta/report-backend
mvn quarkus:dev -Dquarkus.http.port=8082
```

### Opción 3: Compilar y Ejecutar
```bash
cd /home/alf/dev/tsunami-beta/report-backend
mvn clean package -DskipTests
java -jar target/quarkus-app/quarkus-run.jar
```

## Pruebas de los Endpoints

### Script de Pruebas Automatizadas
```bash
cd /home/alf/dev/tsunami-beta/report-backend
./test_endpoints.sh
```

### Pruebas Manuales con curl

#### Test Health Check
```bash
curl -H "Accept: application/json" \
     http://localhost:8082/api/v1/graph/health
```

#### Test Análisis del Grafo
```bash
curl -H "Accept: application/json" \
     http://localhost:8082/api/v1/graph/analysis
```

#### Test Análisis de Dominio
```bash
curl -H "Accept: application/json" \
     http://localhost:8082/api/v1/reports/domain/bancochile.cl/analysis
```

## Configuración OpenAPI/Swagger

### ✅ **Características Configuradas**
- **Swagger UI** habilitado permanentemente
- **Documentación automática** de todos los endpoints
- **Esquemas JSON** para requests/responses
- **Ejemplos interactivos** en Swagger UI
- **Descripciones detalladas** en español
- **Códigos de respuesta** documentados
- **Parámetros** con validación

### 📖 **Acceso a Documentación**
1. **Swagger UI**: `http://localhost:8082/swagger-ui`
   - Interfaz interactiva para probar endpoints
   - Documentación visual de la API
   - Ejemplos de requests/responses

2. **OpenAPI JSON**: `http://localhost:8082/openapi`
   - Especificación completa en formato JSON
   - Compatible con herramientas OpenAPI
   - Generación automática de clientes

## Dependencias y Tecnologías

### 🛠️ **Stack Tecnológico**
- **Quarkus 3.15.0**: Framework Java nativo en la nube
- **JAX-RS**: API REST estándar
- **Neo4j Driver 5.15.0**: Conectividad con base de datos de grafo
- **SmallRye OpenAPI**: Documentación automática
- **Jackson**: Serialización JSON
- **CDI**: Inyección de dependencias

### 📦 **Dependencias Principales**
```xml
<dependency>
    <groupId>io.quarkus</groupId>
    <artifactId>quarkus-smallrye-openapi</artifactId>
</dependency>
<dependency>
    <groupId>org.neo4j.driver</groupId>
    <artifactId>neo4j-java-driver</artifactId>
    <version>5.15.0</version>
</dependency>
```

## Configuración del Sistema

### 🔧 **application.properties**
```properties
# Puerto del servicio
quarkus.http.port=8082

# Configuración OpenAPI/Swagger
quarkus.swagger-ui.always-include=true
quarkus.swagger-ui.path=/swagger-ui
quarkus.smallrye-openapi.info-title=Tsunami Report Backend API
quarkus.smallrye-openapi.info-version=1.0.0
quarkus.smallrye-openapi.info-description=API para análisis de grafos Neo4j

# Neo4j
quarkus.neo4j.uri=bolt://localhost:7687
quarkus.neo4j.authentication.username=neo4j
quarkus.neo4j.authentication.password=test.password

# CORS habilitado
quarkus.http.cors=true
quarkus.http.cors.origins=*
```

## Arquitectura del Sistema

### 🏗️ **Componentes Principales**

#### 1. GraphAnalysisResource
- **Endpoint**: `/api/v1/graph/*`
- **Función**: Análisis del grafo Neo4j
- **Métodos**: GET, POST para análisis y health checks

#### 2. ReportResource  
- **Endpoint**: `/api/v1/reports/*`
- **Función**: Análisis de dominios específicos
- **Métodos**: Análisis detallado por dominio

#### 3. DomainDataService
- **Función**: Lógica de negocio para consultas Neo4j
- **Métodos**: Obtención de datos del grafo
- **Análisis**: Riesgos, tecnologías, proveedores

#### 4. Neo4jConfig
- **Función**: Configuración de conectividad Neo4j
- **Patrón**: CDI Producer para inyección de dependencias

### 🗄️ **Integración con Neo4j**
- Conexión directa via Bolt protocol (puerto 7687)
- Consultas Cypher optimizadas
- Manejo de sesiones automático
- Configuración CDI para inyección

## Datos del Grafo Analizados

### 📊 **Estadísticas Actuales** (última actualización)
- **Total nodos**: 6,889
- **Total relaciones**: 8,375
- **Dominios base**: 28
- **Subdominios**: 1,822
- **Tecnologías**: 43
- **Proveedores**: 36
- **Servicios**: 4,954

### 🏦 **Sectores Analizados**
- Instituciones financieras chilenas (.cl)
- Bancos principales (Banco de Chile, BCI, Santander, etc.)
- Cooperativas (Cooperativa)
- Servicios internacionales (.com)

## Monitoreo y Logs

### 📝 **Configuración de Logs**
```properties
quarkus.log.level=INFO
quarkus.log.category."com.example.report".level=DEBUG
```

### 🔍 **Health Checks Disponibles**
- **Neo4j Connectivity**: Verifica conexión a base de datos
- **Service Status**: Estado del servicio REST
- **Analysis Status**: Estado del último análisis

## Próximos Pasos

### 🚀 **Mejoras Recomendadas**
1. **Autenticación**: JWT o OAuth2 para seguridad
2. **Rate Limiting**: Control de frecuencia de requests
3. **Caching**: Redis para consultas frecuentes
4. **Métricas**: Prometheus para monitoreo
5. **Tests**: Cobertura de pruebas automatizadas

### 🔧 **Optimizaciones**
1. **Consultas**: Optimización de queries Cypher
2. **Conexiones**: Pool de conexiones Neo4j
3. **Async**: Procesamiento asíncrono para análisis largos
4. **Streaming**: Respuestas streaming para datos grandes

---

**Servicio listo en puerto 8082 con documentación OpenAPI/Swagger completa** 🎉