# Análisis Detallado del Grafo Neo4j - Sistema Tsunami

## Resumen Ejecutivo

El sistema Tsunami ha sido analizado completamente, revelando una base de datos de grafo robusta con **6,889 nodos** y **8,375 relaciones** que representan la infraestructura de ciberseguridad de dominios chilenos principalmente del sector financiero.

## Arquitectura del Grafo

### Configuración Docker Compose

El grafo está implementado usando Neo4j 2025.06.0 con las siguientes características:

```yaml
neo4j:
  image: neo4j:2025.06.0
  environment:
    - NEO4J_AUTH=neo4j/test.password
    - NEO4J_PLUGINS=["apoc"]
    - NEO4J_dbms_security_procedures_unrestricted=apoc.*
  ports:
    - "7474:7474"  # Browser
    - "7687:7687"  # Bolt
```

### Componentes del Stack

1. **Neo4j**: Base de datos de grafo principal
2. **MinIO**: Almacenamiento de objetos (para Iceberg)
3. **Apache Iceberg**: Formato de tabla para analytics
4. **Apache Spark**: Motor de procesamiento distribuido
5. **PostgreSQL**: Base de datos relacional para estadísticas

## Estadísticas del Grafo

### Distribución de Nodos

| Tipo de Nodo | Cantidad | Descripción |
|---------------|----------|-------------|
| Service | 4,954 | Servicios detectados (puertos, protocolos) |
| Subdomain | 1,822 | Subdominios descubiertos |
| Technology | 43 | Tecnologías genéricas identificadas |
| Provider | 36 | Proveedores de servicios cloud/hosting |
| Domain | 28 | Dominios principales (base) |
| TechnologyVersion | 6 | Versiones específicas de tecnologías |

**Total: 6,889 nodos**

### Distribución de Relaciones

| Tipo de Relación | Cantidad | Descripción |
|------------------|----------|-------------|
| RUNS_SERVICE | 5,001 | Servicios ejecutándose en dominios |
| HAS_SUBDOMAIN | 1,822 | Relación dominio → subdominio |
| USES_TECHNOLOGY | 1,162 | Uso de tecnologías |
| USES_PROVIDER | 265 | Uso de proveedores |
| USES | 90 | Relaciones de uso genéricas |
| USES_TECHNOLOGY_VERSION | 12 | Uso de versiones específicas |
| IS_VERSION_OF | 11 | Versiones de tecnologías |

**Total: 8,375 relaciones**

## Análisis de Dominios

### Distribución Geográfica
- **Dominios .cl**: 26 (principalmente instituciones financieras chilenas)
- **Dominios .com**: 2 (servicios internacionales)

### Dominios Base
- **Total**: 28 dominios principales
- **Subdominios**: 1,822 subdominios descubiertos
- **Ratio**: ~65 subdominios por dominio base

### Principales Dominios Analizados
- Bancos: bancochile.cl, bci.cl, santander.cl, itau.cl
- Cooperativas: cooperativa.cl
- Instituciones financieras: bancofalabella.cl, bancosecurity.cl

## Análisis de Tecnologías

### Tecnologías Más Detectadas
1. **TLS Certificate (Basic)**: 12 dominios
2. **IP Geolocation & ISP**: 12 dominios  
3. **AlienVault OTX Intelligence**: 12 dominios
4. **Enhanced WHOIS Data**: 12 dominios
5. **VirusTotal Reputation**: 12 dominios
6. **TLS TLSv1.3**: 11 dominios
7. **Cloudflare**: 6 dominios
8. **Google Tag Manager**: 4 dominios
9. **Angular**: 4 dominios

### Categorías de Tecnologías
- **third_party_provider**: 10 tecnologías
- **web_server**: 8 tecnologías
- **javascript**: 6 tecnologías  
- **threat_intelligence_risk**: 4 tecnologías
- **tls_configuration**: 2 tecnologías

### Niveles de Riesgo
- **Low**: 2 versiones
- **Unknown**: 1 versión

## Análisis de Riesgos

### Distribución de Riesgos
- **Puntuación promedio**: 19.06/100
- **Critical (80-100)**: 0 dominios
- **High (60-80)**: 0 dominios  
- **Medium-High (40-60)**: 3 dominios
- **Medium (20-40)**: 9 dominios
- **Low-Medium (10-20)**: 5 dominios
- **Low (0-10)**: 8 dominios

## Análisis de Proveedores

### Proveedores Más Utilizados
1. **Cloudflare**: 5 dominios (CDN/Seguridad)
2. **Google Tag Manager**: 4 dominios (Analytics)
3. **Incapsula**: 3 dominios (Seguridad)
4. **Google Fonts**: 2 dominios (Assets)
5. **Microsoft Azure**: 2 dominios (Cloud)

### Tipos de Proveedores
- **Cloud**: 7 proveedores
- **CDN**: 5 proveedores
- **Hosting**: 4 proveedores
- **Social Media**: 3 proveedores
- **Infrastructure**: 3 proveedores

## Métricas de Conectividad

### Dominios con Mayor Complejidad Tecnológica
1. **cooperativa.cl**: 13 tecnologías
2. **bancosecurity.cl**: 13 tecnologías
3. **bancofalabella.cl**: 11 tecnologías
4. **github.com**: 11 tecnologías
5. **itau.cl**: 11 tecnologías

### Servicios Más Comunes
1. **Puerto 443 (HTTPS)**: 905 servicios
2. **Puerto 80 (HTTP)**: 839 servicios
3. **Puerto 8443 (HTTPS Alt)**: 526 servicios
4. **Puerto 8080 (HTTP Alt)**: 518 servicios
5. **Puerto 53 (DNS)**: 217 servicios

## Implementación en Report-Backend

### Endpoints Creados

#### 1. Análisis Completo del Grafo
```http
GET /api/v1/graph/analysis
Content-Type: application/json
```
Retorna análisis completo en formato JSON con todas las métricas.

#### 2. Reporte de Texto
```http
GET /api/v1/graph/report  
Content-Type: text/plain
```
Retorna reporte detallado en formato texto legible.

#### 3. Trigger de Análisis
```http
POST /api/v1/graph/analyze
Content-Type: application/json
```
Inicia nuevo análisis en background.

#### 4. Health Check
```http
GET /api/v1/graph/health
Content-Type: application/json
```
Verifica conectividad con Neo4j.

### Servicios Java Implementados

#### DomainDataService
```java
public class DomainDataService {
    @Inject Driver neo4jDriver;
    
    public GraphAnalysisData getGraphAnalysisData();
    public DomainRiskData getDomainRiskData(String domain);
}
```

#### GraphAnalysisResource
```java
@Path("/api/v1/graph")
public class GraphAnalysisResource {
    // Endpoints REST para análisis del grafo
}
```

### Script de Análisis Python
- **Archivo**: `graph_analysis_demo.py`
- **Funcionalidades**:
  - Conexión automática a Neo4j
  - Análisis estadístico completo
  - Generación de reportes JSON y texto
  - Métricas de rendimiento del grafo

## Configuración Técnica

### Dependencias Maven
```xml
<dependency>
    <groupId>org.neo4j.driver</groupId>
    <artifactId>neo4j-java-driver</artifactId>
    <version>5.15.0</version>
</dependency>
```

### Configuración Neo4j CDI
```java
@ApplicationScoped
public class Neo4jConfig {
    @Produces @Singleton
    public Driver createDriver() {
        return GraphDatabase.driver(uri, AuthTokens.basic(username, password));
    }
}
```

### Propiedades de Aplicación
```properties
quarkus.neo4j.uri=bolt://localhost:7687
quarkus.neo4j.authentication.username=neo4j
quarkus.neo4j.authentication.password=test.password
```

## Casos de Uso

### 1. Monitoreo de Infraestructura
- Identificación de servicios críticos por puerto
- Análisis de proveedores de terceros
- Detección de configuraciones TLS

### 2. Análisis de Riesgos
- Evaluación automática de puntuaciones de riesgo
- Identificación de tecnologías vulnerables
- Mapeo de superficie de ataque

### 3. Intelligence de Amenazas
- Integración con AlienVault OTX
- Reputación de dominios con VirusTotal
- Análisis geográfico de IPs

### 4. Compliance y Auditoría
- Inventario completo de activos digitales
- Identificación de subdominios shadow
- Análisis de certificados TLS

## Próximos Pasos

### Mejoras Recomendadas
1. **Dashboard en Tiempo Real**: Integración con frontend React
2. **Alertas Automáticas**: Notificaciones por cambios de riesgo
3. **API GraphQL**: Query flexibility para datos del grafo
4. **Machine Learning**: Detección de anomalías en patrones
5. **Exportación**: Integración con formatos STIX/TAXII

### Escalabilidad
- **Sharding**: Distribución del grafo por geografía
- **Caching**: Redis para consultas frecuentes  
- **Backup**: Automatización con MinIO S3
- **Monitoring**: Métricas de performance con Prometheus

---

**Fecha de Análisis**: 2025-08-24  
**Versión del Sistema**: Tsunami Beta  
**Estado del Grafo**: Operacional (6,889 nodos activos)