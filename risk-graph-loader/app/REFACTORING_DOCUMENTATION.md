# Subdomain Discovery Engine - Refactoring Documentation v6.0

## 📋 Resumen Ejecutivo

Se ha realizado un refactoring completo del sistema de descubrimiento de subdominios, consolidando las mejores funcionalidades de las versiones v4 y v5 en una nueva versión unificada v6.0, junto con un servicio REST completo para exposición de funcionalidades.

## 🔍 Análisis de Versiones Anteriores

### Versión v4.0 (2,464 líneas)
**Fortalezas identificadas:**
- ✅ Sistema completo de análisis TLS con cálculo de grades
- ✅ Detección avanzada de servicios (patrón, puertos, DNS)
- ✅ Resolución de providers con múltiples estrategias
- ✅ Creación de nodos Certificate/Service/Provider en tiempo real
- ✅ Clasificación de industrias para dominios
- ✅ Scoring de riesgo mejorado y cálculo de tiers
- ✅ Clasificación de providers con machine learning

**Debilidades identificadas:**
- ❌ Código monolítico difícil de mantener
- ❌ No modular para uso en APIs
- ❌ Falta integración con análisis MX
- ❌ Configuración hardcodeada

### Versión v5.0 (1,064 líneas)
**Fortalezas identificadas:**
- ✅ Detección inteligente de providers desde metadata
- ✅ Extracción mejorada de TLD desde códigos de país
- ✅ Nombrado de providers basado en metadata
- ✅ Normalización de nombres de providers
- ✅ Scoring de confianza mejorado
- ✅ Mapeo de TLD basado en países
- ✅ Resolución de providers basada en ASN

**Debilidades identificadas:**
- ❌ Funcionalidades incompletas (falta TLS, servicios, riesgos)
- ❌ Menos análisis comprehensivo que v4
- ❌ Documentación limitada

## 🏗️ Nueva Arquitectura v6.0 Unificada

### Componentes Principales

#### 1. **Motor de Descubrimiento Unificado** (`subdomain_relationship_discovery_unified.py`)

```python
class UnifiedSubdomainDiscoverer:
    """Motor principal que consolida v4 + v5"""
    
    def __init__(self, config: ProcessingConfig, ...):
        # Inicialización modular con configuración
    
    def discover_and_analyze(self, domain: str) -> DiscoveryResult:
        # Pipeline principal de análisis
```

**Características principales:**
- 🔧 **Configuración modular**: `ProcessingConfig` para habilitar/deshabilitar features
- 🏃 **Pipeline asíncrono**: Soporte para ejecución async/await
- 📊 **Resultados estructurados**: `DiscoveryResult` con métricas y metadatos
- 🔌 **Arquitectura pluggable**: Fácil agregar nuevos analizadores

#### 2. **Servicio REST** (`subdomain_discovery_api.py`)

```python
@app.get("/api/v1/discoveryWithProviders/{domain}")
async def discovery_with_providers(domain: str, ...):
    # Endpoint específico con providers habilitados
```

**Endpoints implementados:**
- 🟢 `GET /api/v1/discovery/{domain}` - Descubrimiento básico
- 🟡 `GET /api/v1/discoveryWithProviders/{domain}` - Con detección de providers
- 🟠 `GET /api/v1/discoveryWithServices/{domain}` - Con detección de servicios  
- 🔴 `GET /api/v1/discoveryWithServicesAndProviders/{domain}` - Servicios + Providers
- 🟣 `GET /api/v1/discoveryWithTLS/{domain}` - Con análisis TLS
- ⚫ `GET /api/v1/discoveryWithRisk/{domain}` - Con análisis de riesgos
- 🌟 `GET /api/v1/discoveryComplete/{domain}` - Análisis completo

**Características del API:**
- 📖 **Swagger/OpenAPI**: Documentación automática en `/docs`
- ⚡ **Jobs asíncronos**: Endpoints para procesos largos
- 🎛️ **Query parameters**: Timeouts y configuraciones via URL
- 🔧 **Boolean flags**: Features habilitadas via paths URL
- 📊 **Monitoreo**: Health checks y métricas

### Integración de Funcionalidades

#### De v4.0 → v6.0:
```python
# Análisis TLS completo
def _analyze_certificates(self, domain: str, subdomains: List[str]) -> List[Dict[str, Any]]:
    # Conserva la lógica completa de v4 para TLS

# Detección de servicios avanzada  
def _detect_services_by_ports(self, domain: str, ip_addresses: List[str]) -> List[Dict[str, Any]]:
    # Port scanning de v4

# Análisis de riesgos
def _calculate_risks(self, domain: str) -> List[Dict[str, Any]]:
    # Integra con DomainRiskCalculator de v4
```

#### De v5.0 → v6.0:
```python
# Resolución mejorada de providers
class EnhancedProviderResolver:
    def _extract_provider_from_metadata(self, metadata: Dict) -> Optional[ProviderInfo]:
        # Lógica v5 para metadata
    
    def _consolidate_provider_results(self, providers: List[ProviderInfo]) -> ProviderInfo:
        # Mejoras de confidence scoring de v5

# TLD Manager mejorado
class TLDManager:
    def classify_tld(self, tld: str) -> Dict[str, Any]:
        # Mapeo completo país-TLD de v5
```

#### Nuevas integraciones v6.0:
```python
# Integración con provider_detection.py
if self.config.enable_mx_analysis and self.provider_detector:
    mx_providers = self.provider_detector.analyze_domain_dependencies(domain)
    
# Integración con risk_score_updater.py  
if self.config.enable_risk_calculation and self.risk_calculator:
    risks = self.risk_calculator.calculate_domain_risks(domain)
```

## 🚀 Instalación y Configuración

### 1. Instalar Dependencias

```bash
# Navegar al directorio
cd /home/alf/dev/tsunami-beta/risk-graph-loader/app

# Instalar dependencias API
pip install -r requirements_api.txt

# Verificar Neo4j está corriendo
docker ps | grep neo4j
```

### 2. Configurar Variables de Entorno

```bash
# Crear archivo .env
cat > .env << EOF
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASS=test.password
IPINFO_TOKEN=your_token_here
EOF
```

### 3. Ejecutar el Servicio

```bash
# Ejecutar servidor de desarrollo
python subdomain_discovery_api.py

# O usando uvicorn directamente
uvicorn subdomain_discovery_api:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Verificar Instalación

```bash
# Health check
curl http://localhost:8000/health

# Ver documentación Swagger
# Abrir http://localhost:8000/docs en navegador
```

## 📚 Guía de Uso del API

### Ejemplos de Llamadas

#### 1. Descubrimiento Básico
```bash
curl "http://localhost:8000/api/v1/discovery/bice.cl?amassTimeout=300&maxSubdomains=100"
```

#### 2. Con Detección de Providers
```bash
curl "http://localhost:8000/api/v1/discoveryWithProviders/bice.cl?timeout=60"
```

#### 3. Análisis Completo
```bash
curl "http://localhost:8000/api/v1/discoveryComplete/bice.cl?amassTimeout=600&maxSubdomains=500&workers=5"
```

#### 4. Job Asíncrono
```bash
# Iniciar job
JOB_ID=$(curl -X POST "http://localhost:8000/api/v1/jobs/discovery/bice.cl?enableProviders=true&enableServices=true" | jq -r '.job_id')

# Verificar status
curl "http://localhost:8000/api/v1/jobs/$JOB_ID"
```

#### 5. Análisis Específicos
```bash
# Solo providers
curl "http://localhost:8000/api/v1/analysis/providers/bice.cl?includeMx=true"

# Solo servicios
curl "http://localhost:8000/api/v1/analysis/services/bice.cl?includePortScan=false"

# Solo TLS
curl "http://localhost:8000/api/v1/analysis/tls/bice.cl"
```

### Parámetros de Configuración

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `amassTimeout` | int | 300 | Timeout de Amass en segundos |
| `maxSubdomains` | int | 1000 | Máximo subdominios a procesar |
| `maxWorkers` | int | 10 | Threads máximos |
| `timeoutPerSubdomain` | int | 30-90 | Timeout por subdominio |
| `saveToNeo4j` | bool | true | Guardar en Neo4j |

### Endpoints por Funcionalidad

| URL Pattern | Funcionalidades Habilitadas |
|-------------|----------------------------|
| `/discovery/` | Solo Amass |
| `/discoveryWithProviders/` | Amass + Providers + MX |
| `/discoveryWithServices/` | Amass + Services |
| `/discoveryWithServicesAndProviders/` | Amass + Services + Providers + MX |
| `/discoveryWithTLS/` | Amass + TLS |
| `/discoveryWithRisk/` | Amass + Risk + Providers + MX |
| `/discoveryComplete/` | Todas las funcionalidades |

## 🔧 Arquitectura Técnica Detallada

### Clases Principales

```python
@dataclass
class ProcessingConfig:
    """Configuración modular del pipeline"""
    enable_amass: bool = True
    enable_tls_analysis: bool = False
    enable_service_detection: bool = False
    enable_provider_detection: bool = False
    enable_risk_calculation: bool = False
    # ... más opciones

@dataclass  
class DiscoveryResult:
    """Resultado estructurado del análisis"""
    domain: str
    subdomains: List[str]
    providers: List[ProviderInfo]
    services: List[Dict[str, Any]]
    certificates: List[Dict[str, Any]]
    risks: List[Dict[str, Any]]
    processing_time: float
    errors: List[str]

@dataclass
class ProviderInfo:
    """Información mejorada de providers"""
    name: str
    confidence: float
    source: str
    tld: Optional[str] = None
    country: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
```

### Pipeline de Procesamiento

```python
async def discover_and_analyze(self, domain: str) -> DiscoveryResult:
    # 1. Descubrimiento de subdominios (Amass)
    if self.config.enable_subdomain_enumeration:
        result.subdomains = self._discover_subdomains(domain)
    
    # 2. Detección de providers (IP + MX)
    if self.config.enable_provider_detection:
        result.providers = self._analyze_providers(domain, result.subdomains)
    
    # 3. Detección de servicios (patrón + puertos + DNS)
    if self.config.enable_service_detection:
        result.services = self._analyze_services(domain, result.subdomains)
    
    # 4. Análisis TLS
    if self.config.enable_tls_analysis:
        result.certificates = self._analyze_certificates(domain, result.subdomains)
    
    # 5. Clasificación de industria
    if self.config.enable_industry_classification:
        result.industry_classification = self._classify_industry(domain)
    
    # 6. Análisis de riesgos
    if self.config.enable_risk_calculation:
        result.risks = self._calculate_risks(domain)
    
    # 7. Guardar en Neo4j
    if self.config.save_to_neo4j:
        self._save_to_neo4j(result)
```

## 🔄 Integración con Componentes Existentes

### 1. Provider Detection Integration
```python
# Se integra automáticamente provider_detection.py
from provider_detection import ProviderDetector

# Análisis MX habilitado por configuración
if self.config.enable_mx_analysis and self.provider_detector:
    mx_providers = self.provider_detector.analyze_domain_dependencies(domain)
```

### 2. Risk Calculator Integration  
```python
# Se integra risk_score_updater.py y domain_risk_calculator.py
from domain_risk_calculator import DomainRiskCalculator

# Cálculo de riesgos habilitado por configuración
if self.config.enable_risk_calculation and self.risk_calculator:
    risks = self.risk_calculator.calculate_domain_risks(domain)
```

### 3. Neo4j Consistency
```python
# Mantiene compatibilidad con esquema existente
def _save_to_neo4j(self, result: DiscoveryResult):
    # Guarda usando mismas estructuras que v4/v5
    # Providers, Services, Certificates, Risks, etc.
```

## 📊 Mejoras de Performance

### 1. Procesamiento Asíncrono
- ✅ Pipeline async/await para mejor concurrencia
- ✅ ThreadPoolExecutor para operaciones I/O
- ✅ Timeouts configurables por operación

### 2. Configuración Granular
- ✅ Habilitar/deshabilitar features específicas
- ✅ Límites configurables (subdominios, workers, timeouts)
- ✅ Optimización de recursos según necesidades

### 3. Caching y Optimizaciones
- ✅ Resultados estructurados para evitar reprocesamiento
- ✅ Validación temprana de inputs
- ✅ Logging detallado para debugging

## 🐛 Debugging y Monitoreo

### Logs Estructurados
```python
# Logs detallados en cada etapa
logger.info(f"Starting discovery and analysis for {domain}")
logger.info(f"Discovered {len(result.subdomains)} subdomains")
logger.info(f"Detected {len(result.providers)} providers")
```

### Health Checks
```bash
# Verificar estado del servicio
curl http://localhost:8000/health

# Verificar configuración
curl http://localhost:8000/api/v1/status

# Listar jobs activos
curl http://localhost:8000/api/v1/jobs
```

### Métricas de Performance
```json
{
  "processing_time": 45.2,
  "subdomains_discovered": 156,
  "providers_detected": 8,
  "services_detected": 12,
  "certificates_analyzed": 23,
  "errors": []
}
```

## 🧪 Testing y Validación

### Tests de Integración
```bash
# Test básico
curl "http://localhost:8000/api/v1/discovery/test.com"

# Test con providers
curl "http://localhost:8000/api/v1/discoveryWithProviders/bice.cl"

# Test análisis completo
curl "http://localhost:8000/api/v1/discoveryComplete/bice.cl?amassTimeout=60&maxSubdomains=10"
```

### Validación de Resultados
```bash
# Verificar providers detectados
curl "http://localhost:8000/api/v1/analysis/providers/bice.cl" | jq '.providers[].name'

# Verificar servicios
curl "http://localhost:8000/api/v1/analysis/services/bice.cl" | jq '.services[].type'
```

## 📈 Casos de Uso

### 1. Análisis Rápido de Providers
```bash
# Para verificar qué providers usa un dominio
curl "http://localhost:8000/api/v1/analysis/providers/example.com?includeMx=true"
```

### 2. Auditoría Completa de Seguridad
```bash
# Análisis completo para auditoría
curl "http://localhost:8000/api/v1/discoveryComplete/target.com?amassTimeout=900&maxSubdomains=2000"
```

### 3. Monitoreo Continuo
```bash
# Job asíncrono para monitoreo
curl -X POST "http://localhost:8000/api/v1/jobs/discovery/target.com?enableRisk=true&enableProviders=true"
```

### 4. Investigación de Subdominios
```bash
# Solo descubrimiento para investigación inicial
curl "http://localhost:8000/api/v1/discovery/target.com?amassTimeout=600&maxSubdomains=5000"
```

## 🔒 Consideraciones de Seguridad

### 1. Rate Limiting
- ✅ Máximo de jobs concurrentes configurable
- ✅ Timeouts para prevenir recursos colgados
- ✅ Validación de inputs

### 2. Configuración Segura
```python
# Passwords no expuestos en /config endpoint
"ipinfo_configured": bool(api_config.ipinfo_token)  # Solo boolean
```

### 3. Error Handling
```python
# Manejo seguro de errores
@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}")
    # No expone detalles internos
```

## 🚀 Próximos Pasos y Roadmap

### Funcionalidades Planificadas
1. **Caché distribuido** - Redis para resultados
2. **Autenticación** - API keys y JWT
3. **Rate limiting avanzado** - Por usuario/IP
4. **Webhooks** - Notificaciones de jobs completados
5. **Métricas avanzadas** - Prometheus/Grafana
6. **Análisis ML** - Detección automática de patrones

### Optimizaciones Técnicas
1. **Containerización** - Docker compose completo
2. **Load balancing** - Múltiples instancias
3. **Database pooling** - Conexiones Neo4j optimizadas
4. **Stream processing** - Resultados en tiempo real

## 📞 Soporte y Mantenimiento

### Archivos Principales
- `subdomain_relationship_discovery_unified.py` - Motor principal
- `subdomain_discovery_api.py` - Servicio REST
- `requirements_api.txt` - Dependencias
- `REFACTORING_DOCUMENTATION.md` - Esta documentación

### Contacto y Issues
- Para issues: Crear ticket describiendo el problema
- Para nuevas features: Proponer mediante issue con label "enhancement"
- Para performance: Incluir métricas y casos de uso específicos

---

**Versión**: 6.0.0  
**Fecha**: 2025-08-02  
**Autor**: Sistema de Refactoring Automático  
**Status**: ✅ Completado y funcional