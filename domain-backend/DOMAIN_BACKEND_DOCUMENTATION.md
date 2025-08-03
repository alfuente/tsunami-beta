# Domain Backend API - Documentación Completa

## 📋 Resumen Ejecutivo

El **Domain Backend** es una API REST unificada que proporciona capacidades avanzadas de análisis de dominios, incluyendo descubrimiento de subdominios, detección de providers, análisis de servicios, evaluación TLS y cálculo de riesgo según las especificaciones de `Risk.md`.

### Características Principales

- 🔍 **Descubrimiento de subdominios** con Amass
- 🏢 **Detección de providers** (IP + MX records)
- 🛡️ **Análisis de servicios** (pattern matching + port scanning)
- 🔐 **Evaluación TLS** completa
- ⚠️ **Cálculo de riesgo** según Risk.md (4 componentes)
- 🔄 **Jobs asíncronos** para procesos largos
- 📊 **Integración Neo4j** para persistencia
- 📖 **Documentación Swagger** interactiva

---

## 🚀 Inicio Rápido

### Prerequisitos

- Python 3.8+
- Neo4j Database
- Amass (para descubrimiento de subdominios)

### Instalación y Configuración

```bash
# 1. Navegar al directorio
cd risk-graph-loader/app

# 2. Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements_api.txt

# 4. Configurar variables de entorno
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASS="test.password"
export IPINFO_TOKEN="your_token_here"  # Opcional

# 5. Iniciar el servicio
python subdomain_discovery_api.py
```

### Usando manage-services.sh

```bash
# Iniciar Domain Backend
./manage-services.sh start-discovery

# Ver logs
./manage-services.sh logs discovery

# Verificar status
./manage-services.sh status

# Parar servicio
./manage-services.sh stop-discovery
```

### Verificación de Instalación

```bash
# Health check
curl http://localhost:8000/health

# Swagger UI
open http://localhost:8000/docs
```

---

## 📚 Arquitectura de la API

### URL Base
```
http://localhost:8000
```

### Estructura de Endpoints

```
/api/v1/
├── discovery/               # Descubrimiento básico
├── discoveryWithProviders/  # Con detección de providers
├── discoveryWithServices/   # Con detección de servicios
├── discoveryWithServicesAndProviders/  # Combinado
├── discoveryWithTLS/        # Con análisis TLS
├── discoveryWithRisk/       # Con análisis de riesgo
├── discoveryComplete/       # Análisis completo
├── analysis/
│   ├── providers/           # Solo análisis de providers
│   ├── services/            # Solo análisis de servicios
│   ├── tls/                # Solo análisis TLS
│   └── risk/               # Solo análisis de riesgo
├── jobs/                   # Gestión de jobs asíncronos
├── config/                 # Configuración del API
└── status/                 # Estado del sistema
```

---

## 🔍 Endpoints de Descubrimiento

### 1. Descubrimiento Básico

**Endpoint:** `GET /api/v1/discovery/{domain}`

Realiza descubrimiento básico de subdominios usando Amass.

#### Parámetros de Query

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `amassTimeout` | int | 300 | Timeout de Amass en segundos |
| `maxSubdomains` | int | 1000 | Máximo subdominios a descubrir |
| `maxWorkers` | int | 10 | Threads máximos |
| `saveToNeo4j` | bool | true | Guardar resultados en Neo4j |
| `timeoutPerSubdomain` | int | 30 | Timeout por subdominio |

#### Ejemplo de Uso

```bash
# Descubrimiento básico
curl "http://localhost:8000/api/v1/discovery/bice.cl?amassTimeout=120&maxSubdomains=50"

# Con configuración personalizada
curl "http://localhost:8000/api/v1/discovery/example.com?amassTimeout=60&maxSubdomains=20&maxWorkers=5&saveToNeo4j=false"
```

#### Respuesta Ejemplo

```json
{
  "domain": "bice.cl",
  "subdomains": [
    "www.bice.cl",
    "mail.bice.cl",
    "api.bice.cl",
    "cdn.bice.cl"
  ],
  "providers": [],
  "services": [],
  "certificates": [],
  "risks": [],
  "processing_time": 45.2,
  "errors": []
}
```

### 2. Descubrimiento con Providers

**Endpoint:** `GET /api/v1/discoveryWithProviders/{domain}`

Incluye detección de providers mediante análisis de IPs y registros MX.

#### Ejemplo de Uso

```bash
curl "http://localhost:8000/api/v1/discoveryWithProviders/bice.cl?amassTimeout=120&maxSubdomains=30"
```

#### Respuesta Ejemplo

```json
{
  "domain": "bice.cl",
  "subdomains": ["www.bice.cl", "mail.bice.cl"],
  "providers": [
    {
      "name": "cloudflare",
      "confidence": 0.95,
      "source": "ip_analysis",
      "country": "US",
      "provider_type": "cdn"
    },
    {
      "name": "microsoft_365",
      "confidence": 0.90,
      "source": "mx_record",
      "country": "US",
      "provider_type": "email"
    }
  ],
  "processing_time": 67.8,
  "errors": []
}
```

### 3. Descubrimiento con Servicios

**Endpoint:** `GET /api/v1/discoveryWithServices/{domain}`

Incluye detección de servicios mediante pattern matching y port scanning.

#### Ejemplo de Uso

```bash
curl "http://localhost:8000/api/v1/discoveryWithServices/bice.cl?amassTimeout=120&maxSubdomains=20"
```

### 4. Descubrimiento Combinado

**Endpoint:** `GET /api/v1/discoveryWithServicesAndProviders/{domain}`

Combina detección de providers y servicios.

#### Ejemplo de Uso

```bash
curl "http://localhost:8000/api/v1/discoveryWithServicesAndProviders/bice.cl?amassTimeout=180&maxSubdomains=25"
```

### 5. Descubrimiento con TLS

**Endpoint:** `GET /api/v1/discoveryWithTLS/{domain}`

Incluye análisis completo de certificados TLS.

#### Ejemplo de Uso

```bash
curl "http://localhost:8000/api/v1/discoveryWithTLS/bice.cl?amassTimeout=120&maxSubdomains=15"
```

### 6. Descubrimiento con Análisis de Riesgo

**Endpoint:** `GET /api/v1/discoveryWithRisk/{domain}`

Incluye cálculo de riesgo según especificaciones de Risk.md.

#### Ejemplo de Uso

```bash
curl "http://localhost:8000/api/v1/discoveryWithRisk/bice.cl?amassTimeout=120&maxSubdomains=15"
```

### 7. Análisis Completo

**Endpoint:** `GET /api/v1/discoveryComplete/{domain}`

Ejecuta todas las funcionalidades: subdominios, providers, servicios, TLS y riesgo.

#### Ejemplo de Uso

```bash
curl "http://localhost:8000/api/v1/discoveryComplete/bice.cl?amassTimeout=300&maxSubdomains=50&maxWorkers=8"
```

---

## 🔬 Endpoints de Análisis Específico

### 1. Análisis de Providers

**Endpoint:** `GET /api/v1/analysis/providers/{domain}`

Analiza únicamente los providers sin descubrimiento completo.

#### Parámetros de Query

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `includeMx` | bool | true | Incluir análisis de registros MX |
| `timeout` | int | 60 | Timeout en segundos |

#### Ejemplo de Uso

```bash
# Con análisis MX
curl "http://localhost:8000/api/v1/analysis/providers/bice.cl?includeMx=true&timeout=60"

# Sin análisis MX
curl "http://localhost:8000/api/v1/analysis/providers/bice.cl?includeMx=false&timeout=30"
```

#### Respuesta Ejemplo

```json
{
  "domain": "bice.cl",
  "providers": [
    {
      "name": "cloudflare",
      "confidence": 0.95,
      "source": "ip_analysis",
      "country": "US",
      "provider_type": "cdn"
    }
  ],
  "processing_time": 23.4
}
```

### 2. Análisis de Servicios

**Endpoint:** `GET /api/v1/analysis/services/{domain}`

#### Parámetros de Query

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `includePortScan` | bool | false | Incluir port scanning |
| `timeout` | int | 60 | Timeout en segundos |

#### Ejemplo de Uso

```bash
# Con port scanning
curl "http://localhost:8000/api/v1/analysis/services/bice.cl?includePortScan=true&timeout=90"

# Solo pattern matching
curl "http://localhost:8000/api/v1/analysis/services/bice.cl?includePortScan=false&timeout=30"
```

### 3. Análisis TLS

**Endpoint:** `GET /api/v1/analysis/tls/{domain}`

#### Ejemplo de Uso

```bash
curl "http://localhost:8000/api/v1/analysis/tls/bice.cl?timeout=60"
```

### 4. Análisis de Riesgo (Risk.md)

**Endpoint:** `GET /api/v1/analysis/risk/{domain}`

Calcula el score de riesgo según las especificaciones exactas de Risk.md.

#### Parámetros de Query

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `timeout` | int | 60 | Timeout en segundos |
| `updateNeo4j` | bool | true | Actualizar scores en Neo4j |

#### Ejemplo de Uso

```bash
# Con actualización en Neo4j
curl "http://localhost:8000/api/v1/analysis/risk/bice.cl?timeout=120&updateNeo4j=true"

# Solo lectura
curl "http://localhost:8000/api/v1/analysis/risk/bice.cl?timeout=60&updateNeo4j=false"
```

#### Respuesta Ejemplo

```json
{
  "domain": "bice.cl",
  "final_score": 67.5,
  "tier": "High",
  "base_tech_score": 45.0,
  "third_party_score": 72.0,
  "incident_impact_score": 80.0,
  "context_boost_score": 15.0,
  "calculation_details": {
    "base_tech_details": {
      "dns_score": 20,
      "tls_score": -5,
      "cve_penalty": -15,
      "redundancy_bonus": 10
    },
    "third_party_details": {
      "critical_exposures": 2,
      "important_exposures": 1,
      "weighted_score": 72.0
    },
    "incident_details": {
      "recent_incidents": 1,
      "severity_impact": 80.0,
      "temporal_decay": 0.85
    },
    "context_details": {
      "certifications": ["ISO27001"],
      "boost_score": 15.0
    },
    "processing_time": 3.2
  },
  "calculated_at": "2025-08-03T15:30:45.123Z"
}
```

---

## ⚙️ Componentes de Análisis de Riesgo

### Fórmula de Cálculo (Risk.md)

```
Final Score = (Base Tech × 0.40) + (Third-Party × 0.25) + (Incident Impact × 0.30) + (Context Boost × 0.05)
```

### 1. Base Tech Score (40%)

Evalúa la seguridad técnica básica del dominio.

#### Componentes:
- **DNS Analysis**
  - DNSSEC habilitado: +20 puntos
  - Single Name Server: -15 puntos
- **TLS Grades**
  - A+/A: 0 puntos
  - B: -5 puntos
  - C: -15 puntos
  - D/E/F: -30 puntos
- **CVE Penalties**
  - Critical CVEs: multiplicador ×5
  - High CVEs: multiplicador ×3
  - Penalty máximo: -25 puntos
- **Redundancy Bonus**
  - Múltiples servidores/IPs: +10 puntos

### 2. Third-Party Score (25%)

Evalúa el riesgo de dependencias de terceros.

#### Componentes:
- **Exposure Weights**
  - Critical dependencies: peso 1.0
  - Important dependencies: peso 0.6
  - Nice-to-have dependencies: peso 0.3
- **Depth Analysis**
  - Máxima profundidad: 2 niveles
  - Atenuación por profundidad: 0.8

### 3. Incident Impact (30%)

Evalúa el impacto de incidentes de seguridad.

#### Componentes:
- **Severity Scores** con decaimiento temporal
- **Lambda de decaimiento**: 0.015
- **Half-life**: 46 días
- Incidentes recientes tienen mayor peso

### 4. Context Boost (5%)

Evalúa certificaciones y controles compensatorios.

#### Componentes:
- Certificaciones de seguridad (ISO27001, SOC2, etc.)
- Controles compensatorios implementados
- Programas de bug bounty

### Risk Tiers

| Tier | Score Range | Descripción |
|------|-------------|-------------|
| **Low** | 0-30 | Riesgo bajo, configuración segura |
| **Medium** | 31-60 | Riesgo moderado, mejoras recomendadas |
| **High** | 61-80 | Riesgo alto, acción requerida |
| **Critical** | 81-100 | Riesgo crítico, acción inmediata |

---

## 🔄 Jobs Asíncronos

Para análisis que pueden tomar mucho tiempo, el API proporciona un sistema de jobs asíncronos.

### Crear Job

**Endpoint:** `POST /api/v1/jobs/discovery/{domain}`

#### Parámetros de Query

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `enableProviders` | bool | false | Habilitar detección de providers |
| `enableServices` | bool | false | Habilitar detección de servicios |
| `enableTls` | bool | false | Habilitar análisis TLS |
| `enableRisk` | bool | false | Habilitar análisis de riesgo |
| `enableMx` | bool | false | Habilitar análisis MX |
| `amassTimeout` | int | 300 | Timeout de Amass |
| `maxSubdomains` | int | 1000 | Máximo subdominios |
| `saveToNeo4j` | bool | true | Guardar en Neo4j |

#### Ejemplo de Uso

```bash
# Crear job completo
curl -X POST "http://localhost:8000/api/v1/jobs/discovery/bice.cl?enableProviders=true&enableServices=true&enableTls=true&enableRisk=true&enableMx=true&amassTimeout=300&maxSubdomains=100"

# Respuesta
{
  "job_id": "123e4567-e89b-12d3-a456-426614174000",
  "status": "started",
  "domain": "bice.cl"
}
```

### Verificar Status de Job

**Endpoint:** `GET /api/v1/jobs/{job_id}`

```bash
curl "http://localhost:8000/api/v1/jobs/123e4567-e89b-12d3-a456-426614174000"

# Respuesta
{
  "job_id": "123e4567-e89b-12d3-a456-426614174000",
  "status": "running",
  "domain": "bice.cl",
  "started_at": "2025-08-03T15:30:00Z",
  "progress": 65,
  "result": null
}
```

### Listar Jobs

**Endpoint:** `GET /api/v1/jobs`

```bash
curl "http://localhost:8000/api/v1/jobs?limit=20"
```

### Eliminar Job

**Endpoint:** `DELETE /api/v1/jobs/{job_id}`

```bash
curl -X DELETE "http://localhost:8000/api/v1/jobs/123e4567-e89b-12d3-a456-426614174000"
```

---

## ⚙️ Configuración y Administración

### Ver Configuración Actual

**Endpoint:** `GET /api/v1/config`

```bash
curl "http://localhost:8000/api/v1/config"

# Respuesta
{
  "neo4j_uri": "bolt://localhost:7687",
  "neo4j_user": "neo4j",
  "max_concurrent_jobs": 10,
  "default_amass_timeout": 300,
  "default_max_subdomains": 1000,
  "default_workers": 10,
  "ipinfo_configured": true
}
```

### Actualizar Configuración

**Endpoint:** `POST /api/v1/config`

```bash
curl -X POST "http://localhost:8000/api/v1/config" \
  -H "Content-Type: application/json" \
  -d '{
    "default_amass_timeout": 600,
    "default_max_subdomains": 2000,
    "max_concurrent_jobs": 15
  }'
```

### Status del Sistema

**Endpoint:** `GET /api/v1/status`

```bash
curl "http://localhost:8000/api/v1/status"

# Respuesta
{
  "version": "6.0.0",
  "discovery_engine": true,
  "active_jobs": 3,
  "max_concurrent_jobs": 10,
  "default_config": {
    "amass_timeout": 300,
    "max_subdomains": 1000,
    "workers": 10
  }
}
```

### Health Check

**Endpoint:** `GET /health`

```bash
curl "http://localhost:8000/health"

# Respuesta
{
  "status": "healthy",
  "timestamp": "2025-08-03T15:30:45.123Z",
  "discovery_engine_available": true,
  "active_jobs": 3
}
```

---

## 📖 Documentación Interactiva

### Swagger UI

Accede a la documentación interactiva completa:

```
http://localhost:8000/docs
```

### ReDoc

Documentación alternativa con ReDoc:

```
http://localhost:8000/redoc
```

### OpenAPI Schema

Obtener el schema completo de la API:

```bash
curl "http://localhost:8000/openapi.json"
```

---

## 🧪 Testing y Validación

### Scripts de Prueba Incluidos

#### 1. Validación Rápida
```bash
./test_quick_validation.sh
```
Pruebas básicas de funcionalidad (2-3 minutos).

#### 2. Suite Completa
```bash
./test_domain_backend.sh
```
Pruebas exhaustivas de todos los endpoints (30-60 minutos).

#### 3. Análisis de Riesgo
```bash
./test_risk_analysis.sh
```
Pruebas específicas del cálculo de riesgo según Risk.md (15-20 minutos).

#### 4. Ejemplos de curl
```bash
./curl_examples.sh
```
Muestra ejemplos de uso para todos los endpoints.

### Pruebas Manuales Rápidas

```bash
# 1. Health check
curl http://localhost:8000/health

# 2. Análisis básico
curl "http://localhost:8000/api/v1/discovery/example.com?amassTimeout=60&maxSubdomains=5"

# 3. Análisis de riesgo
curl "http://localhost:8000/api/v1/analysis/risk/example.com?updateNeo4j=false"

# 4. Providers
curl "http://localhost:8000/api/v1/analysis/providers/example.com?includeMx=true"
```

---

## 🔧 Troubleshooting

### Problemas Comunes

#### 1. API no responde
```bash
# Verificar si el servicio está corriendo
./manage-services.sh status

# Ver logs
./manage-services.sh logs discovery

# Reiniciar servicio
./manage-services.sh restart-discovery
```

#### 2. Errores de Neo4j
```bash
# Verificar conexión Neo4j
docker ps | grep neo4j

# Verificar variables de entorno
echo $NEO4J_URI
echo $NEO4J_USER
```

#### 3. Timeouts en análisis
```bash
# Aumentar timeouts para dominios complejos
curl "http://localhost:8000/api/v1/discovery/complex-domain.com?amassTimeout=600&maxSubdomains=2000"
```

#### 4. Dependencias faltantes
```bash
# Reinstalar dependencias
cd risk-graph-loader/app
source venv/bin/activate
pip install -r requirements_api.txt
```

### Logs y Debugging

```bash
# Ver logs en tiempo real
tail -f discovery-api-dev.log

# Logs con timestamps
./manage-services.sh logs discovery

# Debug de endpoint específico
curl -v "http://localhost:8000/api/v1/status"
```

---

## 📊 Integración con Neo4j

### Estructura de Datos

El Domain Backend guarda los siguientes tipos de nodos en Neo4j:

- **Domain** - Dominio principal
- **Subdomain** - Subdominios descubiertos
- **Provider** - Providers identificados
- **Service** - Servicios detectados
- **Certificate** - Certificados TLS
- **Risk** - Scores de riesgo calculados

### Consultas Ejemplo

```cypher
// Obtener todos los subdominios de un dominio
MATCH (d:Domain {name: "bice.cl"})-[:HAS_SUBDOMAIN]->(s:Subdomain)
RETURN s.name

// Obtener providers de un dominio
MATCH (d:Domain {name: "bice.cl"})-[:USES_PROVIDER]->(p:Provider)
RETURN p.name, p.confidence

// Obtener score de riesgo
MATCH (d:Domain {name: "bice.cl"})-[:HAS_RISK]->(r:Risk)
RETURN r.final_score, r.tier, r.calculated_at
```

---

## 🚀 Casos de Uso Prácticos

### 1. Investigación de Dominio Básica

```bash
# Descubrimiento rápido para investigación inicial
curl "http://localhost:8000/api/v1/discovery/target.com?amassTimeout=60&maxSubdomains=20"

# Ver solo providers
curl "http://localhost:8000/api/v1/analysis/providers/target.com?includeMx=true" | jq '.providers[].name'
```

### 2. Auditoría de Seguridad Completa

```bash
# Análisis completo para auditoría
curl "http://localhost:8000/api/v1/discoveryComplete/target.com?amassTimeout=600&maxSubdomains=500"

# Análisis de riesgo detallado
curl "http://localhost:8000/api/v1/analysis/risk/target.com?updateNeo4j=true"
```

### 3. Monitoreo Continuo

```bash
# Job asíncrono para monitoreo regular
JOB_ID=$(curl -s -X POST "http://localhost:8000/api/v1/jobs/discovery/target.com?enableProviders=true&enableRisk=true" | jq -r '.job_id')

# Verificar progreso
curl "http://localhost:8000/api/v1/jobs/$JOB_ID"
```

### 4. Análisis de Riesgo Empresarial

```bash
# Calcular riesgo de múltiples dominios
for domain in domain1.com domain2.com domain3.com; do
  echo "Analyzing $domain..."
  curl "http://localhost:8000/api/v1/analysis/risk/$domain?updateNeo4j=true" | jq '{domain, final_score, tier}'
done
```

---

## 📈 Performance y Optimización

### Configuración de Performance

```bash
# Para análisis rápidos
amassTimeout=60
maxSubdomains=20
maxWorkers=5

# Para análisis completos
amassTimeout=600
maxSubdomains=2000
maxWorkers=10

# Para análisis exhaustivos
amassTimeout=1800
maxSubdomains=5000
maxWorkers=15
```

### Mejores Prácticas

1. **Usar jobs asíncronos** para análisis largos
2. **Ajustar timeouts** según complejidad del dominio
3. **Limitar subdominios** para primeras investigaciones
4. **Usar análisis específicos** cuando solo necesites ciertos datos
5. **Monitorear logs** para identificar problemas

---

## 🔐 Seguridad

### Configuración Segura

```bash
# Variables de entorno recomendadas
export NEO4J_PASS="strong_password_here"
export IPINFO_TOKEN="your_token_here"

# Configurar firewall para puerto 8000
sudo ufw allow 8000/tcp
```

### Rate Limiting

El API incluye límites de concurrencia:
- Máximo 10 jobs simultáneos por defecto
- Timeouts configurables por endpoint
- Validación de parámetros de entrada

---

## 📞 Soporte y Contribución

### Reportar Issues

Para reportar problemas:

1. Ejecutar `./test_quick_validation.sh`
2. Revisar logs: `./manage-services.sh logs discovery`
3. Incluir configuración del sistema
4. Proporcionar ejemplos reproducibles

### Archivos Importantes

- `subdomain_discovery_api.py` - API principal
- `risk_score_updater.py` - Cálculo de riesgo
- `requirements_api.txt` - Dependencias
- `DOMAIN_BACKEND_DOCUMENTATION.md` - Esta documentación

---

## 📄 Changelog

### v6.0.0 (2025-08-03)
- ✅ API REST completa con FastAPI
- ✅ Integración de cálculo de riesgo según Risk.md
- ✅ Jobs asíncronos para procesos largos
- ✅ Documentación Swagger completa
- ✅ Integración con manage-services.sh
- ✅ Scripts de testing completos

### Características v6.0.0
- **Descubrimiento unificado** - Consolida v4 y v5
- **Análisis modular** - Endpoints específicos por funcionalidad  
- **Risk.md compliance** - Cálculo exacto según especificaciones
- **Performance optimizada** - Configuración granular
- **Documentación completa** - Swagger + ejemplos prácticos

---

**🎯 El Domain Backend está listo para producción con todas las funcionalidades de análisis de dominios y cálculo de riesgo empresarial!**