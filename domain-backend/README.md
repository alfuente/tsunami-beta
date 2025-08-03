# Domain Backend

REST API unificada para análisis de dominios con capacidades avanzadas de seguridad.

## Características

- 🔍 **Descubrimiento de subdominios** con Amass
- 🏢 **Detección de providers** (IP + MX records)  
- 🛡️ **Análisis de servicios** (pattern + port scanning)
- 🔐 **Evaluación TLS** completa
- ⚠️ **Cálculo de riesgo** según Risk.md
- 🔄 **Jobs asíncronos** para procesos largos
- 📊 **Integración Neo4j** para persistencia

## Inicio Rápido

```bash
# Instalar dependencias
pip install -r requirements_api.txt

# Configurar variables de entorno  
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASS="test.password"

# Iniciar API
python subdomain_discovery_api.py
```

## Gestión con manage-services.sh

```bash
# Desde la raíz del proyecto
./manage-services.sh start-discovery  # Iniciar domain-backend
./manage-services.sh logs discovery   # Ver logs
./manage-services.sh status           # Verificar estado
./manage-services.sh stop-discovery   # Parar servicio
```

## Testing

```bash
# Validación rápida (2 minutos)
./test_quick_validation.sh

# Suite completa (30-60 minutos)  
./test_domain_backend.sh

# Pruebas de riesgo (15 minutos)
./test_risk_analysis.sh

# Ver ejemplos
./curl_examples.sh
```

## Documentación

- **Documentación completa**: `DOMAIN_BACKEND_DOCUMENTATION.md`
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Endpoints Principales

- `GET /api/v1/discovery/{domain}` - Descubrimiento básico
- `GET /api/v1/discoveryWithProviders/{domain}` - Con providers
- `GET /api/v1/analysis/risk/{domain}` - Análisis de riesgo (Risk.md)
- `GET /api/v1/discoveryComplete/{domain}` - Análisis completo

## Arquitectura

```
domain-backend/
├── subdomain_discovery_api.py          # API principal
├── subdomain_relationship_discovery_unified.py  # Motor unificado
├── risk_score_updater.py               # Cálculo riesgo Risk.md
├── provider_detection.py               # Detección providers
├── domain_risk_calculator.py           # Calculadora riesgos
├── test_*.sh                          # Scripts de testing
├── requirements_api.txt               # Dependencias
└── DOMAIN_BACKEND_DOCUMENTATION.md   # Documentación completa
```