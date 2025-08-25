# Tsunami Beta - Risk Quality Module

El módulo `risk-quality` proporciona herramientas de validación y completitud de datos para el grafo Neo4j de Tsunami Beta. Este módulo asegura que el grafo contenga toda la información requerida según el modelo de datos definido en `docs/Modelo.md`.

## Estructura del Módulo

```
risk-quality/
├── README.md                           # Este archivo
├── graph_validator.py                  # Validador principal del grafo
├── data_completeness_analyzer.py       # Analizador de completitud de datos
└── tasks/                             # Scripts de completado de datos
    ├── complete_subdomains.sh          # Completar descubrimiento de subdominios
    ├── complete_dns_analysis.sh        # Completar análisis DNS
    ├── complete_certificates.sh        # Completar análisis de certificados
    ├── complete_risk_scores.sh         # Completar cálculos de riesgo
    └── run_all_completions.sh          # Script maestro para ejecutar todas las tareas
```

## Scripts de Python

### `graph_validator.py`

Valida que el grafo Neo4j contenga todas las estructuras de datos esperadas según el modelo:

- **Tipos de nodos**: Organization, Domain, DNSServer, Certificate, Service, Provider, Technology, Vulnerability
- **Tipos de relaciones**: OWNS, DEPENDS_ON, RESOLVES_TO, SECURED_BY, PROVIDES, ISSUED_BY, USES_TECH, SUPPLIES_TO, HAS_VULNERABILITY
- **Propiedades requeridas**: Valida que los nodos tengan las propiedades obligatorias
- **Integridad referencial**: Verifica relaciones críticas como dominios sin organizaciones

#### Uso

```bash
# Validación básica
python3 graph_validator.py

# Guardar reporte en archivo JSON
python3 graph_validator.py --output validation_report.json

# Configurar conexión Neo4j personalizada
python3 graph_validator.py --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-password password

# Modo verbose
python3 graph_validator.py --verbose
```

#### Salida del Reporte

```json
{
  "timestamp": "2025-08-25T10:30:00",
  "total_issues": 15,
  "errors": 3,
  "warnings": 8,
  "info": 4,
  "results": [
    {
      "level": "ERROR",
      "category": "Missing DNS Resolution",
      "description": "125 domains without DNS resolution data",
      "details": {"no_dns_count": 125},
      "remediation_action": "Run DNS analysis for domains missing resolution data"
    }
  ]
}
```

### `data_completeness_analyzer.py`

Analiza qué datos faltan en el grafo y genera tareas específicas para completarlos usando el domain-backend:

- **Análisis de gaps**: Identifica dominios sin subdominios, DNS, certificados, etc.
- **Priorización**: Clasifica gaps por criticidad (CRITICAL, HIGH, MEDIUM, LOW)
- **Generación de comandos**: Crea comandos curl específicos para completar cada gap
- **Scripts de completado**: Genera scripts bash ejecutables para automatizar el proceso

#### Uso

```bash
# Análisis de completitud básico
python3 data_completeness_analyzer.py

# Guardar reporte y generar script de completado
python3 data_completeness_analyzer.py --output completeness_report.json --generate-script ./

# Configurar API del domain-backend
python3 data_completeness_analyzer.py --domain-backend http://localhost:8081
```

#### Salida del Reporte

```json
{
  "timestamp": "2025-08-25T10:30:00",
  "total_domains": 500,
  "total_gaps": 25,
  "critical_gaps": 5,
  "high_priority_gaps": 12,
  "gaps_by_type": {
    "subdomain": 8,
    "dns": 5,
    "certificate": 7,
    "technology": 3,
    "risk": 2
  },
  "completion_estimate_hours": 3.5,
  "data_gaps": [...]
}
```

## Scripts de Bash (tasks/)

### `complete_subdomains.sh`

Completa el descubrimiento de subdominios para dominios base que no tienen subdominios asociados.

#### Uso

```bash
# Procesar todos los dominios sin subdominios
./complete_subdomains.sh --all

# Procesar dominio específico
./complete_subdomains.sh --domain example.com

# Procesar dominios desde archivo
./complete_subdomains.sh --file domains.txt

# Configurar concurrencia
./complete_subdomains.sh --all --concurrent 3
```

### `complete_dns_analysis.sh`

Completa el análisis DNS para dominios sin datos de resolución DNS.

#### Uso

```bash
# Procesar todos los dominios sin DNS
./complete_dns_analysis.sh --all

# Procesar en lotes más grandes
./complete_dns_analysis.sh --all --batch-size 100

# Procesar con más concurrencia
./complete_dns_analysis.sh --all --concurrent 5
```

### `complete_certificates.sh`

Completa el análisis de certificados SSL/TLS para dominios sin información de certificados.

#### Uso

```bash
# Procesar todos los dominios sin certificados
./complete_certificates.sh --all

# Verificar certificados próximos a expirar
./complete_certificates.sh --check-expiry

# Procesar con lotes más pequeños (más conservador)
./complete_certificates.sh --all --batch-size 10
```

### `complete_risk_scores.sh`

Completa el cálculo de scores de riesgo para entidades que no tienen valores asignados.

#### Uso

```bash
# Calcular riesgo para todas las entidades
./complete_risk_scores.sh --all

# Calcular solo para dominios
./complete_risk_scores.sh --all --type domain

# Recalcular scores existentes
./complete_risk_scores.sh --all --recalculate

# Ver estadísticas actuales
./complete_risk_scores.sh --stats
```

### `run_all_completions.sh`

Script maestro que ejecuta todos los procesos de completado en el orden correcto.

#### Uso

```bash
# Ejecutar todo el proceso de completado
./run_all_completions.sh

# Ejecutar en paralelo (más rápido)
./run_all_completions.sh --parallel

# Ver qué se ejecutaría sin hacerlo
./run_all_completions.sh --dry-run

# Ejecutar solo tareas específicas
./run_all_completions.sh --only subdomains
./run_all_completions.sh --only dns
./run_all_completions.sh --only certificates
./run_all_completions.sh --only risk

# Saltar tareas específicas
./run_all_completions.sh --skip-subdomains --skip-dns
```

## Flujo de Trabajo Recomendado

### 1. Validación Inicial

```bash
# Validar estado actual del grafo
python3 graph_validator.py --output initial_validation.json --verbose
```

### 2. Análisis de Completitud

```bash
# Analizar qué datos faltan
python3 data_completeness_analyzer.py --output completeness_analysis.json --generate-script ./
```

### 3. Completado de Datos

```bash
# Opción 1: Ejecutar todo automáticamente
./tasks/run_all_completions.sh --parallel

# Opción 2: Ejecutar tareas individuales según prioridad
./tasks/complete_dns_analysis.sh --all          # CRITICAL
./tasks/complete_subdomains.sh --all            # HIGH  
./tasks/complete_certificates.sh --all          # HIGH
./tasks/complete_risk_scores.sh --all           # HIGH
```

### 4. Validación Final

```bash
# Validar el grafo después del completado
python3 graph_validator.py --output final_validation.json
```

## Configuración

### Variables de Entorno

```bash
# URL del domain-backend API
export DOMAIN_BACKEND_API="http://localhost:8081"

# Configuración Neo4j (si es diferente del default)
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="password"
```

### Dependencias

#### Python
- `neo4j` - Driver para conexión a Neo4j
- Incluido en el proyecto Tsunami Beta

#### Bash
- `curl` - Para llamadas a APIs
- `jq` - Para procesamiento JSON
- `python3` - Para scripts auxiliares

### Instalación de Dependencias

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install curl jq python3

# CentOS/RHEL
sudo yum install curl jq python3

# macOS
brew install curl jq python3
```

## Monitoreo y Logs

Todos los scripts generan logs detallados con timestamps:

```bash
# Los logs se guardan automáticamente con nombres descriptivos
subdomain_completion_20250825_103000.log
dns_completion_20250825_103000.log
certificate_completion_20250825_103000.log
risk_completion_20250825_103000.log
completion_master_20250825_103000.log
```

### Formato de Log

```
[2025-08-25 10:30:00] Starting DNS analysis completion script
[2025-08-25 10:30:01] API: http://localhost:8081
[2025-08-25 10:30:01] Batch size: 50
[2025-08-25 10:30:01] Max concurrent: 3
[2025-08-25 10:30:02] Checking domain-backend health...
[2025-08-25 10:30:02] Domain backend is healthy
[2025-08-25 10:30:03] Found 125 domains missing DNS data
[2025-08-25 10:30:03] Processing 125 domains in batches of 50
[2025-08-25 10:30:04] Started batch 1 with 50 domains (PID: 12345, Active: 1)
```

## Solución de Problemas

### Error: Domain backend not available

```bash
# Verificar que el domain-backend esté ejecutándose
curl http://localhost:8081/health

# Iniciar el domain-backend si no está corriendo
cd domain-backend
./async_domain_discovery_api.py
```

### Error: Neo4j driver not available

```bash
# Instalar el driver de Neo4j
pip install neo4j

# Verificar conexión Neo4j
python3 -c "from neo4j import GraphDatabase; print('Neo4j driver OK')"
```

### Error: jq command not found

```bash
# Instalar jq
sudo apt install jq  # Ubuntu/Debian
sudo yum install jq  # CentOS/RHEL
brew install jq      # macOS
```

### Tasks que se cuelgan o fallan

```bash
# Ver tasks activas en el domain-backend
curl http://localhost:8081/tasks/

# Cancelar task específica
curl -X DELETE http://localhost:8081/tasks/{task_id}

# Reiniciar domain-backend si hay problemas
pkill -f async_domain_discovery_api
cd domain-backend && ./async_domain_discovery_api.py &
```

## Extensión del Módulo

### Agregar Nueva Validación

1. Editar `graph_validator.py`
2. Agregar método `validate_nuevo_aspecto()`
3. Llamar el método desde `run_full_validation()`

### Agregar Nueva Tarea de Completado

1. Crear script en `tasks/complete_nuevo_aspecto.sh`
2. Seguir el patrón de los scripts existentes
3. Agregar llamada en `run_all_completions.sh`

## Contribución

Para contribuir al módulo risk-quality:

1. Seguir las convenciones de código existentes
2. Agregar logs detallados a cualquier script nuevo
3. Incluir manejo de errores y reintentos
4. Documentar nuevas funcionalidades en este README