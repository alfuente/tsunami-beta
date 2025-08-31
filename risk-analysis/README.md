# Risk Analysis Module - Tsunami Beta

Implementación avanzada de algoritmos de análisis y evaluación de riesgo sistémico para el ecosistema digital chileno, basado en las especificaciones de `docs/stats.md`.

## Características Principales

### 🧮 Algoritmos Implementados

1. **Algoritmo de Centralidad y Criticidad Sistémica (ACCS)**
   - Índice de Criticidad Sistémica (ICS)
   - Métricas de centralidad (grado, intermediación, PageRank, cercanía)
   - Bonificaciones por sector crítico

2. **Algoritmo de Concentración de Proveedores (ACP)**
   - Índice Herfindahl-Hirschman Modificado (HHI-M)
   - Detección de concentraciones peligrosas

3. **Algoritmo de Propagación de Riesgo (APR)**
   - Modelo epidemiológico adaptado (S-E-I-R)
   - Simulación de cascadas de fallos

4. **Algoritmo de Evaluación de Cadena de Suministro (AECS)**
   - Índice de Resiliencia de Cadena (IRC)
   - Análisis de dependencias transitivas

5. **Algoritmo de Evaluación de Proveedores Críticos (AEPC)**
   - Índice de Importancia Sistémica del Proveedor (IISP)

6. **Algoritmo de Priorización de Riesgos Nacionales (APRN)**
   - Índice de Riesgo Nacional (IRN)
   - Perspectiva de seguridad nacional chilena

### 🏗️ Arquitectura

```
risk-stats/
├── __init__.py              # Módulo principal
├── config.py                # Configuración del sistema
├── models.py                # Modelos de datos y estructuras
├── neo4j_connector.py       # Conector y carga de grafos
├── risk_calculator.py       # Motor de cálculos de riesgo
├── api.py                   # API backend FastAPI
├── main.py                  # CLI principal
├── requirements.txt         # Dependencias
└── README.md               # Este archivo
```

## Instalación y Configuración

### Dependencias

```bash
cd risk-stats
pip install -r requirements.txt
```

### Configuración

Configure las variables de entorno o edite `config.py`:

```bash
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="test.password"
export DEBUG="false"
```

## Uso

### 1. API Backend

Inicie el servidor FastAPI:

```bash
cd risk-stats
python -m api
# o directamente
python api.py
```

El servidor estará disponible en `http://localhost:8002`

- **Documentación Swagger**: `http://localhost:8002/docs`
- **Health Check**: `http://localhost:8002/health`
- **Estadísticas**: `http://localhost:8002/stats`

#### Endpoints Principales

```bash
# Iniciar cálculo de riesgo en lote
POST /calculate/risk
{
  "node_types": ["Organization", "Domain"],
  "sectors": ["banking", "telecommunications"],
  "save_to_neo4j": true
}

# Ver estado del cálculo
GET /calculate/risk/{task_id}/status

# Obtener resultados
GET /calculate/risk/{task_id}/results

# Obtener riesgo de nodo específico
GET /risk/{node_id}

# Buscar nodos por criterios de riesgo
GET /risk?risk_level=high&node_type=Organization

# Simular propagación de riesgo
POST /simulate/propagation/{node_id}
```

### 2. Interfaz de Línea de Comandos (CLI)

#### Cálculo en Lote

```bash
# Calcular riesgo para todos los nodos
python main.py calculate --output results.json

# Filtrar por tipos de nodo
python main.py calculate --node-types Organization Domain --limit 1000

# Filtrar por sectores
python main.py calculate --sectors banking telecommunications

# No guardar en Neo4j
python main.py calculate --no-save --output results.json
```

#### Cálculo Individual

```bash
# Calcular riesgo para un nodo específico
python main.py single --node-id "bancochile.cl" --output single_result.json
```

#### Estadísticas de Riesgo

```bash
# Obtener estadísticas generales
python main.py stats --output stats.json
```

#### Simulación de Propagación

```bash
# Simular propagación desde un nodo
python main.py simulate --node-id "bancochile.cl" --max-time 100 --output simulation.json
```

### 3. Uso Programático

```python
import asyncio
from risk_stats.neo4j_connector import Neo4jConnector
from risk_stats.risk_calculator import RiskCalculator

async def calculate_risks():
    # Inicializar servicios
    connector = Neo4jConnector()
    calculator = RiskCalculator()
    
    # Cargar grafo
    graph = connector.load_dependency_graph(['Organization', 'Domain'])
    nx_graph = connector.create_networkx_graph(graph)
    
    # Calcular riesgo para un nodo
    extended_risk = calculator.calculate_extended_risk(nx_graph, "bancochile.cl")
    
    # Guardar resultado
    connector.save_extended_risk("bancochile.cl", extended_risk)
    
    connector.close()

# Ejecutar
asyncio.run(calculate_risks())
```

## Datos Generados

### Propiedad `ext_risk` en Neo4j

Cada nodo procesado recibe una propiedad `ext_risk` con la siguiente estructura:

```json
{
  "systemic_criticality_index": 0.85,
  "provider_concentration_risk": 0.3,
  "supply_chain_resilience": 0.7,
  "national_risk_index": 0.9,
  "degree_centrality": 0.12,
  "betweenness_centrality": 0.08,
  "closeness_centrality": 0.15,
  "pagerank": 0.005,
  "risk_level": "high",
  "systemic_classification": "Alto Riesgo Sistémico",
  "critical_sectors_affected": ["banking", "telecommunications"],
  "cascade_potential": 0.35,
  "single_point_of_failure": false,
  "calculation_timestamp": "2025-08-30T11:30:00",
  "confidence_score": 0.95
}
```

### Clasificaciones de Riesgo

- **Crítico** (≥0.8): "Sistémicamente Crítico"
- **Alto** (≥0.6): "Alto Riesgo Sistémico"  
- **Medio** (≥0.4): "Riesgo Moderado"
- **Bajo** (<0.4): "Bajo Riesgo"

## Configuración para Contexto Chileno

### Umbrales Específicos

- **Concentración crítica**: HHI > 0.25
- **Dependencia extranjera**: > 70% considerado alto riesgo
- **Tiempo de recuperación**: > 7 días considerado crítico
- **Cobertura geográfica**: < 3 regiones considerado concentrado

### Pesos Sectoriales

```python
sectoral_weights = {
    'banking': 3.0,           # Bancario - crítico
    'telecommunications': 2.8, # Telecomunicaciones - crítico  
    'energy': 2.7,            # Energía - crítico
    'government': 2.5,        # Gobierno - muy importante
    'mining': 2.3,            # Minería - contexto chileno
    'health': 2.2,            # Salud - muy importante
    # ... otros sectores
}
```

## Monitoreo y Alertas

### Métricas Sistémicas

- **Índice de Concentración Nacional (ICN)**
- **Índice de Dependencia Externa (IDE)**  
- **Índice de Resiliencia Sectorial (IRS)**
- **Índice de Diversificación Geográfica (IDG)**

### Consultas de Monitoreo

```cypher
// Nodos con riesgo crítico
MATCH (n) 
WHERE n.ext_risk IS NOT NULL 
AND JSON_EXTRACT(n.ext_risk, '$.risk_level') = 'critical'
RETURN n.name, n.ext_risk

// Puntos únicos de falla
MATCH (n)
WHERE n.ext_risk IS NOT NULL
AND JSON_EXTRACT(n.ext_risk, '$.single_point_of_failure') = true
RETURN n.name, JSON_EXTRACT(n.ext_risk, '$.systemic_criticality_index') as ics

// Distribución de riesgo por sector
MATCH (n)
WHERE n.ext_risk IS NOT NULL
RETURN n.sector, 
       JSON_EXTRACT(n.ext_risk, '$.risk_level') as risk_level,
       count(*) as count
ORDER BY count DESC
```

## Rendimiento y Escalabilidad

### Configuración de Rendimiento

```python
# config.py
batch_size = 1000              # Procesamiento en lotes
max_graph_load_size = 50000    # Máximo nodos en memoria
calculation_timeout = 300      # 5 minutos timeout
```

### Recomendaciones

- **Carga parcial**: Use filtros por `node_types` y `sectors` para grafos grandes
- **Procesamiento por lotes**: El sistema procesa automáticamente en lotes configurables
- **Caché de grafos**: Considere implementar caché para grafos frecuentemente analizados
- **Paralelización**: Use múltiples instancias de la API para procesamiento distribuido

## Ejemplos de Análisis

### Identificar Organizaciones Críticas

```bash
curl -X GET "http://localhost:8002/risk?risk_level=critical&node_type=Organization&limit=20"
```

### Análisis Sectorial Bancario

```bash
python main.py calculate --sectors banking --output banking_risks.json
```

### Simulación de Falla de Proveedor Principal

```bash
python main.py simulate --node-id "aws-provider-node" --max-time 100 --output aws_failure_simulation.json
```

## Troubleshooting

### Problemas Comunes

1. **Error de memoria con grafos grandes**: Reduzca `max_graph_load_size` o use filtros más específicos
2. **Timeout en cálculos**: Aumente `calculation_timeout` en la configuración
3. **Conexión Neo4j fallida**: Verifique URI, credenciales y que el servicio esté corriendo
4. **Dependencias faltantes**: Ejecute `pip install -r requirements.txt`

### Logs y Debugging

```bash
# Habilitar logging detallado
export DEBUG=true
python main.py calculate --verbose

# Ver logs de API
python api.py  # Los logs aparecen en consola
```

## Contribución y Extensión

### Agregar Nuevos Algoritmos

1. Implemente el algoritmo en `risk_calculator.py`
2. Agregue métricas al modelo `ExtendedRisk`
3. Actualice el método `calculate_extended_risk`
4. Agregue endpoints API si es necesario

### Configuración de Nuevos Sectores

Edite los pesos sectoriales en `config.py`:

```python
sectoral_weights = {
    'nuevo_sector': 2.0,  # Agregar peso apropiado
    # ... otros sectores
}
```

El módulo Risk Stats proporciona una base sólida para el análisis de riesgos sistémicos del ecosistema digital chileno, con capacidades de escalabilidad y extensibilidad para necesidades futuras.