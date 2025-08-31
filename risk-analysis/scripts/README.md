# Risk Analysis Algorithm Test Scripts

Este directorio contiene scripts de prueba para todos los algoritmos de análisis de riesgo implementados según las especificaciones del archivo `docs/stats.md`.

## Scripts Disponibles

### 🔧 Scripts Individuales

#### `test_accs.sh` - ACCS Algorithm Test
Prueba el **Algoritmo de Centralidad y Criticidad Sistémica**
- **Función**: Calcula el Índice de Criticidad Sistémica (ICS)
- **Fórmula**: `ICS = 0.3 × Grado + 0.25 × Intermediación + 0.25 × PageRank + 0.2 × Cercanía + Bonus`
- **Tiempo estimado**: 5-30 segundos (dependiendo del tamaño del grafo)
- **Uso**: `./test_accs.sh`

#### `test_acp.sh` - ACP Algorithm Test  
Prueba el **Algoritmo de Concentración de Proveedores**
- **Función**: Detecta concentraciones peligrosas usando HHI modificado
- **Fórmula**: `HHI-M = Σ(cuota_mercado_ponderada²)`
- **Tiempo estimado**: 3-15 segundos
- **Uso**: `./test_acp.sh`

#### `test_apr.sh` - APR Algorithm Test
Prueba el **Algoritmo de Propagación de Riesgo** 
- **Función**: Simula propagación usando modelo epidemiológico S-E-I-R
- **Tiempo estimado**: 10-60 segundos (según parámetros de simulación)
- **Uso**: `./test_apr.sh`

### 🎯 Script Completo

#### `test_all_algorithms.sh` - Comprehensive Test Suite
Ejecuta **TODOS** los algoritmos en secuencia con análisis completo:
- **ACCS** - Centralidad y Criticidad Sistémica
- **ACP** - Concentración de Proveedores  
- **APR** - Propagación de Riesgo
- **AECS** - Evaluación de Cadena de Suministro
- **AEPC** - Evaluación de Proveedores Críticos
- **APRN** - Priorización de Riesgos Nacionales

**Tiempo estimado total**: 2-5 minutos

**Uso**: `./test_all_algorithms.sh`

## Requisitos Previos

### 1. Servicio Risk Analysis ejecutándose
```bash
# Desde el directorio tsunami-beta
./manage-services.sh start-analysis

# Verificar que esté funcionando
curl http://localhost:8002/health
```

### 2. Dependencias del sistema
- `curl` - para llamadas API
- `jq` - para procesamiento JSON
- `bc` - para cálculos matemáticos

**Instalar dependencias (Ubuntu/Debian):**
```bash
sudo apt-get install curl jq bc
```

## Interpretación de Resultados

### Métricas de Tiempo
Los scripts muestran:
- **Tiempo de inicio**: Timestamp cuando inicia el cálculo
- **Tiempo de fin**: Timestamp cuando termina
- **Tiempo total**: Duración del cálculo
- **Velocidad de procesamiento**: Nodos/segundo cuando aplique

### Clasificaciones de Riesgo

#### ACCS (Índice ICS)
- **Critical** (≥ 0.8): Entidades de criticidad sistémica extrema
- **High** (≥ 0.6): Alto riesgo sistémico
- **Medium** (≥ 0.4): Riesgo moderado
- **Low** (< 0.4): Bajo riesgo sistémico

#### ACP (HHI Modificado)
- **< 0.15**: Mercado competitivo (riesgo bajo)
- **0.15 - 0.25**: Moderadamente concentrado (riesgo medio)
- **> 0.25**: Altamente concentrado (riesgo alto)

#### AEPC (Índice IISP)
- **≥ 8**: Proveedor Sistémicamente Crítico
- **≥ 6**: Proveedor de Alto Riesgo
- **≥ 4**: Proveedor de Riesgo Moderado
- **< 4**: Proveedor de Bajo Riesgo

## Ejemplos de Uso

### Prueba Rápida Individual
```bash
# Ejecutar solo el algoritmo ACCS
cd /home/alf/dev/tsunami-beta/risk-analysis/scripts
./test_accs.sh
```

### Suite Completa
```bash
# Ejecutar todos los algoritmos con análisis completo
./test_all_algorithms.sh > results_$(date +%Y%m%d_%H%M%S).log 2>&1
```

### Análisis de Performance
```bash
# Ejecutar múltiples veces para análisis de rendimiento
for i in {1..5}; do
    echo "=== Iteration $i ===" 
    ./test_accs.sh | grep "execution time"
done
```

## Troubleshooting

### Error: "API connectivity failed"
```bash
# Verificar que el servicio esté ejecutándose
./manage-services.sh status | grep -i analysis

# Reiniciar si es necesario
./manage-services.sh restart-analysis
```

### Error: "Node not found in graph" 
```bash
# Para APR, verificar nodos disponibles
curl -s http://localhost:8002/stats | jq '.node_counts'

# Usar un nodo real del grafo en lugar del ejemplo
```

### Error: "Invalid JSON response"
```bash
# Verificar logs del servicio
./manage-services.sh logs analysis

# Verificar conectividad Neo4j
curl -s http://localhost:8002/health | jq '.services.neo4j'
```

### Dependencias faltantes
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install curl jq bc

# CentOS/RHEL  
sudo yum install curl jq bc

# macOS
brew install curl jq bc
```

## Interpretación de Resultados Críticos

### 🔴 Alertas Críticas
- **ACCS**: > 10 nodos críticos indica ecosistema frágil
- **ACP**: HHI > 0.25 requiere diversificación urgente
- **APR**: > 100 nodos afectados indica riesgo de cascada sistémica
- **APRN**: Cualquier "Riesgo Nacional Crítico" requiere atención inmediata

### ⚠️ Umbrales de Atención (Chile)
- **Concentración crítica**: HHI > 0.25 (más estricto por tamaño del mercado)
- **Dependencia extranjera**: > 70% considerado alto riesgo
- **Tiempo de recuperación**: > 7 días considerado crítico
- **Cobertura geográfica**: < 3 regiones considerado concentrado

## Archivos de Output

Los scripts generan output detallado incluyendo:
- Timestamps de inicio/fin
- Resultados numéricos de cada algoritmo
- Análisis de riesgo contextualizado para Chile
- Recomendaciones de acciones
- Métricas de rendimiento

Para guardar resultados:
```bash
./test_all_algorithms.sh | tee results_$(date +%Y%m%d_%H%M%S).txt
```

## Contacto y Soporte

Para problemas con los algoritmos o interpretación de resultados, consulte:
- **Documentación técnica**: `docs/stats.md`
- **API documentation**: http://localhost:8002/docs
- **Health endpoint**: http://localhost:8002/health