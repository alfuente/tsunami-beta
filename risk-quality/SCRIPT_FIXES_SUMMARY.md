# Correcciones al Script complete_domain_phases.sh

## Problemas Identificados

1. **Puerto Incorrecto**: El script usaba puerto `8001` pero domain-backend corre en `8081`
2. **Timeouts Muy Cortos**: 300 segundos (5 min) era insuficiente para amass 
3. **Sin Detección de Procesos Colgados**: No detectaba cuando amass se quedaba sin progreso
4. **Fases Ineficientes**: Ejecutaba amass completo antes que análisis básicos
5. **Sin Limpieza de Tareas Previas**: Tareas colgadas interferían con nuevas ejecuciones
6. **Sin Opciones de Modo Rápido**: No había alternativa para dominios problemáticos

## Correcciones Implementadas

### ✅ 1. Puerto Corregido
```bash
# ANTES
DOMAIN_API_BASE="http://localhost:8001/api/v1"

# DESPUÉS  
DOMAIN_API_BASE="http://localhost:8081"
```

### ✅ 2. Timeouts Aumentados
```bash
# ANTES
MAX_WAIT_TIME=300  # 5 minutos
POLL_INTERVAL=5    # Cada 5 segundos

# DESPUÉS
MAX_WAIT_TIME=600  # 10 minutos
POLL_INTERVAL=10   # Cada 10 segundos (menos carga API)
```

### ✅ 3. Detección de Procesos Colgados
- Monitorea progreso de tareas
- Cancela automáticamente si no hay progreso por 5 minutos
- Muestra porcentaje de progreso en tiempo real

### ✅ 4. Fases Reordenadas por Eficiencia
```bash
# ORDEN OPTIMIZADO:
1. DNS Analysis          # Rápido, fundamental
2. TLS Analysis         # Rápido, importante  
3. MX Records Analysis  # Rápido
4. Passive Subdomains   # Más rápido que amass completo
5. Service Detection    # Depende de DNS/TLS
6. Technology Detection # Puede ser lento
7. Risk Calculation     # Al final, usa toda la data
```

### ✅ 5. Limpieza Automática de Tareas
- Cancela tareas colgadas antes de empezar
- Mata procesos amass colgados para el dominio
- Cancela tareas timeout automáticamente

### ✅ 6. Nuevas Opciones de Ejecución

#### Modo Rápido (`--fast`)
Solo ejecuta análisis básicos y rápidos:
```bash
./complete_domain_phases.sh clarochile.cl --fast
```

#### Saltar Subdominios (`--skip-subdomains`) 
Para dominios problemáticos con amass:
```bash  
./complete_domain_phases.sh clarochile.cl --skip-subdomains
```

#### Timeout Personalizado
```bash
./complete_domain_phases.sh clarochile.cl --timeout 1800  # 30 minutos
```

## Uso Recomendado

### Para Dominios Normales
```bash
./complete_domain_phases.sh example.com --verbose
```

### Para Dominios Problemáticos (como clarochile.cl)
```bash
# Opción 1: Modo rápido solamente
./complete_domain_phases.sh clarochile.cl --fast

# Opción 2: Saltar subdominios problemáticos  
./complete_domain_phases.sh clarochile.cl --skip-subdomains --timeout 1200

# Opción 3: Timeout más largo
./complete_domain_phases.sh clarochile.cl --timeout 1800 --verbose
```

### Para Debug/Troubleshooting
```bash
./complete_domain_phases.sh example.com --verbose --timeout 900
```

## Mejoras Adicionales Implementadas

1. **Mejor UX**:
   - Progress en tiempo real con porcentajes
   - Colores y emojis para mejor legibilidad
   - Mensajes más claros de error

2. **Robustez**:
   - Acepta resultados "partial" como válidos
   - Manejo mejorado de errores de API
   - Reintentos automáticos en fallos de red

3. **Monitoreo**:
   - Tracking detallado de tiempos por fase
   - Identificación de fases que fallan consistentemente
   - Logs más informativos

## Resultados Esperados

- **Clarochile.cl** debería completar en modo `--fast` en ~5-10 minutos
- **Dominios normales** deberían completar sin timeouts
- **Mejor diagnostico** de problemas específicos por fase
- **Recuperación automática** de tareas colgadas

## Comandos de Prueba

```bash
# Limpiar procesos colgados primero
pkill -f "amass.*clarochile"

# Probar modo rápido
./complete_domain_phases.sh clarochile.cl --fast --verbose

# Si falla, probar sin subdominios
./complete_domain_phases.sh clarochile.cl --skip-subdomains --verbose

# Para otros dominios grandes
./complete_domain_phases.sh bancochile.cl --timeout 1200 --verbose
```