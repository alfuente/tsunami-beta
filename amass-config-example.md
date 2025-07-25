# Configuración de Amass - Parámetros Personalizables

## Problema Resuelto

Los mensajes de timeout y configuración de Amass ahora son configurables:

### Antes (hardcodeado):
```
[AMASS] cuentasdigitales-qa.bancochile.cl (passive, 15s)
[AMASS] Timeout for faniai-qa.bancochile.cl - checking partial results
[AMASS] www.gslb.pyme.bancochile.cl (passive, 15s)
```

### Ahora (configurable):
```bash
# Usar timeout personalizado de 30 segundos
python3 subdomain_relationship_discovery.py --domains domains.txt --password test \
  --amass-timeout 30

# Forzar modo activo (no passive)
python3 subdomain_relationship_discovery.py --domains domains.txt --password test \
  --amass-timeout 60

# Forzar modo passive independientemente del sample-mode
python3 subdomain_relationship_discovery.py --domains domains.txt --password test \
  --amass-timeout 45 --amass-passive
```

## Nuevos Parámetros

### `--amass-timeout SECONDS`
- **Descripción**: Configura el timeout de Amass en segundos
- **Valores por defecto**: 
  - `15` segundos en sample-mode
  - `120` segundos en modo normal
- **Ejemplo**: `--amass-timeout 60`

### `--amass-passive`
- **Descripción**: Fuerza Amass a usar solo modo pasivo
- **Comportamiento por defecto**: 
  - Modo pasivo si `--sample-mode` está activo
  - Modo activo si `--sample-mode` no está activo
- **Ejemplo**: `--amass-passive`

## Prioridad de Configuración

1. **Timeout**: `--amass-timeout` > `--sample-mode` (15s) > default (120s)
2. **Modo**: `--amass-passive` > `--sample-mode` (passive) > default (active)

## Ejemplos de Uso

### Escaneo rápido y silencioso (sin timeout messages)
```bash
python3 subdomain_relationship_discovery.py \
  --domains bancochile_domains.txt \
  --password test.password \
  --amass-timeout 30 \
  --amass-passive \
  --sample-mode
```

### Escaneo profundo con timeout personalizado
```bash
python3 subdomain_relationship_discovery.py \
  --domains bancochile_domains.txt \
  --password test.password \
  --amass-timeout 180
```

### Solo discovery sin processing (para testing)
```bash
python3 subdomain_relationship_discovery.py \
  --domains bancochile_domains.txt \
  --password test.password \
  --amass-timeout 60 \
  --amass-passive \
  --phase1-only
```

## Salida de Log Mejorada

Ahora verás mensajes más claros:
```
[AMASS] bancochile.cl (active, 60s)
[AMASS] bancochile.cl (passive, 30s)
```

En lugar de los valores hardcodeados anteriores.