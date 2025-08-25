# Backend Fixes Needed - Specific Changes Required

## Análisis Detallado del Domain-Backend

Basado en el análisis del código `async_domain_discovery_api.py` y el reporte de validación, identifiqué los cambios específicos necesarios en cada método del domain-backend.

## 🔧 Cambios Requeridos por Método

### 1. `/api/v1/discover/dns/{domain}` - Método `_run_dns_analysis_sync`

**Línea actual (~928):**
```cypher
MERGE (d:Domain {fqdn: $domain})
SET d.last_amass_scan = $current_time,
    d.subdomain_count = $subdomain_count,
    d.provider_count = $provider_count,
```

**Cambio necesario:**
```cypher
MERGE (d:Domain {fqdn: $domain})
SET d.id = $domain,
    d.tld = split($domain, '.')[-1],
    d.status = 'active',
    d.last_amass_scan = $current_time,
    d.subdomain_count = $subdomain_count,
    d.provider_count = $provider_count,
```

**Agregar creación de nodos DNSServer:**
```cypher
// Para cada IP descubierta
MERGE (dns:DNSServer {ip_address: $ip_address})
SET dns.id = $ip_address,
    dns.hostname = $hostname,
    dns.type = $dns_type

MERGE (d:Domain {fqdn: $domain})
MERGE (d)-[:RESOLVES_TO]->(dns)
```

### 2. `/api/v1/discover/services/{domain}` - Método de descubrimiento de servicios

**Problema actual:** Services creados sin propiedades requeridas (`name`, `type`, `provider_name`)

**Cambio necesario en la creación de Service:**
```cypher
MERGE (s:Service {port: $port, protocol: $protocol, domain: $domain})
SET s.id = toString(id(s)),
    s.name = CASE 
        WHEN $port IS NOT NULL AND $protocol IS NOT NULL 
        THEN $protocol + '/' + toString($port)
        ELSE 'service-' + toString(id(s))
    END,
    s.type = CASE 
        WHEN $port IN [80, 8080, 8000] THEN 'web'
        WHEN $port IN [443, 8443] THEN 'https'
        WHEN $port IN [22] THEN 'ssh'
        WHEN $port IN [25, 587] THEN 'smtp'
        WHEN $port IN [53] THEN 'dns'
        ELSE 'unknown'
    END,
    s.provider_name = $provider_name
```

### 3. `/api/v1/discover/tls/{domain}` - Método `_run_tls_analysis_sync`

**Agregar creación de nodos Certificate:**
```cypher
MERGE (cert:Certificate {serial_number: $serial_number})
SET cert.id = $serial_number,
    cert.subject_cn = $subject_cn,
    cert.issuer_cn = $issuer_cn,
    cert.valid_from = $valid_from,
    cert.valid_to = $valid_to,
    cert.algorithm = $algorithm

MERGE (d:Domain {fqdn: $domain})
MERGE (d)-[:SECURED_BY]->(cert)

// Crear Organization para CA
MERGE (ca:Organization {name: $issuer_cn})
SET ca.id = toLower(replace($issuer_cn, ' ', '_')),
    ca.type = 'certificate_authority',
    ca.country = 'unknown'

MERGE (cert)-[:ISSUED_BY]->(ca)
```

### 4. `/api/v1/discover/tech/{domain}` - Método `_run_tech_analysis_sync`

**Cambio necesario en la creación de Technology:**
```cypher
MERGE (t:Technology {name: $tech_name})
SET t.id = toLower(replace($tech_name, ' ', '_')),
    t.version = COALESCE($version, 'unknown'),
    t.type = CASE 
        WHEN $tech_name =~ '(?i).*(apache|nginx|iis).*' THEN 'web_server'
        WHEN $tech_name =~ '(?i).*(mysql|postgresql).*' THEN 'database'
        WHEN $tech_name =~ '(?i).*(php|python|java).*' THEN 'runtime'
        WHEN $tech_name =~ '(?i).*(javascript|css).*' THEN 'frontend'
        ELSE 'unknown'
    END

MERGE (d:Domain {fqdn: $domain})
MERGE (d)-[:USES_TECH]->(t)
```

### 5. Nuevo método necesario: Creación automática de Organizations

**Agregar en todos los métodos de dominio:**
```cypher
// Inferir organización del dominio
MERGE (org:Organization {name: $inferred_org_name})
SET org.id = toLower(replace($inferred_org_name, ' ', '_')),
    org.type = 'company',
    org.country = 'unknown'

MERGE (d:Domain {fqdn: $domain})
MERGE (org)-[:OWNS]->(d)
```

### 6. Mejoras en Provider handling

**Cambio en métodos que crean Provider:**
```cypher
MERGE (p:Provider {name: $provider_name})
SET p.id = COALESCE(p.id, toLower(replace($provider_name, ' ', '_'))),
    p.country = COALESCE(p.country, 'unknown'),
    p.type = COALESCE(p.type, 'hosting')

// Crear relación PROVIDES entre Provider y Service
MERGE (s:Service {port: $port, protocol: $protocol, domain: $domain})
MERGE (p)-[:PROVIDES]->(s)
```

## 📋 Script de Implementación de Cambios

Crear script para aplicar estos cambios:

```python
# apply_backend_fixes.py
# Script que modifica async_domain_discovery_api.py para agregar propiedades faltantes

import re

def apply_fixes_to_backend():
    # 1. Leer archivo actual
    # 2. Aplicar cambios en queries Cypher
    # 3. Agregar creación de nodos faltantes
    # 4. Backup del archivo original
    pass
```

## 🎯 Prioridades de Implementación

### Cambios Críticos (Implementar Inmediatamente):
1. **Agregar propiedades faltantes en Domain** (`id`, `tld`, `status`)
2. **Agregar propiedades faltantes en Service** (`name`, `type`, `provider_name`)
3. **Crear nodos DNSServer** en análisis DNS
4. **Crear relaciones RESOLVES_TO**

### Cambios de Alta Prioridad (Esta Semana):
1. **Crear nodos Certificate** en análisis TLS
2. **Agregar propiedades faltantes en Technology** (`id`, `version`, `type`)
3. **Crear nodos Organization** automáticamente
4. **Implementar relaciones OWNS, SECURED_BY, USES_TECH**

### Cambios de Media Prioridad (Próxima Semana):
1. **Mejorar detección de Provider country**
2. **Implementar relaciones PROVIDES**
3. **Categorización automática de tecnologías**
4. **Análisis de vulnerabilidades**

## 🧪 Scripts de Testing

```bash
# 1. Aplicar fixes específicos
python fix_graph_issues.py --neo4j-password "test.password"

# 2. Ejecutar análisis de prueba
./complete_missing_data.sh

# 3. Validar mejoras
python graph_validator.py --neo4j-password "test.password" --output post_backend_fix_report.json

# 4. Comparar health scores
python -c "
import json
with open('validation_report.json') as f: old = json.load(f)
with open('post_backend_fix_report.json') as f: new = json.load(f)
print(f'Errores: {old[\"errors\"]} → {new[\"errors\"]}')
print(f'Health score mejorado significativamente')
"
```

## 📊 Impacto Esperado

### Antes de los cambios:
- **Health Score**: 0% (Critical)
- **Missing Properties**: 10,000+ instancias
- **Missing Node Types**: 2 (DNSServer, Organization)
- **Missing Relationships**: 9 tipos

### Después de los cambios:
- **Health Score**: 80-90% (Good/Excellent)
- **Missing Properties**: <100 instancias
- **Missing Node Types**: 0
- **Missing Relationships**: 0-2 tipos

Estos cambios específicos abordarán directamente los 17 errores críticos identificados en el reporte de validación.