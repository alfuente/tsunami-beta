# Risk Calculation and Visualization

## ✅ Problemas Solucionados

### 1. Error de Conversión de Fechas
**Problema**: `Cannot coerce DATE_TIME to LocalDateTime`

**Solución**: Implementado método `safeAsLocalDateTime()` en `DomainResource.java` que maneja automáticamente la conversión entre `ZonedDateTime` (Neo4j DATE_TIME) y `LocalDateTime` (Java).

### 2. Visualización de Cálculo de Riesgo
**Problema**: No se mostraba información sobre cómo se calculó el riesgo de un dominio/subdominio.

**Solución**: Extendido el endpoint `/api/v1/domains/base-domains/{domain}/details?includeRiskBreakdown=true` para incluir:

## 📊 Modelo de Datos de Riesgo

### Estructura del Score Breakdown
```json
{
  "risk_breakdown": {
    "base_score": 0.0,           // Puntuación base del dominio
    "third_party_score": 0.0,    // Riesgo de terceros
    "incident_impact": 0.0,      // Impacto de incidentes
    "context_boost": 0.0,        // Boost contextual
    "weights": {                 // Pesos del cálculo
      "base_score": 0.40,        // 40%
      "third_party_score": 0.25, // 25%
      "incident_impact": 0.30,   // 30%
      "context_boost": 0.05      // 5%
    },
    "risk_details": [            // Detalles específicos de riesgos
      {
        "risk_type": "dns_missing_spf",
        "severity": "medium",
        "score": 5.0,
        "description": "Missing SPF record - domain vulnerable to email spoofing",
        "remediation": "Add SPF record to DNS: 'v=spf1 -all' or configure properly",
        "discovered_at": "2025-01-10T..."
      }
    ]
  }
}
```

## 🔍 Tipos de Riesgos Detectados

### DNS Configuration Risks
- `dns_missing_spf`: Falta registro SPF
- `dns_missing_dmarc`: Falta registro DMARC  
- `dns_wildcard_configured`: DNS wildcard configurado

### SSL/TLS Certificate Risks
- `ssl_no_certificate`: Sin certificado SSL válido
- `ssl_expiring_certificate`: Certificado próximo a expirar
- `ssl_weak_signature`: Algoritmo de firma débil
- `ssl_self_signed`: Certificado auto-firmado

### IP Address & Infrastructure Risks
- `ip_no_resolution`: Dominio no resuelve a IP
- `ip_private_exposed`: IP privada expuesta públicamente
- `ip_multiple_providers`: Múltiples proveedores de cloud

### Subdomain Exposure Risks
- `subdomain_high_exposure`: Alto número de subdominios expuestos
- `subdomain_sensitive_exposed`: Subdominios sensibles expuestos (admin, test, dev)

### Cloud Provider Risks
- `cloud_single_provider_dependency`: Dependencia de un solo proveedor
- `cloud_unknown_provider`: Proveedor desconocido/no identificado

### Domain Reputation Risks
- `domain_very_new`: Dominio muy nuevo (< 30 días)
- `domain_new`: Dominio nuevo (< 90 días)
- `domain_expiring`: Dominio próximo a expirar

## 🎯 Puntuación de Severidad

- **0.0-3.0**: `low` - Riesgo Bajo
- **3.1-5.0**: `medium` - Riesgo Medio
- **5.1-7.0**: `high` - Riesgo Alto
- **7.1-10.0**: `critical` - Riesgo Crítico

## 🚀 Uso de la API

### Obtener detalles con breakdown de riesgo:
```bash
curl "http://localhost:8081/api/v1/domains/base-domains/bice.cl/details?includeRiskBreakdown=true"
```

### Respuesta esperada:
```json
{
  "base_domain": "bice.cl",
  "subdomains": [
    {
      "fqdn": "bice.cl",
      "risk_score": 8.0,
      "risk_tier": "Critical",
      "risk_breakdown": {
        "base_score": 8.0,
        "third_party_score": 0.0,
        "incident_impact": 0.0,
        "context_boost": 0.0,
        "weights": {...},
        "risk_details": [...]
      }
    }
  ],
  "include_risk_breakdown": true
}
```

## 🛠️ Herramientas Incluidas

### 1. Script de Cálculo de Riesgos
```bash
# Analizar todos los dominios
python3 domain_risk_calculator.py --password tu_password

# Analizar dominio específico
python3 domain_risk_calculator.py --password tu_password --domain bice.cl

# Ver solo estadísticas
python3 domain_risk_calculator.py --password tu_password --stats-only
```

### 2. Scripts de Discovery con Anti-Deadlock
- `risk_loader_two_phase.py`: Versión mejorada con manejo de deadlocks
- `subdomain_relationship_discovery.py`: Discovery con relaciones entre dominios

## 📈 Dashboard Integration

El dashboard ahora puede mostrar:
1. **Score Breakdown Visual**: Gráfico de barras mostrando contribución de cada componente
2. **Risk Details Timeline**: Línea de tiempo de riesgos descubiertos
3. **Remediation Actions**: Lista priorizada de acciones de remediación
4. **Risk Trend**: Evolución del riesgo a lo largo del tiempo

## 🔧 Configuración

### Variables de entorno requeridas:
```bash
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=tu_password
IPINFO_TOKEN=tu_token_ipinfo
```

### Estructura de datos en Neo4j:
```cypher
// Nodos de riesgo
(:Risk {
  risk_id: "bice.cl_dns_missing_spf_1736123456",
  domain_fqdn: "bice.cl",
  risk_type: "dns_missing_spf",
  severity: "medium",
  score: 5.0,
  description: "Missing SPF record...",
  remediation: "Add SPF record...",
  discovered_at: "2025-01-10T...",
  evidence: "{...}"
})

// Relaciones
(:Risk)-[:AFFECTS]->(:Domain)
```

## 🎯 Próximos Pasos

1. **Alerting**: Configurar alertas automáticas para riesgos críticos
2. **Trending**: Implementar análisis de tendencias de riesgo
3. **ML Integration**: Integrar machine learning para predicción de riesgos
4. **Compliance**: Mapear riesgos a frameworks de compliance (ISO 27001, NIST)