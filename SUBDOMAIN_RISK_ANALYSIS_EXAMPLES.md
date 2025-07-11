# Análisis de Riesgos de Subdominios y Dependencias

## 🚀 Nuevas Funcionalidades Añadidas

El script `domain_risk_calculator.py` ahora incluye capacidades avanzadas para analizar subdominios y dependencias de dominios base.

## 📋 Opciones de Análisis Disponibles

### 1. **Análisis Estándar** (Solo dominios base)
```bash
# Analizar solo el dominio base
python3 domain_risk_calculator.py --domain bice.cl

# Analizar múltiples dominios base desde archivo
python3 domain_risk_calculator.py --domains domains.txt
```

### 2. **Análisis de Subdominios**
```bash
# Incluir subdominios en el análisis del dominio base
python3 domain_risk_calculator.py --domain bice.cl --include-subdomains

# Analizar SOLO los subdominios (excluir dominio base)
python3 domain_risk_calculator.py --domain bice.cl --subdomains-only
```

### 3. **Análisis de Dependencias**
```bash
# Incluir análisis de dependencias (servicios, proveedores, IPs)
python3 domain_risk_calculator.py --domain bice.cl --include-dependencies

# Combinar subdominios + dependencias
python3 domain_risk_calculator.py --domain bice.cl --include-subdomains --include-dependencies
```

### 4. **Análisis Comprensivo** (Recomendado)
```bash
# Análisis completo: dominio base + subdominios + dependencias
python3 domain_risk_calculator.py --domain bice.cl --comprehensive
```

### 5. **Estadísticas**
```bash
# Ver solo estadísticas de riesgos existentes
python3 domain_risk_calculator.py --stats-only
```

## 🔍 Tipos de Riesgos Específicos para Subdominios

### **Subdominios Sensibles Expuestos**
- `subdomain_sensitive_admin_exposed`: Subdominios de administración públicos
- `subdomain_sensitive_dev_exposed`: Subdominios de desarrollo expuestos
- `subdomain_sensitive_test_exposed`: Subdominios de testing públicos
- `subdomain_sensitive_api_exposed`: APIs internas expuestas
- `subdomain_sensitive_internal_exposed`: Recursos internos públicos

### **Vulnerabilidades de Subdominios**
- `subdomain_takeover_vulnerable`: Riesgo de subdomain takeover
- `subdomain_wildcard_certificate`: Uso de certificados wildcard

### **Riesgos de Dependencias**
- `dependency_high_complexity`: Demasiadas dependencias externas
- `dependency_risky_provider`: Proveedores no confiables
- `dependency_ip_concentration`: Concentración alta de IPs

## 📊 Estructura de Resultados

### Análisis Comprensivo - Ejemplo de Respuesta:
```json
{
  "base_domain": "bice.cl",
  "domain_risks": [
    {
      "fqdn": "bice.cl",
      "risk_type": "dns_missing_spf",
      "severity": "medium",
      "score": 5.0,
      "description": "Missing SPF record - domain vulnerable to email spoofing",
      "remediation": "Add SPF record to DNS: 'v=spf1 -all' or configure properly"
    }
  ],
  "subdomain_risks": [
    {
      "fqdn": "admin.bice.cl",
      "risk_count": 2,
      "risks": [
        {
          "risk_type": "subdomain_sensitive_admin_exposed",
          "severity": "high",
          "score": 7.5,
          "description": "Sensitive subdomain exposed: admin subdomain is publicly accessible",
          "remediation": "Restrict access to admin subdomain or move to internal network"
        }
      ]
    }
  ],
  "dependency_risks": [
    {
      "risk_type": "dependency_risky_provider",
      "severity": "high",
      "score": 7.0,
      "description": "Domain uses risky provider: unknown",
      "remediation": "Migrate away from unknown to trusted provider"
    }
  ],
  "summary": {
    "total_risks": 15,
    "subdomains_analyzed": 8,
    "dependencies_found": {
      "services": ["nginx", "apache"],
      "providers": ["AWS", "Cloudflare"],
      "ip_addresses": ["1.2.3.4", "5.6.7.8"],
      "related_domains": ["related.cl"]
    },
    "severity_breakdown": {
      "high": 5,
      "medium": 8,
      "low": 2
    },
    "elapsed_time": 45.2
  }
}
```

## 🎯 Casos de Uso Específicos

### **Auditoría de Seguridad Completa**
```bash
# Análisis completo para auditoría
python3 domain_risk_calculator.py --domain empresa.cl --comprehensive > auditoria_empresa.json
```

### **Revisión de Subdominios de Desarrollo**
```bash
# Buscar solo riesgos en subdominios (dev, test, staging)
python3 domain_risk_calculator.py --domain empresa.cl --subdomains-only
```

### **Análisis de Infraestructura**
```bash
# Enfocar en dependencias y proveedores
python3 domain_risk_calculator.py --domain empresa.cl --include-dependencies
```

### **Monitoreo Continuo**
```bash
# Script para monitoreo diario
#!/bin/bash
echo "$(date): Iniciando análisis de riesgo diario"
python3 domain_risk_calculator.py --domain $DOMAIN --comprehensive \
  | tee "risk_analysis_$(date +%Y%m%d).json"
```

## 🔧 Configuración Avanzada

### **Variables de entorno opcionales:**
```bash
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="your_password"
export IPINFO_TOKEN="your_ipinfo_token"
```

### **Ejecución con configuración personalizada:**
```bash
python3 domain_risk_calculator.py \
  --domain bice.cl \
  --comprehensive \
  --bolt bolt://remote-neo4j:7687 \
  --user admin \
  --password secret123 \
  --ipinfo-token abc123token
```

## 📈 Interpretación de Resultados

### **Niveles de Severidad:**
- **Critical (8.0-10.0)**: Requiere atención inmediata
- **High (6.0-7.9)**: Alta prioridad, resolver en 24-48h
- **Medium (4.0-5.9)**: Prioridad media, resolver en 1 semana
- **Low (0.0-3.9)**: Baja prioridad, revisar mensualmente

### **Tipos de Riesgo por Prioridad:**
1. **Subdomain Takeover** (Critical): Vulnerabilidad crítica
2. **Admin/Internal Exposed** (High): Exposición de recursos críticos
3. **Missing DMARC/SPF** (Medium): Configuración de email
4. **Development Subdomains** (Medium): Exposición de desarrollo
5. **Certificate Issues** (Medium): Problemas de certificados

## 🚨 Alertas y Remediación

### **Riesgos Críticos - Acción Inmediata:**
- Subdomain takeover → Verificar propiedad del servicio
- Admin subdomain exposed → Restringir acceso inmediatamente
- Certificate expired → Renovar certificado

### **Riesgos Altos - 24-48 horas:**
- Development subdomains public → Mover a red interna
- Missing security headers → Configurar headers apropiados
- Risky providers → Migrar a proveedores confiables

### **Riesgos Medios - 1 semana:**
- Missing SPF/DMARC → Configurar registros DNS
- High subdomain exposure → Revisar necesidad de subdominios
- Wildcard certificates → Considerar certificados específicos

## 🔄 Integración con CI/CD

### **GitHub Actions Example:**
```yaml
name: Security Risk Analysis
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
jobs:
  risk-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Risk Analysis
        run: |
          python3 domain_risk_calculator.py \
            --domain ${{ secrets.DOMAIN }} \
            --comprehensive \
            --password ${{ secrets.NEO4J_PASSWORD }}
```

## 📞 Troubleshooting

### **Errores Comunes:**
1. **"No subdomains found"** → Verificar que el dominio tenga subdominios en el grafo
2. **"Cannot connect to Neo4j"** → Verificar credenciales y conectividad
3. **"DNS resolution failed"** → Verificar conectividad de red

### **Debug Mode:**
```bash
# Ejecutar con información detallada
python3 domain_risk_calculator.py --domain test.cl --comprehensive -v
```

Esta funcionalidad extendida proporciona un análisis de seguridad mucho más completo y granular para dominios y sus ecosistemas completos.