# Análisis del Sistema de Cálculo de Riesgos - Tsunami Beta

## Resumen Ejecutivo

Después de una revisión exhaustiva del código y la base de datos, he identificado problemas críticos en el sistema de cálculo de riesgos que explican:
1. **Por qué hay tantos registros con riesgo 0-0**: Algoritmos conservadores que solo suman riesgos ante problemas específicos detectados
2. **Por qué DNS/MX aparece en subdominios**: Lógica de recolección que no distingue entre dominios base y subdominios
3. **Inconsistencias en el sistema de grading**: Escala A-E implementada de forma invertida

## Estado Actual del Sistema

### Problemas Identificados

#### 1. **Información DNS/MX mal ubicada** ❌
- **Problema**: Los registros DNS y MX se recolectan y almacenan indiscriminadamente para dominios y subdominios
- **Ubicación en código**: `domain-backend/async_domain_discovery_api.py:1261-1420`
- **Evidencia técnica**:
  ```python
  # Función run_mx_analysis() no distingue entre base domain y subdomain
  async def run_mx_analysis(self, domain: str, task_id: str) -> MXAnalysisResult:
      # Se ejecuta para cualquier FQDN sin validación
      mx_answers = dns.resolver.resolve(domain, 'MX')  # ← PROBLEMA
  ```
- **Evidencia en Neo4j**:
  ```cypher
  // CORRECTO: Dominios base con MX
  bancochile.cl: mx_records=[mx.iphmx.com, ...]
  
  // INCORRECTO: Subdominios con registros MX/DNS propios
  extranet.bancochile.cl: mx_records=[...], dns_records=[...]
  api.bancochile.cl: dns_records=[...]
  ```
- **Impacto**: Los subdominios raramente tienen registros MX independientes. Esta información debería estar solo a nivel de dominio base.

#### 2. **Risk Scores en 0.0 - Problema Principal** ❌
- **Estadísticas críticas**:
  - **11 de 27 dominios (40.7%) tienen riskScore=0.0**
  - Ejemplo: `bice.cl` tiene datos completos (MX, DNS, tecnologías) pero riskScore=0.0
- **Causas raíz identificadas**:
  1. **Algoritmo conservador**: Solo suma riesgos ante problemas específicos detectados
  2. **Datos faltantes**: Los algoritmos esperan campos que no existen en Neo4j
  3. **Excepciones silenciosas**: Errores en cálculo resultan en valores por defecto 0.0
  4. **Falta de riesgo base**: Dominios sin problemas detectados = riesgo 0

### Algoritmos de Cálculo de Riesgo

#### A. **Risk Score Principal** (async_domain_discovery_api.py:5051)
```python
# Función _calculate_local_risk_score
risk_score = 0.0

# TLS Issues
if not has_ssl: risk_score += 15.0
if cert_expired: risk_score += 5.0

# Technology Risks
if vulnerable_tech: risk_score += 20.0
if outdated_tech: risk_score += 10.0
if insecure_tech: risk_score += 5.0

# DNS Issues  
if missing_spf: risk_score += 15.0
if missing_dmarc: risk_score += 5.0

# Final cap
risk_score = min(risk_score, 100.0)
```

#### B. **Risk Profile Calculation** (línea 1776)
```python
# _calculate_domain_risk_profile
overall_risk_score = 0.0

# Technology-based risks
if "apache" in tech: overall_risk_score += 40.0
if "nginx" in tech: overall_risk_score += 25.0
if "wordpress" in tech: overall_risk_score += 10.0
if "php" in tech: overall_risk_score += 3.0
if "mysql" in tech: overall_risk_score += 15.0
if "javascript" in tech: overall_risk_score += 8.0

# Version-based risks
if version_outdated: overall_risk_score += 50.0
if version_unsupported: overall_risk_score += 30.0
if version_vulnerable: overall_risk_score += 15.0

# Cap at 100
overall_risk_score = min(overall_risk_score, 100.0)
```

#### C. **Domain Risk Calculator** (domain_risk_calculator.py)
- Sistema más sofisticado con análisis DNS, SSL, IP
- Genera objetos `DomainRisk` específicos
- Calcula riesgos por categoría:
  - DNS vulnerabilities (SPF, DMARC, wildcard)
  - SSL/TLS issues (expiration, weak ciphers)
  - IP geolocation risks
  - Certificate chain problems

### Sistema de Escalas de Riesgo

#### **Escala Actual** (Problemas):
```python
# En el código actual:
if risk_score >= 80: risk_tier = "A"  # ❌ INCORRECTO: A=Alto riesgo
elif risk_score >= 60: risk_tier = "B"
elif risk_score >= 40: risk_tier = "C"
else: risk_tier = "D"
```

#### **Escala Correcta** (Como debería ser):
- **A**: Riesgo MUY BAJO (0-20)
- **B**: Riesgo BAJO (21-40) 
- **C**: Riesgo MEDIO (41-60)
- **D**: Riesgo ALTO (61-80)
- **E**: Riesgo CRÍTICO (81-100)

### Causas de Riesgos en 0.0

#### 1. **Falta de Datos Base**
```python
# Si no hay tecnologías detectadas
if not technologies: risk_score = 0.0

# Si no hay problemas SSL detectados  
if ssl_valid and not expired: risk_score += 0.0

# Si no hay problemas DNS
if spf_valid and dmarc_valid: risk_score += 0.0
```

#### 2. **Algoritmo Conservador**
- Solo suma riesgos cuando encuentra problemas específicos
- No considera factores como:
  - Cantidad de subdominios expuestos
  - Diversidad de tecnologías
  - Configuraciones por defecto
  - Patterns de naming inseguros

#### 3. **Datos Incompletos**
- Muchos dominios no han sido completamente analizados
- Proceso de discovery incompleto
- APIs externas no disponibles o con rate limits

## Recomendaciones de Mejoras

### 1. **Corregir Ubicación DNS/MX**
```cypher
// Mover registros MX solo a dominios base
MATCH (s:Subdomain)
WHERE s.mx_records IS NOT NULL
WITH s, s.fqdn as subdomain_fqdn
MATCH (d:Domain) 
WHERE subdomain_fqdn CONTAINS d.fqdn AND subdomain_fqdn <> d.fqdn
// Validar si el subdominio realmente tiene MX independiente
// Si no, eliminar la propiedad mx_records del subdominio
```

### 2. **Corregir Escala de Riesgo**
```python
def get_risk_grade(risk_score: float) -> str:
    if risk_score <= 20: return "A"    # Excelente
    elif risk_score <= 40: return "B"  # Bueno
    elif risk_score <= 60: return "C"  # Regular
    elif risk_score <= 80: return "D"  # Malo
    else: return "E"                   # Crítico
```

### 3. **Mejorar Algoritmo de Cálculo**
```python
def enhanced_risk_calculation(domain_data):
    base_risk = 10.0  # Riesgo base mínimo
    
    # Factores positivos de riesgo
    if excessive_subdomains: base_risk += 15.0
    if default_configurations: base_risk += 10.0  
    if outdated_tech_stack: base_risk += 20.0
    if missing_security_headers: base_risk += 8.0
    if weak_dns_config: base_risk += 12.0
    
    # Factores que reducen riesgo
    if good_ssl_grade: base_risk -= 5.0
    if security_headers_present: base_risk -= 3.0
    if recent_updates: base_risk -= 2.0
    
    return max(0.0, min(100.0, base_risk))
```

### 4. **Implementar Risk Score Base**
- Todos los dominios deberían tener un riesgo mínimo base (ej: 5-15 puntos)
- Factores base: exposición pública, complejidad del stack, cantidad de servicios
- Ajustar según contexto: bancos vs sitios informativos

## Problemas en la UI

### **Reports Backend** (DomainDataService.java)
- Consulta incorrecta para subdominios:
  ```java
  // INCORRECTO: busca HAS_SUBDOMAIN
  MATCH (d:Domain {fqdn: $domain})-[:HAS_SUBDOMAIN]->(s:Domain)
  
  // CORRECTO: debería ser BELONGS_TO
  MATCH (d:Domain {fqdn: $domain})<-[:BELONGS_TO]-(s:Subdomain)
  ```

### **Frontend** (Technologies.tsx)
- No muestra información DNS/MX por dominio base
- Mezcla datos de dominios y subdominios sin distinción clara

## Conclusiones

1. **Arquitectura de datos**: DNS/MX debe estar principalmente a nivel de dominio base
2. **Escala invertida**: La escala A-E está implementada al revés
3. **Algoritmo conservador**: Muchos casos legítimos resultan en 0.0 por falta de factores de riesgo detectados
4. **Datos incompletos**: El proceso de discovery necesita ser más completo y sistemático

El sistema necesita una refactorización del algoritmo de riesgo y corrección de la escala de calificación para ser útil en un contexto de seguridad real.