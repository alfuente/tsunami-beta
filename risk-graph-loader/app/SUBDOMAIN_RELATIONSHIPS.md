# Subdomain Relationships Documentation

## Tipos de Relaciones en el Grafo

### 1. HAS_SUBDOMAIN (Subdominios Reales)
**Descripción:** Dominios que son subdominios directos del dominio objetivo.

**Ejemplo:** `cdn.banco.itau.cl` es subdominio de `banco.itau.cl`

**Estructura del Grafo:**
```
(Domain:banco.itau.cl)-[:HAS_SUBDOMAIN]->(Subdomain:cdn.banco.itau.cl)
```

**Propiedades del Nodo Subdomain:**
- `fqdn`: Nombre completo del subdominio
- `base_domain`: Dominio base
- `subdomain_parts`: Partes del subdominio 
- `tld`: Top Level Domain
- `discovered_by`: Método de descubrimiento (ej: "amass")
- `processing_phase`: Si fue procesado completamente
- `created_at`: Timestamp de creación
- `last_updated`: Última actualización

### 2. DISCOVERED_RELATED (Dominios Relacionados)
**Descripción:** Dominios encontrados durante el escaneo pero que NO son subdominios directos del dominio objetivo.

**Ejemplo:** `ns1.a0.impervasecuritydns.net` encontrado durante scan de `banco.itau.cl`

**Estructura del Grafo:**
```
(Domain:banco.itau.cl)-[:DISCOVERED_RELATED {source: 'amass', method: 'enumeration'}]->(RelatedDomain:ns1.a0.impervasecuritydns.net)
```

**Propiedades del Nodo RelatedDomain:**
- `fqdn`: Nombre completo del dominio relacionado
- `base_domain`: Su dominio base real (ej: "impervasecuritydns.net")
- `tld`: Su TLD real
- `discovered_during_scan_of`: Dominio original que se estaba escaneando
- `relationship_type`: "discovered_related"
- `discovery_source`: "amass_scan"
- `discovery_method`: "subdomain_enumeration"
- `discovery_context`: Descripción de cómo se encontró
- `original_domain_scan`: Dominio original del scan
- `created_at`: Timestamp de creación

**Propiedades de la Relación DISCOVERED_RELATED:**
- `source`: Herramienta que encontró la relación (ej: "amass")
- `method`: Método de descubrimiento (ej: "enumeration")
- `timestamp`: Cuándo se estableció la relación

## ¿Por qué aparecen dominios relacionados?

Los dominios relacionados aparecen porque **Amass** durante su proceso de enumeración encuentra referencias a otros dominios que están técnicamente conectados con el objetivo:

### Tipos Comunes de Dominios Relacionados:

1. **Servidores DNS:**
   - `ns1.a0.impervasecuritydns.net`
   - `dns1.registrar-servers.com`

2. **Servicios CDN/Proxy:**
   - `cloudflare.com` endpoints
   - `fastly.com` endpoints
   - Imperva/Incapsula proxies

3. **Servicios Cloud:**
   - `amazonaws.com` endpoints
   - `azurewebsites.net` endpoints
   - `googleusercontent.com` endpoints

4. **Servicios de Terceros:**
   - Email providers
   - Analytics services
   - Security services

## Controlar el Almacenamiento de Dominios Relacionados

### Flag para Deshabilitar Dominios Relacionados

**En subdomain_relationship_discovery_v4.py:**
```bash
python3 subdomain_relationship_discovery_v4.py --domains domains.txt --password pass --no-related-domains
```

**En batch_domain_processor.py:**
```bash
python3 batch_domain_processor.py --domains domains.txt --password pass --no-related-domains
```

**Efecto:**
- ✅ Se crean nodos `Subdomain` con relación `HAS_SUBDOMAIN`
- ❌ NO se crean nodos `RelatedDomain` con relación `DISCOVERED_RELATED`
- 📝 Se logea información sobre dominios relacionados encontrados pero no almacenados

## Consultas Útiles

### Ver solo subdominios reales:
```cypher
MATCH (d:Domain {fqdn: "banco.itau.cl"})-[:HAS_SUBDOMAIN]->(s:Subdomain)
RETURN s.fqdn ORDER BY s.fqdn
```

### Ver solo dominios relacionados:
```cypher
MATCH (d:Domain {fqdn: "banco.itau.cl"})-[:DISCOVERED_RELATED]->(rd:RelatedDomain)
RETURN rd.fqdn, rd.base_domain, rd.discovery_context ORDER BY rd.fqdn
```

### Estadísticas completas:
```cypher
MATCH (d:Domain {fqdn: "banco.itau.cl"})
OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
OPTIONAL MATCH (d)-[:DISCOVERED_RELATED]->(rd:RelatedDomain)
RETURN 
  d.fqdn as domain,
  count(DISTINCT s) as real_subdomains,
  count(DISTINCT rd) as related_domains
```

### Clasificar dominios relacionados por tipo:
```cypher
MATCH (d:Domain {fqdn: "banco.itau.cl"})-[:DISCOVERED_RELATED]->(rd:RelatedDomain)
WITH rd,
  CASE 
    WHEN rd.fqdn CONTAINS "dns" OR rd.fqdn CONTAINS "ns" THEN "DNS Server"
    WHEN rd.fqdn CONTAINS "cdn" OR rd.fqdn CONTAINS "cloudflare" THEN "CDN Service"
    WHEN rd.fqdn CONTAINS "imperva" OR rd.fqdn CONTAINS "security" THEN "Security Service"
    WHEN rd.fqdn CONTAINS "amazonaws.com" THEN "AWS Service"
    ELSE "Other"
  END as service_type
RETURN service_type, count(*) as count, collect(rd.fqdn)[0..3] as examples
ORDER BY count DESC
```

## Limpieza de Datos

### Eliminar solo dominios relacionados:
```cypher
MATCH (d:Domain {fqdn: "banco.itau.cl"})-[:DISCOVERED_RELATED]->(rd:RelatedDomain)
DETACH DELETE rd
```

### Eliminar TODOS los dominios relacionados (¡CUIDADO!):
```cypher
MATCH (rd:RelatedDomain)
DETACH DELETE rd
```

## Logging en Modo Debug

Con `--debug` activado, el sistema registra:

- 🔍 **Fuente de relación:** De dónde viene cada dominio relacionado
- 📊 **Clasificación automática:** DNS, CDN, Security, Cloud, etc.
- ⏱️ **Timestamps:** Cuándo se descubrió cada relación
- 🎯 **Contexto:** Por qué se considera relacionado

**Ejemplo de log:**
```
2024-01-15 10:30:45 - DEBUG - Related domain found: ns1.a0.impervasecuritydns.net (likely source: dns_server) for domain banco.itau.cl
2024-01-15 10:30:45 - INFO - Domain banco.itau.cl: 15 valid subdomains, 8 related domains
```

## Recomendaciones de Uso

### Para análisis de infraestructura propia:
```bash
# Solo subdominios reales
python3 batch_domain_processor.py --domains domains.txt --password pass --no-related-domains
```

### Para análisis de ecosystem completo:
```bash
# Incluir dominios relacionados
python3 batch_domain_processor.py --domains domains.txt --password pass
```

### Para debugging:
```bash
# Con logging detallado
python3 batch_domain_processor.py --domains domains.txt --password pass --debug
```

## Ejemplo de Archivo de Consultas

Ver `query_examples.cypher` para consultas completas y ejemplos de uso.