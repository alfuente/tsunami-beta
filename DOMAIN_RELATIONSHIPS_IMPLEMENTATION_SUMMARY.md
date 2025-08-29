# Implementación de Detección de Relaciones entre Dominios

## 📋 Resumen Ejecutivo

Se ha implementado exitosamente un sistema de detección de relaciones entre dominios durante el web scraping, creando relaciones "suaves" (`REFERENCES`) que reflejan conexiones de contenido entre dominios, complementando las relaciones técnicas existentes.

## 🚀 Componentes Implementados

### 1. Detector de Relaciones de Dominio (`domain_relationship_detector.py`)

**Funcionalidades principales:**
- ✅ Detecta enlaces a otros dominios durante web scraping
- ✅ Extrae dominios base de URLs complejas
- ✅ Identifica subdominios vs dominios base
- ✅ Clasifica tipos de referencias (navegacional, recurso, servicio externo, etc.)
- ✅ Clasifica contextos de referencias (social media, CDN, payment, etc.)

**Tipos de relaciones detectadas:**
- `link` - Enlaces navegacionales (`<a href>`)
- `script` - Scripts externos (`<script src>`)
- `image` - Imágenes externas (`<img src>`)
- `stylesheet` - CSS externos (`<link rel="stylesheet">`)
- `form` - Formularios externos (`<form action>`)
- `iframe` - Contenido embebido (`<iframe src>`)

**Contextos clasificados:**
- `navigational` - Enlaces de navegación
- `resource` - Recursos (JS, CSS, imágenes)
- `external_service` - Servicios externos
- `social_media` - Redes sociales
- `tracking_service` - Servicios de tracking
- `cdn_resource` - Recursos CDN
- `payment_service` - Servicios de pago
- `api_service` - APIs
- `government` - Sitios gubernamentales

### 2. Integración con Sistema de Web Scraping

**Archivo modificado:** `domain-backend/async_domain_discovery_api.py`

**Mejoras implementadas:**
- ✅ Integración automática durante `run_web_scraping_analysis`
- ✅ Detección de referencias ejecutada como paso 5 del análisis
- ✅ Creación automática de nodos de dominio si no existen
- ✅ Establecimiento de relaciones `HAS_SUBDOMAIN` cuando corresponde
- ✅ Nuevo endpoint: `/api/v1/domain/{domain}/relationships`

### 3. Esquema Neo4j Actualizado

**Script:** `update_neo4j_schema_references.py`

**Nuevos índices creados:**
- ✅ `references_type` - Por tipo de referencia
- ✅ `references_context` - Por contexto de referencia  
- ✅ `references_confidence` - Por confianza
- ✅ `references_count` - Por conteo de referencias
- ✅ `references_discovery_source` - Por fuente de descubrimiento
- ✅ Índices compuestos para consultas optimizadas

### 4. API de Visualización de Grafos Extendida

**Archivo modificado:** `graph-view/backend/graph_visualization_api.py`

**Nuevas funcionalidades:**
- ✅ Color coral (#FF6B6B) para relaciones `REFERENCES`
- ✅ Parámetro `include_references` en `/graph/complete`
- ✅ Endpoint `/graph/domain/{domain}/references` para explorar referencias
- ✅ Endpoint `/graph/references/statistics` para estadísticas

### 5. Scripts de Integración y Utilidades

**Scripts creados:**
- ✅ `integrate_domain_relationship_detection.py` - Integrador automático
- ✅ `add_references_to_graph_visualization.py` - Extensor de visualización
- ✅ Ambos con modos --dry-run, --apply, --test, --backup

## 📊 Estadísticas Actuales

```json
{
    "total_references": 3,
    "average_confidence": 0.8,
    "reference_types": ["link", "script"],
    "reference_contexts": ["navigational", "resource"],
    "top_referencing_domains": [
        {"domain": "example.cl", "outgoing_references": 3}
    ],
    "top_referenced_domains": [
        {"domain": "google.cl", "incoming_references": 1},
        {"domain": "bancochile.cl", "incoming_references": 1},
        {"domain": "jquery.com", "incoming_references": 1}
    ]
}
```

## 🔗 Nuevas Relaciones en Neo4j

### Relación REFERENCES
```cypher
(dominio_origen:Domain)-[r:REFERENCES]->(dominio_destino:Domain)
```

**Propiedades de la relación:**
- `reference_type`: Tipo de referencia (link, script, image, etc.)
- `reference_context`: Contexto (navigational, resource, social_media, etc.)
- `confidence`: Nivel de confianza (0.0-1.0)
- `reference_count`: Número de veces que se ha visto la referencia
- `discovery_source`: 'web_scraping'
- `discovered_at`: Timestamp de primer descubrimiento
- `last_seen`: Timestamp de última observación
- `target_url`: URL original referenciada
- `link_text`: Texto del enlace (si aplica)
- `target_subdomain`: Subdominio específico referenciado

## 🔧 Endpoints de API Disponibles

### Backend de Dominio (Puerto por defecto)
- `POST /api/v1/discover/web-scraping/{domain}` - Ejecuta web scraping con detección de relaciones
- `GET /api/v1/domain/{domain}/relationships` - Obtiene relaciones de un dominio

### Backend de Visualización (Puerto 8500)
- `GET /graph/complete?include_references=true` - Grafo completo con referencias
- `GET /graph/domain/{domain}/references?direction=both&min_confidence=0.5` - Referencias de dominio
- `GET /graph/references/statistics` - Estadísticas de referencias

## 🎯 Casos de Uso

### 1. Análisis de Relaciones de Contenido
```bash
curl "http://localhost:8500/graph/domain/bancochile.cl/references"
```

### 2. Exploración de Referencias por Contexto
```bash
curl "http://localhost:8500/graph/domain/example.cl/references?direction=outgoing&min_confidence=0.8"
```

### 3. Estadísticas del Ecosistema
```bash
curl "http://localhost:8500/graph/references/statistics"
```

## 📈 Ventajas del Sistema

### Diferenciación de Relaciones
- **Relaciones Técnicas** (`USES_PROVIDER`, `HAS_SUBDOMAIN`): Infraestructura y configuración
- **Relaciones de Contenido** (`REFERENCES`): Enlaces y referencias web

### Flexibilidad
- Detección automática durante web scraping
- Clasificación inteligente por contexto
- Filtrado por confianza y tipo
- Soporte bidireccional (entrante/saliente)

### Escalabilidad
- Índices optimizados para consultas rápidas
- Contadores automáticos de frecuencia
- Detección de duplicados

## 🔄 Flujo de Procesamiento

1. **Web Scraping** → Análisis de HTML
2. **Detección de Referencias** → Extracción de enlaces externos
3. **Clasificación** → Tipo y contexto de referencia
4. **Creación de Nodos** → Dominios base y subdominio si no existen
5. **Establecimiento de Relaciones** → `REFERENCES` y `HAS_SUBDOMAIN`
6. **Visualización** → Disponible en API de grafos

## 🛡️ Filtros y Validaciones

- **Filtro de Auto-referencias** - Evita referencias al mismo dominio
- **Filtro de Dominios Comunes** - Excluye dominios muy genéricos en ciertos contextos
- **Validación de URLs** - Solo procesa URLs válidas
- **Detección de TLD Compuestos** - Maneja `.com.ar`, `.gob.cl`, etc.

## 🎨 Visualización

- **Color coral (#FF6B6B)** para relaciones `REFERENCES`
- **Diferenciación visual** de relaciones técnicas vs contenido
- **Metadata enriquecida** con contexto y confianza
- **Filtros interactivos** por dirección y confianza

## ✅ Estado de Implementación

| Componente | Estado | Descripción |
|------------|--------|-------------|
| Detector Core | ✅ Completado | `DomainRelationshipDetector` funcional |
| Integración Web Scraping | ✅ Completado | Automático durante análisis |
| Esquema Neo4j | ✅ Completado | Índices y constraints creados |
| API Visualización | ✅ Completado | Endpoints funcionales |
| Scripts Utilidades | ✅ Completado | Con backup y testing |
| Documentación | ✅ Completado | Este archivo |

## 🚀 Próximos Pasos Recomendados

1. **Ejecutar análisis masivo** de dominios existentes para poblar relaciones
2. **Configurar frontend** para mostrar referencias en visualización 2D/3D
3. **Implementar alertas** para referencias sospechosas o riesgosas
4. **Análisis de patrones** de referencias para detección de amenazas
5. **Exportación de datos** para análisis externos

---

**📅 Implementación completada:** 28 de Agosto, 2025  
**🔧 Desarrollador:** Asistente Claude con integración automática  
**📊 Estado:** ✅ Totalmente funcional y probado