# Neo4j Backup and Restore System for Tsunami Beta

Este documento describe el sistema completo de respaldo y restauración para Neo4j, así como la inicialización de grafos limpios con la estructura correcta para domain-backend.

## 📁 Archivos Creados

### 1. `neo4j_backup_restore.sh`
Script principal para respaldo y restauración del grafo Neo4j en Docker Compose.

**Características:**
- Respaldo completo usando APOC JSON export
- Restauración automática con script generado
- Inicialización de grafo limpio con estructura básica
- Validación de estructura del grafo
- Manejo de errores y logs detallados

### 2. `init_graph_schema.py`
Script Python para inicializar el esquema completo del grafo Neo4j.

**Características:**
- Crea todos los constraints necesarios
- Crea todos los índices de rendimiento
- Inicializa nodos del sistema (SystemConfig, RiskConfiguration)
- Crea nodos Technology básicos
- Documenta tipos de relaciones
- Exporta información del esquema

### 3. `ensure_graph_schema.py`
Script Python para asegurar compatibilidad específica con domain-backend.

**Características:**
- Verifica y crea estructuras específicas que domain-backend usa
- Asegura nodos Provider compatibles
- Crea nodos Technology que domain-backend puede detectar
- Documenta patrones de relaciones usados por domain-backend
- Verificación de compatibilidad completa

## 🚀 Uso Básico

### Hacer Respaldo Completo

**Respaldo Rápido (Recomendado para Producción):**
```bash
./neo4j_backup_restore.sh backup
```

**Respaldo con Dump Completo (Detiene Neo4j temporalmente):**
```bash
./neo4j_backup_restore.sh backup-full
```

**Con nombre personalizado:**
```bash
./neo4j_backup_restore.sh backup pre-migration
./neo4j_backup_restore.sh backup-full critical-backup
```

### Restaurar desde Respaldo
```bash
./neo4j_backup_restore.sh restore 20250826_143000
```

### Inicializar Grafo Limpio
```bash
./neo4j_backup_restore.sh init-clean
```

### Listar Respaldos
```bash
./neo4j_backup_restore.sh list
```

### Validar Estructura
```bash
./neo4j_backup_restore.sh validate
```

## 🔧 Inicialización de Esquema

### Inicializar Esquema Completo
```bash
python3 init_graph_schema.py
```

### Solo Validar Esquema Existente
```bash
python3 init_graph_schema.py --validate-only
```

### Con Parámetros Personalizados
```bash
python3 init_graph_schema.py --uri bolt://localhost:7687 --user neo4j --password mypassword
```

## 🏗️ Asegurar Compatibilidad con Domain-Backend

### Asegurar Compatibilidad Completa
```bash
python3 ensure_graph_schema.py
```

### Solo Verificar Compatibilidad
```bash
python3 ensure_graph_schema.py --verify-only
```

## 📊 Estructura del Grafo

### Nodos Principales
- **Domain**: Dominios principales y subdominios
- **Provider**: Proveedores de hosting/servicios
- **Service**: Servicios detectados en dominios
- **Certificate**: Certificados SSL/TLS
- **Risk**: Riesgos asociados a dominios
- **Technology**: Tecnologías detectadas
- **IPAddress**: Direcciones IP
- **SystemConfig**: Configuración del sistema
- **RiskConfiguration**: Configuración de cálculo de riesgo

### Relaciones Principales
- `SUBDOMAIN_OF`: Relación de subdominios
- `HOSTED_BY`: Dominio alojado en proveedor
- `HAS_SERVICE`: Dominio tiene servicio
- `HAS_CERTIFICATE`: Dominio tiene certificado
- `HAS_RISK`: Dominio tiene riesgo asociado
- `USES_TECHNOLOGY`: Dominio usa tecnología
- `RESOLVES_TO`: Dominio resuelve a IP
- `DISCOVERED_BY`: Entidad descubierta por método

### Constraints Principales
```cypher
CREATE CONSTRAINT domain_fqdn_unique FOR (d:Domain) REQUIRE d.fqdn IS UNIQUE;
CREATE CONSTRAINT provider_name_unique FOR (p:Provider) REQUIRE p.name IS UNIQUE;
CREATE CONSTRAINT service_name_domain_unique FOR (s:Service) REQUIRE (s.name, s.domain) IS UNIQUE;
```

### Índices de Rendimiento
```cypher
CREATE INDEX domain_base_domain FOR (d:Domain) ON (d.base_domain);
CREATE INDEX domain_risk_score FOR (d:Domain) ON (d.risk_score);
CREATE INDEX domain_tld FOR (d:Domain) ON (d.tld);
```

## 📋 Flujo Recomendado

### Para Partir de Cero
1. **Hacer respaldo del grafo actual (si existe):**
   ```bash
   ./neo4j_backup_restore.sh backup before-clean-start
   ```

2. **Inicializar grafo limpio:**
   ```bash
   ./neo4j_backup_restore.sh init-clean
   ```

3. **Inicializar esquema completo:**
   ```bash
   python3 init_graph_schema.py
   ```

4. **Asegurar compatibilidad con domain-backend:**
   ```bash
   python3 ensure_graph_schema.py
   ```

5. **Validar que todo esté listo:**
   ```bash
   ./neo4j_backup_restore.sh validate
   ```

### Para Migrar de Grafo Existente
1. **Hacer respaldo completo:**
   ```bash
   ./neo4j_backup_restore.sh backup pre-migration
   ```

2. **Asegurar compatibilidad (sin limpiar):**
   ```bash
   python3 ensure_graph_schema.py
   ```

3. **Validar estructura:**
   ```bash
   ./neo4j_backup_restore.sh validate
   ```

## 📂 Estructura de Respaldos

```
backups/neo4j/
├── 20250826_143000/
│   ├── backup_metadata.json       # Metadatos del respaldo
│   ├── domains.json               # Datos de dominios
│   ├── providers.json             # Datos de proveedores
│   ├── services.json              # Datos de servicios
│   ├── certificates.json          # Datos de certificados
│   ├── relationships.json         # Datos de relaciones
│   ├── database_stats.json        # Estadísticas de la BD
│   └── restore.sh                # Script de restauración
└── 20250826_120000/
    └── ... (estructura similar)
```

## 🔍 Verificación y Diagnóstico

### Verificar Estado de Neo4j
```bash
docker-compose ps neo4j
```

### Conectar a Neo4j Manualmente
```bash
docker exec neo4j cypher-shell -u neo4j -p test.password
```

### Ver Logs de Neo4j
```bash
docker logs neo4j
```

### Verificar Constraints e Índices
```cypher
SHOW CONSTRAINTS;
SHOW INDEXES;
```

### Verificar Nodos del Sistema
```cypher
MATCH (sc:SystemConfig) RETURN sc;
MATCH (rc:RiskConfiguration) RETURN rc;
```

## ⚠️ Consideraciones Importantes

1. **Siempre hacer respaldo antes de cambios importantes**
2. **Los scripts requieren que Neo4j esté corriendo en Docker Compose**
3. **Los respaldos usan exportación manual confiable (no requiere APOC)**
4. **La restauración limpia completamente la base de datos existente**
5. **Los scripts son compatibles con la estructura de domain-backend**

## 📋 Recomendaciones de Uso

### Para Producción
- **Usar:** `backup` (respaldo rápido)
- **Ventajas:** No interrumpe el servicio, rápido, confiable
- **Cuándo:** Respaldos automáticos, antes de deployments

### Para Migración Crítica
- **Usar:** `backup-full` (respaldo completo)
- **Ventajas:** Incluye dump binario completo
- **Cuándo:** Antes de migraciones mayores, cambios de versión

### Para Desarrollo
- **Usar:** `backup` + `init-clean` para reset completo
- **Ventajas:** Rápido ciclo desarrollo/testing

## 🆘 Solución de Problemas

### Neo4j no responde
```bash
docker-compose restart neo4j
```

### Error de permisos en respaldo
```bash
docker exec neo4j chmod 755 /backups
```

### APOC no disponible
Verificar en `docker-compose.yml`:
```yaml
environment:
  - NEO4J_PLUGINS=["apoc"]
  - NEO4J_dbms_security_procedures_unrestricted=apoc.*
```

### Restoration falla
1. Verificar que los archivos de respaldo existan
2. Verificar permisos del contenedor
3. Revisar logs: `docker logs neo4j`

## 📞 Soporte

Para problemas o mejoras, contactar al equipo de desarrollo o crear un issue en el repositorio del proyecto.