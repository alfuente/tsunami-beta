# Algoritmos de Evaluación de Riesgo Sistémico - Ecosistema Digital Chile

## 1. Algoritmo de Centralidad y Criticidad Sistémica (ACCS)

### Objetivo:
Identificar empresas y proveedores cuyo fallo tendría el mayor impacto sistémico en el ecosistema digital chileno.

### Metodología:

#### Paso 1: Construcción del Grafo de Dependencias
```python
def construir_grafo_dependencias(datos_dns, datos_proveedores):
    """
    Nodos: Empresas/Organizaciones
    Aristas: Dependencias tecnológicas (peso = intensidad de dependencia)
    """
    G = Graph()
    
    # Agregar nodos con atributos
    for empresa in empresas:
        G.add_node(empresa.id, 
                  sector=empresa.sector,
                  tamano=empresa.empleados,
                  criticidad_nacional=empresa.es_critica,
                  dominios_count=len(empresa.dominios))
    
    # Agregar aristas de dependencia
    for dependencia in analizar_dependencias_dns(datos_dns):
        peso = calcular_peso_dependencia(dependencia)
        G.add_edge(dependencia.origen, dependencia.destino, weight=peso)
    
    return G
```

#### Paso 2: Cálculo de Métricas de Centralidad
```python
def calcular_criticidad_sistemica(grafo):
    metricas = {}
    
    # Centralidad de grado ponderada
    grado_centralidad = dict(grafo.degree(weight='weight'))
    
    # Centralidad de cercanía (qué tan rápido se propagan fallos)
    cercania_centralidad = nx.closeness_centrality(grafo, distance='weight')
    
    # Centralidad de intermediación (cuántas rutas críticas pasan por el nodo)
    intermediacion = nx.betweenness_centrality(grafo, weight='weight')
    
    # PageRank modificado para dependencias
    pagerank = nx.pagerank(grafo, weight='weight')
    
    return {
        'grado': grado_centralidad,
        'cercania': cercania_centralidad,
        'intermediacion': intermediacion,
        'pagerank': pagerank
    }
```

#### Paso 3: Índice de Criticidad Sistémica (ICS)
```
ICS = 0.3 × Normalizado(Grado) + 
      0.25 × Normalizado(Intermediación) + 
      0.25 × Normalizado(PageRank) + 
      0.2 × Normalizado(Cercanía) + 
      Bonificador_Sector_Crítico
```

## 2. Algoritmo de Concentración de Proveedores (ACP)

### Objetivo:
Detectar concentraciones peligrosas de dependencias en pocos proveedores.

### Implementación:

#### Índice Herfindahl-Hirschman Modificado (HHI-M)
```python
def calcular_concentracion_proveedores(datos_empresas):
    """
    HHI modificado para medir concentración de dependencias
    """
    # Por cada proveedor, calcular su cuota de mercado ponderada
    cuotas_mercado = {}
    
    for proveedor in proveedores:
        # Cuota basada en número de clientes críticos
        clientes_criticos = contar_clientes_criticos(proveedor)
        peso_sector = calcular_peso_por_sector(proveedor.clientes)
        
        cuota = (clientes_criticos / total_empresas_criticas) * peso_sector
        cuotas_mercado[proveedor.id] = cuota
    
    # Calcular HHI modificado
    hhi_modificado = sum(cuota**2 for cuota in cuotas_mercado.values())
    
    return {
        'hhi': hhi_modificado,
        'nivel_concentracion': clasificar_concentracion(hhi_modificado),
        'proveedores_dominantes': identificar_dominantes(cuotas_mercado)
    }

def clasificar_concentracion(hhi):
    if hhi < 0.15: return "Competitivo"
    elif hhi < 0.25: return "Moderadamente concentrado"
    else: return "Altamente concentrado"
```

#### Algoritmo de Punto Único de Falla (APUF)
```python
def detectar_puntos_unicos_falla(grafo_dependencias):
    """
    Identifica nodos cuya eliminación fragmentaría significativamente la red
    """
    puntos_criticos = []
    
    for nodo in grafo_dependencias.nodes():
        # Simular eliminación del nodo
        grafo_temp = grafo_dependencias.copy()
        grafo_temp.remove_node(nodo)
        
        # Analizar conectividad resultante
        componentes = list(nx.connected_components(grafo_temp))
        fragmentacion = len(componentes)
        tamaño_componente_mayor = max(len(c) for c in componentes)
        
        # Calcular impacto de fragmentación
        impacto = calcular_impacto_fragmentacion(
            fragmentacion, 
            tamaño_componente_mayor, 
            len(grafo_dependencias.nodes())
        )
        
        if impacto > UMBRAL_CRITICIDAD:
            puntos_criticos.append({
                'nodo': nodo,
                'impacto': impacto,
                'fragmentacion': fragmentacion
            })
    
    return sorted(puntos_criticos, key=lambda x: x['impacto'], reverse=True)
```

## 3. Algoritmo de Propagación de Riesgo (APR)

### Objetivo:
Simular cómo se propagarían las fallas a través del ecosistema digital chileno.

### Implementación:

#### Modelo de Contagio Adaptado
```python
def simular_propagacion_riesgo(grafo, nodo_inicial, parametros):
    """
    Simula propagación de fallas usando modelo epidemiológico modificado
    """
    # Estados: Sano (S), Expuesto (E), Infectado (I), Recuperado (R)
    estados = {nodo: 'S' for nodo in grafo.nodes()}
    estados[nodo_inicial] = 'I'
    
    tiempo_simulacion = parametros['max_tiempo']
    resultados_temporales = []
    
    for t in range(tiempo_simulacion):
        nuevos_estados = estados.copy()
        
        for nodo in grafo.nodes():
            if estados[nodo] == 'I':
                # Infectar vecinos basado en probabilidad
                for vecino in grafo.neighbors(nodo):
                    if estados[vecino] == 'S':
                        prob_infeccion = calcular_probabilidad_contagio(
                            grafo[nodo][vecino]['weight'],
                            parametros['tasa_base_contagio'],
                            tiempo_exposicion=t
                        )
                        
                        if random.random() < prob_infeccion:
                            nuevos_estados[vecino] = 'E'
            
            elif estados[nodo] == 'E':
                # Transición a infectado
                if random.random() < parametros['tasa_incubacion']:
                    nuevos_estados[nodo] = 'I'
            
            elif estados[nodo] == 'I':
                # Posible recuperación
                if random.random() < parametros['tasa_recuperacion']:
                    nuevos_estados[nodo] = 'R'
        
        estados = nuevos_estados
        resultados_temporales.append(estados.copy())
    
    return analizar_resultados_simulacion(resultados_temporales)

def calcular_probabilidad_contagio(peso_dependencia, tasa_base, tiempo_exposicion):
    """
    Probabilidad de que una falla se propague entre nodos conectados
    """
    factor_dependencia = min(peso_dependencia / 10.0, 1.0)
    factor_tiempo = 1 - math.exp(-0.1 * tiempo_exposicion)  # Saturación exponencial
    
    return tasa_base * factor_dependencia * factor_tiempo
```

## 4. Algoritmo de Evaluación de Cadena de Suministro (AECS)

### Objetivo:
Evaluar riesgos específicos de la cadena de suministro tecnológica.

### Implementación:

#### Análisis de Dependencias Transitivas
```python
def analizar_cadena_suministro(empresa_objetivo):
    """
    Análiza dependencias de n-niveles para identificar riesgos ocultos
    """
    dependencias_directas = obtener_dependencias_nivel_1(empresa_objetivo)
    cadena_completa = {}
    
    def explorar_dependencias(nodo, nivel=1, max_nivel=5):
        if nivel > max_nivel:
            return
        
        for dependencia in obtener_dependencias(nodo):
            if dependencia.id not in cadena_completa:
                cadena_completa[dependencia.id] = {
                    'proveedor': dependencia,
                    'nivel': nivel,
                    'criticidad': evaluar_criticidad_proveedor(dependencia),
                    'riesgo_pais': evaluar_riesgo_jurisdiccional(dependencia),
                    'alternativas': contar_alternativas(dependencia)
                }
                
                # Recursión para siguiente nivel
                explorar_dependencias(dependencia, nivel + 1, max_nivel)
    
    # Explorar cadena completa
    explorar_dependencias(empresa_objetivo)
    
    return {
        'mapa_dependencias': cadena_completa,
        'puntos_criticos': identificar_cuellos_botella(cadena_completa),
        'riesgo_concentracion': calcular_riesgo_concentracion_cadena(cadena_completa),
        'recomendaciones': generar_recomendaciones_diversificacion(cadena_completa)
    }
```

#### Índice de Resiliencia de Cadena (IRC)
```python
def calcular_resiliencia_cadena(cadena_suministro):
    """
    Evalúa la resiliencia general de la cadena de suministro
    """
    factores = {
        'diversificacion_geografica': calcular_diversificacion_geografica(cadena),
        'redundancia_proveedores': calcular_redundancia_proveedores(cadena),
        'tiempo_recuperacion': estimar_tiempo_recuperacion(cadena),
        'alternativas_disponibles': evaluar_alternativas(cadena),
        'dependencia_critica': evaluar_dependencias_criticas(cadena)
    }
    
    # Pesos específicos para contexto chileno
    pesos = {
        'diversificacion_geografica': 0.3,  # Alto por aislamiento geográfico
        'redundancia_proveedores': 0.25,
        'tiempo_recuperacion': 0.2,
        'alternativas_disponibles': 0.15,
        'dependencia_critica': 0.1
    }
    
    irc = sum(factores[factor] * pesos[factor] for factor in factores)
    return normalizar_irc(irc)
```

## 5. Algoritmo de Detección de Clusters de Riesgo (ADCR)

### Objetivo:
Identificar grupos de empresas con riesgos correlacionados que podrían fallar simultáneamente.

### Implementación:

#### Clustering por Similitud de Riesgo
```python
def detectar_clusters_riesgo(matriz_empresas):
    """
    Agrupa empresas con perfiles de riesgo similares usando clustering jerárquico
    """
    from sklearn.cluster import AgglomerativeClustering
    from sklearn.metrics.pairwise import cosine_similarity
    
    # Preparar matriz de características de riesgo
    caracteristicas_riesgo = []
    
    for empresa in empresas:
        vector_riesgo = [
            empresa.riesgo_dns,
            empresa.riesgo_infraestructura,
            empresa.concentracion_proveedores,
            empresa.dependencia_extranjera,
            empresa.diversificacion_geografica,
            empresa.redundancia_servicios
        ]
        caracteristicas_riesgo.append(vector_riesgo)
    
    # Clustering jerárquico
    clustering = AgglomerativeClustering(
        n_clusters=None, 
        distance_threshold=UMBRAL_SIMILITUD,
        linkage='ward'
    )
    
    clusters = clustering.fit_predict(caracteristicas_riesgo)
    
    # Evaluar riesgo de cada cluster
    clusters_evaluados = []
    for cluster_id in set(clusters):
        empresas_cluster = [e for i, e in enumerate(empresas) if clusters[i] == cluster_id]
        
        riesgo_cluster = evaluar_riesgo_cluster(empresas_cluster)
        clusters_evaluados.append({
            'id': cluster_id,
            'empresas': empresas_cluster,
            'riesgo_sistémico': riesgo_cluster,
            'tamaño': len(empresas_cluster)
        })
    
    return sorted(clusters_evaluados, key=lambda x: x['riesgo_sistémico'], reverse=True)

def evaluar_riesgo_cluster(empresas_cluster):
    """
    Evalúa el riesgo sistémico de un cluster específico
    """
    # Factores de amplificación por clustering
    factor_tamaño = min(len(empresas_cluster) / 10.0, 2.0)  # Max 2x
    factor_sector = calcular_concentracion_sectorial(empresas_cluster)
    factor_interdependencia = calcular_interdependencias_internas(empresas_cluster)
    
    riesgo_promedio = sum(e.riesgo_individual for e in empresas_cluster) / len(empresas_cluster)
    
    return riesgo_promedio * factor_tamaño * factor_sector * factor_interdependencia
```

## 6. Algoritmo de Evaluación de Proveedores Críticos (AEPC)

### Objetivo:
Clasificar proveedores por su importancia sistémica y riesgo asociado.

### Implementación:

#### Índice de Importancia Sistémica del Proveedor (IISP)
```python
def evaluar_proveedor_critico(proveedor, ecosistema):
    """
    Evalúa la criticidad sistémica de un proveedor específico
    """
    
    # 1. Análisis de cuota de mercado crítica
    clientes_criticos = [c for c in proveedor.clientes if c.es_critico]
    cuota_sector_critico = len(clientes_criticos) / total_empresas_criticas
    
    # 2. Análisis de sustituibilidad
    alternativas = contar_alternativas_viables(proveedor)
    indice_sustituibilidad = max(0, (5 - alternativas) / 5)  # Menos alternativas = más riesgo
    
    # 3. Análisis de tiempo de reemplazo
    tiempo_reemplazo = estimar_tiempo_migracion(proveedor)
    factor_tiempo = min(tiempo_reemplazo / 30, 2.0)  # 30 días como baseline
    
    # 4. Análisis de dependencias técnicas
    dependencias_tecnicas = analizar_dependencias_tecnicas(proveedor)
    factor_tecnico = evaluar_complejidad_tecnica(dependencias_tecnicas)
    
    # 5. Factor geopolítico y jurisdiccional
    factor_jurisdiccional = evaluar_riesgo_jurisdiccional(proveedor.pais)
    
    # Cálculo IISP
    iisp = (
        0.3 * cuota_sector_critico +
        0.25 * indice_sustituibilidad +
        0.2 * factor_tiempo +
        0.15 * factor_tecnico +
        0.1 * factor_jurisdiccional
    ) * 10  # Normalizar a escala 0-10
    
    return {
        'iisp': iisp,
        'clasificacion': clasificar_proveedor(iisp),
        'recomendaciones': generar_recomendaciones_proveedor(proveedor, iisp)
    }

def clasificar_proveedor(iisp):
    if iisp >= 8: return "Proveedor Sistémicamente Crítico"
    elif iisp >= 6: return "Proveedor de Alto Riesgo"
    elif iisp >= 4: return "Proveedor de Riesgo Moderado"
    else: return "Proveedor de Bajo Riesgo"
```

## 7. Algoritmo de Matriz de Riesgo Sectorial (AMRS)

### Objetivo:
Evaluar riesgos específicos por sectores de la economía chilena.

### Implementación:

#### Matriz Sectorial de Interdependencias
```python
def construir_matriz_riesgo_sectorial():
    """
    Construye matriz de riesgo entre sectores económicos
    """
    sectores = ['bancario', 'retail', 'mineria', 'energia', 'telecomunicaciones', 
                'gobierno', 'salud', 'educacion', 'transporte', 'manufactura']
    
    # Matriz de dependencias inter-sectoriales
    matriz_dependencias = crear_matriz_dependencias_sectoriales(sectores)
    
    # Para cada par de sectores, calcular:
    for i, sector_a in enumerate(sectores):
        for j, sector_b in enumerate(sectores):
            if i != j:
                # Intensidad de dependencia tecnológica
                dependencia_tech = calcular_dependencia_tecnologica(sector_a, sector_b)
                
                # Criticidad económica de la relación
                criticidad_economica = evaluar_criticidad_economica(sector_a, sector_b)
                
                # Tiempo de recuperación en caso de falla
                tiempo_recuperacion = estimar_tiempo_recuperacion_sectorial(sector_a, sector_b)
                
                matriz_dependencias[i][j] = {
                    'dependencia': dependencia_tech,
                    'criticidad': criticidad_economica,
                    'recuperacion': tiempo_recuperacion,
                    'riesgo_cascada': dependencia_tech * criticidad_economica / tiempo_recuperacion
                }
    
    return matriz_dependencias

def identificar_sectores_sistemicamente_importantes(matriz):
    """
    Identifica sectores cuya falla tendría mayor impacto sistémico
    """
    impactos_sectoriales = {}
    
    for i, sector in enumerate(sectores):
        # Sumar impactos hacia otros sectores (outdegree)
        impacto_saliente = sum(matriz[i][j]['riesgo_cascada'] for j in range(len(sectores)) if i != j)
        
        # Sumar dependencias desde otros sectores (indegree)  
        dependencia_entrante = sum(matriz[j][i]['riesgo_cascada'] for j in range(len(sectores)) if i != j)
        
        # Índice de Importancia Sistémica Sectorial (IISS)
        iiss = 0.6 * impacto_saliente + 0.4 * dependencia_entrante
        
        impactos_sectoriales[sector] = {
            'iiss': iiss,
            'impacto_saliente': impacto_saliente,
            'dependencia_entrante': dependencia_entrante
        }
    
    return sorted(impactos_sectoriales.items(), key=lambda x: x[1]['iiss'], reverse=True)
```

## 8. Algoritmo de Análisis de Vulnerabilidades en Cascada (AAVC)

### Objetivo:
Identificar cadenas de vulnerabilidades que podrían amplificar riesgos sistémicos.

### Implementación:

```python
def analizar_vulnerabilidades_cascada(empresas, vulnerabilidades_conocidas):
    """
    Identifica cadenas de vulnerabilidades que podrían crear efectos cascada
    """
    # Construir grafo de vulnerabilidades compartidas
    grafo_vuln = construir_grafo_vulnerabilidades(empresas, vulnerabilidades_conocidas)
    
    # Encontrar caminos críticos
    caminos_criticos = []
    
    for vuln in vulnerabilidades_conocidas:
        if vuln.severidad >= UMBRAL_SEVERIDAD_ALTA:
            empresas_afectadas = obtener_empresas_vulnerables(vuln)
            
            # Evaluar potencial de cascada
            potencial_cascada = evaluar_potencial_cascada(
                empresas_afectadas, 
                grafo_dependencias
            )
            
            if potencial_cascada > UMBRAL_CASCADA:
                caminos_criticos.append({
                    'vulnerabilidad': vuln,
                    'empresas_directas': empresas_afectadas,
                    'empresas_indirectas': calcular_empresas_indirectas(empresas_afectadas),
                    'potencial_cascada': potencial_cascada,
                    'sectores_impactados': identificar_sectores_impactados(empresas_afectadas),
                    'tiempo_explotacion_estimado': estimar_tiempo_explotacion(vuln)
                })
    
    return priorizar_vulnerabilidades_cascada(caminos_criticos)

def evaluar_potencial_cascada(empresas_afectadas, grafo):
    """
    Calcula el potencial de una vulnerabilidad para crear efectos cascada
    """
    potencial_total = 0
    
    for empresa in empresas_afectadas:
        # Centralidad de la empresa en el ecosistema
        centralidad = nx.eigenvector_centrality(grafo)[empresa.id]
        
        # Número de conexiones críticas
        conexiones_criticas = contar_conexiones_criticas(empresa, grafo)
        
        # Factor de criticidad sectorial
        factor_sectorial = PESOS_SECTORIALES.get(empresa.sector, 1.0)
        
        potencial_empresa = centralidad * conexiones_criticas * factor_sectorial
        potencial_total += potencial_empresa
    
    return potencial_total
```

## 9. Algoritmo de Priorización de Riesgos Nacionales (APRN)

### Objetivo:
Priorizar riesgos desde una perspectiva de seguridad nacional chilena.

### Implementación:

#### Índice de Riesgo Nacional (IRN)
```python
def calcular_riesgo_nacional(entidad):
    """
    Evalúa riesgo desde perspectiva de seguridad nacional
    """
    componentes = {
        # Criticidad para infraestructura nacional
        'criticidad_nacional': evaluar_criticidad_nacional(entidad),
        
        # Dependencia de actores extranjeros
        'dependencia_extranjera': calcular_dependencia_extranjera(entidad),
        
        # Capacidad de respuesta nacional
        'capacidad_respuesta': evaluar_capacidad_respuesta_local(entidad),
        
        # Impacto económico potencial
        'impacto_economico': estimar_impacto_economico(entidad),
        
        # Riesgo reputacional país
        'riesgo_reputacional': evaluar_riesgo_reputacional_chile(entidad)
    }
    
    # Pesos ajustados para prioridades nacionales chilenas
    pesos = {
        'criticidad_nacional': 0.35,
        'dependencia_extranjera': 0.25,
        'capacidad_respuesta': 0.2,
        'impacto_economico': 0.15,
        'riesgo_reputacional': 0.05
    }
    
    irn = sum(componentes[comp] * pesos[comp] for comp in componentes)
    
    return {
        'irn': irn,
        'componentes': componentes,
        'clasificacion_nacional': clasificar_riesgo_nacional(irn),
        'acciones_recomendadas': definir_acciones_nacionales(irn, componentes)
    }
```

## 10. Framework de Implementación y Monitoreo

### Sistema de Alertas Tempranas
```python
def sistema_alertas_sistemicas():
    """
    Sistema de monitoreo continuo para riesgos sistémicos emergentes
    """
    alertas = []
    
    # Monitor de concentración
    concentracion_actual = calcular_concentracion_mercado()
    if concentracion_actual > UMBRAL_CONCENTRACION:
        alertas.append(crear_alerta_concentracion(concentracion_actual))
    
    # Monitor de nuevas dependencias críticas
    nuevas_dependencias = detectar_nuevas_dependencias_criticas()
    for dep in nuevas_dependencias:
        if dep.riesgo > UMBRAL_DEPENDENCIA_CRITICA:
            alertas.append(crear_alerta_nueva_dependencia(dep))
    
    # Monitor de cambios en proveedores críticos
    cambios_proveedores = monitorear_cambios_proveedores_criticos()
    for cambio in cambios_proveedores:
        impacto = evaluar_impacto_cambio_proveedor(cambio)
        if impacto > UMBRAL_IMPACTO:
            alertas.append(crear_alerta_cambio_proveedor(cambio, impacto))
    
    return priorizar_alertas(alertas)
```

### Dashboard de Métricas Sistémicas
- **Índice de Concentración Nacional (ICN)**: Mide concentración general del mercado
- **Índice de Dependencia Externa (IDE)**: Mide dependencia de servicios extranjeros
- **Índice de Resiliencia Sectorial (IRS)**: Mide capacidad de recuperación por sector
- **Índice de Diversificación Geográfica (IDG)**: Mide distribución geográfica de infraestructura crítica

## Datos Adicionales Recomendados para Algoritmos Sistémicos

### Información Empresarial:
1. **Datos financieros**: Ingresos, empleados, participación de mercado
2. **Clasificación sectorial**: Según taxonomía de infraestructura crítica chilena
3. **Interdependencias contractuales**: Contratos críticos entre empresas
4. **Ubicación física**: Centros de datos, oficinas principales

### Información de Proveedores:
5. **Cartera de clientes completa**: Todos los clientes, no solo los principales
6. **Capacidad operativa**: Volumen máximo, redundancias
7. **Tiempo de implementación**: Para servicios críticos
8. **Acuerdos de nivel de servicio (SLA)**

### Contexto Regulatorio:
9. **Clasificación de criticidad nacional**: Según autoridades chilenas
10. **Requerimientos de continuidad**: Por sector y por empresa
11. **Planes de contingencia**: Existencia y calidad de planes DR/BC

### Inteligencia de Amenazas:
12. **Incidentes históricos**: Base de datos de incidentes previos
13. **Amenazas específicas por sector**: Intel específica para cada industria
14. **Indicadores de compromiso (IoC)**: Específicos del ecosistema chileno

## Implementación Práctica

### Fase 1: Recopilación y Normalización (Mes 1-2)
- Automatización de recolección de datos DNS
- APIs para información empresarial y sectorial
- Integración con fuentes de threat intelligence

### Fase 2: Implementación de Algoritmos (Mes 3-4)
- Desarrollo de módulos de cálculo
- Implementación de grafos de dependencias
- Sistema de scoring y clasificación

### Fase 3: Validación y Calibración (Mes 5-6)
- Validación con incidentes históricos chilenos
- Ajuste de umbrales y pesos
- Pruebas de stress del sistema

### Fase 4: Operación y Mejora (Mes 7+)
- Dashboard operativo
- Sistema de alertas automatizadas
- Retroalimentación y mejora continua

## Consideraciones Especiales para Chile

### Factores Únicos del Contexto Chileno:
- **Aislamiento geográfico**: Mayor dependencia de cables submarinos
- **Concentración económica**: Pocas empresas grandes dominan sectores
- **Dependencia tecnológica**: Alta dependencia de proveedores extranjeros
- **Sectores críticos**: Minería, agricultura, servicios financieros

### Umbrales Sugeridos para el Contexto Chileno:
- **Concentración crítica**: HHI > 0.25 (más estricto por tamaño del mercado)
- **Dependencia extranjera**: > 70% considerado alto riesgo
- **Tiempo de recuperación**: > 7 días considerado crítico
- **Cobertura geográfica**: < 3 regiones considerado concentrado

Este framework proporciona una base sólida para evaluar y monitorear riesgos sistémicos en el ecosistema digital chileno, permitiendo identificar proactivamente amenazas a la seguridad nacional cibernética y la resiliencia de la cadena de suministro digital.