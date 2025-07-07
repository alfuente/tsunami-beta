Propuesta de algoritmo de Risk Score
(versión 1.0 – pensada para implementarse en Neo4j + Iceberg, con soporte de propagación a lo largo del grafo y retro-cálculo histórico)

| Componente                     | Intuición                                                                                                                  | Peso por defecto |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| **Base Tech Score**            | Configuración técnica del nodo (DNSSEC, TLS, versiones, CVEs, redundancia, etc.)                                           | 40 %             |
| **Third-Party Score**          | Riesgo inherente de los Proveedores y Servicios de los que depende el nodo                                                 | 25 %             |
| **Incident Impact**            | Penalización temporal basada en la severidad y antigüedad de incidentes que *Afectan* al nodo (directos o por propagación) | **30 %**         |
| **Context Boost / Mitigation** | Reducciones por controles compensatorios, certificaciones, planes de continuidad probados                                  | −5 %             |



Risk Score final = Σ (componente × peso) → normalizado 0 – 100
Se recalcula por dominio y proveedor; las organizaciones heredan el promedio ponderado de sus dominios y servicios críticos.

1. Base Tech Score (0-100)

| Factor                    | Fórmula                                                                 | Puntaje parcial |
| ------------------------- | ----------------------------------------------------------------------- | --------------- |
| **DNS**                   | +20 pts si DNSSEC habilitado; −15 pts si un solo NS en el mismo ASN/geo | 0…35            |
| **TLS**                   | `grade = SSL-Labs` → A+ = 0 penalización; B = −5; C = −15; ≤D = −30     | 0…30            |
| **Tecnologías obsoletas** | `(n_crit_CVE × 5) + (n_high × 3)` limitado a −25 pts                    | 0…25            |
| **Redundancia / HA**      | +10 pts si Multi-AZ / Multi-Region; 0 si Single AZ                      | 0…10            |


BaseTechScore = 100 + Σ penalizaciones - Σ bonificaciones → recortado 0-100
(se guarda como d.base_score o p.base_score en el nodo)

2. Third-Party Score
Para un nodo X (Domain o Provider):

third_party_score(X) =
      Σ_dep( risk_score(dep) × exposure_weight(dep) )
      -----------------------------------------------
      Σ_dep exposure_weight(dep)


exposure_weight por defecto:

Critical dependencia → 1.0

Important → 0.6

Nice-to-have → 0.3

Para evitar bucles, corta la propagación a profundidad 2; más lejos se atenúa con 0.8^hops.

3. Incident Impact
3.1 Severidad base

| Severidad | `incident_score_raw` |
| --------- | -------------------- |
| Critical  | 100                  |
| High      | 70                   |
| Medium    | 40                   |
| Low       | 10                   |


3.2 Decaimiento temporal

incident_score = incident_score_raw × e^{ - λ · Δd }

Δd = días desde la fecha de detección; λ ≈ 0.015 (½-vida ≈ 46 días)

3.3 Propagación
Directa: (:Incident)-[:AFFECTS]->(v)

Suma incident_score a ImpactDirect del nodo v.

Indirecta (Tercer Partes)

Si un Provider está afectado, propaga a cada dominio que lo usa:
incident_score × 0.5 × exposure_weight.

Si un Service está afectado, propaga con factor 0.4, etc.

Descuentos

Si el nodo tiene failover_exists=true o redundancia alta: multiplica por 0.6.

3.4 Score de incidente acumulado

incident_component(X) = Σ incident_scores_direct_indirect (máx 100)
Se limita a 100, luego se re-escala al margen de incidente (30 %) → incident_score_component = incident_component × 0.30.

4. Context Boost / Mitigación
ISO 27001 / SOC2 Type II certificado → −3 pts

Plan de continuidad probado < 12 meses → −2 pts

Bug-bounty activo → −1 pt
(guardados como propiedades booleanas / fechas en Provider u Organization)

5. Risk Score final
RiskScore(X) = 0.40·BaseTech +
               0.25·ThirdParty +
               0.30·IncidentImpact –
               0.05·MitigationBonus


Normaliza a 0-100 y etiqueta:

Score	Tier
80-100	Critical
60-79	High
40-59	Medium
20-39	Low
< 20	Minimal
