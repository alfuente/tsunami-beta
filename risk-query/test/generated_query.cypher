MATCH (n)-[r]->()
WITH n, count(r) AS outDegree
ORDER BY outDegree DESC
LIMIT 1

// Observamos que los nodos con más dependencias son probablemente los proveedores o servicios principales
// Por tanto, podemos refinar la consulta para buscar específicamente en las etiquetas de proveedor y servicio
MATCH (p:Provider)-[]->() OR MATCH (s:Service)-[]->()
WITH p, s, count(r) AS outDegree
ORDER BY outDegree DESC
LIMIT 1

// Si el usuario pregunta por "cual es el nodo con más dependencias", supondremos que busca el proveedor o servicio con más servicios asociados a él (en lugar de subdominios u otros tipos de relaciones)
MATCH (p:Provider)-[:PROVIDES_SERVICE]->(s:Service) OR MATCH (s:Service)-[:SERVICED_BY]->(p:Provider)
WITH p, count(s) AS serviceCount
ORDER BY serviceCount DESC
LIMIT 1

// Si el usuario pregunta por "cual es el nodo con más dependencias", supondremos que busca el proveedor o servicio con más servicios asociados a él (en lugar de subdominios u otros tipos de relaciones)
MATCH (p:Provider)-[:PROVIDES_SERVICE]->(s:Service) OR MATCH (s:Service)-[:SERVICED_BY]->(p:Provider)
WITH p, count(s) AS serviceCount
ORDER BY serviceCount DESC
LIMIT 1;
