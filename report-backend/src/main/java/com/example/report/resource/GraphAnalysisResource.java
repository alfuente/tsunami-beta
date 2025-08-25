package com.example.report.resource;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

@Path("/api/v1/graph")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Tag(name = "Graph Analysis", description = "Análisis detallado del grafo Neo4j")
public class GraphAnalysisResource {
    
    private static final Logger LOGGER = Logger.getLogger(GraphAnalysisResource.class.getName());
    
    @GET
    @Path("/analysis")
    @Operation(
        summary = "Obtener análisis completo del grafo",
        description = "Ejecuta un análisis detallado del grafo Neo4j y retorna estadísticas completas en formato JSON"
    )
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Análisis completado exitosamente",
            content = @Content(
                mediaType = MediaType.APPLICATION_JSON,
                schema = @Schema(implementation = Object.class)
            )
        ),
        @APIResponse(
            responseCode = "500",
            description = "Error interno del servidor",
            content = @Content(mediaType = MediaType.APPLICATION_JSON)
        )
    })
    public Response getGraphAnalysis() {
        try {
            LOGGER.info("Generating graph analysis report");
            
            // Ejecutar el script de análisis Python
            ProcessBuilder pb = new ProcessBuilder("python3", "graph_analysis_demo.py");
            pb.directory(new java.io.File("/home/alf/dev/tsunami-beta/report-backend"));
            pb.redirectErrorStream(true);
            
            Process process = pb.start();
            
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\\n");
                }
            }
            
            int exitCode = process.waitFor();
            
            if (exitCode == 0) {
                // Buscar el archivo JSON más reciente
                String jsonFile = findLatestAnalysisFile("json");
                if (jsonFile != null) {
                    String jsonContent = Files.readString(Paths.get(jsonFile));
                    return Response.ok(jsonContent).build();
                } else {
                    return Response.ok(createSuccessResponse("Analysis completed but JSON file not found", output.toString())).build();
                }
            } else {
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                        .entity(createErrorResponse("Analysis failed", output.toString()))
                        .build();
            }
            
        } catch (Exception e) {
            LOGGER.severe("Failed to generate graph analysis: " + e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(createErrorResponse("Internal error", e.getMessage()))
                    .build();
        }
    }
    
    @GET
    @Path("/report")
    @Produces(MediaType.TEXT_PLAIN)
    @Operation(
        summary = "Obtener reporte en texto plano",
        description = "Retorna el último reporte de análisis del grafo en formato texto legible"
    )
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Reporte obtenido exitosamente",
            content = @Content(mediaType = MediaType.TEXT_PLAIN)
        ),
        @APIResponse(
            responseCode = "404",
            description = "Reporte no encontrado",
            content = @Content(mediaType = MediaType.TEXT_PLAIN)
        ),
        @APIResponse(
            responseCode = "500",
            description = "Error interno del servidor",
            content = @Content(mediaType = MediaType.TEXT_PLAIN)
        )
    })
    public Response getGraphReport() {
        try {
            LOGGER.info("Generating graph analysis text report");
            
            // Buscar el archivo de reporte más reciente
            String reportFile = findLatestAnalysisFile("txt");
            if (reportFile != null) {
                String reportContent = Files.readString(Paths.get(reportFile));
                return Response.ok(reportContent).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("No analysis report found")
                        .build();
            }
            
        } catch (Exception e) {
            LOGGER.severe("Failed to get graph report: " + e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Failed to get graph report: " + e.getMessage())
                    .build();
        }
    }
    
    @POST
    @Path("/analyze")
    @Operation(
        summary = "Ejecutar nuevo análisis",
        description = "Inicia un nuevo análisis del grafo en segundo plano"
    )
    @APIResponses({
        @APIResponse(
            responseCode = "202",
            description = "Análisis iniciado exitosamente",
            content = @Content(
                mediaType = MediaType.APPLICATION_JSON,
                schema = @Schema(implementation = Object.class)
            )
        ),
        @APIResponse(
            responseCode = "500",
            description = "Error al iniciar análisis",
            content = @Content(mediaType = MediaType.APPLICATION_JSON)
        )
    })
    public Response triggerAnalysis() {
        try {
            LOGGER.info("Triggering new graph analysis");
            
            ProcessBuilder pb = new ProcessBuilder("python3", "graph_analysis_demo.py");
            pb.directory(new java.io.File("/home/alf/dev/tsunami-beta/report-backend"));
            
            Process process = pb.start();
            
            // No esperar a que termine, devolver respuesta inmediata
            Map<String, Object> response = new HashMap<>();
            response.put("status", "Analysis started");
            response.put("message", "Graph analysis has been triggered and is running in background");
            response.put("timestamp", LocalDateTime.now().toString());
            
            return Response.accepted(response).build();
            
        } catch (Exception e) {
            LOGGER.severe("Failed to trigger graph analysis: " + e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(createErrorResponse("Failed to trigger analysis", e.getMessage()))
                    .build();
        }
    }
    
    @GET
    @Path("/health")
    @Operation(
        summary = "Health check del grafo",
        description = "Verifica la conectividad y estado de salud de la base de datos Neo4j"
    )
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Sistema saludable",
            content = @Content(
                mediaType = MediaType.APPLICATION_JSON,
                schema = @Schema(implementation = Object.class)
            )
        ),
        @APIResponse(
            responseCode = "503",
            description = "Servicio no disponible",
            content = @Content(mediaType = MediaType.APPLICATION_JSON)
        )
    })
    public Response getGraphHealth() {
        try {
            // Verificar conectividad básica con Neo4j mediante un comando simple
            ProcessBuilder pb = new ProcessBuilder("python3", "-c", 
                "from neo4j import GraphDatabase; " +
                "driver = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', 'test.password')); " +
                "session = driver.session(); " +
                "result = session.run('RETURN 1 as test'); " +
                "print('Connected'); " +
                "driver.close()");
            
            Process process = pb.start();
            int exitCode = process.waitFor();
            
            Map<String, Object> health = new HashMap<>();
            health.put("neo4j_connection", exitCode == 0 ? "healthy" : "unhealthy");
            health.put("timestamp", LocalDateTime.now().toString());
            health.put("service", "graph-analysis");
            
            return Response.ok(health).build();
            
        } catch (Exception e) {
            Map<String, Object> health = new HashMap<>();
            health.put("neo4j_connection", "error");
            health.put("error", e.getMessage());
            health.put("timestamp", LocalDateTime.now().toString());
            
            return Response.status(Response.Status.SERVICE_UNAVAILABLE)
                    .entity(health)
                    .build();
        }
    }
    
    private String findLatestAnalysisFile(String extension) {
        try {
            java.nio.file.Path dir = Paths.get("/home/alf/dev/tsunami-beta");
            return Files.list(dir)
                    .filter(path -> path.getFileName().toString().matches("graph_analysis_.*\\." + extension))
                    .max((p1, p2) -> {
                        try {
                            return Files.getLastModifiedTime(p1).compareTo(Files.getLastModifiedTime(p2));
                        } catch (IOException e) {
                            return 0;
                        }
                    })
                    .map(path -> path.toString())
                    .orElse(null);
        } catch (IOException e) {
            LOGGER.warning("Error finding latest analysis file: " + e.getMessage());
            return null;
        }
    }
    
    private Map<String, Object> createErrorResponse(String error, String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("error", error);
        response.put("message", message);
        response.put("timestamp", LocalDateTime.now().toString());
        return response;
    }
    
    private Map<String, Object> createSuccessResponse(String status, String details) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", status);
        response.put("details", details);
        response.put("timestamp", LocalDateTime.now().toString());
        return response;
    }
}