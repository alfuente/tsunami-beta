package com.example.risk;

import org.neo4j.driver.*;

import java.io.IOException;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;

public class Neo4jSchemaManager {
  private static final String NEO4J_URI = "bolt://localhost:7687";
  private static final String USER = "neo4j";
  private static final String PASS = "test";
  private static final String CONTAINER = "neo4j";  // nombre del servicio docker

  public static void main(String[] args) throws Exception {
    if (args.length == 0) {
      System.err.println("Acciones: create|backup|drop");
      return;
    }
    switch (args[0]) {
      case "create" -> createSchema();
      case "backup" -> backupSchema();
      case "drop"   -> dropSchema();
      default -> System.err.println("Acción no reconocida");
    }
  }

  private static void createSchema() {
    try (Driver driver = GraphDatabase.driver(NEO4J_URI, AuthTokens.basic(USER, PASS));
         Session session = driver.session()) {
      List<String> ddl = List.of(
        // constraints + índices mínimos (ajusta a tu dominio)
        "CREATE CONSTRAINT domain_fqdn IF NOT EXISTS FOR (d:Domain) REQUIRE d.fqdn IS UNIQUE",
        "CREATE INDEX provider_cat IF NOT EXISTS FOR (p:Provider) ON (p.category)"
      );
      ddl.forEach(session::run);
      System.out.println("Esquema creado/actualizado");
    }
  }

  private static void backupSchema() throws IOException, InterruptedException {
    String backupFile = "neo4j_" + LocalDateTime.now().toString().replace(':','-') + ".dump";
    // Ejecuta dentro del contenedor el admin-dump hacia /backups
    Process p = new ProcessBuilder(
        "docker", "exec", CONTAINER,
        "neo4j-admin", "database", "dump",
        "--expand-commands", "--overwrite-destination",
        "--to=/backups/" + backupFile)
        .inheritIO()
        .start();
    if (p.waitFor() == 0)
      System.out.println("Backup generado: " + backupFile);
  }

  private static void dropSchema() {
    try (Driver driver = GraphDatabase.driver(NEO4J_URI, AuthTokens.basic(USER, PASS));
         Session session = driver.session()) {
      session.run("MATCH (n) DETACH DELETE n");
      System.out.println("Base Neo4j limpia (esquema lógico reiniciado)");
    }
  }
}
