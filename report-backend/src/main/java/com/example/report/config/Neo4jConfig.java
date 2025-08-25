package com.example.report.config;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;

import jakarta.annotation.PreDestroy;
import java.util.logging.Logger;

@ApplicationScoped
public class Neo4jConfig {
    
    private static final Logger LOGGER = Logger.getLogger(Neo4jConfig.class.getName());
    
    @ConfigProperty(name = "quarkus.neo4j.uri")
    String uri;
    
    @ConfigProperty(name = "quarkus.neo4j.authentication.username")
    String username;
    
    @ConfigProperty(name = "quarkus.neo4j.authentication.password")
    String password;
    
    private Driver driver;
    
    @Produces
    @Singleton
    public Driver createDriver() {
        if (driver == null) {
            LOGGER.info("Creating Neo4j driver connection to: " + uri);
            driver = GraphDatabase.driver(uri, AuthTokens.basic(username, password));
        }
        return driver;
    }
    
    @PreDestroy
    public void closeDriver() {
        if (driver != null) {
            LOGGER.info("Closing Neo4j driver connection");
            driver.close();
        }
    }
}