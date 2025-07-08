package com.example.risk.config;

import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import org.neo4j.driver.AuthTokens;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.annotation.PreDestroy;

@ApplicationScoped
public class Neo4jConfiguration {

    @ConfigProperty(name = "neo4j.uri")
    String uri;

    @ConfigProperty(name = "neo4j.username")
    String username;

    @ConfigProperty(name = "neo4j.password")
    String password;

    private Driver driver;

    @Produces
    @ApplicationScoped
    public Driver neo4jDriver() {
        if (driver == null) {
            driver = GraphDatabase.driver(uri, AuthTokens.basic(username, password));
        }
        return driver;
    }

    @PreDestroy
    public void close() {
        if (driver != null) {
            driver.close();
        }
    }
}