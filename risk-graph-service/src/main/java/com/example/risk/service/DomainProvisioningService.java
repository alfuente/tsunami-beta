package com.example.risk.service;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.neo4j.driver.Driver;
import org.neo4j.driver.Session;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

@ApplicationScoped
public class DomainProvisioningService {

    @Inject Driver driver;
    @Inject RiskCalculator riskCalc;

    @ConfigProperty(name = "risk.loader.path")
    String loaderPath;

    @ConfigProperty(name = "warehouse.snapshot.url")
    String warehouseUrl;

    @ConfigProperty(name = "ipinfo.token")
    String ipinfoToken;

    public boolean ensureDomain(String fqdn, int depth) {
        boolean exists;
        try (Session s = driver.session()) {
            exists = s.run("MATCH (d:Domain {fqdn:$f}) RETURN d", Map.of("f", fqdn)).hasNext();
        }
        if (exists) return false;

        // run loader python
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "python3", loaderPath,
                    "--seeds", fqdn,
                    "--depth", String.valueOf(depth),
                    "--bolt", "bolt://localhost:7687",
                    "--user", "neo4j", "--password", "test",
                    "--ipinfo-token", ipinfoToken
            );
            pb.inheritIO();
            int code = pb.start().waitFor();
            if (code != 0) throw new IllegalStateException("Loader exit " + code);
        } catch (InterruptedException | IOException e) {
            throw new RuntimeException(e);
        }

        int updated = riskCalc.recalcForDomainTree(fqdn);
        System.out.println("Risk updated in " + updated + " domains");

        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(warehouseUrl + "?fqdn=" + fqdn))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();
            HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.discarding());
        } catch (Exception ex) {
            System.err.println("Warehouse notify failed " + ex.getMessage());
        }
        return true;
    }
}
