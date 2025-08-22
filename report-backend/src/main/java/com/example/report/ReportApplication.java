package com.example.report;

import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.QuarkusApplication;
import io.quarkus.runtime.annotations.QuarkusMain;

@QuarkusMain
public class ReportApplication {
    public static void main(String... args) {
        System.out.println("Starting Report Backend Service...");
        Quarkus.run(ReportApp.class, args);
    }

    public static class ReportApp implements QuarkusApplication {
        @Override
        public int run(String... args) throws Exception {
            System.out.println("Report Backend Service started successfully!");
            System.out.println("Swagger UI available at: http://localhost:8082/swagger-ui");
            System.out.println("API Documentation: http://localhost:8082/q/openapi");
            
            Quarkus.waitForExit();
            return 0;
        }
    }
}