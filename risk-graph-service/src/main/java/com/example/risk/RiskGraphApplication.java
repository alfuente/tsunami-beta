package com.example.risk;

import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.QuarkusApplication;
import io.quarkus.runtime.annotations.QuarkusMain;

@QuarkusMain
public class RiskGraphApplication implements QuarkusApplication {

    public static void main(String[] args) {
        Quarkus.run(RiskGraphApplication.class, args);
    }

    @Override
    public int run(String... args) throws Exception {
        System.out.println("Risk Graph Service started successfully!");
        Quarkus.waitForExit();
        return 0;
    }
}